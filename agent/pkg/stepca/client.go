//go:build windows
// +build windows

package stepca

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"vt-audit/agent/pkg/pki"
)

const (
	storeName        = "MY"
	keyContainerName = "VTAgent-Client"

	certEncoding = windows.X509_ASN_ENCODING | windows.PKCS_7_ASN_ENCODING
	renewLeeway  = 12 * time.Hour
)

var (
	errNotFound = errors.New("stepca: certificate not found")
	errExpired  = errors.New("stepca: certificate expiring soon")
)

// Client handles lifecycle of the agent's mTLS certificate backed by the Windows cert store.
type Client struct {
	httpClient     *http.Client
	serverURL      string
	subject        string
	bootstrapToken string
	stepcaURL      string

	signer crypto.Signer

	renewBefore time.Duration

	mu      sync.Mutex
	tlsCert *tls.Certificate
	caPool  *x509.CertPool
}

// New creates a StepCA client that will request client certificates tied to the machine key store.
func New(httpClient *http.Client, serverURL, subject, bootstrapToken string) (*Client, error) {
	if httpClient == nil {
		return nil, errors.New("stepca: http client required")
	}
	serverURL = strings.TrimRight(strings.TrimSpace(serverURL), "/")
	if serverURL == "" {
		return nil, errors.New("stepca: server url required")
	}
	subject = strings.TrimSpace(subject)
	if subject == "" {
		return nil, errors.New("stepca: subject required")
	}

	keyHandle, err := pki.OpenPlatformKey(keyContainerName)
	if err != nil {
		return nil, fmt.Errorf("stepca: open key: %w", err)
	}
	signer, err := keyHandle.Signer()
	if err != nil {
		return nil, fmt.Errorf("stepca: signer: %w", err)
	}

	return &Client{
		httpClient:     httpClient,
		serverURL:      serverURL,
		subject:        subject,
		bootstrapToken: strings.TrimSpace(bootstrapToken),
		signer:         signer,
		renewBefore:    renewLeeway,
	}, nil
}

// Ensure returns a valid client certificate, issuing a new one if the existing certificate is missing or near expiry.
func (c *Client) Ensure(ctx context.Context) (*tls.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.tlsCert != nil && c.tlsCert.Leaf != nil && time.Until(c.tlsCert.Leaf.NotAfter) > c.renewBefore {
		return c.tlsCert, nil
	}

	if cert, err := c.loadFromStore(); err == nil {
		c.tlsCert = cert
		return cert, nil
	} else if !errors.Is(err, errNotFound) && !errors.Is(err, errExpired) {
		return nil, err
	}

	cert, err := c.issue(ctx)
	if err != nil {
		return nil, err
	}
	c.tlsCert = cert
	return cert, nil
}

// CAPool returns the CA pool provided during the last issuance (if any).
func (c *Client) CAPool() *x509.CertPool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.caPool == nil {
		return nil
	}
	return c.caPool.Clone()
}

func (c *Client) loadFromStore() (*tls.Certificate, error) {
	store, err := openCertStore(true)
	if err != nil {
		return nil, err
	}
	defer windows.CertCloseStore(store, 0)

	ctx, err := findCertificate(store, c.subject)
	if ctx == nil {
		if err == nil {
			err = errNotFound
		} else if errors.Is(err, windows.Errno(windows.CRYPT_E_NOT_FOUND)) {
			err = errNotFound
		}
		return nil, err
	}
	defer windows.CertFreeCertificateContext(ctx)

	der := dupCertDER(ctx)
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("stepca: parse stored certificate: %w", err)
	}
	if time.Until(leaf.NotAfter) <= c.renewBefore {
		return nil, errExpired
	}
	tlsCert := &tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  c.signer,
		Leaf:        leaf,
	}
	return tlsCert, nil
}

func (c *Client) issue(ctx context.Context) (*tls.Certificate, error) {
	csrPEM, err := c.buildCSR()
	if err != nil {
		return nil, err
	}

	info, err := c.requestBootstrap(ctx, []string{c.subject})
	if err != nil {
		return nil, err
	}
	if info.StepCAURL != "" {
		c.stepcaURL = info.StepCAURL
	}
	if info.CAPEM != "" {
		c.updateCAPool(info.CAPEM)
	}

	leaf, chain, caPEM, err := c.requestStepCACertificate(ctx, csrPEM, info.OTT)
	if err != nil {
		return nil, err
	}

	if err := storeCertificate(chain[0], c.subject); err != nil {
		return nil, err
	}

	tlsCert := &tls.Certificate{
		Certificate: chain,
		PrivateKey:  c.signer,
		Leaf:        leaf,
	}

	if caPEM != "" {
		c.updateCAPool(caPEM)
	}

	return tlsCert, nil
}

type bootstrapResponse struct {
	OTT       string `json:"ott"`
	StepCAURL string `json:"stepca_url"`
	CAPEM     string `json:"ca_pem"`
	ExpiresAt string `json:"expires_at"`
}

func (c *Client) requestBootstrap(ctx context.Context, sans []string) (*bootstrapResponse, error) {
	body := map[string]any{
		"subject":         c.subject,
		"sans":            sans,
		"bootstrap_token": c.bootstrapToken,
	}
	b, _ := json.Marshal(body)
	url := c.serverURL + "/bootstrap/ott"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return nil, fmt.Errorf("stepca: bootstrap request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("stepca: bootstrap post: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("stepca: bootstrap failed: %s: %s", resp.Status, strings.TrimSpace(string(msg)))
	}
	var out bootstrapResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("stepca: bootstrap decode: %w", err)
	}
	if strings.TrimSpace(out.OTT) == "" {
		return nil, errors.New("stepca: bootstrap response missing ott")
	}
	return &out, nil
}

func (c *Client) requestStepCACertificate(ctx context.Context, csrPEM []byte, ott string) (*x509.Certificate, [][]byte, string, error) {
	if strings.TrimSpace(ott) == "" {
		return nil, nil, "", errors.New("stepca: ott required")
	}
	if c.stepcaURL == "" {
		c.stepcaURL = deriveStepCAURL(c.serverURL)
	}
	if c.stepcaURL == "" {
		return nil, nil, "", errors.New("stepca: missing step-ca endpoint")
	}
	signURL := strings.TrimRight(c.stepcaURL, "/") + "/1.0/sign"
	body := map[string]any{
		"csr": string(csrPEM),
		"ott": ott,
	}
	b, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, signURL, bytes.NewReader(b))
	if err != nil {
		return nil, nil, "", fmt.Errorf("stepca: sign request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, nil, "", fmt.Errorf("stepca: sign call: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, nil, "", fmt.Errorf("stepca: sign failed: %s: %s", resp.Status, strings.TrimSpace(string(msg)))
	}
	var out struct {
		ServerPEM string   `json:"crt"`
		CAPEM     string   `json:"ca"`
		CertChain []string `json:"certChain"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, nil, "", fmt.Errorf("stepca: sign decode: %w", err)
	}
	if strings.TrimSpace(out.ServerPEM) == "" {
		return nil, nil, "", errors.New("stepca: empty certificate response")
	}
	leaf, chain, err := parseCertificatePEM(out.ServerPEM)
	if err != nil {
		return nil, nil, "", err
	}
	seen := make(map[string]struct{}, len(chain))
	for _, der := range chain {
		seen[string(der)] = struct{}{}
	}
	for _, pemStr := range out.CertChain {
		if strings.TrimSpace(pemStr) == "" {
			continue
		}
		_, extra, err := parseCertificatePEM(pemStr)
		if err != nil {
			return nil, nil, "", err
		}
		for _, der := range extra {
			key := string(der)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			chain = append(chain, der)
		}
	}
	return leaf, chain, out.CAPEM, nil
}

func (c *Client) updateCAPool(pem string) {
	if strings.TrimSpace(pem) == "" {
		return
	}
	pool := x509.NewCertPool()
	if pool.AppendCertsFromPEM([]byte(pem)) {
		c.caPool = pool
	}
}

func deriveStepCAURL(agentURL string) string {
	u, err := url.Parse(agentURL)
	if err != nil {
		return ""
	}
	segments := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(segments) == 0 || segments[0] == "" {
		u.Path = "/step-ca"
		return u.String()
	}
	segments[len(segments)-1] = "step-ca"
	u.Path = "/" + strings.Join(segments, "/")
	return u.String()
}

func (c *Client) buildCSR() ([]byte, error) {
	tmpl := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: c.subject,
		},
		DNSNames: []string{c.subject},
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, tmpl, c.signer)
	if err != nil {
		return nil, fmt.Errorf("stepca: create csr: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr}), nil
}

func openCertStore(readOnly bool) (windows.Handle, error) {
	namePtr, err := windows.UTF16PtrFromString(storeName)
	if err != nil {
		return 0, fmt.Errorf("stepca: store name: %w", err)
	}
	flags := uint32(windows.CERT_SYSTEM_STORE_LOCAL_MACHINE | windows.CERT_STORE_OPEN_EXISTING_FLAG)
	if readOnly {
		flags |= windows.CERT_STORE_READONLY_FLAG
	}
	handle, err := windows.CertOpenStore(windows.CERT_STORE_PROV_SYSTEM_W, 0, 0, flags, uintptr(unsafe.Pointer(namePtr)))
	if err != nil {
		return 0, fmt.Errorf("stepca: open cert store: %w", err)
	}
	return handle, nil
}

func findCertificate(store windows.Handle, subject string) (*windows.CertContext, error) {
	subjectPtr, err := windows.UTF16PtrFromString(subject)
	if err != nil {
		return nil, fmt.Errorf("stepca: subject utf16: %w", err)
	}
	ctx, err := windows.CertFindCertificateInStore(store, certEncoding, 0, windows.CERT_FIND_SUBJECT_STR, unsafe.Pointer(subjectPtr), nil)
	if ctx == nil {
		if err == nil {
			err = windows.Errno(windows.CRYPT_E_NOT_FOUND)
		}
		return nil, err
	}
	return ctx, nil
}

func dupCertDER(ctx *windows.CertContext) []byte {
	if ctx == nil || ctx.Length == 0 || ctx.EncodedCert == nil {
		return nil
	}
	data := unsafe.Slice(ctx.EncodedCert, int(ctx.Length))
	out := make([]byte, len(data))
	copy(out, data)
	return out
}

func storeCertificate(leafDER []byte, subject string) error {
	if len(leafDER) == 0 {
		return errors.New("stepca: empty certificate der")
	}
	store, err := openCertStore(false)
	if err != nil {
		return err
	}
	defer windows.CertCloseStore(store, 0)

	if err := purgeSubject(store, subject); err != nil {
		return err
	}

	ctx, err := windows.CertCreateCertificateContext(certEncoding, &leafDER[0], uint32(len(leafDER)))
	if err != nil {
		return fmt.Errorf("stepca: create cert context: %w", err)
	}
	defer windows.CertFreeCertificateContext(ctx)

	if err := windows.CertAddCertificateContextToStore(store, ctx, windows.CERT_STORE_ADD_NEW, nil); err != nil {
		if errors.Is(err, windows.Errno(windows.CRYPT_E_EXISTS)) {
			if err := windows.CertAddCertificateContextToStore(store, ctx, windows.CERT_STORE_ADD_REPLACE_EXISTING, nil); err != nil {
				return fmt.Errorf("stepca: replace cert in store: %w", err)
			}
			return nil
		}
		return fmt.Errorf("stepca: add cert to store: %w", err)
	}
	return nil
}

func purgeSubject(store windows.Handle, subject string) error {
	subjectPtr, err := windows.UTF16PtrFromString(subject)
	if err != nil {
		return fmt.Errorf("stepca: subject utf16: %w", err)
	}
	for {
		ctx, err := windows.CertFindCertificateInStore(store, certEncoding, 0, windows.CERT_FIND_SUBJECT_STR, unsafe.Pointer(subjectPtr), nil)
		if ctx == nil {
			if err == nil || errors.Is(err, windows.Errno(windows.CRYPT_E_NOT_FOUND)) {
				return nil
			}
			return fmt.Errorf("stepca: purge find: %w", err)
		}
		if err := windows.CertDeleteCertificateFromStore(ctx); err != nil {
			return fmt.Errorf("stepca: delete cert: %w", err)
		}
	}
}

func parseCertificatePEM(pemData string) (*x509.Certificate, [][]byte, error) {
	rest := []byte(pemData)
	var chain [][]byte
	for {
		block, remaining := pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			rest = remaining
			continue
		}
		der := make([]byte, len(block.Bytes))
		copy(der, block.Bytes)
		chain = append(chain, der)
		rest = remaining
	}
	if len(chain) == 0 {
		return nil, nil, errors.New("stepca: empty certificate pem")
	}
	leaf, err := x509.ParseCertificate(chain[0])
	if err != nil {
		return nil, nil, fmt.Errorf("stepca: parse leaf: %w", err)
	}
	return leaf, chain, nil
}
