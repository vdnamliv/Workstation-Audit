// agent/pkg/enroll/enroll.go
package enroll

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
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
	"os"
	"path/filepath"
	"strings"
)

const (
	bootstrapURL      = "https://gateway.local/agent/bootstrap/ott"
	defaultStepCASign = "https://gateway.local/step-ca/1.0/sign"
	certDir           = "data/certs"
	certFile          = "agent.crt"
	keyFile           = "agent.key"
	caFile            = "ca.pem"
	bootstrapTokenEnv = "VT_AGENT_BOOTSTRAP_TOKEN"
)

type bootstrapResp struct {
	Token     string `json:"token,omitempty"`
	OTT       string `json:"ott,omitempty"`
	StepCAURL string `json:"stepca_url,omitempty"`
	CAPEM     string `json:"ca_pem,omitempty"`
}

// CertMaterial represents the client certificate and trusted CA bundle on disk.
type CertMaterial struct {
	Certificate *tls.Certificate
	CA          *x509.CertPool
}

// EnsureCertificate checks the local cache and, if missing, bootstraps a new mTLS certificate.
func EnsureCertificate(ctx context.Context, bootstrapToken string) (*CertMaterial, error) {
	certPath := filepath.Join(certDir, certFile)
	keyPath := filepath.Join(certDir, keyFile)
	caPath := filepath.Join(certDir, caFile)

	if _, err := os.Stat(certPath); err == nil {
		cert, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err == nil {
			pool := x509.NewCertPool()
			if caBytes, err := os.ReadFile(caPath); err == nil {
				_ = pool.AppendCertsFromPEM(caBytes)
			}
			return &CertMaterial{Certificate: &cert, CA: pool}, nil
		}
	}

	if strings.TrimSpace(bootstrapToken) == "" {
		bootstrapToken = os.Getenv(bootstrapTokenEnv)
	}
	if strings.TrimSpace(bootstrapToken) == "" {
		return nil, errors.New("bootstrap token required; set --bootstrap-token or VT_AGENT_BOOTSTRAP_TOKEN")
	}

	subject := hostname()
	resp, err := fetchBootstrapJWT(ctx, subject, bootstrapToken)
	if err != nil {
		return nil, fmt.Errorf("fetch bootstrap jwt: %w", err)
	}

	token := resp.Token
	if token == "" {
		token = resp.OTT
	}
	if token == "" {
		return nil, errors.New("bootstrap response did not include an OTT")
	}

	signURL := defaultStepCASign
	if strings.TrimSpace(resp.StepCAURL) != "" {
		signURL = strings.TrimRight(resp.StepCAURL, "/") + "/1.0/sign"
	}

	priv, csrDER, err := generateCSR()
	if err != nil {
		return nil, fmt.Errorf("generate csr: %w", err)
	}

	certPEM, err := requestCert(signURL, token, csrDER)
	if err != nil {
		return nil, fmt.Errorf("request cert: %w", err)
	}

	if err := os.MkdirAll(certDir, 0o755); err != nil {
		return nil, err
	}

	der, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("marshal EC private key: %w", err)
	}

	keyOut, err := os.OpenFile(keyPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open key file: %w", err)
	}
	defer keyOut.Close()
	if err := pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: der}); err != nil {
		return nil, fmt.Errorf("encode key pem: %w", err)
	}

	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		return nil, err
	}

	if resp.CAPEM != "" {
		if err := os.WriteFile(caPath, []byte(resp.CAPEM), 0o644); err != nil {
			return nil, err
		}
	}

	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}

	pool := x509.NewCertPool()
	if resp.CAPEM != "" {
		_ = pool.AppendCertsFromPEM([]byte(resp.CAPEM))
	} else if caBytes, err := os.ReadFile(caPath); err == nil {
		_ = pool.AppendCertsFromPEM(caBytes)
	}

	return &CertMaterial{Certificate: &cert, CA: pool}, nil
}

func fetchBootstrapJWT(ctx context.Context, subject, bootstrapToken string) (bootstrapResp, error) {
	payload := map[string]any{
		"subject":         subject,
		"sans":            []string{subject},
		"bootstrap_token": bootstrapToken,
	}
	body, _ := json.Marshal(payload)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, bootstrapURL, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return bootstrapResp{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return bootstrapResp{}, fmt.Errorf("bootstrap failed: %s", resp.Status)
	}

	var out bootstrapResp
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return bootstrapResp{}, err
	}
	return out, nil
}

func generateCSR() (*ecdsa.PrivateKey, []byte, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   hostname(),
			Organization: []string{"VTAgent"},
		},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, priv)
	if err != nil {
		return nil, nil, err
	}
	return priv, csrDER, nil
}

func requestCert(signURL, jwt string, csrDER []byte) ([]byte, error) {
	body := map[string]any{
		"csr": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})),
		"ott": jwt,
	}
	b, _ := json.Marshal(body)

	req, _ := http.NewRequest(http.MethodPost, signURL, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		slurp, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("sign failed: %s - %s", resp.Status, string(slurp))
	}
	return io.ReadAll(resp.Body)
}

func hostname() string {
	h, _ := os.Hostname()
	if h == "" {
		return "unknown-agent"
	}
	return h
}
