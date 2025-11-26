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
	_ "embed"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

const (
	certDir  = "data/certs"
	certFile = "agent.crt"
	keyFile  = "agent.key"
	caFile   = "ca.pem"
)

// Embedded CA certificate - này sẽ được compile vào trong binary
// Không cần user phải cài đặt certificate thủ công
//
//go:embed ca_cert.pem
var embeddedCACert []byte

type enrollResp struct {
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

// EnsureCertificate checks the local cache and, if missing, auto-enrolls a new mTLS certificate.
func EnsureCertificate(ctx context.Context) (*CertMaterial, error) {
	// Use default localhost URL - main.go will call EnsureCertificateWithServer directly
	serverURL := "https://localhost:443"
	return EnsureCertificateWithServer(ctx, serverURL)
}

// EnsureCertificateWithServer allows specifying the server base URL
func EnsureCertificateWithServer(ctx context.Context, serverBaseURL string) (*CertMaterial, error) {
	certPath := filepath.Join(certDir, certFile)
	keyPath := filepath.Join(certDir, keyFile)
	caPath := filepath.Join(certDir, caFile)

	if _, err := os.Stat(certPath); err == nil {
		cert, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err == nil {
			// Always use embedded CA certificate for trust
			pool := x509.NewCertPool()
			pool.AppendCertsFromPEM(embeddedCACert)

			// Also load cached CA if exists (for backwards compatibility)
			if caBytes, err := os.ReadFile(caPath); err == nil {
				_ = pool.AppendCertsFromPEM(caBytes)
			}
			return &CertMaterial{Certificate: &cert, CA: pool}, nil
		}
	}

	subject := hostname()
	// Determine enrollment URL based on server address
	// Remove /agent suffix to get base URL that matches nginx routes
	// Example: https://localhost:443/agent -> https://localhost:443/api/enroll
	baseURL := strings.TrimSuffix(serverBaseURL, "/agent")
	baseURL = strings.TrimSuffix(baseURL, "/")
	enrollURL := baseURL + "/api/enroll"

	log.Printf("Enrollment URL: %s", enrollURL)
	resp, err := fetchEnrollmentOTT(ctx, subject, enrollURL)
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

	// Remove /agent suffix to construct Step-CA sign URL via nginx proxy
	// Example: https://localhost:443/agent -> https://localhost:443/step-ca/1.0/sign
	// Reuse baseURL from enrollment (already has /agent removed)
	// ALWAYS use nginx proxy route instead of direct Step-CA connection
	signURL := baseURL + "/step-ca/1.0/sign"

	log.Printf("Attempting to sign certificate via nginx proxy: %s", signURL)

	priv, csrDER, err := generateCSR()
	if err != nil {
		return nil, fmt.Errorf("generate csr: %w", err)
	}

	certPEM, caPEM, err := requestCert(signURL, token, csrDER)
	if err != nil {
		return nil, fmt.Errorf("request cert: %w", err)
	}

	// Set CA PEM from Step-CA response
	resp.CAPEM = caPEM

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

	// Always use embedded CA certificate as the primary trust anchor
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(embeddedCACert)

	// Also add server-provided CA if available
	if resp.CAPEM != "" {
		_ = pool.AppendCertsFromPEM([]byte(resp.CAPEM))
	} else if caBytes, err := os.ReadFile(caPath); err == nil {
		_ = pool.AppendCertsFromPEM(caBytes)
	}

	return &CertMaterial{Certificate: &cert, CA: pool}, nil
}

func fetchEnrollmentOTT(ctx context.Context, subject, enrollURL string) (enrollResp, error) {
	payload := map[string]any{
		"subject": subject,
		"sans":    []string{subject},
	}
	body, _ := json.Marshal(payload)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, enrollURL, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	// Use embedded CA certificate for HTTPS validation
	// This allows the agent to trust the server's self-signed certificate
	// without requiring manual certificate installation on the client machine
	var client *http.Client
	if strings.HasPrefix(enrollURL, "https://") {
		// Create CA pool from embedded certificate
		caPool := x509.NewCertPool()
		if !caPool.AppendCertsFromPEM(embeddedCACert) {
			log.Printf("Warning: Failed to parse embedded CA certificate, using system CA pool")
		}

		client = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs: caPool, // Trust our embedded CA
				},
			},
		}
	} else {
		// Plain HTTP - no TLS config needed
		client = &http.Client{}
	}

	resp, err := client.Do(req)
	if err != nil {
		return enrollResp{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return enrollResp{}, fmt.Errorf("enrollment failed: %s", resp.Status)
	}

	var out enrollResp
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return enrollResp{}, err
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

func requestCert(signURL, jwt string, csrDER []byte) ([]byte, string, error) {
	body := map[string]any{
		"csr": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})),
		"ott": jwt,
	}
	b, _ := json.Marshal(body)

	req, _ := http.NewRequest(http.MethodPost, signURL, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")

	// Use embedded CA certificate for certificate signing request
	// This ensures secure communication even during initial enrollment
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(embeddedCACert) {
		log.Printf("Warning: Failed to parse embedded CA certificate for signing request")
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: caPool, // Trust our embedded CA
			},
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		slurp, _ := io.ReadAll(resp.Body)
		return nil, "", fmt.Errorf("sign failed: %s - %s", resp.Status, string(slurp))
	}

	// Parse JSON response from Step-CA
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", fmt.Errorf("error reading response body: %w", err)
	}

	var signResp struct {
		Certificate string   `json:"crt"`
		CA          string   `json:"ca"`
		CertChain   []string `json:"certChain"`
	}

	if err := json.Unmarshal(respBody, &signResp); err != nil {
		return nil, "", fmt.Errorf("error parsing JSON response: %w", err)
	}

	if signResp.Certificate == "" {
		return nil, "", fmt.Errorf("certificate not found in response")
	}

	// Return both certificate and CA
	return []byte(signResp.Certificate), signResp.CA, nil
}

func hostname() string {
	h, _ := os.Hostname()
	if h == "" {
		return "unknown-agent"
	}
	return h
}
