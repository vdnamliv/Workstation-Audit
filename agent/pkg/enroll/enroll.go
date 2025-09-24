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
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
)

// Config constants (có thể move sang config/global)
const (
	bootstrapURL = "https://gateway.local/bootstrap"
	stepCAURL    = "https://stepca:9000/1.0/sign" // nội bộ Docker, agent sẽ gọi qua nginx nếu bạn reverse proxy
	certDir      = "data/certs"
	certFile     = "agent.crt"
	keyFile      = "agent.key"
)

// bootstrapResp là JWT do Enroll Gateway trả về
type bootstrapResp struct {
	Token string `json:"token"`
}

// CertMaterial lưu private key + cert được cấp
type CertMaterial struct {
	Certificate *tls.Certificate
	CA          *x509.CertPool
}

// EnsureCertificate kiểm tra cert local, nếu chưa có thì bootstrap → xin cert → lưu
func EnsureCertificate(ctx context.Context) (*CertMaterial, error) {
	// 1. check nếu đã tồn tại cert local
	certPath := filepath.Join(certDir, certFile)
	keyPath := filepath.Join(certDir, keyFile)

	if _, err := os.Stat(certPath); err == nil {
		cert, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err == nil {
			pool := x509.NewCertPool()
			// agent cần trust CA của step-ca, bạn có thể load từ file ca.crt nếu mount vào
			return &CertMaterial{Certificate: &cert, CA: pool}, nil
		}
	}

	// 2. Gọi Enroll Gateway để lấy OTT JWT
	jwt, err := fetchBootstrapJWT()
	if err != nil {
		return nil, fmt.Errorf("fetch bootstrap jwt: %w", err)
	}

	// 3. Sinh private key + CSR
	priv, csrDER, err := generateCSR()
	if err != nil {
		return nil, fmt.Errorf("generate csr: %w", err)
	}

	// 4. Gửi CSR + JWT đến step-CA để lấy cert
	certPEM, err := requestCert(jwt, csrDER)
	if err != nil {
		return nil, fmt.Errorf("request cert: %w", err)
	}

	// 5. Save cert + key ra disk
	if err := os.MkdirAll(certDir, 0o755); err != nil {
		return nil, err
	}
	// Marshal private key ra DER
	der, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("marshal EC private key: %w", err)
	}

	keyOut, _ := os.Create(keyPath)
	defer keyOut.Close()
	if err := pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: der}); err != nil {
		return nil, fmt.Errorf("encode key pem: %w", err)
	}

	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		return nil, err
	}

	// 6. Load lại thành tls.Certificate
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}

	pool := x509.NewCertPool()
	return &CertMaterial{Certificate: &cert, CA: pool}, nil
}

// fetchBootstrapJWT gọi Enroll Gateway /bootstrap
func fetchBootstrapJWT() (string, error) {
	req, _ := http.NewRequest("GET", bootstrapURL, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return "", fmt.Errorf("bootstrap failed: %s", resp.Status)
	}
	var out bootstrapResp
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	if out.Token == "" {
		return "", fmt.Errorf("empty bootstrap token")
	}
	return out.Token, nil
}

// generateCSR sinh private key + CSR DER
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

// requestCert gửi CSR + OTT JWT tới step-CA
func requestCert(jwt string, csrDER []byte) ([]byte, error) {
	body := map[string]any{
		"csr": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})),
		"ott": jwt,
	}
	b, _ := json.Marshal(body)

	req, _ := http.NewRequest("POST", stepCAURL, bytes.NewReader(b))
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

// hostname helper
func hostname() string {
	h, _ := os.Hostname()
	if h == "" {
		return "unknown-agent"
	}
	return h
}
