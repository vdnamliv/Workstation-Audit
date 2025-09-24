// server/pkg/stepca/enroll_gateway_handler.go
package stepca

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"go.step.sm/crypto/jose"
)

// OTTClaims mô tả payload token do Enroll Gateway ký (IssueOTT trong provisioner.go)
type OTTClaims struct {
	jose.Claims
	SANs []string `json:"sans,omitempty"`
}

// NewEnrollGatewayHandler tạo HTTP handler cho /1.0/sign.
// - issuer: CA issuer để ký CSR
// - verifierKey: public JWK tương ứng với provisioner key của Enroll Gateway (chỉ public)
// - expectedAudience: phải trùng với Audience mà IssueOTT đã set (ví dụ ".../1.0/sign")
// - expectedIssuer: tên provisioner (cfg.Name) mà IssueOTT đã dùng làm "iss"
func NewEnrollGatewayHandler(
	issuer *Issuer,
	verifierKey *jose.JSONWebKey,
	expectedAudience string,
	expectedIssuer string,
) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 1) Lấy Bearer token
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			http.Error(w, "missing bearer token", http.StatusUnauthorized)
			return
		}
		token := strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))

		// 2) Parse + verify chữ ký
		parsed, err := jose.ParseSigned(token)
		if err != nil {
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}
		if verifierKey == nil || verifierKey.Key == nil {
			http.Error(w, "verifier key not configured", http.StatusInternalServerError)
			return
		}

		var claims OTTClaims
		// Verify signature + decode claims
		if err := parsed.Claims(verifierKey.Key, &claims); err != nil {
			http.Error(w, "bad token signature", http.StatusUnauthorized)
			return
		}

		// 3) Validate standard claims (time/aud/iss)
		if err := claims.Validate(jose.Expected{
			Issuer:   expectedIssuer,
			Audience: jose.Audience{expectedAudience},
			Time:     time.Now(),
		}); err != nil {
			http.Error(w, fmt.Sprintf("claims invalid: %v", err), http.StatusUnauthorized)
			return
		}

		// 4) Đọc CSR từ body (hỗ trợ raw PEM hoặc JSON {"csr":"-----BEGIN ..."})
		csrPEM, err := readCSRPEM(r.Body)
		if err != nil {
			http.Error(w, fmt.Sprintf("read csr: %v", err), http.StatusBadRequest)
			return
		}

		// Parse CSR để so khớp SANs/Subject với token
		csrBlock, _ := pem.Decode(csrPEM)
		if csrBlock == nil || !strings.Contains(csrBlock.Type, "CERTIFICATE REQUEST") {
			http.Error(w, "csr pem invalid", http.StatusBadRequest)
			return
		}
		csr, err := x509.ParseCertificateRequest(csrBlock.Bytes)
		if err != nil {
			http.Error(w, fmt.Sprintf("parse csr: %v", err), http.StatusBadRequest)
			return
		}
		if err := csr.CheckSignature(); err != nil {
			http.Error(w, fmt.Sprintf("csr signature invalid: %v", err), http.StatusBadRequest)
			return
		}

		// 5) Ràng buộc danh tính: mọi SAN trong CSR phải nằm trong claims.SANs (+ Subject)
		if err := enforceSANBinding(&claims, csr); err != nil {
			http.Error(w, fmt.Sprintf("san/subject mismatch: %v", err), http.StatusUnauthorized)
			return
		}

		// 6) Ký cert
		certPEM, err := issuer.SignCSR(csr)
		if err != nil {
			http.Error(w, fmt.Sprintf("sign csr: %v", err), http.StatusInternalServerError)
			return
		}

		// 7) Trả JSON: cert + CA + expires_at
		resp := map[string]string{
			"certificate": string(certPEM),
			"ca":          string(issuer.BundlePEM()),
			"expires_at":  expiryRFC3339(claims.Expiry),
			"subject":     subjectString(csr),
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})
}

// readCSRPEM hỗ trợ body ở 2 dạng:
// - Raw PEM
// - JSON: {"csr":"-----BEGIN CERTIFICATE REQUEST-----\n...\n-----END CERTIFICATE REQUEST-----\n"}
func readCSRPEM(body io.ReadCloser) ([]byte, error) {
	defer body.Close()
	all, err := io.ReadAll(body)
	if err != nil {
		return nil, err
	}
	raw := strings.TrimSpace(string(all))
	if raw == "" {
		return nil, errors.New("empty body")
	}
	// Nếu có vẻ là JSON
	if strings.HasPrefix(raw, "{") {
		var in struct {
			CSR string `json:"csr"`
		}
		if err := json.Unmarshal([]byte(raw), &in); err != nil {
			return nil, fmt.Errorf("parse json: %w", err)
		}
		return []byte(in.CSR), nil
	}
	// Mặc định coi là PEM
	return []byte(raw), nil
}

func expiryRFC3339(nd *jose.NumericDate) string {
	if nd == nil {
		return ""
	}
	return nd.Time().UTC().Format(time.RFC3339)
}

func subjectString(csr *x509.CertificateRequest) string {
	return csr.Subject.String()
}

// enforceSANBinding yêu cầu mọi SAN trong CSR phải xuất hiện trong (claims.SANs ∪ {claims.Subject})
func enforceSANBinding(claims *OTTClaims, csr *x509.CertificateRequest) error {
	allowed := make(map[string]struct{}, len(claims.SANs)+1)
	allowed[strings.TrimSpace(claims.Subject)] = struct{}{}
	for _, s := range claims.SANs {
		s = strings.TrimSpace(s)
		if s != "" {
			allowed[s] = struct{}{}
		}
	}

	// Subject CN (nếu có)
	if cn := strings.TrimSpace(csr.Subject.CommonName); cn != "" {
		if _, ok := allowed[cn]; !ok {
			return fmt.Errorf("CN %q not allowed by token", cn)
		}
	}

	// DNS
	for _, dns := range csr.DNSNames {
		if _, ok := allowed[dns]; !ok {
			return fmt.Errorf("DNS SAN %q not allowed by token", dns)
		}
	}
	// IP
	for _, ip := range csr.IPAddresses {
		if _, ok := allowed[ip.String()]; !ok {
			return fmt.Errorf("IP SAN %q not allowed by token", ip.String())
		}
	}
	// Email
	for _, em := range csr.EmailAddresses {
		if _, ok := allowed[em]; !ok {
			return fmt.Errorf("Email SAN %q not allowed by token", em)
		}
	}
	// URI
	for _, u := range csr.URIs {
		u2 := u.String()
		if _, ok := allowed[u2]; !ok {
			// Cho phép dạng host-only cho các URI dạng spiffe://host
			host := strings.TrimSpace(u.Host)
			if host == "" || !isHostAllowed(host, allowed) {
				return fmt.Errorf("URI SAN %q not allowed by token", u2)
			}
		}
	}
	return nil
}

func isHostAllowed(host string, allowed map[string]struct{}) bool {
	// Cho phép kiểm host thuần nếu token cấp host (tuỳ nhu cầu, có thể bỏ)
	_, ok := allowed[host]
	return ok
}
