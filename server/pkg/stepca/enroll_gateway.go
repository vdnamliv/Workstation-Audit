// server/pkg/stepca/enroll_gateway.go
package stepca

import (
	"encoding/json"
	"net/http"
	"time"
)

// EnrollRequest là payload agent gửi để xin OTT
type EnrollRequest struct {
	Subject string   `json:"subject"`
	SANs    []string `json:"sans,omitempty"`
}

// EnrollResponse là response trả về cho agent
type EnrollResponse struct {
	Token     string `json:"token"`
	ExpiresAt string `json:"expires_at"`
	Issuer    string `json:"issuer"`
	Audience  string `json:"audience"`
	StepCAURL string `json:"stepca_url,omitempty"`
}

// NewEnrollGatewayHandler tạo HTTP handler cho endpoint /api/enroll
// Nó dùng TokenProvisioner (được init bằng provisioner.go) để sinh OTT cho agent.
func NewEnrollGatewayHandler(prov TokenProvisioner, externalURL string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req EnrollRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
		if req.Subject == "" {
			http.Error(w, "subject required", http.StatusBadRequest)
			return
		}

		token, exp, err := prov.IssueOTT(req.Subject, req.SANs)
		if err != nil {
			http.Error(w, "failed to issue OTT: "+err.Error(), http.StatusInternalServerError)
			return
		}

		resp := EnrollResponse{
			Token:     token,
			ExpiresAt: exp.UTC().Format(time.RFC3339),
			Issuer:    prov.Name(),
			Audience:  prov.Audience(),
			StepCAURL: externalURL,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})
}
