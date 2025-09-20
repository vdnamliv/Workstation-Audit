package dashboard

import (
	"context"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

type tokenClaims struct {
	PreferredUsername string `json:"preferred_username"`
	Email             string `json:"email"`
	RealmAccess       struct {
		Roles []string `json:"roles"`
	} `json:"realm_access"`
	ResourceAccess map[string]struct {
		Roles []string `json:"roles"`
	} `json:"resource_access"`
}

type authContextKey string

const principalKey authContextKey = "principal"

func (s *Server) initOIDC() {
	if s.Cfg.OIDCIssuer == "" || s.Cfg.OIDCClientID == "" {
		log.Println("dashboard: OIDC verifier disabled (missing issuer/client id)")
		return
	}
	if s.adminRole == "" {
		s.adminRole = "admin"
	}
	if err := s.loadVerifier(); err != nil {
		log.Printf("dashboard: waiting for OIDC issuer %s: %v", s.Cfg.OIDCIssuer, err)
		go s.pollOIDC()
		return
	}
	log.Printf("dashboard: OIDC enabled (issuer=%s client=%s)", s.Cfg.OIDCIssuer, s.Cfg.OIDCClientID)
}

func (s *Server) loadVerifier() error {
	provider, err := oidc.NewProvider(context.Background(), s.Cfg.OIDCIssuer)
	if err != nil {
		return err
	}
	verifier := provider.Verifier(&oidc.Config{ClientID: s.Cfg.OIDCClientID})
	s.setVerifier(verifier)
	return nil
}

func (s *Server) pollOIDC() {
	backoff := 5 * time.Second
	for {
		time.Sleep(backoff)
		if err := s.loadVerifier(); err != nil {
			log.Printf("dashboard: OIDC still unavailable (issuer=%s): %v", s.Cfg.OIDCIssuer, err)
			if backoff < 30*time.Second {
				backoff *= 2
				if backoff > 30*time.Second {
					backoff = 30 * time.Second
				}
			}
			continue
		}
		log.Printf("dashboard: OIDC enabled (issuer=%s client=%s)", s.Cfg.OIDCIssuer, s.Cfg.OIDCClientID)
		return
	}
}

func (s *Server) setVerifier(v *oidc.IDTokenVerifier) {
	s.verifierMu.Lock()
	s.verifier = v
	s.verifierMu.Unlock()
}

func (s *Server) currentVerifier() *oidc.IDTokenVerifier {
	s.verifierMu.RLock()
	defer s.verifierMu.RUnlock()
	return s.verifier
}

func (s *Server) withAuth(role string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		verifier := s.currentVerifier()
		if verifier == nil {
			http.Error(w, "oidc not configured", http.StatusServiceUnavailable)
			return
		}
		principal, err := s.authenticateRequestWith(verifier, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		if role != "" && !principalHasRole(principal.claims, role, s.Cfg.OIDCClientID) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		ctx := context.WithValue(r.Context(), principalKey, principal)
		next(w, r.WithContext(ctx))
	}
}

func (s *Server) authenticateRequest(r *http.Request) (*authPrincipal, error) {
	verifier := s.currentVerifier()
	if verifier == nil {
		return nil, errors.New("oidc verifier unavailable")
	}
	return s.authenticateRequestWith(verifier, r)
}

func (s *Server) authenticateRequestWith(verifier *oidc.IDTokenVerifier, r *http.Request) (*authPrincipal, error) {
	header := r.Header.Get("Authorization")
	if header == "" {
		return nil, errors.New("missing authorization header")
	}
	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return nil, errors.New("invalid authorization header")
	}
	idToken, err := verifier.Verify(r.Context(), parts[1])
	if err != nil {
		log.Printf("dashboard: token verify failed: %v", err)
		return nil, errors.New("token verification failed")
	}
	var claims tokenClaims
	if err := idToken.Claims(&claims); err != nil {
		log.Printf("dashboard: decode claims failed: %v", err)
		return nil, errors.New("invalid token claims")
	}
	return &authPrincipal{Username: claims.PreferredUsername, Email: claims.Email, claims: claims}, nil
}

type authPrincipal struct {
	Username string
	Email    string
	claims   tokenClaims
}

func principalHasRole(claims tokenClaims, required, clientID string) bool {
	for _, r := range claims.RealmAccess.Roles {
		if r == required {
			return true
		}
	}
	if ra, ok := claims.ResourceAccess[clientID]; ok {
		for _, r := range ra.Roles {
			if r == required {
				return true
			}
		}
	}
	return false
}
