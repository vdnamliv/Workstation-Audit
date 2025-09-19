package dashboard

import (
	"context"
	"errors"
	"log"
	"net/http"
	"strings"

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
	provider, err := oidc.NewProvider(context.Background(), s.Cfg.OIDCIssuer)
	if err != nil {
		log.Printf("dashboard: failed to initialise OIDC provider: %v", err)
		return
	}
	s.verifier = provider.Verifier(&oidc.Config{ClientID: s.Cfg.OIDCClientID})
	if s.adminRole == "" {
		s.adminRole = "admin"
	}
	log.Printf("dashboard: OIDC enabled (issuer=%s client=%s)", s.Cfg.OIDCIssuer, s.Cfg.OIDCClientID)
}

func (s *Server) withAuth(role string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.verifier == nil {
			http.Error(w, "oidc not configured", http.StatusUnauthorized)
			return
		}
		principal, err := s.authenticateRequest(r)
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
	header := r.Header.Get("Authorization")
	if header == "" {
		return nil, errors.New("missing authorization header")
	}
	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return nil, errors.New("invalid authorization header")
	}
	idToken, err := s.verifier.Verify(r.Context(), parts[1])
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
