package stepca

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"go.step.sm/crypto/jose"
	"go.step.sm/crypto/randutil"
)

// TokenProvisioner issues one-time tokens so agents can request certificates from step-ca.
type TokenProvisioner interface {
	IssueOTT(subject string, sans []string) (token string, expiresAt time.Time, err error)
	Audience() string
	Name() string
}

// JWKConfig captures the parameters required to load a JWK-based provisioner key.
type JWKConfig struct {
	Name     string
	KeyPath  string
	Password string
	Audience string
	TTL      time.Duration
}

type jwkProvisioner struct {
	name     string
	audience string
	ttl      time.Duration
	signer   jose.Signer
}

// LoadJWKProvisioner initialises a TokenProvisioner backed by a JWK private key file.
// The key file can be a raw JWK (JSON), a JWE blob encrypted with the provided password,
// or a Step-CA ca.json containing the provisioner definition. If the configuration is
// incomplete the function returns nil without error so callers can treat Step-CA as optional.
func LoadJWKProvisioner(cfg JWKConfig) (TokenProvisioner, error) {
	if cfg.Name == "" || cfg.KeyPath == "" || cfg.Audience == "" {
		return nil, nil
	}
	if cfg.TTL <= 0 {
		cfg.TTL = 5 * time.Minute
	}

	jwk, err := loadProvisionerKey(cfg.KeyPath, cfg.Password, cfg.Name)
	if err != nil {
		return nil, err
	}
	if jwk.IsPublic() {
		return nil, errors.New("stepca: provisioner key must contain a private key")
	}

	alg := jose.SignatureAlgorithm(jwk.Algorithm)
	if alg == "" {
		if inferred := inferJWKAlgorithm(jwk); inferred != "" {
			alg = inferred
		} else {
			return nil, errors.New("stepca: unable to infer signing algorithm for provisioner key")
		}
	}

	if jwk.KeyID == "" {
		if kid, err := jose.Thumbprint(jwk); err == nil {
			jwk.KeyID = kid
		}
	}

	opts := new(jose.SignerOptions).WithType("JWT")
	if jwk.KeyID != "" {
		opts = opts.WithHeader("kid", jwk.KeyID)
	}

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: jwk.Key}, opts)
	if err != nil {
		return nil, fmt.Errorf("stepca: init signer: %w", err)
	}

	audience := strings.TrimRight(cfg.Audience, "/")
	return &jwkProvisioner{
		name:     cfg.Name,
		audience: audience,
		ttl:      cfg.TTL,
		signer:   signer,
	}, nil
}

func (p *jwkProvisioner) IssueOTT(subject string, sans []string) (string, time.Time, error) {
	subject = strings.TrimSpace(subject)
	if subject == "" {
		return "", time.Time{}, errors.New("stepca: subject required for OTT")
	}
	now := time.Now().UTC()
	expires := now.Add(p.ttl)

	id, err := randutil.ASCII(48)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("stepca: rand id: %w", err)
	}

	sans = append([]string{subject}, sans...)
	sans = dedupeStrings(sans)

	claims := struct {
		jose.Claims
		SANs []string `json:"sans,omitempty"`
	}{
		Claims: jose.Claims{
			ID:        id,
			Subject:   subject,
			Issuer:    p.name,
			NotBefore: jose.NewNumericDate(now),
			Expiry:    jose.NewNumericDate(expires),
			Audience:  []string{p.audience},
		},
		SANs: sans,
	}

	token, err := jose.Signed(p.signer).Claims(claims).CompactSerialize()
	if err != nil {
		return "", time.Time{}, fmt.Errorf("stepca: sign ott: %w", err)
	}
	return token, expires, nil
}

func (p *jwkProvisioner) Audience() string { return p.audience }

func (p *jwkProvisioner) Name() string { return p.name }

func loadProvisionerKey(path, password, provisionerName string) (*jose.JSONWebKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("stepca: read provisioner key: %w", err)
	}

	if jwk, ok, err := parseProvisionerKeyData(data, password); err != nil {
		return nil, err
	} else if ok {
		return jwk, nil
	}

	jwk, err := extractProvisionerFromCAConfig(path, data, provisionerName, password)
	if err != nil {
		return nil, err
	}
	if jwk != nil {
		return jwk, nil
	}
	return nil, errors.New("stepca: unable to parse provisioner key")
}

func parseProvisionerKeyData(data []byte, password string) (*jose.JSONWebKey, bool, error) {
	raw := strings.TrimSpace(string(data))
	if raw == "" {
		return nil, false, errors.New("stepca: empty provisioner key")
	}

	type stored struct {
		Key          *jose.JSONWebKey `json:"key"`
		EncryptedKey string           `json:"encryptedKey"`
	}
	var container stored
	if err := json.Unmarshal([]byte(raw), &container); err == nil {
		if container.EncryptedKey != "" {
			jwk, err := decryptProvisionerJWE(container.EncryptedKey, password)
			if err != nil {
				return nil, false, err
			}
			return jwk, true, nil
		}
		if container.Key != nil && container.Key.Key != nil && !container.Key.IsPublic() {
			return container.Key, true, nil
		}
	}

	if password != "" && !strings.HasPrefix(raw, "{") {
		if jwk, err := decryptProvisionerJWE(raw, password); err == nil {
			return jwk, true, nil
		}
	}

	var jwk jose.JSONWebKey
	if err := json.Unmarshal([]byte(raw), &jwk); err == nil && jwk.Key != nil && !jwk.IsPublic() {
		return &jwk, true, nil
	}

	return nil, false, nil
}

func extractProvisionerFromCAConfig(path string, data []byte, provisionerName, password string) (*jose.JSONWebKey, error) {
	var cfg struct {
		Authority struct {
			Type         string `json:"type"`
			Provisioners []struct {
				Name         string           `json:"name"`
				Type         string           `json:"type"`
				Key          *jose.JSONWebKey `json:"key"`
				EncryptedKey string           `json:"encryptedKey"`
				KeyID        string           `json:"kid"`
			} `json:"provisioners"`
		} `json:"authority"`
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("stepca: unable to parse provisioner key: %w", err)
	}
	if cfg.Authority.Type == "" && len(cfg.Authority.Provisioners) == 0 {
		return nil, errors.New("stepca: unable to parse provisioner key")
	}
	if provisionerName == "" {
		return nil, errors.New("stepca: provisioner name required for ca.json lookup")
	}
	for _, prov := range cfg.Authority.Provisioners {
		if prov.Name != provisionerName {
			continue
		}
		if prov.Type != "" && !strings.EqualFold(prov.Type, "JWK") {
			return nil, fmt.Errorf("stepca: provisioner %s is type %s, expected JWK", provisionerName, prov.Type)
		}
		if prov.EncryptedKey != "" {
			jwk, err := decryptProvisionerJWE(prov.EncryptedKey, password)
			if err != nil {
				return nil, fmt.Errorf("stepca: decrypt provisioner key: %w", err)
			}
			if prov.KeyID != "" && jwk.KeyID == "" {
				jwk.KeyID = prov.KeyID
			}
			return jwk, nil
		}
		if prov.Key != nil && prov.Key.Key != nil && !prov.Key.IsPublic() {
			return prov.Key, nil
		}
		return nil, fmt.Errorf("stepca: provisioner %s missing key material", provisionerName)
	}
	return nil, fmt.Errorf("stepca: provisioner %s not found in %s", provisionerName, path)
}

func decryptProvisionerJWE(payload, password string) (*jose.JSONWebKey, error) {
	if strings.TrimSpace(password) == "" {
		return nil, errors.New("stepca: password required to decrypt provisioner key")
	}
	decrypted, err := jose.Decrypt([]byte(strings.TrimSpace(payload)), jose.WithPassword([]byte(password)))
	if err != nil {
		return nil, err
	}
	var jwk jose.JSONWebKey
	if err := json.Unmarshal(decrypted, &jwk); err != nil {
		return nil, fmt.Errorf("stepca: parse decrypted provisioner key: %w", err)
	}
	if jwk.Key == nil {
		return nil, errors.New("stepca: decrypted provisioner key is empty")
	}
	return &jwk, nil
}

func inferJWKAlgorithm(jwk *jose.JSONWebKey) jose.SignatureAlgorithm {
	switch key := jwk.Key.(type) {
	case *ecdsa.PrivateKey:
		switch key.Curve {
		case elliptic.P256():
			return jose.ES256
		case elliptic.P384():
			return jose.ES384
		case elliptic.P521():
			return jose.ES512
		}
	case *rsa.PrivateKey:
		return jose.RS256
	case ed25519.PrivateKey:
		return jose.EdDSA
	}
	return ""
}

func dedupeStrings(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}
