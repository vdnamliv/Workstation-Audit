package stepca

import (
    "crypto"
    "crypto/ecdsa"
    "crypto/ed25519"
    "crypto/rand"
    "crypto/rsa"
    "crypto/x509"
    "encoding/pem"
    "errors"
    "fmt"
    "math/big"
    "os"
    "time"
)

// Issuer handles signing client certificates for agents.
type Issuer struct {
    caCert *x509.Certificate
    caPEM  []byte
    signer crypto.Signer
    ttl    time.Duration
    pool   *x509.CertPool
}

// LoadIssuer loads a CA certificate/key pair from disk.
func LoadIssuer(caCertPath, caKeyPath string, ttl time.Duration) (*Issuer, error) {
    if caCertPath == "" || caKeyPath == "" {
        return nil, errors.New("ca cert/key required")
    }
    certPEM, err := os.ReadFile(caCertPath)
    if err != nil {
        return nil, fmt.Errorf("read ca cert: %w", err)
    }
    block, _ := pem.Decode(certPEM)
    if block == nil {
        return nil, errors.New("invalid CA certificate PEM")
    }
    caCert, err := x509.ParseCertificate(block.Bytes)
    if err != nil {
        return nil, fmt.Errorf("parse ca cert: %w", err)
    }
    keyPEM, err := os.ReadFile(caKeyPath)
    if err != nil {
        return nil, fmt.Errorf("read ca key: %w", err)
    }
    signer, err := parsePrivateKey(keyPEM)
    if err != nil {
        return nil, fmt.Errorf("parse ca key: %w", err)
    }
    if ttl <= 0 {
        ttl = 24 * time.Hour
    }
    pool := x509.NewCertPool()
    if !pool.AppendCertsFromPEM(certPEM) {
        return nil, errors.New("failed to build CA pool")
    }
    return &Issuer{
        caCert: caCert,
        caPEM:  certPEM,
        signer: signer,
        ttl:    ttl,
        pool:   pool,
    }, nil
}

// SignCSR signs a CSR and returns a PEM encoded certificate.
func (i *Issuer) SignCSR(csr *x509.CertificateRequest) ([]byte, error) {
    if csr == nil {
        return nil, errors.New("csr nil")
    }
    if err := csr.CheckSignature(); err != nil {
        return nil, fmt.Errorf("csr signature: %w", err)
    }
    serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
    if err != nil {
        return nil, fmt.Errorf("serial: %w", err)
    }
    usage := x509.KeyUsageDigitalSignature
    if _, ok := csr.PublicKey.(*rsa.PublicKey); ok {
        usage |= x509.KeyUsageKeyEncipherment
    }
    tmpl := &x509.Certificate{
        SerialNumber: serial,
        Subject:      csr.Subject,
        DNSNames:     csr.DNSNames,
        IPAddresses:  csr.IPAddresses,
        URIs:         csr.URIs,
        EmailAddresses: csr.EmailAddresses,
        NotBefore:      time.Now().Add(-5 * time.Minute),
        NotAfter:       time.Now().Add(i.ttl),
        KeyUsage:       usage,
        ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
    }
    certDER, err := x509.CreateCertificate(rand.Reader, tmpl, i.caCert, csr.PublicKey, i.signer)
    if err != nil {
        return nil, fmt.Errorf("sign cert: %w", err)
    }
    return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), nil
}

// SignCSRPEM decodes a PEM CSR and signs it.
func (i *Issuer) SignCSRPEM(csrPEM []byte) ([]byte, error) {
    block, _ := pem.Decode(csrPEM)
    if block == nil {
        return nil, errors.New("csr pem invalid")
    }
    csr, err := x509.ParseCertificateRequest(block.Bytes)
    if err != nil {
        return nil, fmt.Errorf("parse csr: %w", err)
    }
    return i.SignCSR(csr)
}

// BundlePEM returns the CA chain PEM used to issue certs.
func (i *Issuer) BundlePEM() []byte { return i.caPEM }

// Pool returns an x509 cert pool with the CA certificate.
func (i *Issuer) Pool() *x509.CertPool { return i.pool }

func parsePrivateKey(pemBytes []byte) (crypto.Signer, error) {
    for {
        var block *pem.Block
        block, pemBytes = pem.Decode(pemBytes)
        if block == nil {
            break
        }
        switch block.Type {
        case "EC PRIVATE KEY":
            key, err := x509.ParseECPrivateKey(block.Bytes)
            if err != nil {
                return nil, err
            }
            return key, nil
        case "PRIVATE KEY":
            pk, err := x509.ParsePKCS8PrivateKey(block.Bytes)
            if err != nil {
                return nil, err
            }
            switch v := pk.(type) {
            case *rsa.PrivateKey:
                return v, nil
            case *ecdsa.PrivateKey:
                return v, nil
            case ed25519.PrivateKey:
                return v, nil
            default:
                return nil, fmt.Errorf("unsupported pkcs8 key: %T", v)
            }
        case "RSA PRIVATE KEY":
            key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
            if err != nil {
                return nil, err
            }
            return key, nil
        }
    }
    return nil, errors.New("no private key found in PEM")
}