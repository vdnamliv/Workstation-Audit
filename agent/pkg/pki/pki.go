package pki


import (
"crypto"
"crypto/x509"
)


// KeyHandle abstracts an OS-backed private key (non-exportable) and where we persist the public cert.
type KeyHandle interface {
	Signer() (crypto.Signer, error)
	LoadCertChain() ([]*x509.Certificate, error)
	InstallLeaf(certPEM []byte) error
}