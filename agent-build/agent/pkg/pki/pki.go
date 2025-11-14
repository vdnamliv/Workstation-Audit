//go:build windows

package pki

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

//
// ==== Interface (common) ====
//

// KeyHandle abstracts an OS-backed private key (non-exportable) and public cert storage.
type KeyHandle interface {
	Signer() (crypto.Signer, error)
	LoadCertChain() ([]*x509.Certificate, error)
	InstallLeaf(certPEM []byte) error
}

//
// ==== NCrypt P/Invoke ====
//

const (
	providerMSKSP             = "Microsoft Software Key Storage Provider"
	algRSA                    = "RSA"
	NCRYPT_PAD_PKCS1_FLAG     = 0x00000002
	NCRYPT_MACHINE_KEY_FLAG   = 0x00000020
	NCRYPT_OVERWRITE_KEY_FLAG = 0x00000080
	NCRYPT_LENGTH_PROPERTY    = "Length"
)

var (
	ncrypt                = windows.NewLazySystemDLL("ncrypt.dll")
	procNCryptOpenStorage = ncrypt.NewProc("NCryptOpenStorageProvider")
	procNCryptCreateKey   = ncrypt.NewProc("NCryptCreatePersistedKey")
	procNCryptFinalizeKey = ncrypt.NewProc("NCryptFinalizeKey")
	procNCryptOpenKey     = ncrypt.NewProc("NCryptOpenKey")
	procNCryptSetProperty = ncrypt.NewProc("NCryptSetProperty")
	procNCryptSignHash    = ncrypt.NewProc("NCryptSignHash")
	procNCryptFreeObject  = ncrypt.NewProc("NCryptFreeObject")
)

type ncryptProv windows.Handle
type ncryptKey windows.Handle

func nErr(r uintptr) error {
	if r == 0 {
		return nil
	}
	return windows.Errno(r)
}

func nOpenProvider(name string) (ncryptProv, error) {
	var h windows.Handle
	pname, _ := windows.UTF16PtrFromString(name)
	r, _, _ := procNCryptOpenStorage.Call(
		uintptr(unsafe.Pointer(&h)),
		uintptr(unsafe.Pointer(pname)),
		0,
	)
	return ncryptProv(h), nErr(r)
}

func nSetProp(handle uintptr, prop string, data unsafe.Pointer, size uint32, flags uint32) error {
	pProp, _ := windows.UTF16PtrFromString(prop)
	r, _, _ := procNCryptSetProperty.Call(
		handle,
		uintptr(unsafe.Pointer(pProp)),
		uintptr(data),
		uintptr(size),
		uintptr(flags),
	)
	return nErr(r)
}

func nCreateKey(p ncryptProv, alg, name string, machineScope bool, overwrite bool) (ncryptKey, error) {
	var h windows.Handle
	pAlg, _ := windows.UTF16PtrFromString(alg)
	pName, _ := windows.UTF16PtrFromString(name)
	flags := uint32(0)
	if machineScope {
		flags |= NCRYPT_MACHINE_KEY_FLAG
	}
	if overwrite {
		flags |= NCRYPT_OVERWRITE_KEY_FLAG
	}
	r, _, _ := procNCryptCreateKey.Call(
		uintptr(p),
		uintptr(unsafe.Pointer(&h)),
		uintptr(unsafe.Pointer(pAlg)),
		uintptr(unsafe.Pointer(pName)),
		uintptr(flags),
	)
	return ncryptKey(h), nErr(r)
}

func nFinalizeKey(k ncryptKey) error {
	r, _, _ := procNCryptFinalizeKey.Call(uintptr(k), 0)
	return nErr(r)
}

func nOpenKey(p ncryptProv, name string, machineScope bool) (ncryptKey, error) {
	var h windows.Handle
	pName, _ := windows.UTF16PtrFromString(name)
	flags := uint32(0)
	if machineScope {
		flags |= NCRYPT_MACHINE_KEY_FLAG
	}
	r, _, _ := procNCryptOpenKey.Call(
		uintptr(p),
		uintptr(unsafe.Pointer(&h)),
		uintptr(unsafe.Pointer(pName)),
		0,
		uintptr(flags),
	)
	return ncryptKey(h), nErr(r)
}

func nSignHash(k ncryptKey, hash []byte, hashOID asn1.ObjectIdentifier) ([]byte, error) {
	type paddingInfo struct {
		AlgID *uint16
	}
	algId := map[string]string{
		asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}.String(): "SHA256",
		asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}.String(): "SHA384",
		asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}.String(): "SHA512",
		asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}.String():             "SHA1",
	}[hashOID.String()]
	if algId == "" {
		return nil, errors.New("unsupported hash OID")
	}
	pAlg, _ := windows.UTF16PtrFromString(algId)
	pad := paddingInfo{AlgID: pAlg}

	var sigLen uint32
	r, _, _ := procNCryptSignHash.Call(
		uintptr(k),
		uintptr(unsafe.Pointer(&pad)),
		uintptr(unsafe.Pointer(&hash[0])),
		uintptr(len(hash)),
		0,
		0,
		uintptr(unsafe.Pointer(&sigLen)),
		uintptr(NCRYPT_PAD_PKCS1_FLAG),
	)
	if err := nErr(r); err != nil {
		return nil, err
	}
	sig := make([]byte, sigLen)
	r, _, _ = procNCryptSignHash.Call(
		uintptr(k),
		uintptr(unsafe.Pointer(&pad)),
		uintptr(unsafe.Pointer(&hash[0])),
		uintptr(len(hash)),
		uintptr(unsafe.Pointer(&sig[0])),
		uintptr(sigLen),
		uintptr(unsafe.Pointer(&sigLen)),
		uintptr(NCRYPT_PAD_PKCS1_FLAG),
	)
	if err := nErr(r); err != nil {
		return nil, err
	}
	return sig[:sigLen], nil
}

//
// ==== Windows KSP Wrapper ====
//

type softwareKSPKey struct {
	prov ncryptProv
	key  ncryptKey
	mu   sync.Mutex
	pub  crypto.PublicKey
	name string
}

func openOrCreateSoftwareKey(container string, bits int) (*softwareKSPKey, error) {
	prov, err := nOpenProvider(providerMSKSP)
	if err != nil {
		return nil, fmt.Errorf("open provider: %w", err)
	}

	key, err := nOpenKey(prov, container, true)
	if err != nil {
		key, err = nCreateKey(prov, algRSA, container, true, false)
		if err != nil {
			return nil, fmt.Errorf("create key: %w", err)
		}
		if err := nSetProp(uintptr(key), NCRYPT_LENGTH_PROPERTY, unsafe.Pointer(&bits), 4, 0); err != nil {
			return nil, err
		}
		if err := nFinalizeKey(key); err != nil {
			return nil, err
		}
	}
	k := &softwareKSPKey{prov: prov, key: key, name: container}
	k.pub, _ = k.exportPublic()
	return k, nil
}

func (k *softwareKSPKey) Public() crypto.PublicKey { return k.pub }

func (k *softwareKSPKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	oid, ok := hashOIDFromSignerOpts(opts)
	if !ok {
		return nil, errors.New("unsupported hash")
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	return nSignHash(k.key, digest, oid)
}

func (k *softwareKSPKey) exportPublic() (crypto.PublicKey, error) {
	tmpl := &x509.CertificateRequest{}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, tmpl, k)
	if err != nil {
		return nil, err
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, err
	}
	return csr.PublicKey, nil
}

//
// ==== KeyHandle Implementation ====
//

type WinSoftKSPHandle struct {
	keyContainer string
	key          *softwareKSPKey
	certPath     string
}

func OpenPlatformKey(container string) (KeyHandle, error) {
	k, err := openOrCreateSoftwareKey(container, 2048)
	if err != nil {
		return nil, err
	}
	base := filepath.Join(os.Getenv("ProgramData"), "VT Agent", "pki")
	if err := os.MkdirAll(base, 0o700); err != nil {
		if la := os.Getenv("LocalAppData"); la != "" {
			base = filepath.Join(la, "VT Agent", "pki")
			_ = os.MkdirAll(base, 0o700)
		}
	}
	return &WinSoftKSPHandle{
		keyContainer: container,
		key:          k,
		certPath:     filepath.Join(base, "client.crt"),
	}, nil
}

func (h *WinSoftKSPHandle) Signer() (crypto.Signer, error) { return h.key, nil }

func (h *WinSoftKSPHandle) LoadCertChain() ([]*x509.Certificate, error) {
	b, err := os.ReadFile(h.certPath)
	if err != nil {
		return nil, err
	}
	var certs []*x509.Certificate
	for {
		block, rest := pem.Decode(b)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			c, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, err
			}
			certs = append(certs, c)
		}
		b = rest
	}
	if len(certs) == 0 {
		return nil, errors.New("no certs found")
	}
	return certs, nil
}

func (h *WinSoftKSPHandle) InstallLeaf(certPEM []byte) error {
	tmp := h.certPath + ".tmp"
	if err := os.WriteFile(tmp, certPEM, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, h.certPath)
}

//
// ==== Helpers ====
//

func hashOIDFromSignerOpts(opts crypto.SignerOpts) (asn1.ObjectIdentifier, bool) {
	switch opts.HashFunc() {
	case crypto.SHA256:
		return asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}, true
	case crypto.SHA384:
		return asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}, true
	case crypto.SHA512:
		return asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}, true
	case crypto.SHA1:
		return asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}, true
	default:
		return nil, false
	}
}
