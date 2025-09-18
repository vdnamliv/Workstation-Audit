package tlsclient

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"
)

type Client = http.Client

type Certificate = tls.Certificate

type CertificateRequestInfo = tls.CertificateRequestInfo

type Options struct {
	CAFile               string
	CAPool               *x509.CertPool
	InsecureSkipVerify   bool
	ClientCertificates   []tls.Certificate
	GetClientCertificate func(*tls.CertificateRequestInfo) (*tls.Certificate, error)
}

// New t?o http.Client v?i CA pinning (??a ???ng d?n caFile) v? tu? ch?n skip verify (lab).
func New(caFile string, insecureSkipVerify bool) (*Client, error) {
	return NewWithOptions(Options{CAFile: caFile, InsecureSkipVerify: insecureSkipVerify})
}

// NewWithOptions builds an HTTP client using the provided TLS options.
func NewWithOptions(opts Options) (*Client, error) {
	tlsCfg := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: opts.InsecureSkipVerify,
	}

	var rootPool *x509.CertPool
	if opts.CAPool != nil && !opts.InsecureSkipVerify {
		rootPool = opts.CAPool
	}
	if opts.CAFile != "" && !opts.InsecureSkipVerify {
		pem, err := os.ReadFile(opts.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read ca file: %w", err)
		}
		if rootPool != nil {
			rootPool = rootPool.Clone()
		} else {
			rootPool = x509.NewCertPool()
		}
		if !rootPool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("bad CA pem")
		}
	}
	if rootPool != nil && !opts.InsecureSkipVerify {
		tlsCfg.RootCAs = rootPool
	}

	if len(opts.ClientCertificates) > 0 {
		tlsCfg.Certificates = append([]tls.Certificate(nil), opts.ClientCertificates...)
	}
	if opts.GetClientCertificate != nil {
		tlsCfg.GetClientCertificate = opts.GetClientCertificate
	}

	tr := &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		TLSClientConfig:     tlsCfg,
		TLSHandshakeTimeout: 10 * time.Second,
		DialContext:         (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:   true,
	}
	return &http.Client{
		Transport: tr,
		Timeout:   60 * time.Second,
	}, nil
}
