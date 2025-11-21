package tlsclient

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"time"
)

type Client = http.Client

type Certificate = tls.Certificate

type CertificateRequestInfo = tls.CertificateRequestInfo

type Options struct {
	CAPool               *x509.CertPool
	ClientCertificates   []tls.Certificate
	GetClientCertificate func(*tls.CertificateRequestInfo) (*tls.Certificate, error)
}

// NewWithOptions builds an HTTP client using the provided TLS options.
func NewWithOptions(opts Options) (*Client, error) {
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	// Dùng CAPool nếu có
	if opts.CAPool != nil {
		tlsCfg.RootCAs = opts.CAPool
	}

	// Dùng cert do step-CA cấp
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

// Convenience helper: build client with just one cert + CAPool
func New(cert tls.Certificate, caPool *x509.CertPool) (*Client, error) {
	opts := Options{
		CAPool:             caPool,
		ClientCertificates: []tls.Certificate{cert},
	}
	return NewWithOptions(opts)
}
