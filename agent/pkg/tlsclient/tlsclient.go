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

// New tạo http.Client với CA pinning (đưa đường dẫn caFile) và tuỳ chọn skip verify (lab).
func New(caFile string, insecureSkipVerify bool) (*Client, error) {
	tlsCfg := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: insecureSkipVerify, // chỉ dùng lab
	}
	if caFile != "" && !insecureSkipVerify {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("read ca file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("bad CA pem")
		}
		tlsCfg.RootCAs = pool
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
