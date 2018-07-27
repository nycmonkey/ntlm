// +build !windows

// Package ntlm provides an http transport implementation to allow
// Go programs running on enterprise Windows machines to connect
// to NTLM-protected web services.
//
// Adapted from https://github.com/Azure/go-ntlmssp
//
package ntlm

import (
	"fmt"
	"net/http"
)

// HTTPDomainClientTransport can be used as an HTTP
// transport for http clients that wish to
// interact with HTTP servers that require NTLM
// authentication.
//
// Example:
// client := http.Client{Transport: ntlm.HTTPDomainClientTransport{}}
type HTTPDomainClientTransport struct{ http.RoundTripper }

// RoundTrip implements http.RoundTripper
func (t HTTPDomainClientTransport) RoundTrip(req *http.Request) (res *http.Response, err error) {
	return nil, fmt.Errorf(`sorry, ntlm client is only implemented on Windows`)
}
