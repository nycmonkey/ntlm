// Package ntlm provides an http transport implementation to allow
// Go programs running on enterprise Windows machines to connect
// to NTLM-protected web services. 
//
// Adapted from https://github.com/Azure/go-ntlmssp
package ntlm

import (
	"bytes"
	"encoding/base64"
	"io"
	"io/ioutil"
	"net/http"

	sspintlm "github.com/alexbrainman/sspi/ntlm"
)

// HttpDomainClientTransport can be used as an HTTP
// transport for http clients running on Windows
// machines authenticated to a domain that wish to
// interact with HTTP servers on the same domain
// that require NTLM authentication.
//
// Example:
// client := http.Client{Transport: ntlm.HTTPDomainClientTransport{}}
type HTTPDomainClientTransport struct{ http.RoundTripper }

// RoundTrip implements http.RoundTripper
func (t HTTPDomainClientTransport) RoundTrip(req *http.Request) (res *http.Response, err error) {
	// use default round tripper if not provided
	if t.RoundTripper == nil {
		t.RoundTripper = http.DefaultTransport
	}

	var body bytes.Buffer
	if req.Body != nil {
		_, err = body.ReadFrom(req.Body)
		if err != nil {
			return
		}
		req.Body.Close()
		req.Body = ioutil.NopCloser(bytes.NewReader(body.Bytes()))
	}

	req.Header.Del("Authorization")
	res, err = t.RoundTripper.RoundTrip(req)
	if err != nil || res.StatusCode != http.StatusUnauthorized {
		return
	}

	resauth := authheader(res.Header.Get(`Www-Authenticate`))
	if !resauth.IsNegotiate() && !resauth.IsNTLM() {
		// can't do anymore here
		return
	}

	cred, err := sspintlm.AcquireCurrentUserCredentials()
	if err != nil {
		return
	}
	defer cred.Release()
	secctx, negotiate, err := sspintlm.NewClientContext(cred)
	if err != nil {
		return
	}
	defer secctx.Release()

	if resauth.IsNegotiate() || resauth.IsNTLM() {
		io.Copy(ioutil.Discard, res.Body)
		res.Body.Close()

		if resauth.IsNTLM() {
			req.Header.Set("Authorization", "NTLM "+base64.StdEncoding.EncodeToString(negotiate))
		} else {
			req.Header.Set("Authorization", "Negotiate "+base64.StdEncoding.EncodeToString(negotiate))
		}
		req.Body = ioutil.NopCloser(bytes.NewReader(body.Bytes()))
		res, err = t.RoundTripper.RoundTrip(req)
		if err != nil {
			return
		}

		resauth = authheader(res.Header.Get(`Www-Authenticate`))
		challenge, err := resauth.GetData()
		if err != nil {
			return
		}
		if !(resauth.IsNegotiate() || resauth.IsNTLM() || len(challenge) == 0 {
			return res, fmt.Errorf("NTLM negotiation failed")
		})
		
		io.Copy(ioutil.Discard, res.Body)
		res.Body.Close()

		authMsg, err := secctx.Update(challenge)
		if err != nil {
			return
		}

		if resauth.IsNTLM() {
			req.Header.Set("Authorization", "NTLM "+base64.StdEncoding.EncodeToString(authMsg))
		} else {
			req.Header.Set("Authorization", "Negotiate "+base64.StdEncoding.EncodeToString(authMsg))
		}
		req.Body = ioutil.NopCloser(bytes.NewReader(body.Bytes()))
		res, err = t.RoundTripper.RoundTrip(req)
	}
	return
}
