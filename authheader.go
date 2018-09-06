package ntlm

import (
	"encoding/base64"
	"fmt"
	"strings"
)

type authheader []string

func (h authheader) IsBasic() bool {
	for _, s := range h {
		if strings.HasPrefix(s, `Basic`) {
			return true
		}
	}
	return false
}

func (h authheader) IsNegotiate() bool {
	for _, s := range h {
		if strings.HasPrefix(s, `Negotiate`) {
			return true
		}
	}
	return false
}

func (h authheader) IsNTLM() bool {
	for _, s := range h {
		if strings.HasPrefix(s, `NTLM`) {
			return true
		}
	}
	return false
}

func (h authheader) GetData() ([]byte, error) {
	for _, s := range h {
		if !strings.HasPrefix(s, `NTLM`) {
			continue
		}
		p := strings.Split(s, " ")
		if len(p) < 2 {
			return nil, nil
		}
		return base64.StdEncoding.DecodeString(string(p[1]))
	}
	return nil, fmt.Errorf(`No NTLM auth header found`)
}
