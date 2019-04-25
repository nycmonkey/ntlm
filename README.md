# ntlm
#### Authenticate HTTP clients on Windows domains to web services that require NTLM



```go
package main

import (
  "net/http"
  "github.com/nycmonkey/ntlm"
)

func main() {
  client := http.Client{Transport: ntlm.HTTPDomainClientTransport{}}
  // client will transparently negotiate NTLM using the credentials of the account running the program
  resp, err := client.Get(`http://megacorp/protectedPage/foo.html`)
  if err != nil {
    panic(err)
  }
}
```

Note: this is only useful on Windows machines connected to a domain controller like Active Directory.
