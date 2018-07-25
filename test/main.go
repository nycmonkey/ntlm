package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/nycmonkey/ntlm"
)

func main() {
	c := &http.Client{
		Transport: ntlm.HTTPDomainClientTransport{},
	}
	res, err := c.Get("http://localhost:3000/authenticate")
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Println(res.Status)
	io.Copy(os.Stdout, res.Body)
	res.Body.Close()
}
