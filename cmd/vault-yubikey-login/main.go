package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/go-piv/piv-go/v2/piv"
	intpiv "github.com/stsch9/vault-yubikey-login/internal/piv"
)

func main() {
	args := os.Args[1:]

	// Validierung: Genau ein Subcommand erforderlich
	if len(args) < 1 {
		log.Fatal("Usage: vault-yubikey-login (approle <role>|cert)")
	}

	subcommand := args[0]

	switch subcommand {
	case "approle":
		if len(args) < 2 {
			log.Fatal("Usage: vault-yubikey-login approle <role>")
		}
		if len(args) > 2 {
			log.Fatal("approle takes exactly one argument")
		}
		appRole := args[1]
		log.Printf("Using AppRole: %s\n", appRole)

	case "cert":
		if len(args) > 1 {
			log.Fatal("cert does not take any arguments")
		}

		loginCert()

	default:
		log.Fatalf("Unknown subcommand: %s. Use 'approle <role>' or 'cert'", subcommand)
	}
}

func loginCert() {
	yk, err := intpiv.OpenYK()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening YubiKey: %v\n", err)
		os.Exit(1)
	}

	cert, err := yk.Certificate(piv.SlotAuthentication)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading certificate: %v\n", err)
		os.Exit(1)
	}

	pin, err := intpiv.GetPINFromInput()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading PIN: %v\n", err)
		os.Exit(1)
	}

	auth := piv.KeyAuth{PIN: pin}

	pub, err := intpiv.GetPublicKey(yk, piv.SlotAuthentication)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting public key: %v\n", err)
		os.Exit(1)
	}

	priv, err := yk.PrivateKey(piv.SlotAuthentication, pub, auth)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting private key: %v\n", err)
		os.Exit(1)
	}

	var certTLS tls.Certificate
	certTLS.PrivateKey = priv
	certTLS.Leaf = cert
	certTLS.Certificate = [][]byte{cert.Raw}

	caCert, _ := os.ReadFile("./vault-ca.pem")
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:      caCertPool,
				Certificates: []tls.Certificate{certTLS},
			},
		},
	}

	resp, err := client.Post("https://localhost:8200/v1/auth/cert/login", "application/json", strings.NewReader(`{"name": "web"}`))
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	fmt.Printf("Response Status: %s\n", resp.Status)
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(body))
}
