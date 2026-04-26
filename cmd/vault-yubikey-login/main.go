// https://github.com/keys-pub/go-libfido2?tab=readme-ov-file#dependencies

package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-piv/piv-go/v2/piv"
	"github.com/stsch9/vault-yubikey-login/internal/fido2"
	intpiv "github.com/stsch9/vault-yubikey-login/internal/piv"
)

func main() {
	args := os.Args[1:]

	// Validierung: Genau ein Subcommand erforderlich
	if len(args) < 1 {
		log.Fatal("Usage: vault-yubikey-login (approle <secretIdFile> <identityFile> |cert [certRole])")
	}

	subcommand := args[0]

	switch subcommand {
	case "approle":
		if len(args) < 3 {
			log.Fatal("Usage: vault-yubikey-login approle <secretIdFile> <identityFile>")
		}
		if len(args) > 3 {
			log.Fatal("approle takes exactly two arguments: secretIdFile identityFile")
		}
		secretIdFile := args[1]
		identityFile := args[2]
		log.Printf("Using AppRole: %s\n", secretIdFile)

		loginAppRole(secretIdFile, identityFile)

	case "cert":
		if len(args) > 2 {
			log.Fatal("cert takes at most one argument: certRole")
		}

		certRole := ""
		if len(args) == 2 {
			certRole = args[1]
		}
		log.Printf("Using cert role: %s\n", certRole)

		loginCert(certRole)

	default:
		log.Fatalf("Unknown subcommand: %s. Use 'approle <role>' or 'cert [certRole]'", subcommand)
	}
}

func loginCert(certRole string) {
	vaultAddr := os.Getenv("VAULT_ADDR")
	if vaultAddr == "" {
		fmt.Fprintf(os.Stderr, "Error: VAULT_ADDR environment variable not set\n")
		os.Exit(1)
	}

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

	var caCertPool *x509.CertPool

	caCertPath := os.Getenv("VAULT_CACERT")
	if caCertPath != "" {
		caCert, err := os.ReadFile(caCertPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading CA certificate: %v\n", err)
			os.Exit(1)
		}
		caCertPool = x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:      caCertPool,
				Certificates: []tls.Certificate{certTLS},
			},
		},
	}

	reqBody, err := json.Marshal(map[string]string{"name": certRole})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating request body: %v\n", err)
		os.Exit(1)
	}

	resp, err := client.Post(vaultAddr+"/v1/auth/cert/login", "application/json", strings.NewReader(string(reqBody)))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error Vault login: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "Vault login failed: %s\n", resp.Status)
		if len(body) > 0 {
			fmt.Fprintf(os.Stderr, "Response body: %s\n", string(body))
		}
		os.Exit(1)
	}

	fmt.Printf("Response Status: %s\n", resp.Status)

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading response body: %v\n", err)
		os.Exit(1)
	}

	var jsonData interface{}
	err = json.Unmarshal(body, &jsonData)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing JSON response: %v\n", err)
		os.Exit(1)
	}

	//prettyJSON, err := json.MarshalIndent(jsonData, "", "  ")
	//if err != nil {
	//	fmt.Fprintf(os.Stderr, "Error formatting JSON: %v\n", err)
	//	os.Exit(1)
	//}
	//fmt.Println(string(prettyJSON))

	// Extract and save the client token
	jsonMap, ok := jsonData.(map[string]interface{})
	if !ok {
		fmt.Fprintf(os.Stderr, "Error: response is not a JSON object\n")
		os.Exit(1)
	}

	jsonAuth, ok := jsonMap["auth"].(map[string]interface{})
	if !ok {
		fmt.Fprintf(os.Stderr, "Error: no auth field in response\n")
		os.Exit(1)
	}

	clientToken, ok := jsonAuth["client_token"].(string)
	if !ok || clientToken == "" {
		fmt.Fprintf(os.Stderr, "Error: no client_token in response\n")
		os.Exit(1)
	}

	// Write token to ~/.vault-token with permissions 0600
	homeDir, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting home directory: %v\n", err)
		os.Exit(1)
	}

	tokenPath := filepath.Join(homeDir, ".vault-token")
	err = os.WriteFile(tokenPath, []byte(clientToken), 0600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error writing token to %s: %v\n", tokenPath, err)
		os.Exit(1)
	}

	fmt.Printf("Token saved to %s\n", tokenPath)
}

func loginAppRole(secretIdFile string, identityFile string) {
	vaultAddr := os.Getenv("VAULT_ADDR")
	if vaultAddr == "" {
		fmt.Fprintf(os.Stderr, "Error: VAULT_ADDR environment variable not set\n")
		os.Exit(1)
	}

	roleID := os.Getenv("APPROLE_ROLE_ID")
	if roleID == "" {
		fmt.Fprintf(os.Stderr, "Error: APPROLE_ROLE_ID environment variable not set\n")
		os.Exit(1)
	}

	rawIdentity, err := os.ReadFile(identityFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading identity file: %v\n", err)
		os.Exit(1)
	}
	// only use the first line, trimming any trailing newline/carriage return
	identity := strings.TrimRight(strings.SplitN(string(rawIdentity), "\n", 2)[0], "\r")

	secretIdAge, err := os.Open(secretIdFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open secretId file: %v\n", err)
		os.Exit(1)
	}
	defer secretIdAge.Close()

	secretId, err := fido2.AgeFido2PrfDec(secretIdAge, string(identity))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to decrypt secretId file: %v\n", err)
		os.Exit(1)
	}

	var caCertPool *x509.CertPool

	caCertPath := os.Getenv("VAULT_CACERT")
	if caCertPath != "" {
		caCert, err := os.ReadFile(caCertPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading CA certificate: %v\n", err)
			os.Exit(1)
		}
		caCertPool = x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: caCertPool,
			},
		},
	}

	reqBody, err := json.Marshal(map[string]string{"role_id": roleID, "secret_id": secretId.String()})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating request body: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(roleID)
	fmt.Println(secretId.String())

	resp, err := client.Post(vaultAddr+"/v1/auth/approle/login", "application/json", strings.NewReader(string(reqBody)))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error Vault login: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "Vault login failed: %s\n", resp.Status)
		if len(body) > 0 {
			fmt.Fprintf(os.Stderr, "Response body: %s\n", string(body))
		}
		os.Exit(1)
	}

	fmt.Printf("Response Status: %s\n", resp.Status)

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading response body: %v\n", err)
		os.Exit(1)
	}

	var jsonData interface{}
	err = json.Unmarshal(body, &jsonData)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing JSON response: %v\n", err)
		os.Exit(1)
	}

	// Extract and save the client token
	jsonMap, ok := jsonData.(map[string]interface{})
	if !ok {
		fmt.Fprintf(os.Stderr, "Error: response is not a JSON object\n")
		os.Exit(1)
	}

	jsonAuth, ok := jsonMap["auth"].(map[string]interface{})
	if !ok {
		fmt.Fprintf(os.Stderr, "Error: no auth field in response\n")
		os.Exit(1)
	}

	clientToken, ok := jsonAuth["client_token"].(string)
	if !ok || clientToken == "" {
		fmt.Fprintf(os.Stderr, "Error: no client_token in response\n")
		os.Exit(1)
	}

	// Write token to ~/.vault-token with permissions 0600
	homeDir, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting home directory: %v\n", err)
		os.Exit(1)
	}

	tokenPath := filepath.Join(homeDir, ".vault-token")
	err = os.WriteFile(tokenPath, []byte(clientToken), 0600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error writing token to %s: %v\n", tokenPath, err)
		os.Exit(1)
	}

	fmt.Printf("Token saved to %s\n", tokenPath)
}
