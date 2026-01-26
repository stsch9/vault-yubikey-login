package main

import (
	"flag"
	"fmt"
	"os"
)

func encrypt(args []string, loginMethod string) {
	fs := flag.NewFlagSet("encrypt", flag.ExitOnError)
	textFlag := fs.String("text", "", "Text to encrypt")
	keyFlag := fs.String("key", "secret", "Encryption key")

	fs.Parse(args)

	if *textFlag == "" {
		fmt.Println("Error: --text flag is required")
		os.Exit(1)
	}

	// Simple encryption (XOR - nur für Demo)
	encrypted := xorEncrypt(*textFlag, *keyFlag)
	fmt.Printf("Encrypted: %s (using %s authentication)\n", encrypted, loginMethod)
}

func decrypt(args []string, loginMethod string) {
	fs := flag.NewFlagSet("decrypt", flag.ExitOnError)
	textFlag := fs.String("text", "", "Text to decrypt")
	keyFlag := fs.String("key", "secret", "Encryption key")

	fs.Parse(args)

	if *textFlag == "" {
		fmt.Println("Error: --text flag is required")
		os.Exit(1)
	}

	// Simple decryption (XOR - nur für Demo)
	decrypted := xorEncrypt(*textFlag, *keyFlag) // XOR is symmetric
	fmt.Printf("Decrypted: %s (using %s authentication)\n", decrypted, loginMethod)
}

func xorEncrypt(text, key string) string {
	result := ""
	for i, char := range text {
		keyChar := key[i%len(key)]
		result += string(char ^ rune(keyChar))
	}
	return result
}

func main() {
	var login string
	flag.StringVar(&login, "login", "cert", "Login method: cert or approle")
	flag.StringVar(&login, "l", "cert", "Login method: cert or approle")
	flag.Parse()

	if login != "cert" && login != "approle" {
		fmt.Println("Error: -l/--login must be 'cert' or 'approle'")
		os.Exit(1)
	}

	if len(flag.Args()) < 1 {
		fmt.Println("Usage: vaultage-cmd [-l|--login cert|approle] [encrypt|decrypt] [flags]")
		fmt.Println("\nCommands:")
		fmt.Println("  encrypt   Encrypt text")
		fmt.Println("  decrypt   Decrypt text")
		os.Exit(1)
	}

	command := flag.Args()[0]
	args := flag.Args()[1:]

	switch command {
	case "encrypt":
		encrypt(args, login)
	case "decrypt":
		decrypt(args, login)
	default:
		fmt.Printf("Unknown command: %s\n", command)
		os.Exit(1)
	}
}
