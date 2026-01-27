package main

import (
	"log"
	"os"
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
		log.Println("Using Certificate")

	default:
		log.Fatalf("Unknown subcommand: %s. Use 'approle <role>' or 'cert'", subcommand)
	}
}
