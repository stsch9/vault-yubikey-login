package piv

import (
	"crypto"
	"errors"
	"fmt"
	"syscall"

	"github.com/go-piv/piv-go/v2/piv"
	"golang.org/x/term"
)

func OpenYK() (yk *piv.YubiKey, err error) {
	cards, err := piv.Cards()
	if err != nil {
		return nil, err
	}
	if len(cards) == 0 {
		return nil, errors.New("no YubiKey detected")
	}
	// TODO: support multiple YubiKeys. For now, select the first one that opens
	// successfully, to skip any internal unused smart card readers.
	for _, card := range cards {
		yk, err = piv.Open(card)
		if err == nil {
			return
		}
	}
	return
}

func GetPublicKey(yk *piv.YubiKey, slot piv.Slot) (crypto.PublicKey, error) {
	cert, err := yk.Certificate(slot)
	if err != nil {
		return nil, fmt.Errorf("could not get public key: %w", err)
	}

	return cert.PublicKey, nil
}
func GetPINFromInput() (string, error) {
	fmt.Print("Enter PIN (Press Enter to use the default PIN): ")
	pinBytes, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return "", fmt.Errorf("error reading PIN: %w", err)
	}
	fmt.Println()

	pin := string(pinBytes)
	if pin == "" {
		fmt.Println("No PIN provided, using default PIN")
		pin = piv.DefaultPIN
	}
	fmt.Println(pin)
	return pin, nil
}
