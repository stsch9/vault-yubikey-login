package fido2

import (
	"bytes"
	"fmt"
	"io"
	"syscall"

	"filippo.io/age"
	"filippo.io/typage/fido2prf"
	"golang.org/x/term"
)

func AgeFido2PrfEnc(input io.Reader, out io.WriteCloser, s string) error {
	defer out.Close()

	identity, err := fido2prf.NewIdentity(s, askForPIN)
	if err != nil {
		return fmt.Errorf("could not get identity: %w", err)
	}

	w, err := age.Encrypt(out, identity)
	if err != nil {
		return fmt.Errorf("could not create encrypted writer: %w", err)
	}
	if _, err := io.Copy(w, input); err != nil {
		return fmt.Errorf("could not copy input to encrypted writer: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("could not close encrypted writer: %w", err)
	}

	return nil
}

func AgeFido2PrfDec(input io.Reader, s string) (out *bytes.Buffer, err error) {
	identity, err := fido2prf.NewIdentity(s, askForPIN)
	if err != nil {
		return nil, fmt.Errorf("could not get identity: %w", err)
	}

	r, err := age.Decrypt(input, identity)
	if err != nil {
		return nil, fmt.Errorf("could not create decrypted reader: %w", err)
	}
	out = &bytes.Buffer{}
	if _, err := io.Copy(out, r); err != nil {
		return nil, fmt.Errorf("could not copy decrypted input: %w", err)
	}

	return out, nil
}

func askForPIN() (string, error) {
	fmt.Print("Enter Fido2 PIN: ")
	bytepw, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return "", err
	}
	pass := string(bytepw)

	return pass, nil
}
