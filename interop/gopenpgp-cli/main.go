// Command gopenpgp-cli drives the GopenPGP library from the command line, so the
// interop matrix can treat it like gpg and sq.
//
//	gopenpgp-cli keygen  --pqc|--classical --uid "r <r@test>" --out-secret k.sec --out-public k.pub
//	gopenpgp-cli encrypt --recipient k.pub --in in.bin --out out.pgp
//	gopenpgp-cli decrypt --key k.sec --in out.pgp --out out.bin
//	gopenpgp-cli version
//
// All key and message files are binary (non-armored). Every failure prints the
// error to stderr and exits with a non-zero code, because a failure is a result.
//
// Adapted from the pqcrypt wrapper in https://github.com/detrin/pqc (MIT License,
// Copyright (c) Daniel Herman), changed to binary I/O and a fixed interface.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"runtime/debug"
	"strings"

	"github.com/ProtonMail/gopenpgp/v3/crypto"
	"github.com/ProtonMail/gopenpgp/v3/profile"
)

const usage = `usage:
  gopenpgp-cli keygen  --pqc|--classical --uid "name <email>" --out-secret FILE --out-public FILE
  gopenpgp-cli encrypt --recipient FILE --in FILE --out FILE
  gopenpgp-cli decrypt --key FILE --in FILE --out FILE
  gopenpgp-cli validate --key FILE
  gopenpgp-cli version`

func main() {
	if len(os.Args) < 2 {
		fail(errors.New(usage))
	}
	var err error
	switch os.Args[1] {
	case "keygen":
		err = keygen(os.Args[2:])
	case "encrypt":
		err = encrypt(os.Args[2:])
	case "decrypt":
		err = decrypt(os.Args[2:])
	case "validate":
		err = validate(os.Args[2:])
	case "version":
		fmt.Println(libraryVersion())
	default:
		err = fmt.Errorf("unknown command %q\n%s", os.Args[1], usage)
	}
	if err != nil {
		fail(err)
	}
}

func validate(args []string) error {
	fs := flag.NewFlagSet("validate", flag.ContinueOnError)
	keyFile := fs.String("key", "", "public certificate or secret key file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *keyFile == "" {
		return errors.New("validate: --key is required")
	}
	if _, err := readKey(*keyFile); err != nil {
		return fmt.Errorf("validate: load key: %w", err)
	}
	return nil
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "gopenpgp-cli:", err)
	os.Exit(1)
}

// libraryVersion reports the GopenPGP module version compiled into this binary.
func libraryVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "gopenpgp unknown"
	}
	for _, dep := range info.Deps {
		if dep.Path == "github.com/ProtonMail/gopenpgp/v3" {
			return "gopenpgp " + dep.Version
		}
	}
	return "gopenpgp unknown"
}

func keygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	pqc := fs.Bool("pqc", false, "post-quantum key (PQC profile: ML-DSA-65+Ed25519 / ML-KEM-768+X25519)")
	classical := fs.Bool("classical", false, "classical key (default profile)")
	uid := fs.String("uid", "", `user ID, "name <email>"`)
	outSecret := fs.String("out-secret", "", "secret key output file")
	outPublic := fs.String("out-public", "", "public cert output file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *pqc == *classical {
		return errors.New("keygen: give exactly one of --pqc or --classical")
	}
	if *uid == "" || *outSecret == "" || *outPublic == "" {
		return errors.New("keygen: --uid, --out-secret and --out-public are required")
	}
	name, email, err := splitUID(*uid)
	if err != nil {
		return err
	}

	// The classical key uses the library default profile rather than RFC9580, so that
	// it is a v4 key every tool can read. That keeps the classical row a valid
	// positive control.
	pgp := crypto.PGP()
	if *pqc {
		pgp = crypto.PGPWithProfile(profile.PQC())
	}
	key, err := pgp.KeyGeneration().AddUserId(name, email).New().GenerateKey()
	if err != nil {
		return fmt.Errorf("keygen: %w", err)
	}

	secret, err := key.Serialize()
	if err != nil {
		return fmt.Errorf("keygen: serialize secret key: %w", err)
	}
	pub, err := key.ToPublic()
	if err != nil {
		return fmt.Errorf("keygen: extract public key: %w", err)
	}
	public, err := pub.Serialize()
	if err != nil {
		return fmt.Errorf("keygen: serialize public key: %w", err)
	}
	if err := os.WriteFile(*outSecret, secret, 0o600); err != nil {
		return err
	}
	return os.WriteFile(*outPublic, public, 0o644)
}

func encrypt(args []string) error {
	fs := flag.NewFlagSet("encrypt", flag.ContinueOnError)
	recipient := fs.String("recipient", "", "recipient public cert file")
	in := fs.String("in", "", "plaintext input file")
	out := fs.String("out", "", "ciphertext output file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *recipient == "" || *in == "" || *out == "" {
		return errors.New("encrypt: --recipient, --in and --out are required")
	}

	pub, err := readKey(*recipient)
	if err != nil {
		return fmt.Errorf("encrypt: load recipient cert: %w", err)
	}
	plaintext, err := os.ReadFile(*in)
	if err != nil {
		return err
	}
	handle, err := crypto.PGP().Encryption().Recipient(pub).New()
	if err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}
	msg, err := handle.Encrypt(plaintext)
	if err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}
	return os.WriteFile(*out, msg.Bytes(), 0o644)
}

func decrypt(args []string) error {
	fs := flag.NewFlagSet("decrypt", flag.ContinueOnError)
	keyFile := fs.String("key", "", "secret key file")
	in := fs.String("in", "", "ciphertext input file")
	out := fs.String("out", "", "plaintext output file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *keyFile == "" || *in == "" || *out == "" {
		return errors.New("decrypt: --key, --in and --out are required")
	}

	key, err := readKey(*keyFile)
	if err != nil {
		return fmt.Errorf("decrypt: load secret key: %w", err)
	}
	ciphertext, err := os.ReadFile(*in)
	if err != nil {
		return err
	}
	handle, err := crypto.PGP().Decryption().DecryptionKey(key).New()
	if err != nil {
		return fmt.Errorf("decrypt: %w", err)
	}
	result, err := handle.Decrypt(ciphertext, crypto.Bytes)
	if err != nil {
		return fmt.Errorf("decrypt: %w", err)
	}
	return os.WriteFile(*out, result.Bytes(), 0o644)
}

// readKey loads a binary (non-armored) OpenPGP key or cert.
func readKey(path string) (*crypto.Key, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return crypto.NewKey(data)
}

func splitUID(uid string) (name, email string, err error) {
	open := strings.LastIndex(uid, "<")
	if open < 0 || !strings.HasSuffix(uid, ">") {
		return "", "", fmt.Errorf("keygen: --uid must look like \"name <email>\", got %q", uid)
	}
	return strings.TrimSpace(uid[:open]), uid[open+1 : len(uid)-1], nil
}
