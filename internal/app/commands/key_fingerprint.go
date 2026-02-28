package commands

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"session-attested/internal/crypto"
)

type keyFingerprintOut struct {
	Fingerprint string `json:"fingerprint"`
	Source      string `json:"source"` // public|private
	Path        string `json:"path"`
}

func RunKeyFingerprint(args []string) int {
	fs := flag.NewFlagSet("key fingerprint", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	pubPath := fs.String("public-key", "", "path to ed25519 public key PEM")
	privPath := fs.String("private-key", "", "path to ed25519 private key PEM")
	jsonOut := fs.Bool("json", false, "output JSON")

	if err := fs.Parse(args); err != nil {
		return 2
	}
	if (*pubPath == "" && *privPath == "") || (*pubPath != "" && *privPath != "") {
		fmt.Fprintln(os.Stderr, "error: specify exactly one of --public-key or --private-key")
		return 2
	}

	var (
		fp     string
		err    error
		source string
		path   string
	)
	if *pubPath != "" {
		source = "public"
		path = *pubPath
		pub, e := crypto.LoadEd25519PublicKey(*pubPath)
		if e != nil {
			fmt.Fprintln(os.Stderr, "error: load public key:", e)
			return 2
		}
		fp, err = crypto.Ed25519PublicKeyFingerprint(pub)
	} else {
		source = "private"
		path = *privPath
		priv, e := crypto.LoadEd25519PrivateKey(*privPath)
		if e != nil {
			fmt.Fprintln(os.Stderr, "error: load private key:", e)
			return 2
		}
		fp, err = crypto.Ed25519PublicKeyFingerprint(crypto.PublicFromPrivate(priv))
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: compute fingerprint:", err)
		return 2
	}

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetEscapeHTML(false)
		_ = enc.Encode(keyFingerprintOut{Fingerprint: fp, Source: source, Path: path})
		return 0
	}
	fmt.Println(fp)
	return 0
}
