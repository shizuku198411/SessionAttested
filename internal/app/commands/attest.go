// internal/app/commands/attest.go
package commands

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	"session-attested/internal/attest"
	"session-attested/internal/crypto"
	"session-attested/internal/model"
	"session-attested/internal/policy"
	"session-attested/internal/spec"
	"session-attested/internal/state"
)

type attestOut struct {
	OutDir          string `json:"out_dir"`
	Pass            bool   `json:"pass"`
	AttestationPath string `json:"attestation_path"`
	SignaturePath   string `json:"signature_path"`
	PublicKeyPath   string `json:"public_key_path"`
}

var commitRe = regexp.MustCompile(`^[0-9a-f]{40}$`)

func RunAttest(args []string) int {
	resolved, err := applyConfigDefaults("attest", args)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 2
	}
	args = resolved

	fs := flag.NewFlagSet("attest", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	sessionID := fs.String("session", "", "session id")
	repo := fs.String("repo", "", "repo (owner/name)")
	commit := fs.String("commit", "", "commit sha (40 hex)")
	ref := fs.String("ref", "", "ref (optional)")
	policyPath := fs.String("policy", "", "path to policy.yaml")
	outDir := fs.String("out", "", "output dir")
	signingKeyPath := fs.String("signing-key", "", "ed25519 private key (PKCS8 PEM)")
	issuerName := fs.String("issuer-name", "", "issuer name (optional)")
	keyID := fs.String("key-id", "", "key id (optional)")
	stateDir := fs.String("state-dir", state.DefaultStateDir().Root, "state dir")
	useBinding := fs.Bool("use-binding", true, "use and enforce session commit binding when available")
	jsonOut := fs.Bool("json", false, "output JSON")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	if *sessionID == "" || *repo == "" || *policyPath == "" || *outDir == "" || *signingKeyPath == "" {
		fmt.Fprintln(os.Stderr, "error: --session --repo --policy --out --signing-key are required")
		return 2
	}

	st := state.StateDir{Root: *stateDir}

	// Load meta/audit_summary/event_root
	var meta state.SessionMeta
	if err := state.ReadJSON(st.MetaPath(*sessionID), &meta); err != nil {
		fmt.Fprintln(os.Stderr, "error: read meta:", err)
		return 4
	}

	commitSHA := *commit
	var binding *state.CommitBinding
	var bindings []state.CommitBinding
	if *useBinding {
		if list, err := state.ReadCommitBindingsJSONL(st.CommitBindingsPath(*sessionID)); err == nil && len(list) > 0 {
			bindings = list
		}
		var cb state.CommitBinding
		if err := state.ReadJSON(st.CommitBindingPath(*sessionID), &cb); err == nil {
			if cb.SessionID != "" && cb.SessionID != *sessionID {
				fmt.Fprintln(os.Stderr, "error: commit binding session mismatch")
				return 4
			}
			if commitSHA != "" && commitSHA != cb.CommitSHA {
				fmt.Fprintln(os.Stderr, "error: --commit does not match session commit binding")
				fmt.Fprintln(os.Stderr, "  commit:", commitSHA)
				fmt.Fprintln(os.Stderr, "  bound :", cb.CommitSHA)
				return 2
			}
			if commitSHA == "" {
				commitSHA = cb.CommitSHA
			}
			binding = &cb
		}
	}
	if commitSHA == "" {
		fmt.Fprintln(os.Stderr, "error: --commit is required (or provide session commit binding via `attested commit`)")
		return 2
	}
	if !commitRe.MatchString(commitSHA) {
		fmt.Fprintln(os.Stderr, "error: --commit must be 40 lowercase hex chars")
		return 2
	}

	var summary model.AuditSummary
	if err := state.ReadJSON(st.AuditSummaryPath(*sessionID), &summary); err != nil {
		fmt.Fprintln(os.Stderr, "error: read audit_summary:", err)
		return 4
	}

	var er state.EventRootFile
	if err := state.ReadJSON(st.EventRootPath(*sessionID), &er); err != nil {
		fmt.Fprintln(os.Stderr, "error: read event_root:", err)
		return 4
	}

	// Load policy + ruleset_hash
	pol, praw, err := policy.LoadPolicyFile(*policyPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: load policy:", err)
		return 2
	}
	pcanon, err := policy.CanonicalizeYAML(praw)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: canonicalize policy:", err)
		return 2
	}
	rulesetHash := policy.RulesetHash(pcanon)

	// Evaluate
	eval := attest.Evaluate(pol, &summary)

	// Build attestation object
	in := attest.BuildInput{
		Repo:              *repo,
		CommitSHA:         commitSHA,
		Ref:               *ref,
		SessionID:         *sessionID,
		Meta:              &meta,
		Summary:           &summary,
		EventRoot:         &er,
		Binding:           binding,
		Bindings:          bindings,
		PolicyPath:        *policyPath,
		Policy:            pol,
		PolicyRulesetHash: rulesetHash,

		CollectorName:    "session-attested-collector",
		CollectorVersion: "0.1.0",
		NodeID:           "poc-node",
	}

	att, err := attest.BuildAttestation(in, eval, *issuerName, *keyID)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: build attestation:", err)
		return 2
	}

	// Canonical bytes for signing (IMPORTANT: this is what verify will canonicalize and verify against)
	canonAtt, err := spec.CanonicalJSON(att)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: canonical attestation:", err)
		return 2
	}

	// Sign
	priv, err := crypto.LoadEd25519PrivateKey(*signingKeyPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: load signing key:", err)
		return 2
	}
	sig := crypto.SignEd25519(priv, canonAtt)

	// Ensure output dir exists
	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, "error: mkdir out:", err)
		return 2
	}

	attPath := filepath.Join(*outDir, "attestation.json")
	sigPath := filepath.Join(*outDir, "attestation.sig")
	pubPath := filepath.Join(*outDir, "attestation.pub")

	// Write attestation.json (pretty)
	if err := state.WriteJSON(attPath, att, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "error: write attestation:", err)
		return 2
	}

	// Write signature envelope
	env := model.SignatureEnvelope{
		Alg:             "ed25519",
		KeyID:           *keyID,
		SignatureBase64: base64.StdEncoding.EncodeToString(sig),
	}
	if err := state.WriteJSON(sigPath, env, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "error: write signature:", err)
		return 2
	}

	// Write public key alongside (PoC: always emit)
	pub := crypto.PublicFromPrivate(priv)
	if err := crypto.SaveEd25519PublicKey(pubPath, pub); err != nil {
		fmt.Fprintln(os.Stderr, "error: write public key:", err)
		return 2
	}

	// Output
	if *jsonOut {
		out := attestOut{
			OutDir:          *outDir,
			Pass:            eval.Pass,
			AttestationPath: attPath,
			SignaturePath:   sigPath,
			PublicKeyPath:   pubPath,
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetEscapeHTML(false)
		_ = enc.Encode(out)
	} else {
		fmt.Printf("wrote:\n  %s\n  %s\n  %s\n", attPath, sigPath, pubPath)
		fmt.Printf("attestation pass=%v\n", eval.Pass)
	}

	if eval.Pass {
		return 0
	}
	return 6
}
