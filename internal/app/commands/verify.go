package commands

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"session-attested/internal/crypto"
	"session-attested/internal/model"
	"session-attested/internal/policy"
	"session-attested/internal/spec"
	"session-attested/internal/state"
)

type verifyOut struct {
	OK                       bool   `json:"ok"`
	Pass                     bool   `json:"pass"`
	Reason                   string `json:"reason,omitempty"`
	PolicyChecked            bool   `json:"policy_checked"`
	PolicyMatch              bool   `json:"policy_match"`
	SigningKeyFingerprint    string `json:"signing_key_fingerprint,omitempty"`
	AuditLogIntegrityChecked bool   `json:"audit_log_integrity_checked,omitempty"`
	AuditLogIntegrityOK      bool   `json:"audit_log_integrity_ok,omitempty"`
}

func RunVerify(args []string) int {
	resolved, err := applyConfigDefaults("verify", args)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 2
	}
	args = resolved

	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	attPath := fs.String("attestation", "", "path to attestation.json")
	sigPath := fs.String("signature", "", "path to attestation.sig")
	pubPath := fs.String("public-key", "", "path to attestation public key (PEM). default: <attestation dir>/attestation.pub")
	expectedKeyFingerprint := fs.String("expected-key-fingerprint", "", "expected signing public key fingerprint (sha256:<hex>)")
	policyPath := fs.String("policy", "", "path to policy.yaml (optional)")
	bindingPath := fs.String("binding", "", "path to commit_binding.json (optional)")
	requirePass := fs.Bool("require-pass", true, "fail verification when attestation conclusion.pass is false")
	writeResult := fs.Bool("write-result", false, "write verification artifacts (ATTESTED, ATTESTED_SUMMARY)")
	resultFile := fs.String("result-file", "", "legacy: path to result summary file (default: ./ATTESTED_SUMMARY)")
	jsonOut := fs.Bool("json", false, "output JSON")

	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *attPath == "" {
		*attPath = filepath.Join(".attest_run", "attestations", "latest", "attestation.json")
	}
	if *sigPath == "" {
		*sigPath = filepath.Join(".attest_run", "attestations", "latest", "attestation.sig")
	}
	if *pubPath == "" {
		defPub := filepath.Join(".attest_run", "attestations", "latest", "attestation.pub")
		if _, err := os.Stat(defPub); err == nil {
			*pubPath = defPub
		}
	}
	if *bindingPath == "" {
		if sid, ok := readLastSessionID(); ok {
			defBinding := filepath.Join(".attest_run", "state", "sessions", sid, "commit_binding.json")
			if _, err := os.Stat(defBinding); err == nil {
				*bindingPath = defBinding
			}
		}
	}
	if *attPath == "" || *sigPath == "" {
		fmt.Fprintln(os.Stderr, "error: --attestation and --signature are required")
		return 2
	}

	attRaw, err := os.ReadFile(*attPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 2
	}

	// Parse attestation (for pass flag + policy hash)
	var att model.Attestation
	if err := json.Unmarshal(attRaw, &att); err != nil {
		fmt.Fprintln(os.Stderr, "error: parse attestation.json:", err)
		return 2
	}
	var policyRawForRecord string
	if *policyPath != "" {
		if b, err := os.ReadFile(*policyPath); err == nil {
			policyRawForRecord = string(b)
		}
	}
	finish := func(out verifyOut, code int) int {
		if *writeResult {
			summaryPath := *resultFile
			if summaryPath == "" {
				summaryPath = defaultVerifySummaryPath()
			}
			if err := writeVerifyResultArtifacts(summaryPath, &att, out, *policyPath, policyRawForRecord); err != nil {
				fmt.Fprintln(os.Stderr, "warn: write result file:", err)
			}
			chownPathToSudoOwnerBestEffort(filepath.Dir(summaryPath))
			chownPathToSudoOwnerBestEffort(filepath.Join(filepath.Dir(summaryPath), "ATTESTED"))
			chownPathToSudoOwnerBestEffort(filepath.Join(filepath.Dir(summaryPath), "ATTESTED_SUMMARY"))
			chownPathToSudoOwnerBestEffort(filepath.Join(filepath.Dir(summaryPath), "ATTESTED_POLICY_LAST"))
			chownPathToSudoOwnerBestEffort(filepath.Join(filepath.Dir(summaryPath), "ATTESTED_WORKSPACE_OBSERVED"))
			chownPathToSudoOwnerBestEffort(filepath.Join(".attest_run", "reports"))
		}
		return emitVerify(*jsonOut, out, code)
	}

	// Canonicalize attestation bytes for signature verification
	canonAtt, err := spec.CanonicalizeJSONBytes(attRaw)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: canonicalize attestation.json:", err)
		return 2
	}

	sigRaw, err := os.ReadFile(*sigPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 2
	}
	var sigEnv model.SignatureEnvelope
	if err := json.Unmarshal(sigRaw, &sigEnv); err != nil {
		fmt.Fprintln(os.Stderr, "error: parse attestation.sig:", err)
		return 2
	}
	if sigEnv.Alg != "ed25519" {
		fmt.Fprintln(os.Stderr, "error: unsupported signature alg:", sigEnv.Alg)
		return 7
	}

	sigBytes, err := base64.StdEncoding.DecodeString(sigEnv.SignatureBase64)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: decode signature_base64:", err)
		return 2
	}

	// Resolve public key path default
	pubKeyPath := *pubPath
	if pubKeyPath == "" {
		pubKeyPath = filepath.Join(filepath.Dir(*attPath), "attestation.pub")
	}

	pub, err := crypto.LoadEd25519PublicKey(pubKeyPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: load public key:", err)
		return 2
	}
	pubFP, err := crypto.Ed25519PublicKeyFingerprint(pub)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: compute public key fingerprint:", err)
		return 2
	}
	if want := normalizeKeyFingerprint(*expectedKeyFingerprint); want != "" && normalizeKeyFingerprint(pubFP) != want {
		return finish(verifyOut{
			OK:                    false,
			Pass:                  att.Conclusion.Pass,
			Reason:                "SIGNING_KEY_FINGERPRINT_MISMATCH",
			PolicyChecked:         *policyPath != "",
			PolicyMatch:           false,
			SigningKeyFingerprint: pubFP,
		}, 7)
	}
	finishFP := func(out verifyOut, code int) int {
		if out.SigningKeyFingerprint == "" {
			out.SigningKeyFingerprint = pubFP
		}
		return finish(out, code)
	}

	if !crypto.VerifyEd25519(pub, canonAtt, sigBytes) {
		return finishFP(verifyOut{
			OK:                    false,
			Pass:                  att.Conclusion.Pass,
			Reason:                "SIGNATURE_INVALID",
			PolicyChecked:         *policyPath != "",
			PolicyMatch:           false,
		}, 7)
	}

	if att.Session.CommitBinding != nil {
		b := att.Session.CommitBinding
		if b.CommitSHA == "" || b.CommitSHA != att.Subject.CommitSHA {
			return finishFP(verifyOut{
				OK:            false,
				Pass:          att.Conclusion.Pass,
				Reason:        "INTEGRITY_MISMATCH",
				PolicyChecked: *policyPath != "",
				PolicyMatch:   false,
			}, 7)
		}
	}
	if n := len(att.Session.CommitBindings); n > 0 {
		last := att.Session.CommitBindings[n-1]
		if last.CommitSHA == "" || last.CommitSHA != att.Subject.CommitSHA {
			return finishFP(verifyOut{
				OK:            false,
				Pass:          att.Conclusion.Pass,
				Reason:        "INTEGRITY_MISMATCH",
				PolicyChecked: *policyPath != "",
				PolicyMatch:   false,
			}, 7)
		}
	}
	if *bindingPath != "" {
		var cb state.CommitBinding
		if err := state.ReadJSON(*bindingPath, &cb); err != nil {
			fmt.Fprintln(os.Stderr, "error: read commit binding:", err)
			return 2
		}
		if cb.SessionID != "" && cb.SessionID != att.Session.SessionID {
			return finishFP(verifyOut{
				OK:            false,
				Pass:          att.Conclusion.Pass,
				Reason:        "INTEGRITY_MISMATCH",
				PolicyChecked: *policyPath != "",
				PolicyMatch:   false,
			}, 7)
		}
		if cb.CommitSHA == "" || cb.CommitSHA != att.Subject.CommitSHA {
			return finishFP(verifyOut{
				OK:            false,
				Pass:          att.Conclusion.Pass,
				Reason:        "INTEGRITY_MISMATCH",
				PolicyChecked: *policyPath != "",
				PolicyMatch:   false,
			}, 7)
		}
		if att.Session.CommitBinding != nil {
			if att.Session.CommitBinding.ParentSHA != "" && cb.ParentSHA != "" && att.Session.CommitBinding.ParentSHA != cb.ParentSHA {
				return finishFP(verifyOut{
					OK:            false,
					Pass:          att.Conclusion.Pass,
					Reason:        "INTEGRITY_MISMATCH",
					PolicyChecked: *policyPath != "",
					PolicyMatch:   false,
				}, 7)
			}
		}
	}

	// Optional local raw-audit integrity check (when state files are present locally).
	ilr := verifyLocalAuditLogIntegrityIfAvailable(&att)
	if ilr.Checked && !ilr.OK {
		return finishFP(verifyOut{
			OK:                       false,
			Pass:                     att.Conclusion.Pass,
			Reason:                   ilr.Reason,
			PolicyChecked:            *policyPath != "",
			PolicyMatch:              false,
			AuditLogIntegrityChecked: true,
			AuditLogIntegrityOK:      false,
		}, 7)
	}

	// Optional: policy hash check
	policyChecked := false
	policyMatch := false
	if *policyPath != "" {
		policyChecked = true
		_, praw, err := policy.LoadPolicyFile(*policyPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error: load policy:", err)
			return 2
		}
		canon, err := policy.CanonicalizeYAML(praw)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error: canonicalize policy:", err)
			return 2
		}
		want := policy.RulesetHash(canon)
		policyMatch = (att.Policy.RulesetHash == want)
		if !policyMatch {
			return finishFP(verifyOut{
				OK:                       false,
				Pass:                     att.Conclusion.Pass,
				Reason:                   "POLICY_MISMATCH",
				PolicyChecked:            true,
				PolicyMatch:              false,
				AuditLogIntegrityChecked: ilr.Checked,
				AuditLogIntegrityOK:      ilr.OK,
			}, 7)
		}
	}
	if *requirePass && !att.Conclusion.Pass {
		reason := "ATTESTATION_FAIL"
		reasonDetail := ""
		if len(att.Conclusion.Reasons) > 0 && att.Conclusion.Reasons[0].Code != "" {
			reason = att.Conclusion.Reasons[0].Code
			reasonDetail = att.Conclusion.Reasons[0].Detail
		}
		if reasonDetail != "" {
			reason = reason + ": " + reasonDetail
		}
		return finishFP(verifyOut{
			OK:                       false,
			Pass:                     att.Conclusion.Pass,
			Reason:                   reason,
			PolicyChecked:            policyChecked,
			PolicyMatch:              policyMatch || !policyChecked,
			AuditLogIntegrityChecked: ilr.Checked,
			AuditLogIntegrityOK:      ilr.OK,
		}, 7)
	}

	// Success: note that att.Conclusion.Pass is the attestor's evaluation result (not verify's).
	return finishFP(verifyOut{
		OK:                       true,
		Pass:                     att.Conclusion.Pass,
		PolicyChecked:            policyChecked,
		PolicyMatch:              policyMatch || !policyChecked,
		AuditLogIntegrityChecked: ilr.Checked,
		AuditLogIntegrityOK:      ilr.OK,
	}, 0)
}

func emitVerify(jsonOut bool, out verifyOut, exitCode int) int {
	if jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetEscapeHTML(false)
		_ = enc.Encode(out)
		return exitCode
	}

	if out.OK {
		if out.PolicyChecked {
			fmt.Printf("OK (signature valid, policy match). attestation pass=%v\n", out.Pass)
		} else {
			fmt.Printf("OK (signature valid). attestation pass=%v\n", out.Pass)
		}
		return exitCode
	}

	// failure
	if out.PolicyChecked {
		fmt.Printf("NG (%s). attestation pass=%v\n", out.Reason, out.Pass)
	} else {
		fmt.Printf("NG (%s). attestation pass=%v\n", out.Reason, out.Pass)
	}
	return exitCode
}

func defaultVerifySummaryPath() string {
	cwd, err := os.Getwd()
	if err != nil || cwd == "" {
		return "ATTESTED_SUMMARY"
	}
	return filepath.Join(cwd, "ATTESTED_SUMMARY")
}

type verifySummaryRecord struct {
	Timestamp                string   `json:"timestamp"`
	SessionID                string   `json:"session_id"`
	Repo                     string   `json:"repo"`
	CommitSHA                []string `json:"commit_sha"`
	CommitURL                []string `json:"commit_url,omitempty"`
	VerifyOK                 bool     `json:"verify_ok"`
	AttestationPass          bool     `json:"attestation_pass"`
	Reason                   string   `json:"reason,omitempty"`
	PolicyChecked            bool     `json:"policy_checked"`
	PolicyMatch              bool     `json:"policy_match"`
	SigningKeyFingerprint    string   `json:"signing_key_fingerprint,omitempty"`
	AuditLogIntegrityChecked bool     `json:"audit_log_integrity_checked,omitempty"`
	AuditLogIntegrityOK      bool     `json:"audit_log_integrity_ok,omitempty"`
	PolicyPath               string   `json:"policy_path,omitempty"`
	PolicyID                 string   `json:"policy_id,omitempty"`
	PolicyVersion            string   `json:"policy_version,omitempty"`
	RulesetHash              string   `json:"ruleset_hash,omitempty"`
}

type attestedObservedRecord struct {
	Timestamp string `json:"timestamp"`
	SessionID string `json:"session_id"`
	Repo      string `json:"repo,omitempty"`

	ExecObservedCount      uint64                     `json:"exec_observed_count"`
	ExecutedIdentities     []model.ExecutableIdentity `json:"executed_identities,omitempty"`
	ExecIdentityUnresolved uint64                     `json:"exec_identity_unresolved,omitempty"`
	ExecUnresolvedHints    []string                   `json:"exec_identity_unresolved_hints,omitempty"`

	WorkspaceWriteCount      uint64                     `json:"workspace_write_count"`
	WriterIdentities         []model.ExecutableIdentity `json:"writer_identities,omitempty"`
	WriterIdentityUnresolved uint64                     `json:"writer_identity_unresolved,omitempty"`
	WriterUnresolvedHints    []string                   `json:"writer_identity_unresolved_hints,omitempty"`
}

type workspaceObservedIdentityRecord struct {
	SHA256           string `json:"sha256"`
	PathHint         string `json:"path_hint,omitempty"`
	FirstSeenSession string `json:"first_seen_session"`
	LastSeenSession  string `json:"last_seen_session"`
	FirstSeenAt      string `json:"first_seen_at"`
	LastSeenAt       string `json:"last_seen_at"`
	SeenCount        uint64 `json:"seen_count"`
}

type workspaceObservedFile struct {
	UpdatedAt                string                            `json:"updated_at"`
	Repo                     string                            `json:"repo,omitempty"`
	SessionsSeen             []string                          `json:"sessions_seen,omitempty"`
	ExecIdentities           []workspaceObservedIdentityRecord `json:"exec_identities,omitempty"`
	WriterIdentities         []workspaceObservedIdentityRecord `json:"writer_identities,omitempty"`
	ExecIdentityUnresolved   uint64                            `json:"exec_identity_unresolved"`
	WriterIdentityUnresolved uint64                            `json:"writer_identity_unresolved"`
}

func writeVerifyResultArtifacts(summaryPath string, att *model.Attestation, out verifyOut, policyPath, policyRaw string) error {
	dir := filepath.Dir(summaryPath)
	if dir == "" {
		dir = "."
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	if err := ensureAttestedMarker(filepath.Join(dir, "ATTESTED"), att); err != nil {
		return err
	}

	ts := time.Now().UTC().Format(time.RFC3339)
	commitSHAs, commitURLs := summaryCommitRefs(att)
	rec := verifySummaryRecord{
		Timestamp:                ts,
		SessionID:                att.Session.SessionID,
		Repo:                     att.Subject.Repo,
		CommitSHA:                commitSHAs,
		CommitURL:                commitURLs,
		VerifyOK:                 out.OK,
		AttestationPass:          out.Pass,
		Reason:                   out.Reason,
		PolicyChecked:            out.PolicyChecked,
		PolicyMatch:              out.PolicyMatch,
		SigningKeyFingerprint:    out.SigningKeyFingerprint,
		AuditLogIntegrityChecked: out.AuditLogIntegrityChecked,
		AuditLogIntegrityOK:      out.AuditLogIntegrityOK,
		PolicyPath:               policyPath,
		PolicyID:                 att.Policy.PolicyID,
		PolicyVersion:            att.Policy.PolicyVersion,
		RulesetHash:              att.Policy.RulesetHash,
	}
	if err := appendVerifySummaryJSON(summaryPath, rec); err != nil {
		return err
	}
	if err := appendWorkspaceObserved(filepath.Join(dir, "ATTESTED_WORKSPACE_OBSERVED"), att); err != nil {
		return err
	}
	if err := writeSessionCorrelationArtifact(filepath.Join(".attest_run", "reports"), att); err != nil {
		return err
	}

	// Keep policy snapshot alongside summary in a readable sidecar when policy is provided.
	if policyRaw != "" {
		_ = os.WriteFile(filepath.Join(dir, "ATTESTED_POLICY_LAST"), []byte(policyRaw), 0o644)
	}
	return nil
}

func writeSessionCorrelationArtifact(reportsRoot string, att *model.Attestation) error {
	if att == nil {
		return nil
	}
	sessionID := strings.TrimSpace(att.Session.SessionID)
	if sessionID == "" {
		return nil
	}
	st := state.StateDir{Root: filepath.Join(".attest_run", "state")}
	forbiddenExecSet := make(map[string]struct{}, len(att.Policy.ForbiddenExec))
	for _, r := range att.Policy.ForbiddenExec {
		if s := strings.TrimSpace(r.SHA256); s != "" {
			forbiddenExecSet[s] = struct{}{}
		}
	}
	forbiddenWriterSet := make(map[string]struct{}, len(att.Policy.ForbiddenWriters))
	for _, r := range att.Policy.ForbiddenWriters {
		if s := strings.TrimSpace(r.SHA256); s != "" {
			forbiddenWriterSet[s] = struct{}{}
		}
	}
	forbiddenExecLineageSet := make(map[string]struct{}, len(att.Policy.ForbiddenExecLineageWrites))
	for _, r := range att.Policy.ForbiddenExecLineageWrites {
		if s := strings.TrimSpace(r.SHA256); s != "" {
			forbiddenExecLineageSet[s] = struct{}{}
		}
	}
	if len(forbiddenExecLineageSet) == 0 {
		forbiddenExecLineageSet = forbiddenExecSet // backward-compatible fallback
	}

	var workspaceFiles []model.WorkspaceWriteFile
	for _, wf := range att.AuditSummary.WorkspaceFiles {
		if isHiddenWorkspacePathForUI(wf.Path) {
			continue
		}
		workspaceFiles = append(workspaceFiles, wf)
	}

	forbiddenRows := buildForbiddenExecLineageRows(st, sessionID, &att.AuditSummary, forbiddenExecLineageSet)
	commitRows, err := buildCommitFileRows(att, workspaceFiles, forbiddenRows, forbiddenWriterSet)
	if err != nil {
		return fmt.Errorf("build commit correlations: %w", err)
	}

	art := sessionCorrelationArtifact{
		SchemaVersion:        "1",
		GeneratedAt:          time.Now().UTC().Format(time.RFC3339),
		SessionID:            sessionID,
		ForbiddenLineageRows: forbiddenRows,
		CommitFileRows:       commitRows,
	}
	outPath := filepath.Join(reportsRoot, "sessions", sessionID, "session_correlation.json")
	if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(art, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	return os.WriteFile(outPath, b, 0o644)
}

func githubCommitURL(repo, commit string) string {
	if repo == "" || commit == "" {
		return ""
	}
	if strings.Contains(repo, "://") {
		return ""
	}
	if strings.Count(repo, "/") != 1 {
		return ""
	}
	return "https://github.com/" + repo + "/commit/" + commit
}

func ensureAttestedMarker(path string, att *model.Attestation) error {
	if _, err := os.Stat(path); err == nil {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	body := strings.Join([]string{
		"SessionAttested verification marker",
		"",
		"This repository/workspace has verification records generated by SessionAttested.",
		"See ATTESTED_SUMMARY for per-session verification results.",
		"repo: " + att.Subject.Repo,
		"created_at: " + time.Now().UTC().Format(time.RFC3339),
		"",
		"SessionAttested created by Shizuku.",
		"https://github.com/shizuku198411/SessionAttested",
	}, "\n")
	return os.WriteFile(path, []byte(body), 0o644)
}

func appendVerifySummaryJSON(path string, rec verifySummaryRecord) error {
	var arr []map[string]any
	if b, err := os.ReadFile(path); err == nil && len(bytesTrimSpace(b)) > 0 {
		if err := json.Unmarshal(b, &arr); err != nil {
			return fmt.Errorf("parse existing ATTESTED_SUMMARY: %w", err)
		}
	}
	recb, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	var recm map[string]any
	if err := json.Unmarshal(recb, &recm); err != nil {
		return err
	}
	arr = append(arr, recm)
	out, err := json.MarshalIndent(arr, "", "  ")
	if err != nil {
		return err
	}
	out = append(out, '\n')
	return os.WriteFile(path, out, 0o644)
}

func writeAttestedObserved(path string, att *model.Attestation) error {
	if att == nil {
		return nil
	}
	rec := attestedObservedRecord{
		Timestamp:                time.Now().UTC().Format(time.RFC3339),
		SessionID:                att.Session.SessionID,
		Repo:                     att.Subject.Repo,
		ExecObservedCount:        att.AuditSummary.ExecObserved.Count,
		ExecutedIdentities:       att.AuditSummary.ExecutedIdentities,
		ExecIdentityUnresolved:   att.AuditSummary.ExecObserved.IdentityUnresolved,
		ExecUnresolvedHints:      att.AuditSummary.ExecObserved.IdentityUnresolvedHints,
		WorkspaceWriteCount:      att.AuditSummary.WorkspaceWritesObserved.Count,
		WriterIdentities:         att.AuditSummary.WriterIdentities,
		WriterIdentityUnresolved: att.AuditSummary.WorkspaceWritesObserved.WriterIdentityUnresolved,
		WriterUnresolvedHints:    att.AuditSummary.WorkspaceWritesObserved.WriterIdentityUnresolvedHints,
	}
	b, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	return os.WriteFile(path, b, 0o644)
}

func appendWorkspaceObserved(path string, att *model.Attestation) error {
	if att == nil {
		return nil
	}
	now := time.Now().UTC().Format(time.RFC3339)

	var f workspaceObservedFile
	if b, err := os.ReadFile(path); err == nil && len(bytesTrimSpace(b)) > 0 {
		if err := json.Unmarshal(b, &f); err != nil {
			return fmt.Errorf("parse existing ATTESTED_WORKSPACE_OBSERVED: %w", err)
		}
	}

	f.UpdatedAt = now
	if f.Repo == "" {
		f.Repo = att.Subject.Repo
	}
	f.SessionsSeen = appendUniqueString(f.SessionsSeen, att.Session.SessionID)
	f.ExecIdentityUnresolved += att.AuditSummary.ExecObserved.IdentityUnresolved
	f.WriterIdentityUnresolved += att.AuditSummary.WorkspaceWritesObserved.WriterIdentityUnresolved
	f.ExecIdentities = mergeWorkspaceObservedIdentities(f.ExecIdentities, att.AuditSummary.ExecutedIdentities, att.Session.SessionID, now)
	f.WriterIdentities = mergeWorkspaceObservedIdentities(f.WriterIdentities, att.AuditSummary.WriterIdentities, att.Session.SessionID, now)

	out, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	out = append(out, '\n')
	return os.WriteFile(path, out, 0o644)
}

func bytesTrimSpace(b []byte) []byte {
	return []byte(strings.TrimSpace(string(b)))
}

func normalizeKeyFingerprint(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return ""
	}
	if !strings.HasPrefix(s, "sha256:") {
		s = "sha256:" + s
	}
	return s
}

func appendUniqueString(dst []string, v string) []string {
	v = strings.TrimSpace(v)
	if v == "" {
		return dst
	}
	for _, x := range dst {
		if x == v {
			return dst
		}
	}
	return append(dst, v)
}

func mergeWorkspaceObservedIdentities(dst []workspaceObservedIdentityRecord, src []model.ExecutableIdentity, sessionID, ts string) []workspaceObservedIdentityRecord {
	idx := make(map[string]int, len(dst))
	for i, r := range dst {
		if strings.TrimSpace(r.SHA256) != "" {
			idx[r.SHA256] = i
		}
	}
	for _, s := range src {
		sha := strings.TrimSpace(s.SHA256)
		if sha == "" {
			continue
		}
		if i, ok := idx[sha]; ok {
			dst[i].LastSeenSession = sessionID
			dst[i].LastSeenAt = ts
			dst[i].SeenCount++
			if dst[i].PathHint == "" && s.PathHint != "" {
				dst[i].PathHint = s.PathHint
			}
			continue
		}
		dst = append(dst, workspaceObservedIdentityRecord{
			SHA256:           sha,
			PathHint:         s.PathHint,
			FirstSeenSession: sessionID,
			LastSeenSession:  sessionID,
			FirstSeenAt:      ts,
			LastSeenAt:       ts,
			SeenCount:        1,
		})
		idx[sha] = len(dst) - 1
	}
	return dst
}

func summaryCommitRefs(att *model.Attestation) ([]string, []string) {
	if att == nil {
		return nil, nil
	}
	seen := map[string]struct{}{}
	var shas []string
	var urls []string
	add := func(sha string) {
		sha = strings.TrimSpace(sha)
		if sha == "" {
			return
		}
		if _, ok := seen[sha]; ok {
			return
		}
		seen[sha] = struct{}{}
		shas = append(shas, sha)
		if u := githubCommitURL(att.Subject.Repo, sha); u != "" {
			urls = append(urls, u)
		}
	}
	for _, b := range att.Session.CommitBindings {
		add(b.CommitSHA)
	}
	if len(shas) == 0 {
		add(att.Subject.CommitSHA)
	}
	return shas, urls
}
