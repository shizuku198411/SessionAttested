package commands

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"html/template"
	"io/fs"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"session-attested/internal/model"
	"session-attested/internal/policy"
	"session-attested/internal/state"
)

type webUIView struct {
	Title                  string
	Now                    string
	SessionID              string
	SessionWindowStart     string
	SessionWindowEnd       string
	Sessions               []webUISessionRow
	Addr                   string
	AttestationPath        string
	AuditSummaryPath       string
	CommitBindingPath      string
	Attestation            *model.Attestation
	AuditSummary           *model.AuditSummary
	CommitBinding          map[string]any
	CommitBindingsJSONL    []map[string]any
	AttestedSummaryRecords []map[string]any
	SelectedSummary        *webUISummaryView
	WorkspaceObserved      map[string]any
	WorkspaceExecRows      []workspaceObservedRow
	WorkspaceWriterRows    []workspaceObservedRow
	AttestedPolicyLast     string
	AttestedPolicyParsed   *policy.Policy
	SummaryCommitLinks     []string
	AttestationCommitLinks []string
	ForbiddenExecSet       map[string]struct{}
	ForbiddenWriterSet     map[string]struct{}
	Errors                 []string
}

type webUISessionRow struct {
	SessionID        string
	Start            string
	End              string
	Conclusion       string
	ConclusionClass  string
	ConclusionReason string
}

type workspaceObservedRow struct {
	PathHint          string
	SHA256            string
	FirstSeenSession  string
	LastSeenSession   string
	SeenCount         int64
	CurrentSessionHit bool
}

type policyRuleRow struct {
	Comment string
	SHA256  string
}

type webUISummaryView struct {
	SessionID       string
	Timestamp       string
	Repo            string
	CommitSHAs      []string
	CommitURLs      []string
	Conclusion      string
	ConclusionClass string
	Reason          string
	ReasonCode      string
	VerifyOKText    string
	AttPassText     string
	PolicyChecked   string
	PolicyMatch     string
}

func RunWebUI(args []string) int {
	fs := flag.NewFlagSet("webui", flag.ContinueOnError)
	addr := fs.String("addr", "127.0.0.1:8443", "listen address for HTTPS server")
	stateDir := fs.String("state-dir", filepath.Join(".attest_run", "state"), "state dir root")
	runDir := fs.String("run-dir", ".attest_run", "run dir root")
	sessionID := fs.String("session", "", "session id to inspect (default: .attest_run/last_session_id)")
	certPath := fs.String("tls-cert", "", "TLS cert path (default: <run-dir>/webui/tls.crt)")
	keyPath := fs.String("tls-key", "", "TLS key path (default: <run-dir>/webui/tls.key)")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	st := state.StateDir{Root: *stateDir}
	sid := strings.TrimSpace(*sessionID)
	if sid == "" {
		if s, ok := readLastSessionID(); ok {
			sid = s
		}
	}

	if strings.TrimSpace(*certPath) == "" {
		*certPath = filepath.Join(*runDir, "webui", "tls.crt")
	}
	if strings.TrimSpace(*keyPath) == "" {
		*keyPath = filepath.Join(*runDir, "webui", "tls.key")
	}

	if err := ensureSelfSignedTLS(*certPath, *keyPath); err != nil {
		fmt.Fprintln(os.Stderr, "error: prepare TLS cert:", err)
		return 2
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		qsid := strings.TrimSpace(r.URL.Query().Get("session"))
		targetSID := sid
		if qsid != "" {
			targetSID = qsid
		}
		view := loadWebUIView(*runDir, st, targetSID, *addr)
		renderWebUI(w, view)
	})
	mux.HandleFunc("/api/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":   true,
			"time": time.Now().UTC().Format(time.RFC3339),
		})
	})

	server := &http.Server{
		Addr:              *addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	fmt.Printf("SessionAttested WebUI (HTTPS)\n")
	fmt.Printf("URL: https://%s/\n", *addr)
	fmt.Printf("TLS cert: %s\n", *certPath)
	fmt.Printf("TLS key: %s\n", *keyPath)
	if sid != "" {
		fmt.Printf("default_session: %s\n", sid)
	}
	fmt.Printf("note: self-signed certificate (browser warning expected)\n")

	if err := server.ListenAndServeTLS(*certPath, *keyPath); err != nil && err != http.ErrServerClosed {
		fmt.Fprintln(os.Stderr, "error: webui server:", err)
		return 1
	}
	return 0
}

func loadWebUIView(runDir string, st state.StateDir, sessionID, addr string) webUIView {
	v := webUIView{
		Title:     "SessionAttested WebUI",
		Now:       time.Now().UTC().Format(time.RFC3339),
		SessionID: sessionID,
		Addr:      addr,
	}
	v.Sessions = listSessions(st)

	attPath, att, attErr := resolveAttestationForSession(runDir, sessionID)
	if attErr == nil {
		v.Attestation = &att
		v.AttestationPath = attPath
		v.ForbiddenExecSet = make(map[string]struct{}, len(att.Policy.ForbiddenExec))
		for _, r := range att.Policy.ForbiddenExec {
			if s := strings.TrimSpace(r.SHA256); s != "" {
				v.ForbiddenExecSet[s] = struct{}{}
			}
		}
		v.ForbiddenWriterSet = make(map[string]struct{}, len(att.Policy.ForbiddenWriters))
		for _, r := range att.Policy.ForbiddenWriters {
			if s := strings.TrimSpace(r.SHA256); s != "" {
				v.ForbiddenWriterSet[s] = struct{}{}
			}
		}
		for _, c := range summaryCommitURLsFromAttestation(&att) {
			v.AttestationCommitLinks = appendUnique(v.AttestationCommitLinks, c)
		}
	} else {
		v.Errors = append(v.Errors, "attestation.json: "+attErr.Error())
	}

	if sessionID != "" {
		sumPath := st.AuditSummaryPath(sessionID)
		var s model.AuditSummary
		if err := state.ReadJSON(sumPath, &s); err == nil {
			v.AuditSummary = &s
			v.AuditSummaryPath = sumPath
			v.SessionWindowStart = s.Window.StartRFC3339
			v.SessionWindowEnd = s.Window.EndRFC3339
		} else {
			v.Errors = append(v.Errors, "audit_summary.json: "+err.Error())
		}

		cbPath := st.CommitBindingPath(sessionID)
		if m, err := readJSONMap(cbPath); err == nil {
			v.CommitBinding = m
			v.CommitBindingPath = cbPath
			if repo, _ := m["repo"].(string); repo != "" {
				if sha, _ := m["commit_sha"].(string); sha != "" {
					if u := githubCommitURL(repo, sha); u != "" {
						v.SummaryCommitLinks = appendUnique(v.SummaryCommitLinks, u)
					}
				}
			}
		}

		if rows, err := readJSONLMaps(st.CommitBindingsPath(sessionID)); err == nil && len(rows) > 0 {
			v.CommitBindingsJSONL = rows
		}
	}

	if recs, err := readJSONArrayMaps(filepath.Join(".", "ATTESTED_SUMMARY")); err == nil {
		v.AttestedSummaryRecords = recs
		// newest first if timestamp exists
		sort.SliceStable(v.AttestedSummaryRecords, func(i, j int) bool {
			return fmt.Sprint(v.AttestedSummaryRecords[i]["timestamp"]) > fmt.Sprint(v.AttestedSummaryRecords[j]["timestamp"])
		})
		// collect links from latest matching session or latest record
		for _, rec := range v.AttestedSummaryRecords {
			if sessionID != "" && fmt.Sprint(rec["session_id"]) != sessionID {
				continue
			}
			if arr, ok := rec["commit_url"].([]any); ok {
				for _, x := range arr {
					v.SummaryCommitLinks = appendUnique(v.SummaryCommitLinks, fmt.Sprint(x))
				}
			}
			if sessionID != "" {
				break
			}
		}
		v.SelectedSummary = selectSummaryForSession(v.AttestedSummaryRecords, sessionID)
		applySessionConclusions(&v, v.AttestedSummaryRecords)
	}

	if m, err := readJSONMap(filepath.Join(".", "ATTESTED_WORKSPACE_OBSERVED")); err == nil {
		v.WorkspaceObserved = m
		execSet, writerSet := currentSessionIdentitySets(v.AuditSummary)
		v.WorkspaceExecRows = parseWorkspaceObservedRows(m, "exec_identities", execSet)
		v.WorkspaceWriterRows = parseWorkspaceObservedRows(m, "writer_identities", writerSet)
	}
	if b, err := os.ReadFile(filepath.Join(".", "ATTESTED_POLICY_LAST")); err == nil {
		v.AttestedPolicyLast = string(b)
		if p, err := policy.ParsePolicy(b); err == nil {
			v.AttestedPolicyParsed = p
		}
	}

	// fallback session from attestation if none selected
	if v.SessionID == "" && v.Attestation != nil {
		v.SessionID = v.Attestation.Session.SessionID
	}
	return v
}

func listSessions(st state.StateDir) []webUISessionRow {
	dir := st.Root
	if strings.TrimSpace(dir) == "" {
		return nil
	}
	root := filepath.Join(dir, "sessions")
	ents, err := os.ReadDir(root)
	if err != nil {
		return nil
	}
	var out []webUISessionRow
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		sid := e.Name()
		row := webUISessionRow{SessionID: sid}
		var sum model.AuditSummary
		if err := state.ReadJSON(st.AuditSummaryPath(sid), &sum); err == nil {
			row.Start = sum.Window.StartRFC3339
			row.End = sum.Window.EndRFC3339
		} else {
			var meta state.SessionMeta
			if err := state.ReadJSON(st.MetaPath(sid), &meta); err == nil {
				row.Start = meta.StartedAt
			}
		}
		out = append(out, row)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Start != out[j].Start {
			return out[i].Start > out[j].Start
		}
		return out[i].SessionID > out[j].SessionID
	})
	return out
}

func resolveAttestationForSession(runDir, sessionID string) (string, model.Attestation, error) {
	latestPath := filepath.Join(runDir, "attestations", "latest", "attestation.json")
	if strings.TrimSpace(sessionID) == "" {
		var att model.Attestation
		if err := state.ReadJSON(latestPath, &att); err != nil {
			return "", model.Attestation{}, err
		}
		return latestPath, att, nil
	}

	type cand struct {
		path string
		att  model.Attestation
		mt   time.Time
	}
	var best *cand
	root := filepath.Join(runDir, "attestations")
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d == nil || d.IsDir() {
			return nil
		}
		if filepath.Base(path) != "attestation.json" {
			return nil
		}
		var att model.Attestation
		if err := state.ReadJSON(path, &att); err != nil {
			return nil
		}
		if att.Session.SessionID != sessionID {
			return nil
		}
		info, err := d.Info()
		mt := time.Time{}
		if err == nil {
			mt = info.ModTime()
		}
		if best == nil || mt.After(best.mt) {
			best = &cand{path: path, att: att, mt: mt}
		}
		return nil
	})
	if best != nil {
		return best.path, best.att, nil
	}

	// Fallback to latest if no session-specific attestation exists.
	var att model.Attestation
	if err := state.ReadJSON(latestPath, &att); err != nil {
		return "", model.Attestation{}, err
	}
	return latestPath, att, nil
}

func applySessionConclusions(v *webUIView, recs []map[string]any) {
	if v == nil || len(v.Sessions) == 0 || len(recs) == 0 {
		return
	}
	// Latest record wins because recs are sorted newest-first in loadWebUIView.
	bySession := map[string]map[string]any{}
	for _, rec := range recs {
		sid := strings.TrimSpace(fmt.Sprint(rec["session_id"]))
		if sid == "" {
			continue
		}
		if _, exists := bySession[sid]; !exists {
			bySession[sid] = rec
		}
	}
	for i := range v.Sessions {
		rec, ok := bySession[v.Sessions[i].SessionID]
		if !ok {
			v.Sessions[i].Conclusion = "-"
			continue
		}
		okVal, hasVerifyOK := rec["verify_ok"].(bool)
		passVal, hasAttPass := rec["attestation_pass"].(bool)
		switch {
		case hasVerifyOK:
			if okVal {
				v.Sessions[i].Conclusion = "PASS"
				v.Sessions[i].ConclusionClass = "ok"
			} else {
				v.Sessions[i].Conclusion = "FAIL"
				v.Sessions[i].ConclusionClass = "ng"
			}
		case hasAttPass:
			if passVal {
				v.Sessions[i].Conclusion = "PASS"
				v.Sessions[i].ConclusionClass = "ok"
			} else {
				v.Sessions[i].Conclusion = "FAIL"
				v.Sessions[i].ConclusionClass = "ng"
			}
		default:
			v.Sessions[i].Conclusion = "-"
		}
		if r := strings.TrimSpace(fmt.Sprint(rec["reason"])); r != "" && r != "<nil>" {
			v.Sessions[i].ConclusionReason = r
		}
	}
}

func selectSummaryForSession(recs []map[string]any, sessionID string) *webUISummaryView {
	if len(recs) == 0 {
		return nil
	}
	var rec map[string]any
	if strings.TrimSpace(sessionID) != "" {
		for _, r := range recs {
			if strings.TrimSpace(fmt.Sprint(r["session_id"])) == sessionID {
				rec = r
				break
			}
		}
	}
	if rec == nil {
		rec = recs[0]
	}
	if rec == nil {
		return nil
	}
	out := &webUISummaryView{
		SessionID:     strings.TrimSpace(fmt.Sprint(rec["session_id"])),
		Timestamp:     strings.TrimSpace(fmt.Sprint(rec["timestamp"])),
		Repo:          strings.TrimSpace(fmt.Sprint(rec["repo"])),
		Reason:        cleanText(rec["reason"]),
		VerifyOKText:  boolFieldText(rec, "verify_ok"),
		AttPassText:   boolFieldText(rec, "attestation_pass"),
		PolicyChecked: boolFieldText(rec, "policy_checked"),
		PolicyMatch:   boolFieldText(rec, "policy_match"),
	}
	out.ReasonCode = summaryReasonCode(out.Reason)
	out.CommitSHAs = stringSliceField(rec, "commit_sha")
	out.CommitURLs = stringSliceField(rec, "commit_url")
	if len(out.CommitSHAs) == 0 {
		if s := cleanText(rec["commit_sha"]); s != "" {
			out.CommitSHAs = []string{s}
		}
	}
	if len(out.CommitURLs) == 0 {
		if s := cleanText(rec["commit_url"]); s != "" {
			out.CommitURLs = []string{s}
		}
	}
	if b, ok := boolField(rec, "verify_ok"); ok {
		if b {
			out.Conclusion, out.ConclusionClass = "PASS", "ok"
		} else {
			out.Conclusion, out.ConclusionClass = "FAIL", "ng"
		}
	} else if b, ok := boolField(rec, "attestation_pass"); ok {
		if b {
			out.Conclusion, out.ConclusionClass = "PASS", "ok"
		} else {
			out.Conclusion, out.ConclusionClass = "FAIL", "ng"
		}
	} else {
		out.Conclusion = "-"
	}
	return out
}

func summaryReasonCode(reason string) string {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return ""
	}
	if i := strings.Index(reason, ":"); i >= 0 {
		return strings.TrimSpace(reason[:i])
	}
	return reason
}

func stringSliceField(m map[string]any, key string) []string {
	v, ok := m[key]
	if !ok {
		return nil
	}
	switch x := v.(type) {
	case []any:
		var out []string
		for _, it := range x {
			if s := cleanText(it); s != "" {
				out = append(out, s)
			}
		}
		return out
	case []string:
		var out []string
		for _, it := range x {
			if s := strings.TrimSpace(it); s != "" {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

func boolField(m map[string]any, key string) (bool, bool) {
	v, ok := m[key]
	if !ok {
		return false, false
	}
	b, ok := v.(bool)
	return b, ok
}

func boolFieldText(m map[string]any, key string) string {
	if b, ok := boolField(m, key); ok {
		if b {
			return "true"
		}
		return "false"
	}
	return "-"
}

func cleanText(v any) string {
	s := strings.TrimSpace(fmt.Sprint(v))
	if s == "" || s == "<nil>" {
		return ""
	}
	return s
}

func renderWebUI(w http.ResponseWriter, v webUIView) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := webUITmpl.Execute(w, v); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func readJSONMap(path string) (map[string]any, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return m, nil
}

func readJSONArrayMaps(path string) ([]map[string]any, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var arr []map[string]any
	if err := json.Unmarshal(b, &arr); err != nil {
		return nil, err
	}
	return arr, nil
}

func readJSONLMaps(path string) ([]map[string]any, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(b), "\n")
	var out []map[string]any
	for _, ln := range lines {
		ln = strings.TrimSpace(ln)
		if ln == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(ln), &m); err != nil {
			continue
		}
		out = append(out, m)
	}
	return out, nil
}

func summaryCommitURLsFromAttestation(att *model.Attestation) []string {
	if att == nil {
		return nil
	}
	var out []string
	if u := githubCommitURL(att.Subject.Repo, att.Subject.CommitSHA); u != "" {
		out = append(out, u)
	}
	for _, c := range att.Session.CommitBindings {
		if u := githubCommitURL(att.Subject.Repo, c.CommitSHA); u != "" {
			out = appendUnique(out, u)
		}
	}
	return out
}

func appendUnique(dst []string, s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return dst
	}
	for _, x := range dst {
		if x == s {
			return dst
		}
	}
	return append(dst, s)
}

func currentSessionIdentitySets(s *model.AuditSummary) (map[string]struct{}, map[string]struct{}) {
	execSet := map[string]struct{}{}
	writerSet := map[string]struct{}{}
	if s == nil {
		return execSet, writerSet
	}
	for _, it := range s.ExecutedIdentities {
		if strings.TrimSpace(it.SHA256) != "" {
			execSet[it.SHA256] = struct{}{}
		}
	}
	for _, it := range s.WriterIdentities {
		if strings.TrimSpace(it.SHA256) != "" {
			writerSet[it.SHA256] = struct{}{}
		}
	}
	return execSet, writerSet
}

func parseWorkspaceObservedRows(m map[string]any, key string, current map[string]struct{}) []workspaceObservedRow {
	raw, ok := m[key]
	if !ok {
		return nil
	}
	arr, ok := raw.([]any)
	if !ok {
		return nil
	}
	rows := make([]workspaceObservedRow, 0, len(arr))
	for _, item := range arr {
		obj, ok := item.(map[string]any)
		if !ok {
			continue
		}
		sha := strings.TrimSpace(fmt.Sprint(obj["sha256"]))
		_, hit := current[sha]
		rows = append(rows, workspaceObservedRow{
			PathHint:          strings.TrimSpace(fmt.Sprint(obj["path_hint"])),
			SHA256:            sha,
			FirstSeenSession:  strings.TrimSpace(fmt.Sprint(obj["first_seen_session"])),
			LastSeenSession:   strings.TrimSpace(fmt.Sprint(obj["last_seen_session"])),
			SeenCount:         anyToInt64(obj["seen_count"]),
			CurrentSessionHit: hit,
		})
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].CurrentSessionHit != rows[j].CurrentSessionHit {
			return rows[i].CurrentSessionHit
		}
		if rows[i].LastSeenSession != rows[j].LastSeenSession {
			return rows[i].LastSeenSession > rows[j].LastSeenSession
		}
		return rows[i].PathHint < rows[j].PathHint
	})
	return rows
}

func anyToInt64(v any) int64 {
	switch x := v.(type) {
	case float64:
		return int64(x)
	case float32:
		return int64(x)
	case int:
		return int64(x)
	case int64:
		return x
	case int32:
		return int64(x)
	default:
		return 0
	}
}

func ensureSelfSignedTLS(certPath, keyPath string) error {
	if _, err := os.Stat(certPath); err == nil {
		if _, err2 := os.Stat(keyPath); err2 == nil {
			// quick parse check
			if _, err3 := tls.LoadX509KeyPair(certPath, keyPath); err3 == nil {
				return nil
			}
		}
	}
	if err := os.MkdirAll(filepath.Dir(certPath), 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o755); err != nil {
		return err
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		return err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "localhost",
			Organization: []string{"SessionAttested WebUI"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses: []net.IP{
			net.ParseIP("127.0.0.1"),
			net.ParseIP("::1"),
		},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return err
	}
	cf, err := os.OpenFile(certPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	if err := pem.Encode(cf, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		_ = cf.Close()
		return err
	}
	_ = cf.Close()

	kb, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return err
	}
	kf, err := os.OpenFile(keyPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if err := pem.Encode(kf, &pem.Block{Type: "PRIVATE KEY", Bytes: kb}); err != nil {
		_ = kf.Close()
		return err
	}
	return kf.Close()
}

func prettyJSON(v any) string {
	if v == nil {
		return ""
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return ""
	}
	return string(b)
}

var webUITmpl = template.Must(template.New("webui").Funcs(template.FuncMap{
	"prettyJSON": prettyJSON,
	"join":       strings.Join,
	"hasPrefix":  strings.HasPrefix,
	"inSet": func(m map[string]struct{}, s string) bool {
		if len(m) == 0 {
			return false
		}
		_, ok := m[s]
		return ok
	},
}).Parse(`<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{{.Title}}</title>
  <style>
    :root { --bg:#0d1117; --fg:#e6edf3; --muted:#8b949e; --card:#161b22; --line:#30363d; --ok:#3fb950; --ng:#f85149; --accent:#58a6ff; --chip:#21262d; }
    body { margin:0; font-family: ui-sans-serif, system-ui, sans-serif; color:var(--fg); background:linear-gradient(180deg,#0d1117, #0b0f14); }
    .wrap { max-width: 1100px; margin: 0 auto; padding: 20px; }
    .hero { background: var(--card); border:1px solid var(--line); border-radius:12px; padding:16px; box-shadow:0 8px 28px rgba(0,0,0,.35); }
    h1,h2,h3 { margin:0 0 8px 0; }
    h2 { margin-top: 20px; font-size: 1.1rem; }
    .muted { color: var(--muted); }
    .grid { display:grid; grid-template-columns: repeat(auto-fit,minmax(260px,1fr)); gap:12px; margin-top:12px; }
    .card { background:var(--card); border:1px solid var(--line); border-radius:12px; padding:14px; }
    .mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; }
    pre { white-space: pre-wrap; word-break: break-word; background:#0d1117; border:1px solid var(--line); border-radius:8px; padding:10px; overflow:auto; }
    code { background:var(--chip); padding:2px 4px; border-radius:4px; }
    a { color: var(--accent); text-decoration:none; }
    a:hover { text-decoration:underline; }
    .ok { color: var(--ok); font-weight: 600; }
    .ng { color: var(--ng); font-weight: 600; }
    .list { margin: 8px 0 0 16px; padding:0; }
    .topbar { display:flex; gap:8px; align-items:center; flex-wrap:wrap; margin-top:10px; }
    .pill { border:1px solid var(--line); border-radius:999px; padding:4px 10px; background:var(--chip); }
    details summary { cursor:pointer; user-select:none; }
    .stack { display:grid; gap:12px; margin-top:12px; }
    .tablewrap { border:1px solid var(--line); border-radius:8px; overflow:auto; max-height:340px; background:#0d1117; margin-top:8px; }
    .tablewrap { scrollbar-color: #30363d #0d1117; scrollbar-width: thin; }
    .tablewrap::-webkit-scrollbar { width: 10px; height: 10px; }
    .tablewrap::-webkit-scrollbar-track { background: #0d1117; }
    .tablewrap::-webkit-scrollbar-thumb { background: #30363d; border-radius: 999px; border: 2px solid #0d1117; }
    .tablewrap::-webkit-scrollbar-thumb:hover { background: #484f58; }
    pre { scrollbar-color: #30363d #0d1117; scrollbar-width: thin; }
    pre::-webkit-scrollbar { width: 10px; height: 10px; }
    pre::-webkit-scrollbar-track { background: #0d1117; }
    pre::-webkit-scrollbar-thumb { background: #30363d; border-radius: 999px; border: 2px solid #0d1117; }
    pre::-webkit-scrollbar-thumb:hover { background: #484f58; }
    table { width:100%; border-collapse:collapse; font-size:12px; }
    th, td { border-bottom:1px solid var(--line); padding:8px; text-align:left; vertical-align:top; }
    th { position:sticky; top:0; background:#161b22; z-index:1; }
    td.path { color:var(--fg); word-break:break-word; }
    tr.hit td.path { color: var(--ok); font-weight: 600; }
    tr.policy-hit td.path { color: var(--ng); font-weight: 600; }
    .sha-cell details { margin:0; }
    .sha-cell summary { color:var(--muted); cursor:pointer; }
    .link-list { margin:8px 0 0 0; padding-left:18px; }
    .link-list li { overflow-wrap:anywhere; }
    .legend { display:flex; gap:12px; align-items:center; flex-wrap:wrap; margin-top:8px; color:var(--muted); font-size:12px; }
    .dot { width:10px; height:10px; border-radius:50%; display:inline-block; border:1px solid var(--line); background:transparent; vertical-align:middle; margin-right:4px; }
    .dot.hit { background:var(--ok); border-color:var(--ok); }
    .footer { margin: 18px 0 8px; color: var(--muted); font-size: 12px; text-align: center; }
  </style>
</head>
<body>
<div class="wrap">
  <div class="hero">
    <h1>SessionAttested WebUI</h1>
    <div class="muted">Local read-only viewer for audit summary, observed identities, and commit-linked proof artifacts.</div>
    <div class="topbar">
      <span class="pill">selected session: <strong>{{if .SessionID}}{{.SessionID}}{{else}}(none){{end}}</strong></span>
      <span class="pill muted">
        session window:
        {{if .SessionWindowStart}}{{.SessionWindowStart}}{{else}}(unknown start){{end}}
        {{if .SessionWindowEnd}} → {{.SessionWindowEnd}}{{else}} → (open / no end yet){{end}}
      </span>
    </div>
    {{if .Sessions}}
    <details style="margin-top:10px;">
      <summary>See other sessions ({{len .Sessions}})</summary>
      <div class="tablewrap" style="margin-top:8px; max-height:260px;">
        <table class="mono">
          <thead><tr><th style="width:16%">Conclusion</th><th style="width:24%">Start</th><th style="width:24%">End</th><th>Session ID</th></tr></thead>
          <tbody>
            {{range .Sessions}}
            <tr>
              <td title="{{.ConclusionReason}}">{{if .ConclusionClass}}<span class="{{.ConclusionClass}}">{{.Conclusion}}</span>{{else}}{{.Conclusion}}{{end}}</td>
              <td>{{if .Start}}{{.Start}}{{else}}-{{end}}</td>
              <td>{{if .End}}{{.End}}{{else}}-{{end}}</td>
              <td><a href="/?session={{.SessionID}}">{{.SessionID}}</a></td>
            </tr>
            {{end}}
          </tbody>
        </table>
      </div>
    </details>
    {{end}}
  </div>

  {{if .Errors}}
  <div class="card" style="margin-top:12px">
    <h2>Load Warnings</h2>
    <ul class="list">
      {{range .Errors}}<li class="mono">{{.}}</li>{{end}}
    </ul>
  </div>
  {{end}}

  <div class="grid">
    <div class="card">
      <h2>Attestation / Verification</h2>
      {{if .SelectedSummary}}
        <div>Repo: <code>{{.SelectedSummary.Repo}}</code></div>
        <div>Commits:
          {{if .SelectedSummary.CommitSHAs}}
            <div class="mono" style="margin-top:4px;">{{range $i, $c := .SelectedSummary.CommitSHAs}}{{if $i}}, {{end}}{{$c}}{{end}}</div>
          {{else}}
            <span class="muted">-</span>
          {{end}}
        </div>
        <div>Conclusion:
          {{if .SelectedSummary.ConclusionClass}}<span class="{{.SelectedSummary.ConclusionClass}}">{{.SelectedSummary.Conclusion}}</span>{{else}}{{.SelectedSummary.Conclusion}}{{end}}
        </div>
        <div>Reason:
          {{if .SelectedSummary.ReasonCode}}<code class="ng">{{.SelectedSummary.ReasonCode}}</code>{{else}}<span class="muted">-</span>{{end}}
        </div>
        <div>
          verify_ok:
          {{if eq .SelectedSummary.VerifyOKText "true"}}<strong class="ok">true</strong>{{else if eq .SelectedSummary.VerifyOKText "false"}}<strong class="ng">false</strong>{{else}}<strong class="muted">-</strong>{{end}}
          /
          attestation_pass:
          {{if eq .SelectedSummary.AttPassText "true"}}<strong class="ok">true</strong>{{else if eq .SelectedSummary.AttPassText "false"}}<strong class="ng">false</strong>{{else}}<strong class="muted">-</strong>{{end}}
        </div>
        <div>
          policy_checked:
          {{if eq .SelectedSummary.PolicyChecked "true"}}<strong class="ok">true</strong>{{else if eq .SelectedSummary.PolicyChecked "false"}}<strong class="ng">false</strong>{{else}}<strong class="muted">-</strong>{{end}}
          /
          policy_match:
          {{if eq .SelectedSummary.PolicyMatch "true"}}<strong class="ok">true</strong>{{else if eq .SelectedSummary.PolicyMatch "false"}}<strong class="ng">false</strong>{{else}}<strong class="muted">-</strong>{{end}}
        </div>
        {{if .SelectedSummary.Timestamp}}<div class="muted mono" style="margin-top:8px">ATTESTED_SUMMARY timestamp: {{.SelectedSummary.Timestamp}}</div>{{end}}
        {{if .AttestationPath}}<div class="muted mono" style="margin-top:4px">attestation source: {{.AttestationPath}}</div>{{end}}
      {{else if .Attestation}}
        <div>Repo: <code>{{.Attestation.Subject.Repo}}</code></div>
        <div>Subject commit: <code>{{.Attestation.Subject.CommitSHA}}</code></div>
        <div>Conclusion:
          {{if .Attestation.Conclusion.Pass}}<span class="ok">PASS</span>{{else}}<span class="ng">FAIL</span>{{end}}
        </div>
        <div>Reasons: <strong>{{len .Attestation.Conclusion.Reasons}}</strong></div>
        <div class="muted mono" style="margin-top:8px">{{.AttestationPath}}</div>
      {{else}}
        <div class="muted">No attestation / summary loaded for selected session.</div>
      {{end}}
    </div>

    <div class="card">
      <h2>Audit Summary</h2>
      {{if .AuditSummary}}
        <div>Exec count: <strong>{{.AuditSummary.ExecObserved.Count}}</strong></div>
        <div>Workspace write count: <strong>{{.AuditSummary.WorkspaceWritesObserved.Count}}</strong></div>
        <div>Exec unresolved: <strong>{{.AuditSummary.ExecObserved.IdentityUnresolved}}</strong></div>
        <div>Writer unresolved: <strong>{{.AuditSummary.WorkspaceWritesObserved.WriterIdentityUnresolved}}</strong></div>
        <div class="muted mono" style="margin-top:8px">{{.AuditSummaryPath}}</div>
      {{else}}
        <div class="muted">No session audit summary loaded.</div>
      {{end}}
    </div>

  </div>

  <div class="card" style="margin-top:12px">
    <h2>Commit Links</h2>
    {{if .SummaryCommitLinks}}
      <ul class="link-list">
        {{range .SummaryCommitLinks}}<li><a href="{{.}}" target="_blank" rel="noreferrer">{{.}}</a></li>{{end}}
      </ul>
    {{else if .AttestationCommitLinks}}
      <ul class="link-list">
        {{range .AttestationCommitLinks}}<li><a href="{{.}}" target="_blank" rel="noreferrer">{{.}}</a></li>{{end}}
      </ul>
    {{else}}
      <div class="muted">No GitHub commit links resolved.</div>
    {{end}}
    {{if .CommitBindingPath}}<div class="muted mono" style="margin-top:8px">{{.CommitBindingPath}}</div>{{end}}
  </div>

  <div class="stack">
    {{if .Attestation}}
    <div class="card">
      <h2>Policy / Conclusion Details</h2>
      <div><strong>Policy:</strong> <code>{{.Attestation.Policy.PolicyID}}</code> / {{.Attestation.Policy.PolicyVersion}}</div>
      <div><strong>Ruleset hash:</strong> <code>{{.Attestation.Policy.RulesetHash}}</code></div>
      {{if .Attestation.Conclusion.Reasons}}
        <ul class="list">
        {{range .Attestation.Conclusion.Reasons}}
          <li><code>{{.Code}}</code>{{if .Detail}}<div class="mono muted">{{.Detail}}</div>{{end}}</li>
        {{end}}
        </ul>
      {{end}}
    </div>
    {{end}}

    {{if or .Attestation .AttestedPolicyLast}}
    <div class="card">
      <h2>Applied Policy (Session Snapshot)</h2>
      {{if .Attestation}}
        <div><strong>Policy:</strong> <code>{{.Attestation.Policy.PolicyID}}</code> / {{.Attestation.Policy.PolicyVersion}}</div>
        <div><strong>Ruleset hash:</strong> <code>{{.Attestation.Policy.RulesetHash}}</code></div>
        <div class="muted mono" style="margin-top:6px;">source: attestation.json (session {{.Attestation.Session.SessionID}})</div>

        <h3 style="margin-top:10px;">Forbidden Exec</h3>
        {{if .Attestation.Policy.ForbiddenExec}}
        <div class="tablewrap">
          <table class="mono">
            <thead><tr><th>Comment / Path Hint</th><th style="width:26%">SHA256</th></tr></thead>
            <tbody>
              {{range .Attestation.Policy.ForbiddenExec}}
              <tr>
                <td class="path">{{.Comment}}</td>
                <td class="sha-cell">
                  <details>
                    <summary>Show SHA256</summary>
                    <div class="mono" style="margin-top:6px; overflow-wrap:anywhere;">{{.SHA256}}</div>
                  </details>
                </td>
              </tr>
              {{end}}
            </tbody>
          </table>
        </div>
        {{else}}<div class="muted">No forbidden exec rules.</div>{{end}}

        <h3 style="margin-top:12px;">Forbidden Writers</h3>
        {{if .Attestation.Policy.ForbiddenWriters}}
        <div class="tablewrap">
          <table class="mono">
            <thead><tr><th>Comment / Path Hint</th><th style="width:26%">SHA256</th></tr></thead>
            <tbody>
              {{range .Attestation.Policy.ForbiddenWriters}}
              <tr>
                <td class="path">{{.Comment}}</td>
                <td class="sha-cell">
                  <details>
                    <summary>Show SHA256</summary>
                    <div class="mono" style="margin-top:6px; overflow-wrap:anywhere;">{{.SHA256}}</div>
                  </details>
                </td>
              </tr>
              {{end}}
            </tbody>
          </table>
        </div>
        {{else}}<div class="muted">No forbidden writer rules.</div>{{end}}

        <details style="margin-top:10px;"><summary>Show Policy Snapshot JSON</summary><pre class="mono">{{prettyJSON .Attestation.Policy}}</pre></details>
      {{else}}
        {{if .AttestedPolicyParsed}}
          <div class="muted" style="margin-bottom:8px;">Fallback: parsed from <code>ATTESTED_POLICY_LAST</code> (no attestation loaded)</div>
          <div><strong>Policy:</strong> <code>{{.AttestedPolicyParsed.PolicyID}}</code> / {{.AttestedPolicyParsed.PolicyVersion}}</div>

          <h3 style="margin-top:10px;">Forbidden Exec</h3>
          {{if .AttestedPolicyParsed.ForbiddenExec}}
          <div class="tablewrap">
            <table class="mono">
              <thead><tr><th>Comment / Path Hint</th><th style="width:26%">SHA256</th></tr></thead>
              <tbody>
                {{range .AttestedPolicyParsed.ForbiddenExec}}
                <tr>
                  <td class="path">{{.Comment}}</td>
                  <td class="sha-cell">
                    <details>
                      <summary>Show SHA256</summary>
                      <div class="mono" style="margin-top:6px; overflow-wrap:anywhere;">{{.SHA256}}</div>
                    </details>
                  </td>
                </tr>
                {{end}}
              </tbody>
            </table>
          </div>
          {{else}}<div class="muted">No forbidden exec rules.</div>{{end}}

          <h3 style="margin-top:12px;">Forbidden Writers</h3>
          {{if .AttestedPolicyParsed.ForbiddenWriters}}
          <div class="tablewrap">
            <table class="mono">
              <thead><tr><th>Comment / Path Hint</th><th style="width:26%">SHA256</th></tr></thead>
              <tbody>
                {{range .AttestedPolicyParsed.ForbiddenWriters}}
                <tr>
                  <td class="path">{{.Comment}}</td>
                  <td class="sha-cell">
                    <details>
                      <summary>Show SHA256</summary>
                      <div class="mono" style="margin-top:6px; overflow-wrap:anywhere;">{{.SHA256}}</div>
                    </details>
                  </td>
                </tr>
                {{end}}
              </tbody>
            </table>
          </div>
          {{else}}<div class="muted">No forbidden writer rules.</div>{{end}}

          <details style="margin-top:10px;"><summary>Show Raw Policy</summary><pre class="mono">{{.AttestedPolicyLast}}</pre></details>
        {{else}}
          <pre class="mono">{{.AttestedPolicyLast}}</pre>
        {{end}}
      {{end}}
    </div>
    {{end}}
  </div>

  <div class="grid">
    <div class="card">
      <h2>Executed Identities (Session)</h2>
      <div class="legend"><span><span class="dot hit" style="background:var(--ng); border-color:var(--ng);"></span>Matched by applied policy (forbidden_exec)</span></div>
      {{if and .AuditSummary (gt (len .AuditSummary.ExecutedIdentities) 0)}}
        <div class="tablewrap">
          <table class="mono">
            <thead><tr><th>Path Hint</th><th style="width:26%">SHA256</th></tr></thead>
            <tbody>
              {{range .AuditSummary.ExecutedIdentities}}
              <tr class="{{if inSet $.ForbiddenExecSet .SHA256}}policy-hit{{end}}">
                <td class="path">{{.PathHint}}</td>
                <td class="sha-cell">
                  <details>
                    <summary>Show SHA256</summary>
                    <div class="mono" style="margin-top:6px; overflow-wrap:anywhere;">{{.SHA256}}</div>
                  </details>
                </td>
              </tr>
              {{end}}
            </tbody>
          </table>
        </div>
      {{else}}<div class="muted">No executed identities.</div>{{end}}
    </div>
    <div class="card">
      <h2>Writer Identities (Session)</h2>
      <div class="legend"><span><span class="dot hit" style="background:var(--ng); border-color:var(--ng);"></span>Matched by applied policy (forbidden_writers)</span></div>
      {{if and .AuditSummary (gt (len .AuditSummary.WriterIdentities) 0)}}
        <div class="tablewrap">
          <table class="mono">
            <thead><tr><th>Path Hint</th><th style="width:26%">SHA256</th></tr></thead>
            <tbody>
              {{range .AuditSummary.WriterIdentities}}
              <tr class="{{if inSet $.ForbiddenWriterSet .SHA256}}policy-hit{{end}}">
                <td class="path">{{.PathHint}}</td>
                <td class="sha-cell">
                  <details>
                    <summary>Show SHA256</summary>
                    <div class="mono" style="margin-top:6px; overflow-wrap:anywhere;">{{.SHA256}}</div>
                  </details>
                </td>
              </tr>
              {{end}}
            </tbody>
          </table>
        </div>
      {{else}}<div class="muted">No writer identities.</div>{{end}}
    </div>
  </div>

  <div class="card" style="margin-top:12px">
    <h2>Workspace Observed (Cumulative)</h2>
    {{if .WorkspaceObserved}}
      <div class="legend">
        <span><span class="dot hit"></span>Seen in selected session</span>
        <span><span class="dot"></span>Historical / other session</span>
      </div>

      <h3 style="margin-top:10px;">Exec Identities</h3>
      {{if .WorkspaceExecRows}}
      <div class="tablewrap">
        <table class="mono">
          <thead><tr><th>Path Hint</th><th style="width:12%">Seen</th><th style="width:20%">Last Session</th><th style="width:18%">SHA256</th></tr></thead>
          <tbody>
            {{range .WorkspaceExecRows}}
            <tr class="{{if .CurrentSessionHit}}hit{{end}}">
              <td class="path">{{.PathHint}}</td>
              <td>{{.SeenCount}}</td>
              <td>{{.LastSeenSession}}</td>
              <td class="sha-cell">
                <details>
                  <summary>Show SHA256</summary>
                  <div class="mono" style="margin-top:6px; overflow-wrap:anywhere;">{{.SHA256}}</div>
                </details>
              </td>
            </tr>
            {{end}}
          </tbody>
        </table>
      </div>
      {{else}}<div class="muted">No cumulative exec identities.</div>{{end}}

      <h3 style="margin-top:12px;">Writer Identities</h3>
      {{if .WorkspaceWriterRows}}
      <div class="tablewrap">
        <table class="mono">
          <thead><tr><th>Path Hint</th><th style="width:12%">Seen</th><th style="width:20%">Last Session</th><th style="width:18%">SHA256</th></tr></thead>
          <tbody>
            {{range .WorkspaceWriterRows}}
            <tr class="{{if .CurrentSessionHit}}hit{{end}}">
              <td class="path">{{.PathHint}}</td>
              <td>{{.SeenCount}}</td>
              <td>{{.LastSeenSession}}</td>
              <td class="sha-cell">
                <details>
                  <summary>Show SHA256</summary>
                  <div class="mono" style="margin-top:6px; overflow-wrap:anywhere;">{{.SHA256}}</div>
                </details>
              </td>
            </tr>
            {{end}}
          </tbody>
        </table>
      </div>
      {{else}}<div class="muted">No cumulative writer identities.</div>{{end}}

      <details style="margin-top:10px;"><summary>Show JSON</summary><pre class="mono">{{prettyJSON .WorkspaceObserved}}</pre></details>
    {{else}}
      <div class="muted">No <code>ATTESTED_WORKSPACE_OBSERVED</code> found in current directory.</div>
    {{end}}
  </div>

  <div class="card" style="margin-top:12px">
    <h2>ATTESTED_SUMMARY (Recent)</h2>
    {{if .AttestedSummaryRecords}}
      <details><summary>Show JSON (latest first)</summary><pre class="mono">{{prettyJSON .AttestedSummaryRecords}}</pre></details>
    {{else}}
      <div class="muted">No <code>ATTESTED_SUMMARY</code> found in current directory.</div>
    {{end}}
  </div>

  {{if .Attestation}}
  <div class="card" style="margin-top:12px; margin-bottom:20px;">
    <h2>Raw attestation.json (latest)</h2>
    <details><summary>Show JSON</summary><pre class="mono">{{prettyJSON .Attestation}}</pre></details>
  </div>
  {{end}}

  <div class="footer">
    <a href="https://github.com/shizuku198411/SessionAttested" target="_blank" rel="noreferrer">SessionAttested</a> created by Shizuku
  </div>
</div>
</body>
</html>`))

// Ensure this file does not drift silently with removed APIs.
var _ fs.FileInfo
