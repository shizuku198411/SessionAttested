package commands

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"session-attested/internal/model"
	"session-attested/internal/policy"
	"session-attested/internal/state"
)

type policyCandidatesOut struct {
	SessionID     string `json:"session_id"`
	SummaryPath   string `json:"summary_path"`
	CandidatePath string `json:"candidate_path"`
	WriterCount   int    `json:"writer_count"`
	ExecCount     int    `json:"exec_count,omitempty"`
}

type candidatePolicyFile struct {
	PolicyID         string        `yaml:"policy_id"`
	PolicyVersion    string        `yaml:"policy_version"`
	ForbiddenExec    []policy.Rule `yaml:"forbidden_exec"`
	ForbiddenWriters []policy.Rule `yaml:"forbidden_writers"`
	Exceptions       []any         `yaml:"exceptions"`
}

func RunPolicyCandidates(args []string) int {
	fs := flag.NewFlagSet("policy candidates", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	sessionID := fs.String("session", "", "session id")
	stateDir := fs.String("state-dir", state.DefaultStateDir().Root, "state dir")
	outPath := fs.String("out", "", "candidate policy output path (default: <run_dir>/policy.<session>.candidate.yaml)")
	includeGit := fs.Bool("include-git", false, "include git identities")
	includeAttested := fs.Bool("include-attested", false, "include attested identities")
	includeExec := fs.Bool("include-exec", false, "also populate forbidden_exec candidates")
	jsonOut := fs.Bool("json", false, "output JSON")

	if err := fs.Parse(args); err != nil {
		return 2
	}
	if strings.TrimSpace(*sessionID) == "" {
		if sid, ok := readLastSessionID(); ok {
			*sessionID = sid
		}
	}
	if strings.TrimSpace(*sessionID) == "" {
		fmt.Fprintln(os.Stderr, "error: --session is required")
		return 2
	}

	st := state.StateDir{Root: *stateDir}
	summaryPath := st.AuditSummaryPath(*sessionID)
	var summary model.AuditSummary
	if err := state.ReadJSON(summaryPath, &summary); err != nil {
		fmt.Fprintln(os.Stderr, "error: read audit_summary:", err)
		return 4
	}

	writers := candidateRules(summary.WriterIdentities, *includeGit, *includeAttested)
	var execs []policy.Rule
	if *includeExec {
		execs = candidateRules(summary.ExecutedIdentities, *includeGit, *includeAttested)
	} else {
		execs = []policy.Rule{}
	}

	candidate := candidatePolicyFile{
		PolicyID:         "candidate-" + *sessionID,
		PolicyVersion:    "1.0.0",
		ForbiddenExec:    execs,
		ForbiddenWriters: writers,
		Exceptions:       []any{},
	}

	dst := *outPath
	if strings.TrimSpace(dst) == "" {
		dst = defaultCandidatePolicyPath(st.Root, *sessionID)
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		fmt.Fprintln(os.Stderr, "error: mkdir output dir:", err)
		return 3
	}

	yb, err := yaml.Marshal(&candidate)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: marshal candidate policy:", err)
		return 3
	}
	header := fmt.Sprintf("# source: %s\n# session_id: %s\n", summaryPath, *sessionID)
	if err := os.WriteFile(dst, append([]byte(header), yb...), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "error: write candidate policy:", err)
		return 3
	}

	if *jsonOut {
		out := policyCandidatesOut{
			SessionID:     *sessionID,
			SummaryPath:   summaryPath,
			CandidatePath: dst,
			WriterCount:   len(writers),
			ExecCount:     len(execs),
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetEscapeHTML(false)
		_ = enc.Encode(out)
		return 0
	}

	fmt.Println("wrote:", dst)
	fmt.Println("next: review and rename if you want to use it as policy")
	return 0
}

func candidateRules(ids []model.ExecutableIdentity, includeGit, includeAttested bool) []policy.Rule {
	seen := map[string]struct{}{}
	out := make([]policy.Rule, 0, len(ids))
	for _, id := range ids {
		sha := strings.TrimSpace(id.SHA256)
		if sha == "" {
			continue
		}
		path := strings.TrimSpace(id.PathHint)
		if !includeGit {
			if strings.Contains(path, "/git") || strings.HasSuffix(path, "/git") {
				continue
			}
		}
		if !includeAttested && strings.Contains(path, "attested") {
			continue
		}
		key := sha + "|" + path
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		r := policy.Rule{SHA256: sha}
		if path != "" {
			r.Comment = path
		}
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Comment != out[j].Comment {
			return out[i].Comment < out[j].Comment
		}
		return out[i].SHA256 < out[j].SHA256
	})
	return out
}

func defaultCandidatePolicyPath(stateDirRoot, sessionID string) string {
	if filepath.Base(filepath.Clean(stateDirRoot)) == "state" {
		runDir := filepath.Dir(filepath.Clean(stateDirRoot))
		return filepath.Join(runDir, fmt.Sprintf("policy.%s.candidate.yaml", sessionID))
	}
	cwd, err := os.Getwd()
	if err != nil || cwd == "" {
		return fmt.Sprintf("policy.%s.candidate.yaml", sessionID)
	}
	return filepath.Join(cwd, fmt.Sprintf("policy.%s.candidate.yaml", sessionID))
}
