package commands

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"session-attested/internal/policy"
)

type policyHashOut struct {
	PolicyPath  string `json:"policy_path"`
	RulesetHash string `json:"ruleset_hash"`
}

func RunPolicyHash(args []string) int {
	resolved, err := applyConfigDefaults("policy_hash", args)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 2
	}
	args = resolved

	fs := flag.NewFlagSet("policy hash", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	policyPath := fs.String("policy", "", "path to policy.yaml")
	jsonOut := fs.Bool("json", false, "output JSON")

	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *policyPath == "" {
		fmt.Fprintln(os.Stderr, "error: --policy is required")
		return 2
	}

	_, raw, err := policy.LoadPolicyFile(*policyPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 2
	}
	canon, err := policy.CanonicalizeYAML(raw)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 2
	}
	h := policy.RulesetHash(canon)

	if *jsonOut {
		out := policyHashOut{PolicyPath: *policyPath, RulesetHash: h}
		enc := json.NewEncoder(os.Stdout)
		enc.SetEscapeHTML(false)
		if err := enc.Encode(out); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 2
		}
		return 0
	}

	fmt.Println(h)
	return 0
}
