package policy

import (
	"fmt"
	"os"
)

type Rule struct {
	SHA256  string `yaml:"sha256" json:"sha256"`
	Comment string `yaml:"comment,omitempty" json:"comment,omitempty"`
}

type Policy struct {
	PolicyID         string `yaml:"policy_id" json:"policy_id"`
	PolicyVersion    string `yaml:"policy_version" json:"policy_version"`
	ForbiddenExec    []Rule `yaml:"forbidden_exec" json:"forbidden_exec"`
	ForbiddenWriters []Rule `yaml:"forbidden_writers" json:"forbidden_writers"`
	AllowedWriters   []Rule `yaml:"allowed_writers,omitempty" json:"allowed_writers,omitempty"` // legacy whitelist (backward compatibility)
	Exceptions       []any  `yaml:"exceptions,omitempty" json:"exceptions,omitempty"`
}

func LoadPolicyFile(path string) (*Policy, []byte /*raw*/, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	p, err := ParsePolicy(raw)
	if err != nil {
		return nil, nil, fmt.Errorf("parse policy: %w", err)
	}
	return p, raw, nil
}
