package policy

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

func ParsePolicy(raw []byte) (*Policy, error) {
	var p Policy
	if err := yaml.Unmarshal(raw, &p); err != nil {
		return nil, err
	}

	// Minimal validation for PoC
	if p.PolicyID == "" {
		return nil, fmt.Errorf("policy_id is required")
	}
	if p.PolicyVersion == "" {
		return nil, fmt.Errorf("policy_version is required")
	}
	if p.ForbiddenExec == nil {
		p.ForbiddenExec = []Rule{}
	}
	if p.ForbiddenExecLineageWrites == nil {
		p.ForbiddenExecLineageWrites = []Rule{}
	}
	if p.ForbiddenWriters == nil {
		p.ForbiddenWriters = []Rule{}
	}
	if p.AllowedWriters == nil {
		p.AllowedWriters = []Rule{}
	}
	return &p, nil
}
