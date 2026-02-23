package commands

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

type cliConfig struct {
	Defaults       map[string]any              `yaml:"defaults"`
	Commands       map[string]map[string]any   `yaml:"commands"`
	DefaultProfile string                      `yaml:"default_profile"`
	Profiles       map[string]cliConfigProfile `yaml:"profiles"`
}

type cliConfigProfile struct {
	Defaults map[string]any            `yaml:"defaults"`
	Commands map[string]map[string]any `yaml:"commands"`
}

var commandFlagAllowlist = map[string]map[string]struct{}{
	"start": setOf(
		"state-dir", "workspace-host", "json",
		"image", "name", "pull", "build", "reuse-container", "build-context", "dockerfile", "build-arg",
		"auto-collect", "auto-collect-sudo", "auto-collect-wait", "auto-collect-log",
		"inject-session-env",
		"mount-attested-bin", "attested-bin-host-path", "attested-bin-container-path",
		"git-user-name", "git-user-email", "git-ssh-key-host-path", "git-ssh-key-container-path",
		"cgroup-parent", "env", "publish",
	),
	"collect": setOf(
		"session", "state-dir", "duration", "until-stop", "poll",
	),
	"stop": setOf(
		"session", "state-dir", "keep-container", "json", "collector-wait",
		"run-attest", "run-verify", "verify-write-result",
	),
	"status": setOf(
		"session", "state-dir", "json",
	),
	"commit": setOf(
		"session", "state-dir", "repo-path", "message", "allow-empty", "json",
	),
	"attest": setOf(
		"session", "repo", "commit", "ref", "policy", "out", "signing-key",
		"issuer-name", "key-id", "state-dir", "use-binding", "json",
	),
	"verify": setOf(
		"attestation", "signature", "public-key", "policy", "binding", "require-pass", "write-result", "result-file", "json",
	),
	"policy_hash": setOf(
		"policy", "json",
	),
	"workspace_init": setOf(
		"state-dir", "workspace-id", "workspace-host", "json",
		"image", "name", "pull", "build", "reuse-container", "build-context", "dockerfile", "build-arg",
		"mount-attested-bin", "attested-bin-host-path", "attested-bin-container-path",
		"repo", "scaffold", "scaffold-force", "scaffold-interactive",
		"git-ssh-key-host-path", "git-ssh-key-container-path",
		"cgroup-parent", "env", "publish",
		"auto-collect", "auto-collect-sudo", "auto-collect-wait", "auto-collect-log",
		"inject-session-env", "git-user-name", "git-user-email",
	),
	"workspace_rm": setOf(
		"state-dir", "workspace-id", "json", "remove-workspace-host",
	),
}

func applyConfigDefaults(command string, args []string) ([]string, error) {
	return applyConfigDefaultsMulti([]string{command}, args)
}

func applyConfigDefaultsMulti(commands []string, args []string) ([]string, error) {
	configPath, profile, filtered := extractConfigArgs(args)
	if configPath == "" {
		return filtered, nil
	}

	raw, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("read --config: %w", err)
	}
	var cfg cliConfig
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("parse --config yaml: %w", err)
	}

	values := map[string]any{}
	mergeValues(values, cfg.Defaults)
	for _, command := range commands {
		mergeValues(values, cfg.Commands[command])
	}

	pname := strings.TrimSpace(profile)
	if pname == "" {
		pname = strings.TrimSpace(cfg.DefaultProfile)
	}
	if pname != "" {
		pc, ok := cfg.Profiles[pname]
		if !ok {
			return nil, fmt.Errorf("profile %q not found in config", pname)
		}
		mergeValues(values, pc.Defaults)
		for _, command := range commands {
			mergeValues(values, pc.Commands[command])
		}
	}

	present := parsePresentFlags(filtered)
	out := make([]string, 0, len(filtered)+len(values)*2)
	out = append(out, filtered...)

	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, key := range keys {
		flagName := normalizeFlagKey(key)
		if flagName == "" || present[flagName] {
			continue
		}
		allowed := false
		for _, command := range commands {
			if isAllowedFlag(command, flagName) {
				allowed = true
				break
			}
		}
		if !allowed {
			continue
		}
		parts, err := flagParts(flagName, values[key])
		if err != nil {
			return nil, fmt.Errorf("config key %q: %w", key, err)
		}
		out = append(out, parts...)
	}
	return out, nil
}

func mergedConfigValues(configPath, profile, command string) (map[string]any, error) {
	if strings.TrimSpace(configPath) == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("read --config: %w", err)
	}
	var cfg cliConfig
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("parse --config yaml: %w", err)
	}

	values := map[string]any{}
	mergeValues(values, cfg.Defaults)
	mergeValues(values, cfg.Commands[command])

	pname := strings.TrimSpace(profile)
	if pname == "" {
		pname = strings.TrimSpace(cfg.DefaultProfile)
	}
	if pname != "" {
		pc, ok := cfg.Profiles[pname]
		if !ok {
			return nil, fmt.Errorf("profile %q not found in config", pname)
		}
		mergeValues(values, pc.Defaults)
		mergeValues(values, pc.Commands[command])
	}
	return values, nil
}

func configStringValue(configPath, profile, command string, keys ...string) (string, bool, error) {
	values, err := mergedConfigValues(configPath, profile, command)
	if err != nil || values == nil {
		return "", false, err
	}
	for _, k := range keys {
		if v, ok := values[k]; ok {
			s, ok := v.(string)
			if ok && strings.TrimSpace(s) != "" {
				return s, true, nil
			}
		}
	}
	return "", false, nil
}

func extractConfigArgs(args []string) (configPath, profile string, filtered []string) {
	filtered = make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--config":
			if i+1 < len(args) {
				configPath = args[i+1]
				i++
			}
		case strings.HasPrefix(a, "--config="):
			configPath = strings.TrimPrefix(a, "--config=")
		case a == "--profile":
			if i+1 < len(args) {
				profile = args[i+1]
				i++
			}
		case strings.HasPrefix(a, "--profile="):
			profile = strings.TrimPrefix(a, "--profile=")
		default:
			filtered = append(filtered, a)
		}
	}
	return configPath, profile, filtered
}

func mergeValues(dst map[string]any, src map[string]any) {
	for k, v := range src {
		dst[k] = v
	}
}

func parsePresentFlags(args []string) map[string]bool {
	m := map[string]bool{}
	for _, a := range args {
		if !strings.HasPrefix(a, "--") || len(a) < 3 {
			continue
		}
		name := strings.TrimPrefix(a, "--")
		if i := strings.IndexByte(name, '='); i >= 0 {
			name = name[:i]
		}
		if name != "" {
			m[name] = true
		}
	}
	return m
}

func normalizeFlagKey(k string) string {
	k = strings.TrimSpace(k)
	if k == "" {
		return ""
	}
	k = strings.ReplaceAll(k, "_", "-")
	return strings.TrimPrefix(k, "--")
}

func isAllowedFlag(command, flagName string) bool {
	m, ok := commandFlagAllowlist[command]
	if !ok {
		return true
	}
	_, ok = m[flagName]
	return ok
}

func setOf(flags ...string) map[string]struct{} {
	m := make(map[string]struct{}, len(flags))
	for _, f := range flags {
		m[f] = struct{}{}
	}
	return m
}

func flagParts(flagName string, v any) ([]string, error) {
	switch x := v.(type) {
	case nil:
		return nil, nil
	case bool:
		return []string{"--" + flagName + "=" + strconv.FormatBool(x)}, nil
	case int:
		return []string{"--" + flagName + "=" + strconv.Itoa(x)}, nil
	case int64:
		return []string{"--" + flagName + "=" + strconv.FormatInt(x, 10)}, nil
	case float64:
		return []string{"--" + flagName + "=" + strconv.FormatFloat(x, 'f', -1, 64)}, nil
	case string:
		if x == "" {
			return nil, nil
		}
		return []string{"--" + flagName, x}, nil
	case []any:
		out := make([]string, 0, len(x)*2)
		for _, it := range x {
			p, err := flagParts(flagName, it)
			if err != nil {
				return nil, err
			}
			out = append(out, p...)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("unsupported value type %T", v)
	}
}
