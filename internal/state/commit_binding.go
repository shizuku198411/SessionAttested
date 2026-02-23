package state

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

type CommitBinding struct {
	SessionID      string `json:"session_id"`
	CommitSHA      string `json:"commit_sha"`
	ParentSHA      string `json:"parent_sha,omitempty"`
	RepoPath       string `json:"repo_path,omitempty"`
	CreatedRFC3339 string `json:"created_rfc3339"`
}

func AppendCommitBindingJSONL(path string, b CommitBinding) error {
	if err := os.MkdirAll(filepathDir(path), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	return enc.Encode(&b)
}

func ReadCommitBindingsJSONL(path string) ([]CommitBinding, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []CommitBinding
	sc := bufio.NewScanner(f)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var b CommitBinding
		if err := json.Unmarshal([]byte(line), &b); err != nil {
			return nil, fmt.Errorf("parse %s line %d: %w", path, lineNo, err)
		}
		out = append(out, b)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func filepathDir(path string) string {
	i := strings.LastIndex(path, string(os.PathSeparator))
	if i < 0 {
		return "."
	}
	if i == 0 {
		return string(os.PathSeparator)
	}
	return path[:i]
}
