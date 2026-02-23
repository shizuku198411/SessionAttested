package ebpf

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

func readPPid(pid int) (int, error) {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, err
	}
	// /proc/<pid>/stat format: pid (comm) state ppid ...
	// comm may contain spaces but is wrapped in parentheses; find last ')'
	s := string(b)
	rp := strings.LastIndex(s, ")")
	if rp < 0 {
		return 0, fmt.Errorf("invalid stat format")
	}
	after := strings.Fields(s[rp+1:])
	if len(after) < 3 {
		return 0, fmt.Errorf("invalid stat fields")
	}
	ppid, err := strconv.Atoi(after[2]) // state=after[0], ppid=after[2]
	if err != nil {
		return 0, err
	}
	return ppid, nil
}

// isDescendant returns true if pid's ancestor chain reaches rootPID.
func isDescendant(pid, rootPID int, limit int) bool {
	cur := pid
	for i := 0; i < limit && cur > 1; i++ {
		if cur == rootPID {
			return true
		}
		pp, err := readPPid(cur)
		if err != nil {
			return false
		}
		cur = pp
	}
	return cur == rootPID
}

func readCgroupPaths(pid int) ([]string, error) {
	f, err := os.Open(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	uniq := map[string]struct{}{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		// format: hierarchy-ID:controllers:path
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			continue
		}
		p := strings.TrimSpace(parts[2])
		if p == "" || p == "/" {
			continue
		}
		uniq[p] = struct{}{}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}

	out := make([]string, 0, len(uniq))
	for p := range uniq {
		out = append(out, p)
	}
	return out, nil
}

func inContainerCgroup(pid int, containerCgroupPaths []string) bool {
	if len(containerCgroupPaths) == 0 {
		return false
	}

	paths, err := readCgroupPaths(pid)
	if err != nil {
		return false
	}

	for _, p := range paths {
		for _, cp := range containerCgroupPaths {
			// Process can be in the same cgroup or a descendant cgroup.
			if p == cp || strings.HasPrefix(p, cp+"/") {
				return true
			}
		}
	}
	return false
}
