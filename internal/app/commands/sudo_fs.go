package commands

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

func isRoot() bool {
	return os.Geteuid() == 0
}

func sudoOwner() (uid, gid int, ok bool) {
	uidStr := strings.TrimSpace(os.Getenv("SUDO_UID"))
	gidStr := strings.TrimSpace(os.Getenv("SUDO_GID"))
	if uidStr == "" || gidStr == "" {
		return 0, 0, false
	}
	uid, err1 := strconv.Atoi(uidStr)
	gid, err2 := strconv.Atoi(gidStr)
	if err1 != nil || err2 != nil || uid <= 0 || gid <= 0 {
		return 0, 0, false
	}
	return uid, gid, true
}

func chownPathToSudoOwnerBestEffort(path string) {
	uid, gid, ok := sudoOwner()
	if !ok {
		return
	}
	if path == "" {
		return
	}
	_ = filepath.Walk(path, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		_ = os.Chown(p, uid, gid)
		return nil
	})
}

func ensureSudoNonInteractiveAvailable(reason string) error {
	if isRoot() {
		return nil
	}
	if _, err := exec.LookPath("sudo"); err != nil {
		return fmt.Errorf("%s requires sudo, but sudo was not found in PATH", reason)
	}
	cmd := exec.Command("sudo", "-n", "true")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s requires sudo (non-interactive). run `sudo -v` first or re-run with sudo", reason)
	}
	return nil
}
