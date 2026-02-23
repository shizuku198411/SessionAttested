package ebpf

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"session-attested/internal/collector"
	"session-attested/internal/model"
	"session-attested/internal/spec"
	"session-attested/internal/state"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

type sessionState struct {
	sessionID string
	initPID   int
	cgroups   []string
	dir       string

	// counters
	seq                 uint64
	execCount           uint64
	workspaceWriteCount uint64
	workspaceWriteByOp  map[string]uint64

	// hash chain input (canonical JSON of events)
	events [][]byte
	// writer fingerprint set
	writers map[string]model.ExecutableIdentity
	// exec fingerprint set
	execs map[string]model.ExecutableIdentity
	// path->sha256 cache
	shaCache map[string]string
	// pid->last resolved executable identity (filled on exec, reused on write)
	pidExec map[int]model.ExecutableIdentity
	// visibility: identity resolution failures
	execIdentityUnresolved        uint64
	writerIdentityUnresolved      uint64
	execIdentityUnresolvedHints   []string
	writerIdentityUnresolvedHints []string

	// window
	start time.Time
	end   time.Time
}

type Collector struct {
	mu sync.Mutex

	statedir state.StateDir

	// sessionID -> state
	sessions map[string]*sessionState

	// bpf
	objs ExecLSMObjects
	lks  []link.Link
	rd   *ringbuf.Reader

	stopCh chan struct{}
	wg     sync.WaitGroup
}

type lsmLoadObjects struct {
	OnBprmCheckSecurity *ebpf.Program `ebpf:"on_bprm_check_security"`
	OnSysEnterOpenat    *ebpf.Program `ebpf:"on_sys_enter_openat"`
	Events              *ebpf.Map     `ebpf:"events"`
}

type traceLoadObjects struct {
	OnSysEnterExecve   *ebpf.Program `ebpf:"on_sys_enter_execve"`
	OnSysEnterExecveat *ebpf.Program `ebpf:"on_sys_enter_execveat"`
	OnSysEnterOpenat   *ebpf.Program `ebpf:"on_sys_enter_openat"`
	Events             *ebpf.Map     `ebpf:"events"`
}

func New(st state.StateDir) *Collector {
	return &Collector{
		statedir: st,
		sessions: map[string]*sessionState{},
		stopCh:   make(chan struct{}),
	}
}

func (c *Collector) Start(ctx context.Context) error {
	_ = ctx
	if err := c.startLSM(); err != nil {
		lsmErr := err
		if err := c.startTracepoints(); err != nil {
			return fmt.Errorf("start ebpf programs failed (lsm: %v, tracepoint: %w)", lsmErr, err)
		}
	}

	rd, err := ringbuf.NewReader(c.objs.Events)
	if err != nil {
		_ = c.closeLinks()
		c.objs.Close()
		return fmt.Errorf("ringbuf reader: %w", err)
	}
	c.rd = rd

	c.wg.Add(1)
	go c.loop()
	return nil
}

func (c *Collector) startLSM() error {
	spec, err := LoadExecLSM()
	if err != nil {
		return fmt.Errorf("load bpf spec: %w", err)
	}

	var objs lsmLoadObjects
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		return fmt.Errorf("load lsm objs: %w", err)
	}

	lk, err := link.AttachLSM(link.LSMOptions{
		Program: objs.OnBprmCheckSecurity,
	})
	if err != nil {
		_ = objs.OnBprmCheckSecurity.Close()
		_ = objs.OnSysEnterOpenat.Close()
		_ = objs.Events.Close()
		return fmt.Errorf("attach lsm: %w", err)
	}
	openat, err := link.Tracepoint("syscalls", "sys_enter_openat", objs.OnSysEnterOpenat, nil)
	if err != nil {
		_ = lk.Close()
		_ = objs.OnBprmCheckSecurity.Close()
		_ = objs.OnSysEnterOpenat.Close()
		_ = objs.Events.Close()
		return fmt.Errorf("attach openat tp: %w", err)
	}

	c.objs.OnBprmCheckSecurity = objs.OnBprmCheckSecurity
	c.objs.OnSysEnterOpenat = objs.OnSysEnterOpenat
	c.objs.Events = objs.Events
	c.lks = []link.Link{lk, openat}
	return nil
}

func (c *Collector) startTracepoints() error {
	spec, err := LoadExecLSM()
	if err != nil {
		return fmt.Errorf("load bpf spec: %w", err)
	}

	var objs traceLoadObjects
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		return fmt.Errorf("load tracepoint objs: %w", err)
	}

	var lks []link.Link
	var errs []string
	if objs.OnSysEnterExecve != nil {
		tp, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.OnSysEnterExecve, nil)
		if err != nil {
			errs = append(errs, fmt.Sprintf("execve: %v", err))
		} else {
			lks = append(lks, tp)
		}
	}
	if objs.OnSysEnterExecveat != nil {
		tp, err := link.Tracepoint("syscalls", "sys_enter_execveat", objs.OnSysEnterExecveat, nil)
		if err != nil {
			errs = append(errs, fmt.Sprintf("execveat: %v", err))
		} else {
			lks = append(lks, tp)
		}
	}
	if objs.OnSysEnterOpenat != nil {
		tp, err := link.Tracepoint("syscalls", "sys_enter_openat", objs.OnSysEnterOpenat, nil)
		if err != nil {
			errs = append(errs, fmt.Sprintf("openat: %v", err))
		} else {
			lks = append(lks, tp)
		}
	}

	if len(lks) == 0 {
		_ = objs.OnSysEnterExecve.Close()
		_ = objs.OnSysEnterExecveat.Close()
		_ = objs.OnSysEnterOpenat.Close()
		_ = objs.Events.Close()
		if len(errs) == 0 {
			return fmt.Errorf("no tracepoint programs were loaded")
		}
		return errors.New(strings.Join(errs, "; "))
	}

	c.objs.OnSysEnterExecve = objs.OnSysEnterExecve
	c.objs.OnSysEnterExecveat = objs.OnSysEnterExecveat
	c.objs.OnSysEnterOpenat = objs.OnSysEnterOpenat
	c.objs.Events = objs.Events
	c.lks = lks
	return nil
}

func (c *Collector) Close() error {
	close(c.stopCh)
	c.wg.Wait()
	if c.rd != nil {
		_ = c.rd.Close()
	}
	_ = c.closeLinks()
	c.objs.Close()
	return nil
}

func (c *Collector) closeLinks() error {
	var firstErr error
	for _, lk := range c.lks {
		if lk == nil {
			continue
		}
		if err := lk.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	c.lks = nil
	return firstErr
}

func (c *Collector) loop() {
	defer c.wg.Done()

	for {
		select {
		case <-c.stopCh:
			return
		default:
		}

		rec, err := c.rd.Read()
		if err != nil {
			return
		}

		var ev ExecEvent
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &ev); err != nil {
			continue
		}

		c.handleEvent(&ev)
	}
}

type auditExecEvent struct {
	Schema string `json:"schema"` // "audit-exec/0.1"
	Seq    uint64 `json:"seq"`
	TsNS   uint64 `json:"ts_ns"`
	Pid    uint32 `json:"pid"`
	Ppid   uint32 `json:"ppid"`
	Uid    uint32 `json:"uid"`
	Comm   string `json:"comm"`
	Fn     string `json:"filename"`
}

type auditWorkspaceWriteEvent struct {
	Schema string `json:"schema"` // "audit-workspace-write/0.1"
	Seq    uint64 `json:"seq"`
	TsNS   uint64 `json:"ts_ns"`
	Pid    uint32 `json:"pid"`
	Ppid   uint32 `json:"ppid"`
	Uid    uint32 `json:"uid"`
	Comm   string `json:"comm"`
	Fn     string `json:"filename"`
	Op     string `json:"op"`
	Flags  uint32 `json:"flags"`
}

func (c *Collector) handleEvent(ev *ExecEvent) {
	pid := int(ev.Pid)

	c.mu.Lock()
	defer c.mu.Unlock()

	// Find matching session by ancestor check against initPID.
	var ss *sessionState
	for _, s := range c.sessions {
		// Prefer cgroup attribution for container scoping.
		if inContainerCgroup(pid, s.cgroups) {
			ss = s
			break
		}
	}
	if ss == nil {
		for _, s := range c.sessions {
			// Fallback when cgroup read failed/unavailable.
			if s.initPID > 0 && isDescendant(pid, s.initPID, 64) {
				ss = s
				break
			}
		}
	}
	if ss == nil && len(c.sessions) == 1 {
		for _, s := range c.sessions {
			// Last resort only when we have no cgroup baseline.
			if len(s.cgroups) == 0 {
				ss = s
			}
		}
	}
	if ss == nil {
		return
	}

	now := time.Now().UTC()
	if ss.start.IsZero() {
		ss.start = now
	}
	ss.end = now

	ss.seq++
	seq := ss.seq

	switch ev.EventType {
	case EventTypeExec:
		ss.execCount++
		execFn := ev.FilenameString()
		if id, ok := writerIdentityForPIDOrExecPath(pid, execFn, ss.shaCache, ss.pidExec); ok {
			key := fmt.Sprintf("%s:%d:%d", id.SHA256, id.Dev, id.Inode)
			ss.execs[key] = id
			ss.pidExec[pid] = id
		} else {
			ss.execIdentityUnresolved++
			ss.execIdentityUnresolvedHints = appendHint(ss.execIdentityUnresolvedHints, fmt.Sprintf("pid=%d comm=%s fn=%s", pid, ev.CommString(), execFn))
		}
		aev := auditExecEvent{
			Schema: "audit-exec/0.1",
			Seq:    seq,
			TsNS:   ev.TsNs,
			Pid:    ev.Pid,
			Ppid:   ev.Ppid,
			Uid:    ev.Uid,
			Comm:   ev.CommString(),
			Fn:     execFn,
		}

		logPath := filepath.Join(ss.dir, "audit_exec.jsonl")
		f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err == nil {
			enc := json.NewEncoder(f)
			enc.SetEscapeHTML(false)
			_ = enc.Encode(aev)
			_ = f.Close()
		}

		canon, err := spec.CanonicalJSON(aev)
		if err == nil {
			ss.events = append(ss.events, canon)
		}
	case EventTypeWorkspaceWrite:
		ss.workspaceWriteCount++
		ss.workspaceWriteByOp["open_write"]++

		if id, ok := writerIdentityForPID(pid, ss.shaCache, ss.pidExec); ok {
			key := fmt.Sprintf("%s:%d:%d", id.SHA256, id.Dev, id.Inode)
			ss.writers[key] = id
		} else {
			ss.writerIdentityUnresolved++
			ss.writerIdentityUnresolvedHints = appendHint(ss.writerIdentityUnresolvedHints, fmt.Sprintf("pid=%d comm=%s fn=%s", pid, ev.CommString(), ev.FilenameString()))
		}

		wev := auditWorkspaceWriteEvent{
			Schema: "audit-workspace-write/0.1",
			Seq:    seq,
			TsNS:   ev.TsNs,
			Pid:    ev.Pid,
			Ppid:   ev.Ppid,
			Uid:    ev.Uid,
			Comm:   ev.CommString(),
			Fn:     ev.FilenameString(),
			Op:     "open_write",
			Flags:  ev.Flags,
		}

		logPath := filepath.Join(ss.dir, "audit_workspace_write.jsonl")
		f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err == nil {
			enc := json.NewEncoder(f)
			enc.SetEscapeHTML(false)
			_ = enc.Encode(wev)
			_ = f.Close()
		}

		canon, err := spec.CanonicalJSON(wev)
		if err == nil {
			ss.events = append(ss.events, canon)
		}
	}
}

func writerIdentityForPID(pid int, cache map[string]string, pidCache map[int]model.ExecutableIdentity) (model.ExecutableIdentity, bool) {
	if id, ok := pidCache[pid]; ok && id.SHA256 != "" {
		return id, true
	}
	exePath, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil || exePath == "" {
		return model.ExecutableIdentity{}, false
	}
	return executableIdentityForPath(exePath, cache, pidCache, pid)
}

func writerIdentityForPIDOrExecPath(pid int, execPath string, cache map[string]string, pidCache map[int]model.ExecutableIdentity) (model.ExecutableIdentity, bool) {
	if strings.TrimSpace(execPath) != "" {
		if id, ok := executableIdentityForPath(execPath, cache, pidCache, pid); ok {
			return id, true
		}
	}
	return writerIdentityForPID(pid, cache, pidCache)
}

func executableIdentityForPath(exePath string, cache map[string]string, pidCache map[int]model.ExecutableIdentity, pid int) (model.ExecutableIdentity, bool) {
	exePath = normalizeExecutablePath(exePath)
	if exePath == "" {
		return model.ExecutableIdentity{}, false
	}
	openPath := exePath
	st, err := os.Stat(openPath)
	if err != nil && pid > 0 && filepath.IsAbs(exePath) {
		// Host-side collector may not resolve container paths directly; retry via target PID mount namespace.
		nsPath := filepath.Join("/proc", fmt.Sprintf("%d", pid), "root", strings.TrimPrefix(exePath, "/"))
		if st2, err2 := os.Stat(nsPath); err2 == nil {
			st = st2
			openPath = nsPath
		}
	}
	if err != nil && st == nil {
		return model.ExecutableIdentity{}, false
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return model.ExecutableIdentity{}, false
	}

	sha, ok := cache[exePath]
	if !ok {
		f, err := os.Open(openPath)
		if err != nil {
			return model.ExecutableIdentity{}, false
		}
		h := sha256.New()
		if _, err := io.Copy(h, f); err != nil {
			_ = f.Close()
			return model.ExecutableIdentity{}, false
		}
		_ = f.Close()
		sha = "sha256:" + hex.EncodeToString(h.Sum(nil))
		cache[exePath] = sha
	}

	id := model.ExecutableIdentity{
		SHA256:   sha,
		Inode:    sys.Ino,
		Dev:      uint64(sys.Dev),
		PathHint: exePath,
	}
	if pidCache != nil {
		pidCache[pid] = id
	}
	return id, true
}

func normalizeExecutablePath(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return ""
	}
	// /proc/<pid>/exe and some tracing outputs may expose deleted executables with this suffix.
	p = strings.TrimSuffix(p, " (deleted)")
	return p
}

func cstr(b []byte) string {
	// bpf2go generates fixed arrays; they are NUL-terminated
	n := 0
	for n < len(b) && b[n] != 0 {
		n++
	}
	return string(b[:n])
}

// --- collector interface ---

func (c *Collector) RegisterSession(ctx context.Context, reg collector.SessionRegistration) error {
	_ = ctx
	c.mu.Lock()
	defer c.mu.Unlock()

	dir := c.statedir.SessionDir(reg.SessionID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	var cgroups []string
	if reg.ContainerInitPID > 0 {
		if paths, err := readCgroupPaths(reg.ContainerInitPID); err == nil {
			cgroups = paths
		}
	}

	c.sessions[reg.SessionID] = &sessionState{
		sessionID:          reg.SessionID,
		initPID:            reg.ContainerInitPID,
		cgroups:            cgroups,
		dir:                dir,
		workspaceWriteByOp: map[string]uint64{},
		writers:            map[string]model.ExecutableIdentity{},
		execs:              map[string]model.ExecutableIdentity{},
		shaCache:           map[string]string{},
		pidExec:            map[int]model.ExecutableIdentity{},
	}
	return nil
}

func (c *Collector) FinalizeSession(ctx context.Context, sessionID string) (*collector.FinalizeResult, error) {
	_ = ctx
	c.mu.Lock()
	ss, ok := c.sessions[sessionID]
	if !ok {
		c.mu.Unlock()
		return nil, fmt.Errorf("unknown session: %s", sessionID)
	}
	execCount := ss.execCount
	execIdentityUnresolved := ss.execIdentityUnresolved
	workspaceWriteCount := ss.workspaceWriteCount
	writerIdentityUnresolved := ss.writerIdentityUnresolved
	workspaceWriteByOp := make(map[string]uint64, len(ss.workspaceWriteByOp))
	for k, v := range ss.workspaceWriteByOp {
		workspaceWriteByOp[k] = v
	}
	writers := make([]model.ExecutableIdentity, 0, len(ss.writers))
	for _, w := range ss.writers {
		writers = append(writers, w)
	}
	execs := make([]model.ExecutableIdentity, 0, len(ss.execs))
	for _, e := range ss.execs {
		execs = append(execs, e)
	}
	sort.Slice(writers, func(i, j int) bool {
		if writers[i].SHA256 != writers[j].SHA256 {
			return writers[i].SHA256 < writers[j].SHA256
		}
		if writers[i].Dev != writers[j].Dev {
			return writers[i].Dev < writers[j].Dev
		}
		if writers[i].Inode != writers[j].Inode {
			return writers[i].Inode < writers[j].Inode
		}
		return writers[i].PathHint < writers[j].PathHint
	})
	sort.Slice(execs, func(i, j int) bool {
		if execs[i].SHA256 != execs[j].SHA256 {
			return execs[i].SHA256 < execs[j].SHA256
		}
		if execs[i].Dev != execs[j].Dev {
			return execs[i].Dev < execs[j].Dev
		}
		if execs[i].Inode != execs[j].Inode {
			return execs[i].Inode < execs[j].Inode
		}
		return execs[i].PathHint < execs[j].PathHint
	})
	start := ss.start
	end := ss.end
	events := append([][]byte(nil), ss.events...)
	execUnresolvedHints := append([]string(nil), ss.execIdentityUnresolvedHints...)
	writerUnresolvedHints := append([]string(nil), ss.writerIdentityUnresolvedHints...)
	c.mu.Unlock()

	// Compute event root (hash chain)
	seed := []byte("session-attested:" + sessionID)
	hc := spec.HashChainRoot(seed, events)

	if start.IsZero() {
		now := time.Now().UTC()
		start = now
		end = now
	}

	summary := &model.AuditSummary{
		Window: model.AuditWindow{
			StartRFC3339: start.Format(time.RFC3339),
			EndRFC3339:   end.Format(time.RFC3339),
		},
		ExecObserved: model.ExecObserved{
			Count:                   execCount,
			ForbiddenSeen:           0, // マイルストーン10で forbidden 照合を入れる（sha256 fingerprint 計算）
			IdentityUnresolved:      execIdentityUnresolved,
			IdentityUnresolvedHints: execUnresolvedHints,
		},
		ExecutedIdentities: execs,
		WorkspaceWritesObserved: model.WorkspaceWritesObserved{
			Count:                         workspaceWriteCount,
			ByOp:                          workspaceWriteByOp,
			WriterIdentityUnresolved:      writerIdentityUnresolved,
			WriterIdentityUnresolvedHints: writerUnresolvedHints,
		},
		WriterIdentities: writers,
	}

	return &collector.FinalizeResult{
		Summary:            summary,
		EventRootAlg:       "hash_chain_sha256",
		EventRootHex:       spec.Hex32(hc.Root),
		EventCount:         hc.Count,
		WindowStartRFC3339: summary.Window.StartRFC3339,
		WindowEndRFC3339:   summary.Window.EndRFC3339,
		CollectorLogID:     "ebpf-lsm:" + sessionID,
	}, nil
}

func appendHint(dst []string, s string) []string {
	const maxHints = 8
	if strings.TrimSpace(s) == "" {
		return dst
	}
	for _, x := range dst {
		if x == s {
			return dst
		}
	}
	if len(dst) >= maxHints {
		return dst
	}
	return append(dst, s)
}

func (c *Collector) Status(ctx context.Context, sessionID string) (string, error) {
	_ = ctx
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.sessions[sessionID]; ok {
		return "running", nil
	}
	return "unknown", nil
}

func (c *Collector) ResolveSession(ctx context.Context, req collector.ContainerResolveRequest) (string, bool, error) {
	_ = ctx
	if req.Labels != nil {
		if sid := req.Labels["attested.session_id"]; sid != "" {
			return sid, true, nil
		}
	}
	return "", false, nil
}
