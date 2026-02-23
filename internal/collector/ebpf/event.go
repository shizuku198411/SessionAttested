package ebpf

// c:
// struct exec_event {
//   __u64 ts_ns;
//   __u32 pid;
//   __u32 ppid;
//   __u32 uid;
//   __u32 event_type;
//   __u32 flags;
//   __u32 _pad;
//   char  comm[16];
//   char  filename[256];
// };

const (
	EventTypeExec           = 1
	EventTypeWorkspaceWrite = 2
)

type ExecEvent struct {
	TsNs      uint64
	Pid       uint32
	Ppid      uint32
	Uid       uint32
	EventType uint32
	Flags     uint32
	_         uint32
	Comm      [16]byte
	Filename  [256]byte
}

func cString(b []byte) string {
	n := 0
	for n < len(b) && b[n] != 0 {
		n++
	}
	return string(b[:n])
}

func (e *ExecEvent) CommString() string     { return cString(e.Comm[:]) }
func (e *ExecEvent) FilenameString() string { return cString(e.Filename[:]) }
