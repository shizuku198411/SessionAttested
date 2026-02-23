package ebpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall" ExecLSM ./bpf/exec_lsm.bpf.c
