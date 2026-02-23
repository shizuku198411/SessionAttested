#ifndef __SESSION_ATTESTED_MIN_VMLINUX_H__
#define __SESSION_ATTESTED_MIN_VMLINUX_H__

/*
 * Minimal vmlinux.h for SessionAttested BPF programs.
 *
 * This project only uses a small subset of kernel types/fields in
 * internal/collector/ebpf/bpf/exec_lsm.bpf.c:
 *   - task_struct.real_parent / task_struct.tgid
 *   - linux_binprm.filename
 *   - trace_event_raw_sys_enter.args[]
 *
 * Keep this file small to reduce repository size and improve readability.
 * If the BPF program starts using additional kernel fields, extend the
 * corresponding struct definitions here.
 */

typedef unsigned char __u8;
typedef signed char __s8;
typedef unsigned short __u16;
typedef signed short __s16;
typedef unsigned int __u32;
typedef signed int __s32;
typedef unsigned long long __u64;
typedef signed long long __s64;

typedef __u16 __be16;
typedef __u32 __be32;
typedef __u32 __wsum;

typedef __u8 u8;
typedef __u16 u16;
typedef __u32 u32;
typedef __u64 u64;
typedef __s8 s8;
typedef __s16 s16;
typedef __s32 s32;
typedef __s64 s64;

typedef __u8 bool;
#ifndef true
#define true 1
#endif
#ifndef false
#define false 0
#endif

#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif

/*
 * libbpf map-definition macros in bpf_helpers.h may rely on BPF_MAP_TYPE_*
 * symbols being visible from vmlinux.h in this project setup.
 * Define only the map types we use.
 */
#ifndef BPF_MAP_TYPE_RINGBUF
#define BPF_MAP_TYPE_RINGBUF 27
#endif

/* Required by CO-RE field accesses. */
#pragma clang attribute push(__attribute__((preserve_access_index)), apply_to = record)

struct task_struct {
	struct task_struct *real_parent;
	int tgid;
};

struct linux_binprm {
	const char *filename;
};

struct trace_entry {
	unsigned short type;
	unsigned char flags;
	unsigned char preempt_count;
	int pid;
};

struct trace_event_raw_sys_enter {
	struct trace_entry ent;
	long id;
	unsigned long args[6];
	char __data[0];
};

#pragma clang attribute pop

#endif /* __SESSION_ATTESTED_MIN_VMLINUX_H__ */
