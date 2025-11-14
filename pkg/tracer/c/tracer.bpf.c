#include <vmlinux.h>
#include <vmlinux_missing.h>

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct {
  __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
  __uint(max_entries, 1);
  __type(key, u32);
  __type(value, u32);
} tail_call_map SEC(".maps");

volatile const int target_pid;

SEC("kprobe/trigger")
int trigger(void *ctx) {
  int pid = bpf_get_current_pid_tgid() >> 32;

  if (target_pid != pid) {
    return 0;
  }

  bpf_printk("triggered");

  // bpf_tail_call_static(ctx, &tail_call_map, 0);
  long err = 0;
  err = bpf_tail_call(ctx, &tail_call_map, 0);
  bpf_printk("failed %d", 1);
  return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
