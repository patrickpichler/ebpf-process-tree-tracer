#include "types.h"
#include <vmlinux.h>

#include <vmlinux_missing.h>

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include <maps.h>

volatile const struct config conf;

SEC("kprobe/trigger")
int trigger(void *ctx) {
  int pid = bpf_get_current_pid_tgid() >> 32;

  if (conf.target_pid != pid) {
    return 0;
  }

  bpf_tail_call_static(ctx, &tail_call_map, 0);
  return 0;
}

void fill_process_identity(struct process_identity *identity,
                           struct task_struct *task) {
  identity->pid = task->pid;
  identity->start_time = task->start_time;
  BPF_PROBE_READ_STR_INTO(&identity->comm, task, comm);
}

u64 get_cgroup_id(struct task_struct *task) {
  return task->cgroups->dfl_cgrp->kn->id;
}

SEC("tp_btf/sched_process_fork")
int BPF_PROG(sched_process_fork, struct task_struct *parent,
             struct task_struct *child) {

  struct fork_event *fork_event =
      bpf_ringbuf_reserve(&events, sizeof(struct fork_event), 0);
  if (!fork_event) {
    return 0;
  }

  struct event *event = &fork_event->event;

  event->type = FORK;
  event->ts = bpf_ktime_get_ns();
  event->cgroup_id = get_cgroup_id(child);
  fill_process_identity(&event->process_identity, child);
  fill_process_identity(&fork_event->parent, parent);

  bpf_ringbuf_submit(event, 0);

  return 0;

err:
  bpf_ringbuf_discard(event, 0);
  return 0;
}

SEC("tp_btf/sched_process_exec")
int BPF_PROG(sched_process_exec, struct task_struct *parent, pid_t pid,
             struct linux_binprm *bprm) {
  struct event *event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
  if (!event) {
    return 0;
  }

  event->type = EXEC;
  event->ts = bpf_ktime_get_ns();
  event->cgroup_id = get_cgroup_id(parent);
  event->process_identity.pid = pid;
  event->process_identity.start_time = parent->start_time;
  BPF_PROBE_READ_STR_INTO(&event->process_identity.comm, parent, comm);

  bpf_ringbuf_submit(event, 0);

  return 0;

err:
  bpf_ringbuf_discard(event, 0);
  return 0;
}

SEC("tp_btf/sched_process_exit")
int BPF_PROG(sched_process_exit, struct task_struct *task) {
  struct event *event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
  if (!event) {
    return 0;
  }

  event->type = EXIT;
  event->ts = bpf_ktime_get_ns();
  event->cgroup_id = get_cgroup_id(task);
  fill_process_identity(&event->process_identity, task);

  bpf_ringbuf_submit(event, 0);

  return 0;

err:
  bpf_ringbuf_discard(event, 0);
  return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
