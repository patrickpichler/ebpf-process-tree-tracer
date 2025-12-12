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

u32 __always_inline get_pidns_inum(struct task_struct *task) {
  return BPF_CORE_READ(task, nsproxy, pid_ns_for_children, ns.inum);
}

pid_t __always_inline get_task_pid_vnr(struct task_struct *task) {
  unsigned int level = 0;
  struct pid *pid = NULL;

  pid = BPF_CORE_READ(task, thread_pid); // NOLINT(bugprone-sizeof-expression)

  level = BPF_CORE_READ(pid, level);

  return BPF_CORE_READ(pid, numbers[level].nr);
}

pid_t __always_inline get_task_ns_pid(struct task_struct *task) {
  return get_task_pid_vnr(task);
}

pid_t __always_inline get_task_ns_tgid(struct task_struct *task) {
  struct task_struct *group_leader =
      BPF_CORE_READ(task, group_leader); // NOLINT(bugprone-sizeof-expression)
  return get_task_pid_vnr(group_leader);
}

void __always_inline fill_process_identity(struct process_identity *identity,
                                           struct task_struct *task) {
  identity->pid = task->tgid;
  identity->tid = task->pid;
  identity->start_time = task->start_time;
}

u64 get_cgroup_id(struct task_struct *task) {
  return task->cgroups->dfl_cgrp->kn->id;
}

SEC("tp_btf/sched_process_fork")
int BPF_PROG(sched_process_fork, struct task_struct *parent,
             struct task_struct *child) {

  u32 pidns_inum = get_pidns_inum(child);
  if (conf.target_pidns > 0 && conf.target_pidns != pidns_inum) {
    return 0;
  }

  struct fork_event *fork_event =
      bpf_ringbuf_reserve(&events, sizeof(struct fork_event), 0);
  if (!fork_event) {
    return 0;
  }

  struct event *event = &fork_event->event;

  event->type = FORK;
  event->ts = bpf_ktime_get_ns();
  event->cgroup_id = get_cgroup_id(child);
  event->ns_pid = get_task_ns_tgid(child);
  event->ns_tid = get_task_ns_pid(child);
  fill_process_identity(&event->process_identity, child);
  fill_process_identity(&fork_event->parent, parent);

  BPF_PROBE_READ_STR_INTO(&event->comm, child, comm);

  bpf_ringbuf_submit(event, 0);

  return 0;

err:
  bpf_ringbuf_discard(event, 0);
  return 0;
}

SEC("tp_btf/sched_process_exec")
int BPF_PROG(sched_process_exec, struct task_struct *parent, pid_t pid,
             struct linux_binprm *bprm) {

  u32 pidns_inum = get_pidns_inum(parent);
  if (conf.target_pidns > 0 && conf.target_pidns != pidns_inum) {
    return 0;
  }

  struct event *event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
  if (!event) {
    return 0;
  }

  event->type = EXEC;
  event->ts = bpf_ktime_get_ns();
  event->cgroup_id = get_cgroup_id(parent);
  event->process_identity.pid = pid;
  event->process_identity.start_time = parent->start_time;
  event->ns_pid = get_task_ns_tgid(parent);
  event->ns_tid = get_task_ns_pid(parent);
  BPF_PROBE_READ_STR_INTO(&event->comm, parent, comm);

  bpf_ringbuf_submit(event, 0);

  return 0;

err:
  bpf_ringbuf_discard(event, 0);
  return 0;
}

SEC("tp_btf/sched_process_exit")
int BPF_PROG(sched_process_exit, struct task_struct *task) {
  u32 pidns_inum = get_pidns_inum(task);
  if (conf.target_pidns > 0 && conf.target_pidns != pidns_inum) {
    return 0;
  }

  struct event *event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
  if (!event) {
    return 0;
  }

  event->type = EXIT;
  event->ts = bpf_ktime_get_ns();
  event->cgroup_id = get_cgroup_id(task);
  event->ns_pid = get_task_ns_tgid(task);
  event->ns_tid = get_task_ns_pid(task);
  fill_process_identity(&event->process_identity, task);
  BPF_PROBE_READ_STR_INTO(&event->comm, task, comm);

  bpf_ringbuf_submit(event, 0);

  return 0;

err:
  bpf_ringbuf_discard(event, 0);
  return 0;
}

SEC("iter/task")
int task_iter(struct bpf_iter__task *ctx) {
  // Simulate a fork and exec event to keep the userspace the same.
  // TODO(patrick.pichler): optimize this in the future.
  struct task_struct *task = ctx->task;
  if (!task) {
    return 0;
  }

  u32 pidns_inum = get_pidns_inum(task);
  if (conf.target_pidns > 0 && conf.target_pidns != pidns_inum) {
    return 0;
  }

  struct fork_event *fork_event =
      bpf_ringbuf_reserve(&events, sizeof(struct fork_event), 0);
  if (!fork_event) {
    return 0;
  }

  struct event *event = &fork_event->event;

  event->type = FORK;
  event->ts = bpf_ktime_get_ns();
  event->cgroup_id = get_cgroup_id(task);
  event->ns_pid = get_task_ns_tgid(task);
  event->ns_tid = get_task_ns_pid(task);
  fill_process_identity(&event->process_identity, task);
  fill_process_identity(&fork_event->parent, task->parent);

  BPF_PROBE_READ_STR_INTO(&event->comm, task, comm);

  bpf_ringbuf_submit(event, 0);

  event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
  if (!event) {
    return 0;
  }

  event->type = EXEC;
  event->ts = bpf_ktime_get_ns();
  event->cgroup_id = get_cgroup_id(task);
  fill_process_identity(&event->process_identity, task);
  event->ns_pid = get_task_ns_tgid(task);
  event->ns_tid = get_task_ns_pid(task);
  BPF_PROBE_READ_STR_INTO(&event->comm, task, comm);

  bpf_ringbuf_submit(event, 0);
  return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
