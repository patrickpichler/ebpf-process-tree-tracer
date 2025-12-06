#ifndef __TYPES_H__
#define __TYPES_H__

#include <helper.h>

#include <vmlinux.h>
#include <vmlinux_missing.h>

struct config {
  pid_t target_pid;
};

struct process_identity {
  u32 pid;
  u64 start_time;
  u8 comm[TASK_COMM_LEN];
};

enum event_type {
  UNKNOWN,
  FORK,
  EXEC,
  EXIT,
  MAX_EVENT_TYPE
} __attribute__((__packed__));

COMPILER_VERIFY(sizeof(enum event_type) == 1);

struct event {
  enum event_type type;
  u64 ts;
  struct process_identity process_identity;
  u64 cgroup_id;
};

struct fork_event {
  struct event event;
  struct process_identity parent;
};

// Force emitting struct event into the ELF.
const struct event *unused_event __attribute__((unused));

// Force emitting struct event into the ELF.
const struct fork_event *unused_fork_event __attribute__((unused));

#endif
