package processtree

import (
	"strconv"
)

type ProcessIdentity struct {
	CgroupID  uint64
	Pid       uint32
	StartTime uint64
}

func (p ProcessIdentity) String() string {
	return strconv.FormatUint(uint64(p.Pid), 10) + " (" +
		strconv.FormatUint(p.StartTime, 10) + ")"
}

type ProcessState uint8

const (
	ProcessStateUnknown = 0
	ProcessStateAlive   = 1
	ProcessStateExited  = 2
)

var processStateNames = map[ProcessState]string{
	ProcessStateAlive:  "alive",
	ProcessStateExited: "exited",
}

func (s ProcessState) String() string {
	if name, found := processStateNames[s]; found {
		return name
	}

	return "unknown"
}

type Process struct {
	Identity ProcessIdentity
	State    ProcessState
	Parent   ProcessIdentity

	Info ProcessInfo
}

type ProcessInfo struct {
	NsPid  uint32
	NsTid  uint32
	Binary string
	Args   string
}

type ProcessTree struct {
	processes map[ProcessIdentity]*Process
}

func New() *ProcessTree {
	return &ProcessTree{
		processes: map[ProcessIdentity]*Process{},
	}
}

func (t *ProcessTree) ProcessFork(
	identity ProcessIdentity,
	parent ProcessIdentity,
	info ProcessInfo,
) error {
	if p, found := t.processes[identity]; found {
		p.Parent = parent
		p.Info = info

		return nil
	}

	t.processes[identity] = &Process{
		Identity: identity,
		State:    ProcessStateAlive,
		Parent:   parent,
		Info:     info,
	}

	return nil
}

func (t *ProcessTree) ProcessExec(
	identity ProcessIdentity,
	binary string,
	args string,
) error {
	if proc, found := t.processes[identity]; found {
		proc.Info.Binary = binary
		proc.Info.Args = args
	}

	return nil
}

func (t *ProcessTree) ProcessExit(identity ProcessIdentity) error {
	if proc, found := t.processes[identity]; found {
		proc.State = ProcessStateExited
		return nil
	}
	return nil
}
