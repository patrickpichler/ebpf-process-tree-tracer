package processtree

import (
	"strconv"
	"sync"
)

type ProcessIdentity struct {
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

func (e ProcessState) MarshallJSON() ([]byte, error) {
	if name, found := processStateNames[e]; found {
		return []byte(name), nil
	}

	return []byte("unknown"), nil
}

type ProcessEvent uint8

var processEventNames = map[ProcessEvent]string{
	ProcessEventFork: "fork",
	ProcessEventExec: "exec",
	ProcessEventExit: "exit",
}

const (
	ProcessEventUnknown = 0
	ProcessEventFork    = 1
	ProcessEventExec    = 2
	ProcessEventExit    = 3
)

func (e ProcessEvent) MarshallJSON() ([]byte, error) {
	if name, found := processEventNames[e]; found {
		return []byte(name), nil
	}

	return []byte("unknown"), nil
}

func (s ProcessEvent) String() string {
	if name, found := processEventNames[s]; found {
		return name
	}

	return "unknown"
}

type Process struct {
	Identity ProcessIdentity `json:"identity"`
	State    ProcessState    `json:"state"`
	Parent   ProcessIdentity `json:"parent"`

	Info      ProcessInfo  `json:"info"`
	LastEvent ProcessEvent `json:"last_event"`
}

type ProcessInfo struct {
	NsPid    uint32 `json:"nspid"`
	NsTid    uint32 `json:"nstid"`
	CgroupID uint64 `json:"cgroupid"`
	Binary   string `json:"binary"`
	Args     string `json:"args"`
	Comm     string `json:"comm"`
}

type ProcessTree struct {
	processes   map[ProcessIdentity]*Process
	processesMu sync.RWMutex
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
	t.processesMu.Lock()
	defer t.processesMu.Unlock()

	if p, found := t.processes[identity]; found {
		p.Parent = parent
		p.Info = info
		p.LastEvent = ProcessEventFork

		return nil
	}

	t.processes[identity] = &Process{
		Identity:  identity,
		State:     ProcessStateAlive,
		Parent:    parent,
		Info:      info,
		LastEvent: ProcessEventFork,
	}

	return nil
}

func (t *ProcessTree) ProcessExec(
	identity ProcessIdentity,
	comm string,
	binary string,
	args string,
) error {
	t.processesMu.Lock()
	defer t.processesMu.Unlock()

	if proc, found := t.processes[identity]; found {
		proc.Info.Comm = comm
		proc.Info.Binary = binary
		proc.Info.Args = args
		proc.LastEvent = ProcessEventExec
	}

	return nil
}

func (t *ProcessTree) ProcessExit(identity ProcessIdentity) error {
	t.processesMu.Lock()
	defer t.processesMu.Unlock()

	if proc, found := t.processes[identity]; found {
		proc.State = ProcessStateExited
		proc.LastEvent = ProcessEventExit
		return nil
	}
	return nil
}

func (t *ProcessTree) FindProcessesForCgroup(cgroupID uint64) []Process {
	t.processesMu.RLock()
	defer t.processesMu.RUnlock()

	result := []Process{}

	for _, p := range t.processes {
		if p.Info.CgroupID != cgroupID {
			continue
		}

		result = append(result, *p)
	}

	return result
}

func (t *ProcessTree) FindProcessesForPid(pid uint32) []Process {
	t.processesMu.RLock()
	defer t.processesMu.RUnlock()

	result := []Process{}

	for _, p := range t.processes {
		if p.Identity.Pid != pid {
			continue
		}

		result = append(result, *p)
	}

	return result
}
