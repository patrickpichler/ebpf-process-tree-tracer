package tracer

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"sync/atomic"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
	"patrickpichler.dev/process-tree-tracer/pkg/processtree"
)

type TracerCfg struct {
	TailCallTarget *ebpf.Program
	TargetPID      int32
	ProcessTree    *processtree.ProcessTree
}

type Tracer struct {
	log    *slog.Logger
	objs   *tracerObjects
	loaded atomic.Bool
	cfg    TracerCfg

	links []link.Link
}

func New(log *slog.Logger, cfg TracerCfg) (Tracer, error) {
	return Tracer{
		log: log,
		cfg: cfg,
	}, nil
}

func (t *Tracer) load() error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("error while removing memlock: %w", err)
	}

	spec, err := loadTracer()
	if err != nil {
		return fmt.Errorf("error while loading bpf spec: %w", err)
	}

	objs := tracerObjects{}

	config := tracerConfig{
		TargetPid: t.cfg.TargetPID,
	}

	if err := spec.Variables["conf"].Set(config); err != nil {
		return err
	}

	if err := spec.LoadAndAssign(&objs, &ebpf.CollectionOptions{}); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			t.log.Error(fmt.Sprintf("Verifier error: %+v", ve))
		}

		return fmt.Errorf("error while loading and assigning tracer objs: %w", err)
	}

	t.objs = &objs

	if err := t.objs.tracerMaps.TailCallMap.Update(int32(0), t.cfg.TailCallTarget, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("error updating tail_call_map: %w", err)
	}

	t.loaded.Store(true)

	return nil
}

func (t *Tracer) Attach() error {
	if !t.loaded.Load() {
		return errors.New("tracer needs to be loaded before it can be attached")
	}

	copyProcessLink, err := link.Kprobe("copy_process", t.objs.tracerPrograms.Trigger, &link.KprobeOptions{})
	if err != nil {
		return fmt.Errorf("error attaching copy_process: %w", err)
	}
	t.links = append(t.links, copyProcessLink)

	schedProcessExecLink, err := link.AttachTracing(link.TracingOptions{
		Program:    t.objs.SchedProcessExec,
		AttachType: ebpf.AttachTraceRawTp,
	})
	if err != nil {
		return fmt.Errorf("error attaching sched_process_exec: %w", err)
	}
	t.links = append(t.links, schedProcessExecLink)

	schedProcessForkLink, err := link.AttachTracing(link.TracingOptions{
		Program:    t.objs.SchedProcessFork,
		AttachType: ebpf.AttachTraceRawTp,
	})
	if err != nil {
		return fmt.Errorf("error attaching sched_process_fork: %w", err)
	}
	t.links = append(t.links, schedProcessForkLink)

	schedProcessExitLink, err := link.AttachTracing(link.TracingOptions{
		Program:    t.objs.SchedProcessExit,
		AttachType: ebpf.AttachTraceRawTp,
	})
	if err != nil {
		return fmt.Errorf("error attaching sched_process_exit: %w", err)
	}
	t.links = append(t.links, schedProcessExitLink)

	return nil
}

func (t *Tracer) Close() {
	for _, l := range t.links {
		l.Close()
	}

	t.objs.Close()
}

func (t *Tracer) Init() error {
	if err := t.load(); err != nil {
		return fmt.Errorf("error loading tracer: %w", err)
	}

	return nil
}

var (
	ErrNotLoaded        = errors.New("not loaded")
	ErrPayloadTooSmall  = errors.New("payload too small")
	ErrUnknownEventType = errors.New("unknown event type")
)

func (t *Tracer) extractEventType(data []byte) (tracerEventType, error) {
	if len(data) == 0 {
		return 0, ErrPayloadTooSmall
	}

	if data[0] == byte(tracerEventTypeUNKNOWN) && data[0] >= byte(tracerEventTypeMAX_EVENT_TYPE) {
		return 0, fmt.Errorf("cannot parse event type %d: %w", data[0], ErrUnknownEventType)
	}

	return tracerEventType(data[0]), nil
}

func (t *Tracer) Run(ctx context.Context) error {
	if !t.loaded.Load() {
		return ErrNotLoaded
	}

	eventReader, err := ringbuf.NewReader(t.objs.Events)
	if err != nil {
		return fmt.Errorf("error while creating ringbuf reader: %w", err)
	}

	go func() {
		<-ctx.Done()
		eventReader.Close()
	}()

	var record ringbuf.Record

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		err := eventReader.ReadInto(&record)
		if err != nil {
			return fmt.Errorf("error reading from ringbuf: %w", err)
		}

		eventType, err := t.extractEventType(record.RawSample)
		_ = eventType
		if err != nil {
			t.log.Error("error parsing event type",
				slog.Any("error", err))
			continue
		}

		switch eventType {
		case tracerEventTypeFORK:
			var forkEvent tracerForkEvent
			r := bytes.NewReader(record.RawSample)

			if err := binary.Read(r, binary.LittleEndian, &forkEvent); err != nil {
				t.log.Error("errro while parsing fork_event from ringbuf",
					slog.Any("error", err))
				continue
			}

			slog.Info("got fork event",
				slog.String("event_type", forkEvent.Event.Type.String()),
				slog.Uint64("cgroup_id", forkEvent.Event.CgroupId),
				slog.Int("pid", int(forkEvent.Event.ProcessIdentity.Pid)),
				slog.Int("nspid", int(forkEvent.Event.NsPid)),
				slog.Int("ppid", int(forkEvent.Parent.Pid)),
				slog.String("comm", unix.ByteSliceToString(forkEvent.Event.Comm[:])),
			)

			t.cfg.ProcessTree.ProcessFork(processtree.ProcessIdentity{
				Pid:       forkEvent.Event.ProcessIdentity.Pid,
				StartTime: forkEvent.Event.ProcessIdentity.StartTime,
			},
				processtree.ProcessIdentity{
					Pid:       forkEvent.Parent.Pid,
					StartTime: forkEvent.Parent.StartTime,
				},
				processtree.ProcessInfo{
					NsPid: forkEvent.Event.NsPid,
					NsTid: forkEvent.Event.NsTid,
				},
			)
			continue
		case tracerEventTypeEXEC, tracerEventTypeEXIT:
			var event tracerEvent

			r := bytes.NewReader(record.RawSample)

			if err := binary.Read(r, binary.LittleEndian, &event); err != nil {
				t.log.Error("errro while parsing event from ringbuf",
					slog.Any("error", err))
				continue
			}

			slog.Info("got event",
				slog.String("event_type", event.Type.String()),
				slog.Uint64("cgroup_id", event.CgroupId),
				slog.Int("pid", int(event.ProcessIdentity.Pid)),
				slog.Int("nspid", int(event.NsPid)),
				slog.String("comm", unix.ByteSliceToString(event.Comm[:])),
			)

			if eventType == tracerEventTypeEXEC {
				t.cfg.ProcessTree.ProcessExec(processtree.ProcessIdentity{
					Pid:       event.ProcessIdentity.Pid,
					StartTime: event.ProcessIdentity.StartTime,
				},
					"",
					"",
				)
			} else {
				t.cfg.ProcessTree.ProcessExit(processtree.ProcessIdentity{
					Pid:       event.ProcessIdentity.Pid,
					StartTime: event.ProcessIdentity.StartTime,
				},
				)
			}
			continue
		}

	}
}
