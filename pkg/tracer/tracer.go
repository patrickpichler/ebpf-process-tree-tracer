package tracer

import (
	"errors"
	"fmt"
	"log/slog"
	"sync/atomic"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

type TracerCfg struct {
	TailCallTarget *ebpf.Program
	TargetPID      int32
}

type Tracer struct {
	log    *slog.Logger
	objs   *tracerObjects
	loaded atomic.Bool
	cfg    TracerCfg

	link link.Link
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

	if err := spec.Variables["target_pid"].Set(t.cfg.TargetPID); err != nil {
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

	l, err := link.Kprobe("copy_process", t.objs.tracerPrograms.Trigger, &link.KprobeOptions{})
	if err != nil {
		return fmt.Errorf("error attaching kprobe: %w", err)
	}

	t.link = l

	return nil
}

func (t *Tracer) Close() {
	t.link.Close()
	t.objs.Close()
}

func (t *Tracer) Init() error {
	if err := t.load(); err != nil {
		return fmt.Errorf("error loading tracer: %w", err)
	}

	return nil
}
