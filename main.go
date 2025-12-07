package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"go.opentelemetry.io/collector/pdata/pprofile/pprofileotlp"
	"go.opentelemetry.io/ebpf-profiler/host"
	"go.opentelemetry.io/ebpf-profiler/reporter"
	"go.opentelemetry.io/ebpf-profiler/times"
	"go.opentelemetry.io/ebpf-profiler/tracehandler"
	profiler "go.opentelemetry.io/ebpf-profiler/tracer"
	profilertracertypes "go.opentelemetry.io/ebpf-profiler/tracer/types"
	"google.golang.org/grpc"
	"patrickpichler.dev/process-tree-tracer/pkg/processtree"
	"patrickpichler.dev/process-tree-tracer/pkg/tracer"
)

func newProfilesServer() *profilesServer {
	return &profilesServer{}
}

type profilesServer struct {
	pprofileotlp.UnimplementedGRPCServer
}

func (f *profilesServer) Export(ctx context.Context, request pprofileotlp.ExportRequest) (pprofileotlp.ExportResponse, error) {
	jsonData, err := request.MarshalJSON()
	if err != nil {
		return pprofileotlp.NewExportResponse(), err
	}

	nowStr := time.Now().Format(time.RFC3339)
	targetFile := "/tmp/profiles/" + nowStr + ".json"
	if err := os.WriteFile(targetFile, jsonData, 0666); err != nil {
		fmt.Println("error writing request:", err)
	}

	fmt.Println("====> written something to", targetFile)

	return pprofileotlp.NewExportResponse(), nil
}

func main() {
	log := slog.Default()
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM)
	defer cancel()

	var opts []grpc.ServerOption
	s := grpc.NewServer(opts...)
	pprofileotlp.RegisterGRPCServer(s, newProfilesServer())

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Error("error creating listener", slog.Any("error", err.Error()))
		os.Exit(1)
	}

	go func() {
		err = s.Serve(lis)
	}()

	fmt.Println("GRPC server started at ", lis.Addr().String())

	intervals := times.New(5*time.Second, 5*time.Second, 5*time.Second)

	// logrus.SetLevel(logrus.ErrorLevel)
	rep, err := reporter.NewOTLP(&reporter.Config{
		CollAgentAddr:          lis.Addr().String(),
		Name:                   "dummy",
		Version:                "dummy",
		MaxRPCMsgSize:          32 << 20,
		MaxGRPCRetries:         5,
		GRPCOperationTimeout:   5 * time.Second,
		GRPCStartupBackoffTime: 2 * time.Second,
		GRPCConnectionTimeout:  1 * time.Second,
		DisableTLS:             true,
		SamplesPerSecond:       100,
		ReportInterval:         intervals.ReportInterval(),
	})
	if err != nil {
		log.Error("error creating otlp reporter", slog.Any("error", err.Error()))
		os.Exit(1)
	}

	if err := rep.Start(ctx); err != nil {
		log.Error("error starting otlp exporter", slog.Any("error", err.Error()))
		os.Exit(1)
	}

	if err := startProfiler(ctx, rep, intervals); err != nil {
		log.Error("error starting profiler", slog.Any("error", err.Error()))
		os.Exit(1)
	}

	fmt.Println("polling profiler links...")
	prog, err := pollFindProfilerLinks(ctx, 5*time.Second)
	if err != nil {
		log.Error("error finding profiler links", slog.Any("error", err.Error()))
		os.Exit(1)
	}

	fmt.Println("loading tracer...")
	t, err := tracer.New(log, tracer.TracerCfg{
		TailCallTarget: prog,
		TargetPID:      695582,
		ProcessTree:    processtree.New(),
	})
	if err != nil {
		log.Error("error creating tracer", slog.Any("error", err.Error()))
		os.Exit(1)
	}
	fmt.Println("tracer loaded...")

	if err := t.Init(); err != nil {
		log.Error("error initializing the tracer", slog.Any("error", err.Error()))
		os.Exit(1)
	}
	defer t.Close()

	if err := t.Attach(); err != nil {
		log.Error("error attaching tracer", slog.Any("error", err.Error()))
		os.Exit(1)
	}

	fmt.Println("running...")
	t.Run(ctx)

	fmt.Println("done...")
	s.GracefulStop()
}

func startProfiler(ctx context.Context, rep reporter.Reporter, intervals *times.Times) error {
	if err := profiler.ProbeBPFSyscall(); err != nil {
		return fmt.Errorf("failed to probe eBPF syscall: %w", err)
	}

	trc, err := profiler.NewTracer(ctx, &profiler.Config{
		Intervals:              intervals,
		IncludeTracers:         profilertracertypes.AllTracers(),
		SamplesPerSecond:       100,
		MapScaleFactor:         0,
		FilterErrorFrames:      false,
		KernelVersionCheck:     true,
		VerboseMode:            false,
		BPFVerifierLogLevel:    0,
		ProbabilisticInterval:  0,
		ProbabilisticThreshold: 0,
		OffCPUThreshold:        0,
		LoadProbe:              true,
	})
	if err != nil {
		return fmt.Errorf("error loading profiler: %w", err)
	}
	trc.StartPIDEventProcessor(ctx)
	if err := trc.AttachSchedMonitor(); err != nil {
		return fmt.Errorf("failed to attach scheduler monitor: %w", err)
	}

	// Spawn monitors for the various result maps
	traceCh := make(chan *host.Trace)

	if err := trc.StartMapMonitors(ctx, traceCh); err != nil {
		return fmt.Errorf("failed to start map monitors: %v", err)
	}

	// TODO(patrick.pichler): random guess
	cacheSize := 100

	if err := rep.Start(ctx); err != nil {
		return fmt.Errorf("error starting reporter: %w", err)
	}

	if _, err := tracehandler.Start(ctx, rep, trc.TraceProcessor(), traceCh, intervals, uint32(cacheSize)); err != nil {
		return fmt.Errorf("error starting tracehandler: %w", err)
	}

	return nil
}

func pollFindProfilerLinks(ctx context.Context, timeout time.Duration) (*ebpf.Program, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	t := time.NewTicker(1 * time.Second)
	defer t.Stop()

	for {
		select {
		case <-t.C:
		case <-ctx.Done():
			return nil, ctx.Err()
		}

		prog, err := findProfilerLinks(ctx)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}

			return nil, err
		}

		return prog, nil
	}
}

func findProfilerLinks(ctx context.Context) (*ebpf.Program, error) {
	prog, err := findProgram(ctx, "uprobe__generic", ebpf.Kprobe)
	if err != nil {
		return nil, err
	}

	return prog, nil
}

func findProgram(ctx context.Context, name string, t ebpf.ProgramType) (*ebpf.Program, error) {
	id := ebpf.ProgramID(0)

	for {
		select {
		case <-ctx.Done():
			return nil, context.Canceled
		default:
		}

		nextID, err := ebpf.ProgramGetNextID(id)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				break
			}
			return nil, err
		}

		prog, err := ebpf.NewProgramFromID(nextID)
		if err != nil {
			// The program can disappear between getting the ID and loading it.
			if errors.Is(err, os.ErrNotExist) {
				break
			}

			return nil, fmt.Errorf("error getting program from ID: %w", err)
		}
		progInfo, err := prog.Info()
		if err != nil {
			prog.Close()
			return nil, fmt.Errorf("error while retrieving program info (id: %d): %w", nextID, err)
		}

		if progInfo.Type == t && progInfo.Name == name {
			return prog, nil
		}

		prog.Close()
		id = nextID
	}

	return nil, fmt.Errorf("error getting progam name: %q, type: %d: %w", name, t, os.ErrNotExist)
}
