module patrickpichler.dev/process-tree-tracer

go 1.24.6

require (
	github.com/cilium/ebpf v0.20.0
	go.opentelemetry.io/collector/pdata/pprofile v0.141.0
	go.opentelemetry.io/ebpf-profiler v0.0.202536
	golang.org/x/sync v0.19.0
	golang.org/x/sys v0.39.0
	google.golang.org/grpc v1.77.0
)

require (
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/elastic/go-freelru v0.16.0 // indirect
	github.com/elastic/go-perf v0.0.0-20241029065020-30bec95324b8 // indirect
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/hashicorp/go-version v1.7.0 // indirect
	github.com/josharian/native v1.1.0 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/klauspost/cpuid/v2 v2.2.8 // indirect
	github.com/mdlayher/kobject v0.0.0-20200520190114-19ca17470d7d // indirect
	github.com/mdlayher/netlink v1.7.2 // indirect
	github.com/mdlayher/socket v0.4.1 // indirect
	github.com/minio/sha256-simd v1.0.1 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.3-0.20250322232337-35a7c28c31ee // indirect
	github.com/rogpeppe/go-internal v1.14.1 // indirect
	github.com/zeebo/xxh3 v1.0.2 // indirect
	go.opentelemetry.io/collector/consumer v1.47.0 // indirect
	go.opentelemetry.io/collector/consumer/xconsumer v0.141.0 // indirect
	go.opentelemetry.io/collector/featuregate v1.47.0 // indirect
	go.opentelemetry.io/collector/pdata v1.47.0 // indirect
	go.opentelemetry.io/otel v1.39.0 // indirect
	go.opentelemetry.io/otel/metric v1.39.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/arch v0.23.0 // indirect
	golang.org/x/exp v0.0.0-20251125195548-87e1e737ad39 // indirect
	golang.org/x/net v0.46.1-0.20251013234738-63d1a5100f82 // indirect
	golang.org/x/text v0.30.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20251022142026-3a174f9686a8 // indirect
	google.golang.org/protobuf v1.36.10 // indirect
)

replace go.opentelemetry.io/ebpf-profiler => github.com/patrickpichler/opentelemetry-ebpf-profiler v0.0.0-20251209163952-646aacc90c1d
