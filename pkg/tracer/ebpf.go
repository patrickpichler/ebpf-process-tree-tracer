package tracer

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target arm64 -type event_type -type fork_event -type event tracer ./c/tracer.bpf.c -- -I../../c/headers -Wno-address-of-packed-member -O2 -fno-stack-protector
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -type event_type -type fork_event -type event tracer ./c/tracer.bpf.c -- -I../../c/headers -Wno-address-of-packed-member -O2 -fno-stack-protector
