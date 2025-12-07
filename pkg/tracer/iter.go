package tracer

import (
	"fmt"
	"io"

	"github.com/cilium/ebpf/link"
)

// TODO(patrick.pichler): this should somehow take a context.
func readIterator(iter *link.Iter) ([]byte, error) {
	r, err := iter.Open()
	if err != nil {
		return nil, fmt.Errorf("error while opening BPF interator: %w", err)
	}
	defer r.Close()
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("error while reading from BPF interator: %w", err)
	}
	return data, nil
}
