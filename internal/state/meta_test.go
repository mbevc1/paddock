package state

import (
	"context"
	"testing"
)

func TestReconciledVersion(t *testing.T) {
	ctx := context.Background()
	s, _ := openTemp(t)
	if v, err := s.ReconciledVersion(ctx); err != nil || v != "" {
		t.Fatalf("fresh ReconciledVersion = %q, %v", v, err)
	}
	for _, want := range []string{"0.5.1", "0.5.2"} {
		if err := s.SetReconciledVersion(ctx, want); err != nil {
			t.Fatal(err)
		}
		if v, err := s.ReconciledVersion(ctx); err != nil || v != want {
			t.Errorf("ReconciledVersion = %q, %v; want %q", v, err, want)
		}
	}
}
