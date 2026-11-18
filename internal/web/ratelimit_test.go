package web

import (
	"testing"
	"time"
)

func TestLimiterBackoff(t *testing.T) {
	now := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	l := newLimiter(func() time.Time { return now })
	if w := l.Wait("ip:a", "user:x"); w != 0 {
		t.Fatalf("fresh wait = %v", w)
	}
	want := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second}
	for _, d := range want {
		l.Fail("ip:a", "user:x")
		if w := l.Wait("ip:a"); w != d {
			t.Errorf("wait = %v, want %v", w, d)
		}
	}
	for range 20 {
		l.Fail("user:x")
	}
	if w := l.Wait("user:x"); w != backoffMax {
		t.Errorf("capped wait = %v", w)
	}
	if w := l.Wait("ip:b", "user:x"); w != backoffMax {
		t.Errorf("wait over several keys = %v", w)
	}
	now = now.Add(backoffMax)
	if w := l.Wait("user:x"); w != 0 {
		t.Errorf("wait after the backoff = %v", w)
	}
	l.Succeed("ip:a")
	if w := l.Wait("ip:a"); w != 0 {
		t.Errorf("wait after success = %v", w)
	}
}
