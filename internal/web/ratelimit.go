package web

import (
	"sync"
	"time"
)

const (
	backoffStart = time.Second
	backoffMax   = 15 * time.Minute
	// limiterForget drops entries idle this long, bounding the table.
	limiterForget = time.Hour
)

// limiter applies exponential backoff per key after failures: 1 s after the first, doubling
// to 15 min (§11.3). A success clears the key.
type limiter struct {
	mu      sync.Mutex
	entries map[string]*backoff
	now     func() time.Time
}

type backoff struct {
	failures int
	until    time.Time
	last     time.Time
}

func newLimiter(now func() time.Time) *limiter {
	return &limiter{entries: map[string]*backoff{}, now: now}
}

// Wait returns how long the key must wait before its next attempt; zero means go ahead.
func (l *limiter) Wait(keys ...string) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	var wait time.Duration
	for _, k := range keys {
		if b, ok := l.entries[k]; ok && b.until.After(now) {
			wait = max(wait, b.until.Sub(now))
		}
	}
	return wait
}

// Fail records a failed attempt for each key.
func (l *limiter) Fail(keys ...string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	for _, k := range keys {
		b, ok := l.entries[k]
		if !ok {
			b = &backoff{}
			l.entries[k] = b
		}
		b.failures++
		delay := backoffStart << min(b.failures-1, 20)
		b.until, b.last = now.Add(min(delay, backoffMax)), now
	}
	for k, b := range l.entries {
		if now.Sub(b.last) > limiterForget && !b.until.After(now) {
			delete(l.entries, k)
		}
	}
}

// Succeed clears the keys.
func (l *limiter) Succeed(keys ...string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, k := range keys {
		delete(l.entries, k)
	}
}
