// Package ratelimit provides a small keyed token-bucket limiter with bounded memory.
package ratelimit

import (
	"math"
	"sync"
	"time"
)

// Limiter is a set of token buckets indexed by key.
type Limiter struct {
	mu      sync.Mutex
	rate    float64 // tokens per second
	burst   float64
	maxKeys int
	buckets map[string]*bucket
	now     func() time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
}

// New returns a limiter refilling `rate` tokens per second up to `burst`.
// At most maxKeys buckets are kept; full buckets are dropped first.
func New(rate float64, burst int, maxKeys int) *Limiter {
	return &Limiter{rate: rate, burst: float64(burst), maxKeys: maxKeys, buckets: map[string]*bucket{}, now: time.Now}
}

// SetClock replaces the clock (tests).
func (l *Limiter) SetClock(now func() time.Time) { l.now = now }

func (l *Limiter) get(key string, now time.Time) *bucket {
	b := l.buckets[key]
	if b == nil {
		if len(l.buckets) >= l.maxKeys {
			l.gc(now)
		}
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[key] = b
		return b
	}
	el := now.Sub(b.last).Seconds()
	if el > 0 {
		b.tokens = math.Min(l.burst, b.tokens+el*l.rate)
		b.last = now
	}
	return b
}

// gc drops refilled buckets; if memory is still full, drops everything
// (fail-open on memory pressure rather than growing without bound).
func (l *Limiter) gc(now time.Time) {
	for k, b := range l.buckets {
		if b.tokens+now.Sub(b.last).Seconds()*l.rate >= l.burst {
			delete(l.buckets, k)
		}
	}
	if len(l.buckets) >= l.maxKeys {
		l.buckets = map[string]*bucket{}
	}
}

// Allow consumes one token for key and reports whether it was available.
// When not allowed, it also returns how long to wait for the next token.
func (l *Limiter) Allow(key string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	b := l.get(key, now)
	if b.tokens >= 1 {
		b.tokens--
		return true, 0
	}
	return false, l.wait(b)
}

// Blocked reports whether key has no token left, without consuming one.
func (l *Limiter) Blocked(key string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	b, ok := l.buckets[key]
	if !ok {
		return false, 0
	}
	b = l.get(key, now)
	if b.tokens >= 1 {
		return false, 0
	}
	return true, l.wait(b)
}

// Consume removes one token (possibly going to zero) for key; used to count failures.
func (l *Limiter) Consume(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.get(key, l.now())
	b.tokens = math.Max(0, b.tokens-1)
}

// Refund gives back one token taken by Allow (capped at the burst), for an
// attempt that turned out not to count (success, server busy).
func (l *Limiter) Refund(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.buckets[key]; !ok {
		return
	}
	b := l.get(key, l.now())
	b.tokens = math.Min(l.burst, b.tokens+1)
}

// Reset forgets key.
func (l *Limiter) Reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.buckets, key)
}

func (l *Limiter) wait(b *bucket) time.Duration {
	if l.rate <= 0 {
		return time.Hour
	}
	d := time.Duration((1 - b.tokens) / l.rate * float64(time.Second))
	if d < time.Second {
		d = time.Second
	}
	return d
}
