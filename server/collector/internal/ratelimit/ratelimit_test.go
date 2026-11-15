package ratelimit

import (
	"testing"
	"time"
)

func TestLimiter(t *testing.T) {
	now := time.Unix(1000, 0)
	l := New(1, 3, 10)
	l.SetClock(func() time.Time { return now })
	for i := range 3 {
		if ok, _ := l.Allow("a"); !ok {
			t.Fatalf("request %d refused", i)
		}
	}
	ok, wait := l.Allow("a")
	if ok || wait < time.Second {
		t.Fatalf("4th request allowed or bad wait %v", wait)
	}
	if ok, _ := l.Allow("b"); !ok {
		t.Fatal("keys are not independent")
	}
	now = now.Add(time.Second)
	if ok, _ := l.Allow("a"); !ok {
		t.Fatal("no refill")
	}
}

func TestConsumeAndBlocked(t *testing.T) {
	now := time.Unix(1000, 0)
	l := New(0.1, 2, 10)
	l.SetClock(func() time.Time { return now })
	if b, _ := l.Blocked("ip"); b {
		t.Fatal("unknown key blocked")
	}
	l.Consume("ip")
	l.Consume("ip")
	if b, wait := l.Blocked("ip"); !b || wait < 9*time.Second {
		t.Fatalf("not blocked after failures (wait %v)", wait)
	}
	now = now.Add(11 * time.Second)
	if b, _ := l.Blocked("ip"); b {
		t.Fatal("still blocked after refill")
	}
	l.Reset("ip")
}

func TestBoundedMemory(t *testing.T) {
	l := New(1, 1, 100)
	for i := range 1000 {
		l.Consume(string(rune(i)))
	}
	if len(l.buckets) > 100 {
		t.Fatalf("%d buckets kept", len(l.buckets))
	}
}
