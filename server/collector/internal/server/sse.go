package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/erwsim/watchpost/server/collector/internal/store"
)

// Broker fans accepted events out to the SSE subscribers. Publishing never
// blocks ingestion: a subscriber whose buffer is full is disconnected (the
// browser's EventSource reconnects by itself).
type Broker struct {
	mu     sync.Mutex
	subs   map[*subscriber]struct{}
	max    int
	closed bool
}

type subscriber struct {
	device string
	ch     chan []byte
	done   chan struct{}
	once   sync.Once
}

func (s *subscriber) stop() { s.once.Do(func() { close(s.done) }) }

// NewBroker returns a broker accepting at most max subscribers.
func NewBroker(max int) *Broker {
	return &Broker{subs: map[*subscriber]struct{}{}, max: max}
}

var errTooManySubscribers = errors.New("too many open streams")

// Subscribe registers a subscriber for one device ("" for all).
func (b *Broker) Subscribe(device string) (*subscriber, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed || len(b.subs) >= b.max {
		return nil, errTooManySubscribers
	}
	s := &subscriber{device: device, ch: make(chan []byte, 512), done: make(chan struct{})}
	b.subs[s] = struct{}{}
	return s, nil
}

// Unsubscribe removes a subscriber.
func (b *Broker) Unsubscribe(s *subscriber) {
	b.mu.Lock()
	delete(b.subs, s)
	b.mu.Unlock()
	s.stop()
}

// Publish sends events to matching subscribers without blocking.
func (b *Broker) Publish(evs []store.StoredEvent) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.subs) == 0 {
		return
	}
	for _, ev := range evs {
		msg, err := json.Marshal(ev)
		if err != nil {
			continue
		}
		for s := range b.subs {
			if s.device != "" && s.device != ev.DeviceID {
				continue
			}
			select {
			case s.ch <- msg:
			default:
				delete(b.subs, s)
				s.stop()
			}
		}
	}
}

// Close disconnects every subscriber (server shutdown).
func (b *Broker) Close() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.closed = true
	for s := range b.subs {
		delete(b.subs, s)
		s.stop()
	}
}

const (
	sseKeepAlive    = 25 * time.Second
	sseWriteTimeout = 30 * time.Second
)

func (s *Server) handleStream(w http.ResponseWriter, r *http.Request) {
	dev, err := deviceParam(r.URL.Query(), false)
	if err != nil {
		s.fail(w, err)
		return
	}
	sub, err := s.broker.Subscribe(dev)
	if err != nil {
		writeRetry(w, 10*time.Second, err.Error())
		return
	}
	defer s.broker.Unsubscribe(sub)

	rc := http.NewResponseController(w)
	// The server-wide ReadTimeout would otherwise end this long-lived request.
	_ = rc.SetReadDeadline(time.Time{})
	h := w.Header()
	h.Set("Content-Type", "text/event-stream; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	write := func(p []byte) bool {
		_ = rc.SetWriteDeadline(time.Now().Add(sseWriteTimeout))
		if _, err := w.Write(p); err != nil {
			return false
		}
		return rc.Flush() == nil
	}
	if !write([]byte("retry: 5000\n: ok\n\n")) {
		return
	}
	ticker := time.NewTicker(sseKeepAlive)
	defer ticker.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-sub.done:
			// Drain what is already buffered is pointless: the client reconnects.
			return
		case msg := <-sub.ch:
			buf := make([]byte, 0, len(msg)+8)
			buf = append(buf, "data: "...)
			buf = append(buf, msg...)
			buf = append(buf, "\n\n"...)
			if !write(buf) {
				return
			}
		case <-ticker.C:
			// End the stream when the session has expired or was logged out.
			if _, _, ok := s.currentUser(r); !ok {
				return
			}
			if !write([]byte(": ping\n\n")) {
				return
			}
		}
	}
}
