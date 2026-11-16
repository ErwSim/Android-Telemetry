package export

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/erwsim/watchpost/server/collector/internal/store"
)

// Delivery guarantee
//
// The exporter is decoupled from ingestion by a persistent cursor: it reads
// events from the database in insertion order (events.pk, AUTOINCREMENT, hence
// strictly increasing in commit order since SQLite has a single writer), writes
// their lines, fsyncs the file and only then stores the cursor (kv
// "export_cursor"). Ingestion only sends a non-blocking wake-up signal, so a
// slow, full or missing export volume never fails or blocks ingestion.
// After a crash or restart the exporter resumes from the stored cursor: an
// accepted event is never lost for export (at-least-once: lines written but not
// yet acknowledged by the cursor may appear twice in Wazuh).

const (
	cursorKey  = "export_cursor"
	batchSize  = 500
	writeChunk = 256 << 10
	pollEvery  = 5 * time.Second
	maxBackoff = time.Minute
)

// Exporter copies stored events to the NDJSON file.
type Exporter struct {
	st     *store.Store
	w      *FileWriter
	log    *slog.Logger
	notify chan struct{}
	names  map[string]string

	mu     sync.Mutex
	cursor int64
	done   chan struct{}
}

// New creates an exporter writing to path.
func New(st *store.Store, path string, maxBytes int64, keep int, log *slog.Logger) *Exporter {
	return &Exporter{
		st: st, w: NewFileWriter(path, maxBytes, keep), log: log,
		notify: make(chan struct{}, 1), names: map[string]string{}, done: make(chan struct{}),
	}
}

// Notify wakes the exporter up; it never blocks.
func (e *Exporter) Notify() {
	select {
	case e.notify <- struct{}{}:
	default:
	}
}

// Cursor returns the pk of the last exported event.
func (e *Exporter) Cursor() int64 {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.cursor
}

// Init loads the cursor; on first use it starts after the newest existing
// event (history is not replayed into Wazuh).
func (e *Exporter) Init(ctx context.Context) error {
	v, ok, err := e.st.GetKV(ctx, cursorKey)
	if err != nil {
		return err
	}
	var c int64
	if ok {
		c, err = strconv.ParseInt(v, 10, 64)
		if err != nil {
			return fmt.Errorf("curseur d'export invalide : %q", v)
		}
	} else {
		if c, err = e.st.MaxEventPK(ctx); err != nil {
			return err
		}
		if err := e.st.SetKV(ctx, cursorKey, strconv.FormatInt(c, 10)); err != nil {
			return err
		}
	}
	e.mu.Lock()
	e.cursor = c
	e.mu.Unlock()
	// Create/open the file now rather than at the first event: wazuh-logcollector opens a file
	// that appears after its own start at the END, so the first lines written would never be
	// read. A failure is not fatal (missing volume): Run retries with backoff.
	if err := e.w.ensureOpen(); err != nil {
		e.log.Warn("export NDJSON : fichier non ouvrable au démarrage, nouvel essai à l'export", "path", e.w.path, "err", err)
	}
	return nil
}

// Run exports until ctx is canceled, then drains what is already stored
// (bounded by a short deadline) and closes the file.
func (e *Exporter) Run(ctx context.Context) {
	defer close(e.done)
	defer e.w.Close()
	backoff := time.Second
	t := time.NewTicker(pollEvery)
	defer t.Stop()
	for {
		err := e.drain(ctx)
		if err != nil && ctx.Err() == nil {
			e.log.Error("export NDJSON en échec, nouvel essai", "err", err, "retry_in", backoff.String())
			select {
			case <-ctx.Done():
			case <-time.After(backoff):
				backoff = min(backoff*2, maxBackoff)
				continue
			}
		} else if err == nil {
			backoff = time.Second
		}
		select {
		case <-ctx.Done():
			fin, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			if err := e.drain(fin); err != nil {
				e.log.Warn("export NDJSON : vidage final incomplet (repris au prochain démarrage)", "err", err)
			}
			cancel()
			return
		case <-e.notify:
		case <-t.C:
		}
	}
}

// Wait blocks until Run has returned.
func (e *Exporter) Wait() { <-e.done }

// drain exports everything after the cursor.
func (e *Exporter) drain(ctx context.Context) error {
	for {
		if err := ctx.Err(); err != nil {
			return nil
		}
		evs, err := e.st.EventsAfter(ctx, e.Cursor(), batchSize)
		if err != nil {
			return err
		}
		if len(evs) == 0 {
			return nil
		}
		var lines [][]byte
		for _, ev := range evs {
			lines = append(lines, Lines(ev, e.deviceName(ctx, ev.DeviceID))...)
		}
		if err := e.w.WriteLines(lines); err != nil {
			return err
		}
		last := evs[len(evs)-1].PK
		if err := e.st.SetKV(ctx, cursorKey, strconv.FormatInt(last, 10)); err != nil {
			return err
		}
		e.mu.Lock()
		e.cursor = last
		e.mu.Unlock()
	}
}

func (e *Exporter) deviceName(ctx context.Context, id string) string {
	if n, ok := e.names[id]; ok {
		return n
	}
	if names, err := e.st.DeviceNames(ctx); err == nil {
		e.names = names
	}
	return e.names[id]
}

// FileWriter appends complete lines to a file with rename-based rotation.
type FileWriter struct {
	path     string
	maxBytes int64
	keep     int
	f        *os.File
	size     int64
}

// NewFileWriter returns a writer; the file is opened lazily.
func NewFileWriter(path string, maxBytes int64, keep int) *FileWriter {
	return &FileWriter{path: path, maxBytes: maxBytes, keep: max(keep, 1)}
}

func (w *FileWriter) open() error {
	f, err := os.OpenFile(w.path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o640)
	if err != nil {
		return err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	w.f, w.size = f, st.Size()
	return w.terminatePartialLine()
}

// terminatePartialLine appends '\n' if the file does not end with one (crash
// or failed write in the middle of a line): never truncate, since Wazuh treats
// a shrinking file as tampering (rule 592).
func (w *FileWriter) terminatePartialLine() error {
	if w.size == 0 {
		return nil
	}
	r, err := os.Open(w.path)
	if err != nil {
		return err
	}
	defer r.Close()
	b := make([]byte, 1)
	if _, err := r.ReadAt(b, w.size-1); err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	if b[0] == '\n' {
		return nil
	}
	n, err := w.f.Write([]byte{'\n'})
	w.size += int64(n)
	return err
}

// ensureOpen (re)opens the file if needed, including when it was moved or
// removed by someone else.
func (w *FileWriter) ensureOpen() error {
	if w.f != nil {
		cur, err1 := w.f.Stat()
		onDisk, err2 := os.Stat(w.path)
		if err1 == nil && err2 == nil && os.SameFile(cur, onDisk) {
			return nil
		}
		w.f.Close()
		w.f = nil
	}
	return w.open()
}

// WriteLines appends lines (each ending with '\n'), rotating as needed, then fsyncs.
// Each write call contains only complete lines.
func (w *FileWriter) WriteLines(lines [][]byte) error {
	if err := w.ensureOpen(); err != nil {
		return err
	}
	var buf []byte
	flush := func() error {
		if len(buf) == 0 {
			return nil
		}
		n, err := w.f.Write(buf)
		w.size += int64(n)
		buf = buf[:0]
		if err != nil {
			// Partial line possible (disk full): terminate it on the next attempt.
			w.f.Close()
			w.f = nil
			return err
		}
		return nil
	}
	for _, l := range lines {
		if w.size+int64(len(buf))+int64(len(l)) > w.maxBytes && w.size+int64(len(buf)) > 0 {
			if err := flush(); err != nil {
				return err
			}
			if err := w.rotate(); err != nil {
				return err
			}
		}
		if len(buf)+len(l) > writeChunk {
			if err := flush(); err != nil {
				return err
			}
		}
		buf = append(buf, l...)
	}
	if err := flush(); err != nil {
		return err
	}
	return w.f.Sync()
}

// rotate renames path -> path.1 -> ... -> path.keep (dropping the oldest) and
// opens a fresh file. The file is never truncated.
func (w *FileWriter) rotate() error {
	if w.f != nil {
		_ = w.f.Sync()
		w.f.Close()
		w.f = nil
	}
	_ = os.Remove(fmt.Sprintf("%s.%d", w.path, w.keep))
	for i := w.keep - 1; i >= 1; i-- {
		from := fmt.Sprintf("%s.%d", w.path, i)
		if _, err := os.Stat(from); err == nil {
			if err := os.Rename(from, fmt.Sprintf("%s.%d", w.path, i+1)); err != nil {
				return err
			}
		}
	}
	if err := os.Rename(w.path, w.path+".1"); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return w.open()
}

// Close closes the file.
func (w *FileWriter) Close() error {
	if w.f == nil {
		return nil
	}
	err := w.f.Close()
	w.f = nil
	return err
}
