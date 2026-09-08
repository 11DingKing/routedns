package rdns

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/miekg/dns"
)

// QueryLogResolver logs requests to STDOUT or file.
type QueryLogResolver struct {
	id       string
	resolver Resolver
	opt      QueryLogResolverOptions
	logger   *slog.Logger
	// Closer for the output file when the resolver opened it. Unset when
	// logging to STDOUT, which the resolver does not own.
	closer io.Closer
}

var _ Resolver = &QueryLogResolver{}

type QueryLogResolverOptions struct {
	OutputFile   string // Output filename, leave blank for STDOUT
	OutputFormat LogFormat
	// MaxSize enables size-based rotation of OutputFile once it grows past
	// the given number of bytes. 0 (the default) disables rotation and keeps
	// the append-only behavior. Ignored when OutputFile is blank.
	MaxSize int64
}

type LogFormat string

const (
	LogFormatText LogFormat = "text"
	LogFormatJSON LogFormat = "json"
)

// NewQueryLogResolver returns a new instance of a QueryLogResolver.
func NewQueryLogResolver(id string, resolver Resolver, opt QueryLogResolverOptions) (*QueryLogResolver, error) {
	var w io.Writer = os.Stdout
	var closer io.Closer
	if opt.OutputFile != "" {
		fw, err := newRotatingFileWriter(opt.OutputFile, opt.MaxSize)
		if err != nil {
			return nil, err
		}
		w = fw
		closer = fw
	}
	handlerOpts := &slog.HandlerOptions{
		ReplaceAttr: logReplaceAttr,
	}
	var logger *slog.Logger
	switch opt.OutputFormat {
	case "", LogFormatText:
		logger = slog.New(slog.NewTextHandler(w, handlerOpts))
	case LogFormatJSON:
		logger = slog.New(slog.NewJSONHandler(w, handlerOpts))
	default:
		if closer != nil {
			_ = closer.Close() // don't leak the opened file on a config error
		}
		return nil, fmt.Errorf("invalid output format %q", opt.OutputFormat)
	}
	return &QueryLogResolver{
		id:       id,
		resolver: resolver,
		opt:      opt,
		logger:   logger,
		closer:  closer,
	}, nil
}

// Resolve logs the query details and passes the query to the next resolver.
func (r *QueryLogResolver) Resolve(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
	question := q.Question[0]
	attrs := []slog.Attr{
		slog.String("source-ip", ci.SourceIP.String()),
		slog.String("question-name", question.Name),
		slog.String("question-class", dns.Class(question.Qclass).String()),
		slog.String("question-type", dns.Type(question.Qtype).String()),
	}

	// Add ECS attributes if present
	edns0 := q.IsEdns0()
	if edns0 != nil {
		// Find the ECS option
		for _, opt := range edns0.Option {
			ecs, ok := opt.(*dns.EDNS0_SUBNET)
			if ok {
				attrs = append(attrs, slog.String("ecs-addr", ecs.Address.String()))
			}
		}
	}

	// Errors from the handler (including a failing or closed log file) are
	// deliberately ignored: logging must never change how the query is
	// forwarded to the downstream resolver.
	r.logger.LogAttrs(context.Background(), slog.LevelInfo, "", attrs...)
	return r.resolver.Resolve(q, ci)
}

// Close stops rotation and releases the file resource the resolver owns. It
// flushes nothing beyond what slog already wrote (each record is handed to the
// writer in a single call) and never closes STDOUT or the downstream resolver.
func (r *QueryLogResolver) Close() error {
	if r.closer != nil {
		return r.closer.Close()
	}
	return nil
}

func (r *QueryLogResolver) String() string {
	return r.id
}

func logReplaceAttr(groups []string, a slog.Attr) slog.Attr {
	if a.Key == "msg" || a.Key == "level" {
		return slog.Attr{}
	}
	return a
}

// errRotatingWriterClosed is returned by writes after the sink has been
// closed. It is not reported through Log: shutdown is deliberate.
var errRotatingWriterClosed = errors.New("query log writer is closed")

// rotatingFileWriter appends records to a file and, once the file reaches a
// size limit, archives the current generation under a deterministically
// numbered suffix and opens a new active file.
//
// Every Write and rotation is serialized under one mutex. slog hands each
// complete record to Write in a single call with the trailing newline, so
// holding the lock across the boundary check, the rotation and the write
// guarantees a record lands whole in exactly one generation -- it can't be
// split by a rotation, written twice, or lost to handler buffering.
//
// A failed rotation (rename or reopen) leaves the current file open and keeps
// writing to it; the next record retries the rotation. The last error stays
// observable through LastError and is reported once through the package
// logger.
type rotatingFileWriter struct {
	mu      sync.Mutex
	path    string
	f       *os.File // active generation; nil once closed
	size    int64    // bytes in the active generation
	maxSize int64    // rotation threshold in bytes; 0 disables rotation
	gen     int      // suffix number to use for the next archive

	// lastErr is the most recent rotation or write error, for deterministic
	// observation. It clears once rotation or writing succeeds again.
	lastErr error
	// errReported says whether lastErr has already been logged, so a
	// persistent failure (e.g. a read-only directory) reports once instead
	// of once per query.
	errReported bool

	// File operations, indirected so tests can inject failures.
	rename   func(oldpath, newpath string) error
	openFile func(name string, flag int, perm os.FileMode) (*os.File, error)
}

// newRotatingFileWriter opens path in append mode (creating it if needed) and
// prepares rotation at maxSize bytes. A maxSize of 0 disables rotation.
func newRotatingFileWriter(path string, maxSize int64) (*rotatingFileWriter, error) {
	w := &rotatingFileWriter{
		path:    path,
		maxSize: maxSize,
		rename:  os.Rename,
		openFile: func(name string, flag int, perm os.FileMode) (*os.File, error) {
			return os.OpenFile(name, flag, perm)
		},
	}
	f, err := w.openFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}
	w.f = f
	// Account for content already in the file: appending to a file that is at
	// or over the limit rotates on the first record rather than waiting for
	// another maxSize bytes.
	if fi, err := f.Stat(); err == nil {
		w.size = fi.Size()
	}
	w.gen = nextArchiveGeneration(path)
	return w, nil
}

// Write implements io.Writer. It is the only place records enter the sink, so
// the rotate decision and the write happen atomically under the lock.
func (w *rotatingFileWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.f == nil {
		return 0, errRotatingWriterClosed
	}

	// Roll before the record if it would push the active generation past the
	// limit. An empty generation takes even an oversized record whole rather
	// than churning empty archives; it rolls again on the record after.
	rotateAttempted := false
	if w.maxSize > 0 && w.size > 0 && w.size+int64(len(p)) > w.maxSize {
		rotateAttempted = true
		if err := w.rotateLocked(); err != nil {
			// Keep using the current, still writable file; retry on the next
			// record.
			w.noteErrorLocked(err)
		} else {
			w.clearErrorLocked()
		}
	}

	n, err := w.f.Write(p)
	w.size += int64(n)
	if err != nil {
		w.noteErrorLocked(err)
		return n, err
	}
	// A successful write without a rotation attempt means the file is
	// writable again after a write error. A failed rotation leaves the error
	// in place until a rotation actually succeeds, even though the fallback
	// writes are going through.
	if !rotateAttempted {
		w.clearErrorLocked()
	}
	return n, nil
}

// rotateLocked archives the active file as path.<gen> and opens a new active
// file at path. The old file stays open until the new one is ready, so any
// failure leaves a writable file in place. Caller holds w.mu.
func (w *rotatingFileWriter) rotateLocked() error {
	// Pick a suffix that does not collide with an existing file, so an
	// archive (including one an operator placed there) is never overwritten.
	var archive string
	for {
		archive = fmt.Sprintf("%s.%d", w.path, w.gen)
		if _, err := os.Stat(archive); err != nil {
			break // absent, or unstatable -- the rename below surfaces it
		}
		w.gen++
	}

	// Move the active generation aside. A missing active path means an
	// earlier attempt moved it but failed before reopening; the reopen below
	// recovers that state.
	if _, err := os.Stat(w.path); err == nil {
		if err := w.rename(w.path, archive); err != nil {
			return fmt.Errorf("rotating query log: rename %s to %s: %w", w.path, archive, err)
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("rotating query log: stat %s: %w", w.path, err)
	}

	f, err := w.openFile(w.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		// Best effort: move the archive back so the path keeps resolving to
		// it. Either way the old fd is still open and writable, so only the
		// open error is returned.
		_ = w.rename(archive, w.path)
		return fmt.Errorf("rotating query log: open new file %s: %w", w.path, err)
	}

	old := w.f
	w.f = f
	w.size = 0
	w.gen++
	if old != nil {
		_ = old.Close()
	}
	return nil
}

// Close stops rotation and closes the active file. It is idempotent and does
// not close anything the resolver does not own (STDOUT never goes through
// this type).
func (w *rotatingFileWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.f == nil {
		return nil
	}
	err := w.f.Close()
	w.f = nil
	return err
}

// LastError returns the most recent rotation or write error, or nil once
// operations are succeeding again. It is the deterministic error observation
// for callers, since slog does not surface errors from a writer.
func (w *rotatingFileWriter) LastError() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.lastErr
}

func (w *rotatingFileWriter) noteErrorLocked(err error) {
	w.lastErr = err
	if !w.errReported {
		w.errReported = true
		Log.Error("query log rotation failed; continuing with the current file",
			"file", w.path, "error", err)
	}
}

func (w *rotatingFileWriter) clearErrorLocked() {
	if w.errReported {
		Log.Warn("query log writer recovered", "file", w.path)
	}
	w.lastErr = nil
	w.errReported = false
}

// nextArchiveGeneration returns the first suffix number not used by an
// existing archive of path, continuing the sequence across restarts
// (query.log.1, query.log.2, ...).
func nextArchiveGeneration(path string) int {
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		return 1
	}
	prefix := filepath.Base(path) + "."
	next := 1
	for _, e := range entries {
		n, err := strconv.Atoi(strings.TrimPrefix(e.Name(), prefix))
		if err != nil || n < 1 {
			continue
		}
		if n >= next {
			next = n + 1
		}
	}
	return next
}
