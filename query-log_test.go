package rdns

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

// readLogGenerations returns the contents of path.1, path.2, ... (in order)
// followed by the active file, i.e. every file rotation can write to.
func readLogGenerations(t *testing.T, path string) [][]byte {
	t.Helper()
	var gens [][]byte
	for i := 1; ; i++ {
		b, err := os.ReadFile(fmt.Sprintf("%s.%d", path, i))
		if errors.Is(err, fs.ErrNotExist) {
			break
		}
		require.NoError(t, err)
		gens = append(gens, b)
	}
	b, err := os.ReadFile(path)
	if err == nil {
		gens = append(gens, b)
	} else {
		require.ErrorIs(t, err, fs.ErrNotExist)
	}
	return gens
}

// Without a size limit the writer appends forever, across restarts, and no
// archives are ever created -- this is the pre-rotation behavior.
func TestRotatingFileWriterNoRotationAppends(t *testing.T) {
	path := filepath.Join(t.TempDir(), "query.log")

	w, err := newRotatingFileWriter(path, 0)
	require.NoError(t, err)
	_, err = w.Write([]byte("first\n"))
	require.NoError(t, err)
	require.NoError(t, w.Close())

	// Reopen in append mode, as a restart would.
	w, err = newRotatingFileWriter(path, 0)
	require.NoError(t, err)
	_, err = w.Write([]byte("second\n"))
	require.NoError(t, err)
	require.NoError(t, w.Close())

	gens := readLogGenerations(t, path)
	require.Len(t, gens, 1, "no archives without a size limit")
	require.Equal(t, "first\nsecond\n", string(gens[0]))
}

// At the limit the active generation is archived as path.<n> and a new active
// file is opened; every record lands whole in exactly one file and archives
// stay within the limit.
func TestRotatingFileWriterRollsAtLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "query.log")
	const maxSize = 25
	w, err := newRotatingFileWriter(path, maxSize)
	require.NoError(t, err)

	const n = 7
	for i := 0; i < n; i++ {
		_, err := w.Write([]byte(fmt.Sprintf("record-%04d\n", i))) // 12 bytes
		require.NoError(t, err)
	}
	require.NoError(t, w.Close())

	gens := readLogGenerations(t, path)
	// 12 bytes/record: two fit per generation (24 bytes), so expect three
	// archives plus an active file with one record.
	require.Len(t, gens, 4)

	var all strings.Builder
	total := 0
	for gi, b := range gens {
		require.True(t, bytes.HasSuffix(b, []byte("\n")), "generation %d ends mid-record", gi)
		lines := strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
		total += len(lines)
		for _, line := range lines {
			require.Len(t, line, len("record-0000"), "record split across files: %q", line)
		}
		if gi < len(gens)-1 {
			require.LessOrEqual(t, len(b), maxSize, "archive %d exceeds the limit", gi)
		}
		all.Write(b)
	}
	require.Equal(t, n, total, "record count")
	require.Equal(t, n, strings.Count(all.String(), "record-"), "no record lost or duplicated")
	for i := 0; i < n; i++ {
		require.Contains(t, all.String(), fmt.Sprintf("record-%04d\n", i))
	}
}

// slog hands each record to Write in a single call; under concurrent Resolve
// calls and repeated rotation no record may be lost, duplicated or split.
func TestRotatingFileWriterConcurrentSlog(t *testing.T) {
	path := filepath.Join(t.TempDir(), "query.log")
	w, err := newRotatingFileWriter(path, 4096)
	require.NoError(t, err)
	logger := slog.New(slog.NewJSONHandler(w, nil))

	const goroutines = 20
	const perG = 50
	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < perG; i++ {
				seq := g*perG + i
				logger.LogAttrs(context.Background(), slog.LevelInfo, "",
					slog.Int("seq", seq), slog.String("worker", fmt.Sprintf("g%02d", g)))
			}
		}(g)
	}
	wg.Wait()
	require.NoError(t, w.Close())

	gens := readLogGenerations(t, path)
	require.Greater(t, len(gens), 1, "small limit should have rolled")

	seen := make(map[int]int)
	for gi, b := range gens {
		require.True(t, bytes.HasSuffix(b, []byte("\n")), "generation %d ends mid-record", gi)
		lines := strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
		for _, line := range lines {
			var rec struct {
				Seq int `json:"seq"`
			}
			require.NoError(t, json.Unmarshal([]byte(line), &rec), "whole JSON record in one file: %q", line)
			seen[rec.Seq]++
		}
	}
	require.Len(t, seen, goroutines*perG, "every record present")
	for seq, count := range seen {
		require.Equal(t, 1, count, "seq %d appears %d times", seq, count)
	}
}

// End to end through the resolver, in both formats, with ECS: rotation keeps
// every query record complete and forwarding is untouched.
func TestQueryLogResolverRotatesEndToEnd(t *testing.T) {
	for _, format := range []LogFormat{LogFormatText, LogFormatJSON} {
		t.Run(string(format), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "query.log")
			down := &TestResolver{}
			r, err := NewQueryLogResolver("ql", down, QueryLogResolverOptions{
				OutputFile:   path,
				OutputFormat: format,
				MaxSize:      300,
			})
			require.NoError(t, err)

			q := testQuery()
			opt := &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT}}
			opt.Option = append(opt.Option, &dns.EDNS0_SUBNET{
				Code: dns.EDNS0SUBNET, Family: 1, SourceNetmask: 24,
				Address: net.IPv4(192, 168, 1, 0),
			})
			q.Extra = append(q.Extra, opt)
			ci := ClientInfo{SourceIP: net.IPv4(10, 0, 0, 1)}

			const n = 12
			for i := 0; i < n; i++ {
				resp, err := r.Resolve(q, ci)
				require.NoError(t, err)
				require.Same(t, q, resp)
			}
			require.NoError(t, r.Close())
			require.Equal(t, n, down.HitCount(), "every query forwarded downstream")

			gens := readLogGenerations(t, path)
			require.Greater(t, len(gens), 1, "limit should have rolled")

			count := 0
			for gi, b := range gens {
				lines := strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
				for _, line := range lines {
					count++
					if format == LogFormatJSON {
						require.Truef(t, strings.HasPrefix(line, "{") && strings.HasSuffix(line, "}"),
							"generation %d holds a split JSON record: %q", gi, line)
						require.Contains(t, line, `"question-name":"www.example.com."`)
						require.Contains(t, line, `"ecs-addr"`)
					} else {
						require.Contains(t, line, "question-name=www.example.com.")
						require.Contains(t, line, "ecs-addr=")
					}
				}
			}
			require.Equal(t, n, count)
		})
	}
}

// Archive numbering continues across restarts and old archives are never
// overwritten.
func TestRotatingFileWriterContinuesSequenceAcrossRestarts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "query.log")

	w, err := newRotatingFileWriter(path, 25)
	require.NoError(t, err)
	for i := 0; i < 3; i++ {
		_, err := w.Write([]byte(fmt.Sprintf("run1-%04d\n", i))) // 10 bytes
		require.NoError(t, err)
	}
	require.NoError(t, w.Close())

	firstArchive, err := os.ReadFile(path + ".1")
	require.NoError(t, err)
	require.Contains(t, string(firstArchive), "run1-0000")

	w, err = newRotatingFileWriter(path, 25)
	require.NoError(t, err)
	require.Equal(t, 2, w.gen, "numbering continues past existing archives")
	for i := 0; i < 4; i++ {
		_, err := w.Write([]byte(fmt.Sprintf("run2-%04d\n", i)))
		require.NoError(t, err)
	}
	require.NoError(t, w.Close())

	gens := readLogGenerations(t, path)
	require.Equal(t, firstArchive, gens[0], "existing archive untouched")

	var all strings.Builder
	for _, b := range gens {
		all.Write(b)
	}
	require.Equal(t, 7, strings.Count(all.String(), "run"), "all records from both runs present")
	for i := 0; i < 3; i++ {
		require.Contains(t, all.String(), fmt.Sprintf("run1-%04d", i))
	}
	for i := 0; i < 4; i++ {
		require.Contains(t, all.String(), fmt.Sprintf("run2-%04d", i))
	}
}

// An active file that is already over the limit rolls on the very first
// appended record rather than waiting for another limit's worth of bytes.
func TestRotatingFileWriterExistingOversizedFileRollsImmediately(t *testing.T) {
	path := filepath.Join(t.TempDir(), "query.log")
	require.NoError(t, os.WriteFile(path, bytes.Repeat([]byte("x"), 100), 0644))

	w, err := newRotatingFileWriter(path, 50)
	require.NoError(t, err)
	require.Equal(t, int64(100), w.size)

	_, err = w.Write([]byte("new\n"))
	require.NoError(t, err)
	require.NoError(t, w.Close())

	_, err = os.Stat(path + ".1")
	require.NoError(t, err, "oversized legacy content archived on first write")
	b, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, "new\n", string(b))
}

// An archive name that already exists (including a file an operator placed
// there) is skipped, not clobbered.
func TestRotatingFileWriterDoesNotClobberExistingArchive(t *testing.T) {
	path := filepath.Join(t.TempDir(), "query.log")
	require.NoError(t, os.WriteFile(path+".1", []byte("operator file\n"), 0644))

	w, err := newRotatingFileWriter(path, 25)
	require.NoError(t, err)
	require.Equal(t, 2, w.gen)
	for i := 0; i < 3; i++ {
		_, err := w.Write([]byte(fmt.Sprintf("rec-%04d\n", i))) // 9 bytes
		require.NoError(t, err)
	}
	require.NoError(t, w.Close())

	b, err := os.ReadFile(path + ".1")
	require.NoError(t, err)
	require.Equal(t, "operator file\n", string(b), "pre-existing archive untouched")
	b, err = os.ReadFile(path + ".2")
	require.NoError(t, err)
	require.Contains(t, string(b), "rec-0000")
}

// When the archive rename fails, the current file stays in use: writes keep
// succeeding, the error stays observable, no archive appears, and a later
// record retries rotation successfully without losing anything.
func TestRotatingFileWriterRenameFailureKeepsCurrentFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "query.log")
	w, err := newRotatingFileWriter(path, 25)
	require.NoError(t, err)

	failRename := true
	realRename := w.rename
	w.rename = func(oldpath, newpath string) error {
		if failRename {
			return errors.New("rename denied")
		}
		return realRename(oldpath, newpath)
	}

	for i := 0; i < 3; i++ {
		_, err := w.Write([]byte(fmt.Sprintf("rec-%04d\n", i))) // 9 bytes; 3rd crosses 25
		require.NoError(t, err, "writes keep going to the current file")
	}
	require.Error(t, w.LastError())
	require.Contains(t, w.LastError().Error(), "rename")

	_, err = os.Stat(path + ".1")
	require.ErrorIs(t, err, fs.ErrNotExist, "no archive on failed rotation")
	b, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, "rec-0000\nrec-0001\nrec-0002\n", string(b), "nothing lost")

	failRename = false
	_, err = w.Write([]byte("rec-0003\n"))
	require.NoError(t, err)
	require.NoError(t, w.LastError(), "recovery clears the error")
	require.NoError(t, w.Close())

	var all strings.Builder
	for _, gen := range readLogGenerations(t, path) {
		all.Write(gen)
	}
	require.Equal(t, 4, strings.Count(all.String(), "rec-"))
}

// When opening the new active file fails, the moved file is renamed back and
// the old fd keeps serving; the next record retries and rotation completes.
func TestRotatingFileWriterOpenFailureKeepsCurrentFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "query.log")
	w, err := newRotatingFileWriter(path, 25)
	require.NoError(t, err)

	// The wrapper is installed after construction, so the reopen during the
	// first rotation is its first call.
	openCalls := 0
	realOpen := w.openFile
	w.openFile = func(name string, flag int, perm os.FileMode) (*os.File, error) {
		openCalls++
		if openCalls == 1 {
			return nil, errors.New("open denied")
		}
		return realOpen(name, flag, perm)
	}

	for i := 0; i < 3; i++ {
		_, err := w.Write([]byte(fmt.Sprintf("rec-%04d\n", i)))
		require.NoError(t, err)
	}
	require.Error(t, w.LastError())
	require.Contains(t, w.LastError().Error(), "open new file")

	_, err = os.Stat(path + ".1")
	require.ErrorIs(t, err, fs.ErrNotExist, "rename-back restored the path")
	b, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, "rec-0000\nrec-0001\nrec-0002\n", string(b))

	_, err = w.Write([]byte("rec-0003\n"))
	require.NoError(t, err)
	require.NoError(t, w.LastError())
	require.NoError(t, w.Close())

	var all strings.Builder
	for _, gen := range readLogGenerations(t, path) {
		all.Write(gen)
	}
	require.Equal(t, 4, strings.Count(all.String(), "rec-"))
}

// Worst case: the archive rename succeeds, the reopen fails, and the rename
// back fails too. The old fd still takes records (into the archive inode) and
// the next rotation recovers by reopening the now-missing active path.
func TestRotatingFileWriterReopenRecoversWhenRestoreFailed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "query.log")
	w, err := newRotatingFileWriter(path, 25)
	require.NoError(t, err)

	// Installed after construction: the reopen during the first rotation is
	// the first call.
	openCalls := 0
	realOpen := w.openFile
	w.openFile = func(name string, flag int, perm os.FileMode) (*os.File, error) {
		openCalls++
		if openCalls == 1 {
			return nil, errors.New("open denied")
		}
		return realOpen(name, flag, perm)
	}
	w.rename = func(oldpath, newpath string) error {
		if newpath == path { // the best-effort rename-back
			return errors.New("restore denied")
		}
		return os.Rename(oldpath, newpath)
	}

	for i := 0; i < 3; i++ {
		_, err := w.Write([]byte(fmt.Sprintf("rec-%04d\n", i)))
		require.NoError(t, err)
	}
	require.Error(t, w.LastError())

	// The active path is missing; fallback records went to the open archive fd.
	b, err := os.ReadFile(path + ".1")
	require.NoError(t, err)
	require.Equal(t, "rec-0000\nrec-0001\nrec-0002\n", string(b))
	_, err = os.Stat(path)
	require.ErrorIs(t, err, fs.ErrNotExist)

	// Next rotation finds no active path, reopens it, and carries on.
	_, err = w.Write([]byte("rec-0003\n"))
	require.NoError(t, err)
	require.NoError(t, w.LastError())
	require.NoError(t, w.Close())

	var all strings.Builder
	for _, gen := range readLogGenerations(t, path) {
		all.Write(gen)
	}
	require.Equal(t, 4, strings.Count(all.String(), "rec-"))
}

// Close stops rotation, rejects further writes and is idempotent.
func TestRotatingFileWriterClose(t *testing.T) {
	path := filepath.Join(t.TempDir(), "query.log")
	w, err := newRotatingFileWriter(path, 25)
	require.NoError(t, err)
	_, err = w.Write([]byte("rec\n"))
	require.NoError(t, err)

	require.NoError(t, w.Close())
	require.NoError(t, w.Close(), "idempotent")

	_, err = w.Write([]byte("rec\n"))
	require.ErrorIs(t, err, errRotatingWriterClosed)

	b, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, "rec\n", string(b))
}

// The resolver only closes what it owns: STDOUT stays open, and a closed log
// file never prevents a query from reaching the downstream resolver.
func TestQueryLogResolverCloseLeavesStdoutAndDownstream(t *testing.T) {
	r, err := NewQueryLogResolver("ql", &TestResolver{}, QueryLogResolverOptions{OutputFormat: LogFormatText})
	require.NoError(t, err)
	_, err = os.Stdout.Stat()
	require.NoError(t, err)
	require.NoError(t, r.Close())
	_, err = os.Stdout.Stat()
	require.NoError(t, err, "STDOUT must remain open after Close")

	path := filepath.Join(t.TempDir(), "query.log")
	down := &TestResolver{}
	r2, err := NewQueryLogResolver("ql2", down, QueryLogResolverOptions{OutputFile: path})
	require.NoError(t, err)
	require.NoError(t, r2.Close())

	q := testQuery()
	resp, err := r2.Resolve(q, ClientInfo{SourceIP: net.IPv4(10, 0, 0, 1)})
	require.NoError(t, err, "logging failure must not fail the query")
	require.Same(t, q, resp, "downstream response passed through")
	require.Equal(t, 1, down.HitCount(), "query still forwarded")
}

func TestNextArchiveGeneration(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "query.log")
	for _, name := range []string{"query.log.1", "query.log.2", "query.log.10", "query.log.abc", "other.9", "query.log"} {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte("x"), 0644))
	}
	require.Equal(t, 11, nextArchiveGeneration(path))
	require.Equal(t, 1, nextArchiveGeneration(filepath.Join(dir, "fresh.log")))
}
