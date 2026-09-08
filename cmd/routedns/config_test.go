package main

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	rdns "github.com/folbricht/routedns"
	"github.com/stretchr/testify/require"
)

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	name := filepath.Join(t.TempDir(), "config.toml")
	require.NoError(t, os.WriteFile(name, []byte(content), 0600))
	return name
}

func TestLoadConfigUnknownOptions(t *testing.T) {
	log := captureLog(t)

	// Every option here is misspelled or made up. The valid ones around them
	// have to still decode.
	name := writeConfig(t, `
[resolvers.upstream]
address = "1.1.1.1:853"
protocol = "dot"
bootstrap-adress = "1.0.0.1"

[groups.cached]
type = "cache"
resolvers = ["upstream"]
cache-siz = 100

[listeners.local-udp]
address = "127.0.0.1:53"
protocol = "udp"
resolver = "cached"
totally-bogus-key = 42
`)

	c, err := loadConfig(name)
	require.NoError(t, err)

	// The valid options are still decoded.
	require.Equal(t, "1.1.1.1:853", c.Resolvers["upstream"].Address)
	require.Equal(t, "cache", c.Groups["cached"].Type)
	require.Equal(t, "udp", c.Listeners["local-udp"].Protocol)

	// Each unknown option is reported with its full path.
	out := log.String()
	require.Contains(t, out, "resolvers.upstream.bootstrap-adress")
	require.Contains(t, out, "groups.cached.cache-siz")
	require.Contains(t, out, "listeners.local-udp.totally-bogus-key")
}

func TestLoadConfigNoFalsePositives(t *testing.T) {
	log := captureLog(t)

	name := writeConfig(t, `
[resolvers.upstream]
address = "1.1.1.1:853"
protocol = "dot"

[groups.cached]
type = "cache"
resolvers = ["upstream"]
backend = {type = "memory", size = 1000}
cache-rcode-max-ttl = {NXDOMAIN = 60, SERVFAIL = 10}

[listeners.local-udp]
address = "127.0.0.1:53"
protocol = "udp"
resolver = "cached"
`)

	_, err := loadConfig(name)
	require.NoError(t, err)
	require.Empty(t, log.String())
}

func TestParseByteSize(t *testing.T) {
	tests := []struct {
		in      string
		want    int64
		wantErr bool
	}{
		{"", 0, false},
		{"  ", 0, false},
		{"1024", 1024, false},
		{"1024b", 1024, false},
		{"1k", 1024, false},
		{"1KB", 1024, false},
		{"1KiB", 1024, false},
		{"2mb", 2 * 1024 * 1024, false},
		{"1MiB", 1024 * 1024, false},
		{"1g", 1 << 30, false},
		{"1GB", 1 << 30, false},
		{"1tib", 1 << 40, false},
		{" 5 MB ", 5 * 1024 * 1024, false},
		{"abc", 0, true},
		{"-1", 0, true},
		{"1.5mb", 0, true},
		{"999999999999999999999tb", 0, true},
	}
	for _, tt := range tests {
		got, err := parseByteSize(tt.in)
		if tt.wantErr {
			require.Errorf(t, err, "input %q", tt.in)
			continue
		}
		require.NoErrorf(t, err, "input %q", tt.in)
		require.Equalf(t, tt.want, got, "input %q", tt.in)
	}
}

// rotation-size requires an output file; an invalid size string is rejected at
// group instantiation.
func TestQueryLogRotationSizeValidation(t *testing.T) {
	upstream := &countingResolver{name: "upstream"}
	resolvers := map[string]rdns.Resolver{"upstream": upstream}

	err := instantiateGroup("ql", group{
		Type:         "query-log",
		Resolvers:    []string{"upstream"},
		RotationSize: "100MB",
	}, resolvers)
	require.Error(t, err)
	require.Contains(t, err.Error(), "rotation-size requires output-file")

	err = instantiateGroup("ql", group{
		Type:         "query-log",
		Resolvers:    []string{"upstream"},
		OutputFile:   filepath.Join(t.TempDir(), "query.log"),
		RotationSize: "not-a-size",
	}, resolvers)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid rotation-size")

	// A valid combination builds and closes cleanly.
	err = instantiateGroup("ql2", group{
		Type:         "query-log",
		Resolvers:    []string{"upstream"},
		OutputFile:   filepath.Join(t.TempDir(), "query.log"),
		RotationSize: "100MB",
	}, resolvers)
	require.NoError(t, err)
	require.NoError(t, resolvers["ql2"].(io.Closer).Close())
}

// Config split over multiple files is concatenated before decoding, so
// unknown options have to be found in all of them.
func TestLoadConfigUnknownOptionsMultipleFiles(t *testing.T) {
	log := captureLog(t)

	dir := t.TempDir()
	resolvers := filepath.Join(dir, "resolvers.toml")
	listeners := filepath.Join(dir, "listeners.toml")
	require.NoError(t, os.WriteFile(resolvers, []byte(`
[resolvers.upstream]
address = "1.1.1.1:853"
protocol = "dot"
query-timout = 5
`), 0600))
	require.NoError(t, os.WriteFile(listeners, []byte(`
[listeners.local-udp]
address = "127.0.0.1:53"
protocol = "udp"
resolver = "upstream"
`), 0600))

	_, err := loadConfig(resolvers, listeners)
	require.NoError(t, err)
	require.Contains(t, log.String(), "resolvers.upstream.query-timout")
}

// All shipped example configs have to load without unknown options. This
// catches examples that document options which don't exist.
func TestExampleConfigsHaveNoUnknownOptions(t *testing.T) {
	files, err := filepath.Glob("example-config/*.toml")
	require.NoError(t, err)
	require.NotEmpty(t, files)

	for _, file := range files {
		t.Run(filepath.Base(file), func(t *testing.T) {
			log := captureLog(t)
			_, err := loadConfig(file)
			require.NoError(t, err)
			require.Empty(t, log.String(), "example config has options that RouteDNS does not support")
		})
	}
}
