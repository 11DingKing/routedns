package rdns

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

// luaStaticAnswerScript is a script version that answers with a fixed A
// record. The IP is what distinguishes generations in the tests below.
const luaStaticAnswerScript = `
function Resolve(msg, ci)
	local answer = Message.new()
	answer:set_reply(msg)
	local rr = RR.new({rtype = TypeA, name = "example.com.", class = ClassIN, ttl = 60, a = "%s"})
	answer.answer = { rr }
	return answer, nil
end
`

// luaAnswerWithGlobal sets a Lua global in the chunk and serves it. A later
// generation must not see globals left behind by an earlier one.
const luaAnswerWithGlobal = `
GENERATION = "%s"
function Resolve(msg, ci)
	if GENERATION ~= "%s" then
		return nil, Error.new("global leaked across generations: " .. tostring(GENERATION))
	end
	local answer = Message.new()
	answer:set_reply(msg)
	local rr = RR.new({rtype = TypeA, name = "example.com.", class = ClassIN, ttl = 60, a = "%s"})
	answer.answer = { rr }
	return answer, nil
end
`

func staticAnswerScript(ip string) string {
	return fmt.Sprintf(luaStaticAnswerScript, ip)
}

func writeLuaScript(t *testing.T, path, content string) {
	t.Helper()
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
}

func luaAnswerIP(t *testing.T, r *Lua) string {
	t.Helper()
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	resp, err := r.Resolve(q, ClientInfo{})
	require.NoError(t, err)
	require.Len(t, resp.Answer, 1)
	a, ok := resp.Answer[0].(*dns.A)
	require.True(t, ok)
	return a.A.String()
}

func newWatchedLua(t *testing.T, path string, concurrency uint) *Lua {
	t.Helper()
	r, err := NewLua("test-lua-watch", LuaOptions{
		ScriptSource:  path,
		Concurrency:   concurrency,
		Watch:         true,
		WatchInterval: 10 * time.Millisecond,
	}, new(TestResolver))
	require.NoError(t, err)
	t.Cleanup(r.Close)
	return r
}

// waitGenFreed asserts every VM of a retired generation is closed.
func waitGenFreed(t *testing.T, g *luaGen, timeout time.Duration) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		g.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(timeout):
		t.Fatalf("retired generation %d did not free its VMs within %s", g.id, timeout)
	}
}

func TestLuaWatchRequiresSourceFile(t *testing.T) {
	_, err := NewLua("test-lua", LuaOptions{
		Script: `function Resolve(msg, ci) return nil, nil end`,
		Watch:  true,
	})
	require.Error(t, err)
}

func TestLuaReloadInlineUnsupported(t *testing.T) {
	r, err := NewLua("test-lua", LuaOptions{
		Script: `function Resolve(msg, ci) return nil, nil end`,
	}, new(TestResolver))
	require.NoError(t, err)
	defer r.Close()

	require.ErrorIs(t, r.Reload(), errLuaNoSource)
	require.NoError(t, r.ReloadError())
}

func TestLuaMissingSourceFileFailsStartup(t *testing.T) {
	_, err := NewLua("test-lua", LuaOptions{
		ScriptSource: filepath.Join(t.TempDir(), "does-not-exist.lua"),
	})
	require.Error(t, err)
}

// With watching disabled (the default), rewriting the file has no effect on
// a running resolver, matching the pre-existing behavior.
func TestLuaNoWatchKeepsStartupGeneration(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "script.lua")
	writeLuaScript(t, path, staticAnswerScript("1.1.1.1"))

	r, err := NewLua("test-lua", LuaOptions{ScriptSource: path}, new(TestResolver))
	require.NoError(t, err)
	defer r.Close()

	require.Equal(t, "1.1.1.1", luaAnswerIP(t, r))

	writeLuaScript(t, path, staticAnswerScript("2.2.2.2"))
	time.Sleep(50 * time.Millisecond)

	// No watcher: still serving the generation built at startup.
	require.Equal(t, "1.1.1.1", luaAnswerIP(t, r))

	// A manual reload picks the new version up.
	require.NoError(t, r.Reload())
	require.Equal(t, "2.2.2.2", luaAnswerIP(t, r))
}

// With watching enabled, a valid new script version is published
// automatically. Requests in flight keep using the generation they borrowed;
// new requests land on the new one.
func TestLuaWatchPublishesNewGeneration(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "script.lua")
	writeLuaScript(t, path, staticAnswerScript("1.1.1.1"))

	r := newWatchedLua(t, path, 4)
	require.Equal(t, "1.1.1.1", luaAnswerIP(t, r))
	require.NoError(t, r.ReloadError())

	old := r.gen.Load()
	writeLuaScript(t, path, staticAnswerScript("2.2.2.2"))

	require.Eventually(t, func() bool {
		return luaAnswerIP(t, r) == "2.2.2.2"
	}, 3*time.Second, 5*time.Millisecond)
	require.NoError(t, r.ReloadError())
	require.NotSame(t, old, r.gen.Load())

	// The superseded generation must close all of its VMs.
	waitGenFreed(t, old, 3*time.Second)
}

// A syntax error in the rewritten file must not affect the running
// generation. The failure must be observable, and fixing the file switches.
func TestLuaWatchSyntaxErrorKeepsPreviousGeneration(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "script.lua")
	writeLuaScript(t, path, staticAnswerScript("1.1.1.1"))

	r := newWatchedLua(t, path, 2)
	require.Equal(t, "1.1.1.1", luaAnswerIP(t, r))

	writeLuaScript(t, path, `function Resolve(msg, ci) this is not lua `)

	require.Eventually(t, func() bool { return r.ReloadError() != nil }, 3*time.Second, 5*time.Millisecond)

	// The previous complete generation keeps serving while the file is bad.
	for range 20 {
		require.Equal(t, "1.1.1.1", luaAnswerIP(t, r))
	}

	// Restore a valid (new) version: the watcher retries and switches.
	writeLuaScript(t, path, staticAnswerScript("3.3.3.3"))
	require.Eventually(t, func() bool {
		return r.ReloadError() == nil && luaAnswerIP(t, r) == "3.3.3.3"
	}, 3*time.Second, 5*time.Millisecond)
}

// A script that fails while executing its chunk (initialization error) is
// not a complete generation and must not leak its partial VMs.
func TestLuaWatchInitErrorKeepsPreviousGeneration(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "script.lua")
	writeLuaScript(t, path, staticAnswerScript("1.1.1.1"))

	r := newWatchedLua(t, path, 2)
	require.Equal(t, "1.1.1.1", luaAnswerIP(t, r))

	writeLuaScript(t, path, `
error("initialization failed on purpose")
function Resolve(msg, ci) return nil, nil end
`)

	require.Eventually(t, func() bool { return r.ReloadError() != nil }, 3*time.Second, 5*time.Millisecond)
	for range 10 {
		require.Equal(t, "1.1.1.1", luaAnswerIP(t, r))
	}

	writeLuaScript(t, path, staticAnswerScript("6.6.6.6"))
	require.Eventually(t, func() bool {
		return r.ReloadError() == nil && luaAnswerIP(t, r) == "6.6.6.6"
	}, 3*time.Second, 5*time.Millisecond)
}

// A script without the Resolve entry point is not a complete generation.
func TestLuaWatchMissingResolveKeepsPreviousGeneration(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "script.lua")
	writeLuaScript(t, path, staticAnswerScript("1.1.1.1"))

	r := newWatchedLua(t, path, 2)
	require.Equal(t, "1.1.1.1", luaAnswerIP(t, r))

	writeLuaScript(t, path, `function SomethingElse(msg, ci) return nil, nil end`)

	require.Eventually(t, func() bool { return r.ReloadError() != nil }, 3*time.Second, 5*time.Millisecond)
	require.Equal(t, "1.1.1.1", luaAnswerIP(t, r))

	// Manual reload reports the same failure deterministically.
	require.Error(t, r.Reload())
	require.Error(t, r.ReloadError())

	writeLuaScript(t, path, staticAnswerScript("4.4.4.4"))
	require.Eventually(t, func() bool {
		return luaAnswerIP(t, r) == "4.4.4.4"
	}, 3*time.Second, 5*time.Millisecond)
}

// Deleting the file must preserve the serving generation while reporting the
// error; recreating a valid file switches again.
func TestLuaWatchFileDeletedAndRestored(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "script.lua")
	writeLuaScript(t, path, staticAnswerScript("1.1.1.1"))

	r := newWatchedLua(t, path, 2)
	require.Equal(t, "1.1.1.1", luaAnswerIP(t, r))

	require.NoError(t, os.Remove(path))
	require.Eventually(t, func() bool { return r.ReloadError() != nil }, 3*time.Second, 5*time.Millisecond)
	require.Equal(t, "1.1.1.1", luaAnswerIP(t, r))

	writeLuaScript(t, path, staticAnswerScript("5.5.5.5"))
	require.Eventually(t, func() bool {
		return r.ReloadError() == nil && luaAnswerIP(t, r) == "5.5.5.5"
	}, 3*time.Second, 5*time.Millisecond)
}

// Globals from a previous generation must never be visible in a new one:
// every generation gets a fresh Lua state.
func TestLuaGenerationsDoNotShareGlobals(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "script.lua")
	writeLuaScript(t, path, fmt.Sprintf(luaAnswerWithGlobal, "one", "one", "1.1.1.1"))

	r := newWatchedLua(t, path, 4)
	require.Equal(t, "1.1.1.1", luaAnswerIP(t, r))

	writeLuaScript(t, path, fmt.Sprintf(luaAnswerWithGlobal, "two", "two", "2.2.2.2"))
	require.Eventually(t, func() bool {
		return luaAnswerIP(t, r) == "2.2.2.2"
	}, 3*time.Second, 5*time.Millisecond)

	// Every VM of the new generation must behave identically.
	for range 20 {
		require.Equal(t, "2.2.2.2", luaAnswerIP(t, r))
	}
}

// Hammer the resolver with concurrent requests while the script file is
// rewritten over and over (including broken versions). No request may panic,
// block, or see a half-built generation, and retired generations must free
// all their VMs.
func TestLuaReloadUnderConcurrentLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "script.lua")
	writeLuaScript(t, path, staticAnswerScript("1.0.0.1"))

	r := newWatchedLua(t, path, 8)
	require.Equal(t, "1.0.0.1", luaAnswerIP(t, r))

	var (
		wg       sync.WaitGroup
		stop     = make(chan struct{})
		validIPs = sync.Map{}
	)
	validIPs.Store("1.0.0.1", struct{}{})

	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				q := new(dns.Msg)
				q.SetQuestion("example.com.", dns.TypeA)
				resp, err := r.Resolve(q, ClientInfo{})
				if err != nil {
					select {
					case <-stop:
						return
					default:
						t.Errorf("unexpected resolve error: %v", err)
						return
					}
				}
				if resp != nil && len(resp.Answer) == 1 {
					if a, ok := resp.Answer[0].(*dns.A); ok {
						if _, known := validIPs.Load(a.A.String()); !known {
							t.Errorf("answer from unknown generation: %s", a.A)
						}
					}
				}
			}
		}()
	}

	// Rewrite the file many times, alternating valid versions and broken
	// ones to exercise failed reloads as well.
	for i := range 30 {
		if i%5 == 4 {
			writeLuaScript(t, path, `function Resolve( broken`)
		} else {
			ip := fmt.Sprintf("1.0.0.%d", i+2)
			validIPs.Store(ip, struct{}{})
			writeLuaScript(t, path, staticAnswerScript(ip))
		}
		time.Sleep(5 * time.Millisecond)
	}

	finalIP := "9.9.9.9"
	validIPs.Store(finalIP, struct{}{})
	writeLuaScript(t, path, staticAnswerScript(finalIP))
	require.Eventually(t, func() bool {
		return r.ReloadError() == nil && luaAnswerIP(t, r) == finalIP
	}, 3*time.Second, 5*time.Millisecond)

	close(stop)
	wg.Wait()

	// Every generation superseded during the storm must have freed all VMs.
	// Force one more reload so the last watched generation is retired too,
	// then wait for the generation that was current when the storm ended.
	last := r.gen.Load()
	writeLuaScript(t, path, staticAnswerScript("8.8.8.8"))
	require.Eventually(t, func() bool { return luaAnswerIP(t, r) == "8.8.8.8" }, 3*time.Second, 5*time.Millisecond)
	waitGenFreed(t, last, 3*time.Second)
}

// Close while requests are in flight and generations are being retired must
// not block, close a VM a request is using, or panic.
func TestLuaCloseDuringLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "script.lua")
	writeLuaScript(t, path, staticAnswerScript("1.1.1.1"))

	r, err := NewLua("test-lua", LuaOptions{
		ScriptSource:  path,
		Concurrency:   4,
		Watch:         true,
		WatchInterval: 5 * time.Millisecond,
	}, new(TestResolver))
	require.NoError(t, err)

	var wg sync.WaitGroup
	stop := make(chan struct{})
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				q := new(dns.Msg)
				q.SetQuestion("example.com.", dns.TypeA)
				_, _ = r.Resolve(q, ClientInfo{}) // errors during shutdown are expected
			}
		}()
	}

	for range 10 {
		_ = r.Reload()
		time.Sleep(2 * time.Millisecond)
	}

	closed := make(chan struct{})
	go func() {
		r.Close()
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("Close() blocked while requests were in flight")
	}
	close(stop)
	wg.Wait()

	// Resolve after Close reports the resolver as closed.
	_, err = r.Resolve(new(dns.Msg), ClientInfo{})
	require.ErrorIs(t, err, errLuaClosed)
}
