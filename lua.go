package rdns

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// defaultLuaWatchInterval is how often an external script file is checked
// for changes when watching is enabled.
const defaultLuaWatchInterval = time.Second

type Lua struct {
	id        string
	resolvers []Resolver

	opt LuaOptions

	// gen points at the currently published generation of Lua VMs. It is
	// swapped atomically when a new generation is published; nil after Close.
	gen    atomic.Pointer[luaGen]
	genSeq atomic.Uint64

	// stop is closed when the resolver is closed. The watcher goroutine
	// (if any) exits on it and reports back via watchDone.
	stop      chan struct{}
	stopOnce  sync.Once
	watchDone chan struct{}

	// reloadMu serializes reload attempts, from the watcher, a manual Reload
	// call, or Close. Holding it is the only time the current generation may
	// be swapped, which guarantees Close never races a publish into oblivion.
	reloadMu sync.Mutex

	// errMu guards lastErr, the observable result of the most recent reload
	// attempt (nil while the last attempt succeeded or no attempt was made).
	errMu   sync.RWMutex
	lastErr error

	// hashMu guards scriptHash, the SHA-256 of the script the current
	// generation was built from. It lets the watcher skip rebuilds when a
	// file changed on disk but contains the same bytes.
	hashMu     sync.Mutex
	scriptHash string
}

var _ Resolver = &Lua{}

type LuaOptions struct {
	// Script is the inline Lua script. Ignored when ScriptSource is set.
	Script string
	// ScriptSource is the path to an external Lua script file. When set,
	// the file (rather than Script) provides the script content.
	ScriptSource string
	Concurrency  uint
	NoSandbox    bool // Disables the sandbox. When false (default), scripts cannot access os/io/debug/etc.

	// Watch enables monitoring ScriptSource for changes and hot-reloading it.
	// It has no effect with inline scripts. Defaults to false, in which case
	// the script is loaded once at startup as with inline scripts.
	Watch bool
	// WatchInterval is how often the script file is polled for changes.
	// Defaults to 1s when zero and Watch is enabled.
	WatchInterval time.Duration
}

// luaGen is one generation of Lua VMs built from a single script version.
// A generation is immutable: its bytecode never changes and requests borrow
// VMs from its pool. A new generation is published atomically; the old one is
// retired and drains as requests that borrowed its VMs complete.
type luaGen struct {
	id uint64

	// idle holds VMs that are not currently serving a request. Buffered to
	// the pool size; it is never closed so receives cannot yield nil.
	idle chan *LuaScript

	// retired is closed once the generation has been superseded (or the
	// resolver is closing). After that point VMs are closed instead of being
	// returned to the pool, and borrowers waiting on an empty pool fail over
	// to the current generation.
	retired    chan struct{}
	retireOnce sync.Once

	// wg tracks VMs that have not been closed yet: one Add per VM created,
	// one Done per VM closed. It reaches zero when every VM of the
	// generation has been freed, which is what Close waits for.
	wg sync.WaitGroup
}

var (
	errLuaGenRetired = errors.New("lua script generation retired")
	errLuaClosed     = errors.New("lua resolver is closed")
	errLuaNoSource   = errors.New("lua reload requires an external script file (lua-script-source)")
)

func NewLua(id string, opt LuaOptions, resolvers ...Resolver) (*Lua, error) {
	if opt.Concurrency == 0 {
		opt.Concurrency = 4
	}
	if opt.Watch {
		if opt.ScriptSource == "" {
			return nil, errors.New("lua script watching requires an external script file (lua-script-source)")
		}
		if opt.WatchInterval <= 0 {
			opt.WatchInterval = defaultLuaWatchInterval
		}
	}

	r := &Lua{
		id:        id,
		resolvers: resolvers,
		opt:       opt,
		stop:      make(chan struct{}),
	}

	// Compile and instantiate the initial generation. This mirrors the
	// startup behavior of inline scripts: a missing, unreadable, or invalid
	// script fails construction, since there is no previous generation to
	// fall back to.
	script, err := r.loadScript()
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(script) == "" {
		return nil, errors.New("lua group requires a script (lua-script or lua-script-source)")
	}
	g, err := r.buildGen(script)
	if err != nil {
		return nil, err
	}
	r.gen.Store(g)
	r.setScriptHash(hashScript(script))

	if opt.Watch {
		r.watchDone = make(chan struct{})
		go r.watch(opt.WatchInterval)
	}
	return r, nil
}

func (r *Lua) Resolve(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
	g, s, err := r.borrow()
	if err != nil {
		return nil, err
	}
	defer g.release(s)

	log := logger(r.id, q, ci)

	// Call the "resolve" function in the script. It should return 2 values.
	ret, err := s.Call("Resolve", 2, q, ci)
	if err != nil {
		log.Error("failed to run lua script", "error", err)
		return nil, err
	}

	// Extract the answer and error from the returned values
	if len(ret) != 2 {
		return nil, fmt.Errorf("invalid return value, expected 2, got %d", len(ret))
	}

	answer, ok := ret[0].(*dns.Msg)
	if ret[0] != nil && !ok {
		return nil, fmt.Errorf("invalid return value, expected Message, got %T", ret[0])
	}

	err, ok = ret[1].(error)
	if ret[1] != nil && !ok {
		return nil, fmt.Errorf("invalid return value, expected Error, got %T", ret[1])
	}

	return answer, err
}

func (r *Lua) String() string {
	return r.id
}

// Close stops watching the script file, retires the current generation, and
// waits until every VM of it has been closed. VMs on loan to in-flight
// requests are closed by those requests when they return them, so no VM is
// closed while a Lua call is in progress.
func (r *Lua) Close() {
	r.stopOnce.Do(func() { close(r.stop) })
	if r.watchDone != nil {
		<-r.watchDone
	}

	r.reloadMu.Lock()
	defer r.reloadMu.Unlock()

	g := r.gen.Swap(nil)
	if g != nil {
		g.retire()
		g.wg.Wait()
	}
}

// borrow hands out a VM from the current generation. If the generation it
// picked gets retired before a VM is available (its whole pool is on loan to
// requests that finish into the retired path), it retries with whatever
// generation is current then.
func (r *Lua) borrow() (*luaGen, *LuaScript, error) {
	for {
		g := r.gen.Load()
		if g == nil {
			return nil, nil, errLuaClosed
		}
		s, err := g.borrow()
		if err == nil {
			return g, s, nil
		}
		// Generation retired while waiting for a VM. Loop and borrow from
		// the now-current generation instead.
	}
}

// Reload re-reads the external script file and, only if it can be read in
// full, compiles, initializes (sandbox, constants, DNS types, ClientInfo and
// upstream resolver injection) and instantiates a complete new VM pool,
// atomically publishes a new generation. Anything short of that leaves the
// previously published generation serving traffic and records the failure,
// which is returned here and exposed via ReloadError.
//
// Reload has no effect on resolvers configured with an inline script.
func (r *Lua) Reload() error {
	if r.opt.ScriptSource == "" {
		return errLuaNoSource
	}

	r.reloadMu.Lock()
	defer r.reloadMu.Unlock()

	select {
	case <-r.stop:
		return errLuaClosed
	default:
	}

	script, err := r.loadScript()
	if err == nil && strings.TrimSpace(script) == "" {
		err = errors.New("lua script file is empty")
	}
	if err == nil {
		// A file can be rewritten with identical content (touch, rewrite to
		// the last good version, etc.). Nothing to do, and this counts as a
		// successful observation: a previously recorded failure against the
		// same path is cleared.
		h := hashScript(script)
		if h == r.currentScriptHash() {
			r.reportReloadResult(nil, false)
			return nil
		}
		g, buildErr := r.buildGen(script)
		if buildErr != nil {
			err = fmt.Errorf("lua script reload failed, keeping previous generation: %w", buildErr)
		} else {
			old := r.gen.Swap(g)
			if old != nil {
				old.retire()
			}
			r.setScriptHash(h)
			r.reportReloadResult(nil, true)
			return nil
		}
	}

	r.reportReloadResult(err, false)
	return err
}

// ReloadError returns the error from the most recent failed reload attempt,
// or nil if the most recent attempt succeeded (or no attempt was made). It
// is the deterministic observation point for operators checking reload
// health while a previous generation keeps serving.
func (r *Lua) ReloadError() error {
	r.errMu.RLock()
	defer r.errMu.RUnlock()
	return r.lastErr
}

func (r *Lua) setReloadError(err error) {
	r.errMu.Lock()
	r.lastErr = err
	r.errMu.Unlock()
}

// reportReloadResult records the outcome of a reload attempt and logs it.
// Failures and recoveries are logged on state transitions so persistent
// problems (a file that stays broken) do not spam the log on every poll,
// while every attempt remains observable via ReloadError.
func (r *Lua) reportReloadResult(err error, published bool) {
	prev := r.ReloadError()
	r.setReloadError(err)

	switch {
	case err != nil && (prev == nil || prev.Error() != err.Error()):
		Log.Error("lua script reload failed; continuing with previous generation",
			"id", r.id, "source", r.opt.ScriptSource, "error", err)
	case err == nil && prev != nil:
		Log.Info("lua script reload recovered",
			"id", r.id, "source", r.opt.ScriptSource)
	}
	if published {
		Log.Info("lua script reloaded", "id", r.id, "source", r.opt.ScriptSource,
			"generation", r.gen.Load().id)
	}
}

func (r *Lua) currentScriptHash() string {
	r.hashMu.Lock()
	defer r.hashMu.Unlock()
	return r.scriptHash
}

func (r *Lua) setScriptHash(h string) {
	r.hashMu.Lock()
	r.scriptHash = h
	r.hashMu.Unlock()
}

// loadScript reads the external script file in full when configured, and
// otherwise returns the inline script.
func (r *Lua) loadScript() (string, error) {
	if r.opt.ScriptSource == "" {
		return r.opt.Script, nil
	}
	b, err := os.ReadFile(r.opt.ScriptSource)
	if err != nil {
		return "", fmt.Errorf("failed to read lua script '%s': %w", r.opt.ScriptSource, err)
	}
	return string(b), nil
}

// buildGen compiles the script and creates a fully initialized pool of VMs.
// The generation is only usable once every VM has been built successfully;
// on any failure the partial pool is torn down and the error is returned,
// leaving whatever generation is currently published untouched.
func (r *Lua) buildGen(script string) (*luaGen, error) {
	bytecode, err := LuaCompile(strings.NewReader(script), r.id)
	if err != nil {
		return nil, err
	}

	g := &luaGen{
		id:      r.genSeq.Add(1),
		idle:    make(chan *LuaScript, r.opt.Concurrency),
		retired: make(chan struct{}),
	}

	for range r.opt.Concurrency {
		s, err := r.newScript(bytecode)
		if err != nil {
			g.discard()
			return nil, err
		}
		g.wg.Add(1)
		g.idle <- s
	}
	return g, nil
}

// discard closes every VM of a generation that failed to build completely.
// Such a generation is never published, so no VM can be on loan.
func (g *luaGen) discard() {
	close(g.retired)
	for {
		select {
		case s := <-g.idle:
			s.L.Close()
			g.wg.Done()
		default:
			return
		}
	}
}

// borrow returns one idle VM from the generation. It fails once the
// generation has been retired so callers can fail over to the current one.
func (g *luaGen) borrow() (*LuaScript, error) {
	select {
	case <-g.retired:
		return nil, errLuaGenRetired
	default:
	}
	select {
	case s := <-g.idle:
		return s, nil
	case <-g.retired:
		return nil, errLuaGenRetired
	}
}

// release returns a borrowed VM to the pool. If the generation was retired
// while the VM was on loan, the VM is closed instead: the request that
// borrowed it is done, and the retired pool is draining.
func (g *luaGen) release(s *LuaScript) {
	select {
	case g.idle <- s:
	case <-g.retired:
		s.L.Close()
		g.wg.Done()
	}
}

// retire marks the generation superseded. Idle VMs are closed immediately;
// VMs still on loan are closed by their borrowers on return.
func (g *luaGen) retire() {
	g.retireOnce.Do(func() { close(g.retired) })

	done := make(chan struct{})
	go func() {
		g.wg.Wait()
		close(done)
	}()
	go func() {
		for {
			select {
			case s := <-g.idle:
				s.L.Close()
				g.wg.Done()
			case <-done:
				return
			}
		}
	}()
}

func (r *Lua) newScript(b ByteCode) (*LuaScript, error) {
	s, err := NewScriptFromByteCode(b, !r.opt.NoSandbox)
	if err != nil {
		// NewScriptFromByteCode returns the state alongside a chunk
		// execution error; close it so a failed (re)load cannot leak VMs.
		if s != nil {
			s.L.Close()
		}
		return nil, err
	}

	// Register types and methods
	s.RegisterConstants()
	s.RegisterMessageType()
	s.RegisterQuestionType()
	s.RegisterRRTypes()
	s.RegisterOPTType()
	s.RegisterEDNS0Types()
	s.RegisterErrorType()
	s.RegisterClientInfoType()

	// Inject the resolvers into the state (so they can be used in the script)
	s.InjectResolvers(r.resolvers)

	// The script must contain a Resolve() function which is the entry point
	if !s.HasFunction("Resolve") {
		s.L.Close()
		return nil, errors.New("no Resolve() function found in lua script")
	}

	return s, nil
}

// watch polls the script file for changes and triggers a reload whenever its
// metadata changes or a previous attempt has not yet succeeded (so transient
// conditions like permission fixes that do not alter mtime still recover).
func (r *Lua) watch(interval time.Duration) {
	defer close(r.watchDone)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	var (
		lastMod   time.Time
		lastSize  int64
		haveStat  bool
		firstTick = true
	)

	for {
		select {
		case <-r.stop:
			return
		case <-ticker.C:
			fi, statErr := os.Stat(r.opt.ScriptSource)
			// Always run one reload at startup so a change (or failure)
			// that raced the watcher start cannot be missed; Reload no-ops
			// when the file content matches the published generation.
			// Keep retrying while a previous attempt is failing.
			changed := firstTick || r.ReloadError() != nil
			firstTick = false
			switch {
			case statErr == nil && (!haveStat || !fi.ModTime().Equal(lastMod) || fi.Size() != lastSize):
				changed = true
				lastMod, lastSize, haveStat = fi.ModTime(), fi.Size(), true
			case statErr != nil:
				// The file is gone (or cannot be stated). Record the
				// transition; the next successful stat establishes a new
				// baseline when it reappears.
				changed = changed || haveStat
				haveStat = false
			}
			if changed {
				_ = r.Reload()
			}
		}
	}
}

func hashScript(script string) string {
	sum := sha256.Sum256([]byte(script))
	return hex.EncodeToString(sum[:])
}
