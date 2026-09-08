package rdns

import (
	"bytes"
	"crypto/tls"
	"errors"
	"expvar"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pion/dtls/v3"
)

// defaultCertRotateInterval is the period between certificate file checks
// when rotation is enabled without an explicit interval.
const defaultCertRotateInterval = time.Minute

// CertRotator serves a server certificate/key pair and, once started,
// periodically re-reads the pair from disk. A pair is published as a new
// generation only when both files can be read and parse into a matching
// certificate/key pair; any failure (missing file, bad permissions, malformed
// PEM, key not matching the certificate) leaves the last valid generation in
// place, so a half-written or temporarily inaccessible file never breaks
// handshakes. New TLS/DTLS handshakes fetch the current generation via the
// GetCertificate hooks; connections whose handshake already completed keep
// using the certificate they negotiated.
//
// A rotator is meant to live for the whole process and be shared by every
// listener instance using its config (netns-supervised listeners are rebuilt
// repeatedly, for example): Start and Close are idempotent and the rotator
// never touches the tls.Config beyond serving certificates, so repeated
// listener (re)starts neither leak watcher goroutines nor close shared state.
type CertRotator struct {
	id       string
	crtFile  string
	keyFile  string
	interval time.Duration

	// Current certificate generation. Swapped atomically on a successful
	// reload; in-flight handshakes hold the pointer they were handed and
	// are unaffected by the swap.
	current atomic.Pointer[tls.Certificate]

	generation *expvar.Int   // number of published generations
	errs       *expvar.Map   // failed reloads by error class
	startOnce  sync.Once     // guards the watcher goroutine
	closeOnce  sync.Once     // guards closing stop
	started    atomic.Bool   // whether Start launched the watcher
	stop       chan struct{} // closed to stop the watcher
	done       chan struct{} // closed when the watcher has exited

	// lastErr is the message of the most recent failed reload, used to log a
	// failure once per episode rather than on every tick.
	mu      sync.Mutex
	lastErr string
}

// NewCertRotator loads the certificate/key pair from crtFile/keyFile and
// returns a rotator serving it as the first generation. The initial load is
// performed eagerly and an error returned, so a missing or invalid pair fails
// startup exactly like a static certificate load. interval is the check
// period; zero defaults to defaultCertRotateInterval.
func NewCertRotator(id, crtFile, keyFile string, interval time.Duration) (*CertRotator, error) {
	if crtFile == "" || keyFile == "" {
		return nil, errors.New("certificate rotation requires server-crt and server-key")
	}
	if interval < 0 {
		return nil, fmt.Errorf("certificate rotation interval must not be negative: %s", interval)
	}
	if interval == 0 {
		interval = defaultCertRotateInterval
	}
	r := &CertRotator{
		id:         id,
		crtFile:    crtFile,
		keyFile:    keyFile,
		interval:   interval,
		stop:       make(chan struct{}),
		done:       make(chan struct{}),
		generation: getVarInt("certrotate", id, "generation"),
		errs:       getVarMap("certrotate", id, "error"),
	}
	cert, err := r.loadPair()
	if err != nil {
		return nil, err
	}
	r.current.Store(&cert)
	r.generation.Set(1)
	return r, nil
}

// Start launches the periodic file watcher. It is safe to call multiple
// times; only the first call starts a goroutine. The watcher does not have to
// be started for the rotator to serve the initial generation.
func (r *CertRotator) Start() {
	r.startOnce.Do(func() {
		r.started.Store(true)
		go r.loop()
	})
}

// Close stops the watcher goroutine and waits for it to exit. It is safe to
// call multiple times and safe to call without Start having run.
func (r *CertRotator) Close() error {
	r.closeOnce.Do(func() { close(r.stop) })
	if r.started.Load() {
		<-r.done
	}
	return nil
}

// Certificate returns the certificate generation currently being served.
func (r *CertRotator) Certificate() tls.Certificate {
	return *r.current.Load()
}

// Generation returns the number of certificate generations published so far.
func (r *CertRotator) Generation() int64 {
	return r.generation.Value()
}

// GetCertificate is the crypto/tls tls.Config.GetCertificate hook. Each new
// handshake calls it and receives the current generation.
func (r *CertRotator) GetCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	cert := r.current.Load()
	if cert == nil {
		return nil, errors.New("no server certificate available")
	}
	return cert, nil
}

// GetDTLSCertificate is the pion/dtls dtls.Config.GetCertificate hook. It
// serves the same generations as GetCertificate.
func (r *CertRotator) GetDTLSCertificate(_ *dtls.ClientHelloInfo) (*tls.Certificate, error) {
	return r.GetCertificate(nil)
}

// EnableCertRotation makes a crypto/tls server config serve its certificate
// from rotator on every new handshake instead of the statically loaded
// Certificates. The CA pool and client-auth settings on the config are left
// untouched.
func EnableCertRotation(tlsConfig *tls.Config, rotator *CertRotator) {
	tlsConfig.Certificates = nil
	tlsConfig.GetCertificate = rotator.GetCertificate
}

// EnableDTLSCertRotation makes a pion/dtls server config serve its certificate
// from rotator on every new handshake instead of the statically loaded
// Certificates. The static pair has to be cleared: pion only consults
// GetCertificate when Certificates is empty (or the client sent SNI), so
// leaving it in place would keep serving the startup certificate on
// handshakes without SNI.
func EnableDTLSCertRotation(dtlsConfig *dtls.Config, rotator *CertRotator) {
	dtlsConfig.Certificates = nil
	dtlsConfig.GetCertificate = rotator.GetDTLSCertificate
}

func (r *CertRotator) loop() {
	defer close(r.done)
	t := time.NewTicker(r.interval)
	defer t.Stop()
	for {
		select {
		case <-r.stop:
			return
		case <-t.C:
			r.reload()
		}
	}
}

// reload reads and validates the pair and, only on success, publishes it as a
// new generation. Any failure is counted and logged and the current
// generation retained.
func (r *CertRotator) reload() {
	cert, err := r.loadPair()
	if err != nil {
		r.errs.Add(certRotateErrorClass(err), 1)
		r.mu.Lock()
		msg := err.Error()
		newEpisode := msg != r.lastErr
		r.lastErr = msg
		r.mu.Unlock()
		if newEpisode {
			Log.Warn("certificate rotation failed, keeping current certificate",
				"id", r.id, "crt", r.crtFile, "key", r.keyFile, "error", err)
		}
		return
	}

	current := r.current.Load()
	r.mu.Lock()
	hadErr := r.lastErr != ""
	r.lastErr = ""
	r.mu.Unlock()

	// Files are healthy but carry the same certificate: no new generation,
	// just clear the failure state.
	if current != nil && bytes.Equal(current.Certificate[0], cert.Certificate[0]) {
		if hadErr {
			Log.Info("certificate files readable again, serving unchanged certificate", "id", r.id)
		}
		return
	}

	r.current.Store(&cert)
	r.generation.Add(1)
	generation := r.generation.Value()
	if hadErr {
		Log.Info("certificate rotation recovered and published new generation",
			"id", r.id, "generation", generation)
	} else {
		Log.Info("server certificate rotated", "id", r.id, "generation", generation)
	}
}

// loadPair reads both files in full and only then parses them into a key
// pair, so a pair is never observed half-written: either both files are
// read and validate together or nothing is published.
func (r *CertRotator) loadPair() (tls.Certificate, error) {
	crtPEM, err := os.ReadFile(r.crtFile)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("reading certificate %q: %w", r.crtFile, err)
	}
	keyPEM, err := os.ReadFile(r.keyFile)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("reading private key %q: %w", r.keyFile, err)
	}
	cert, err := tls.X509KeyPair(crtPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("parsing certificate/key pair %q, %q: %w", r.crtFile, r.keyFile, err)
	}
	return cert, nil
}

// certRotateErrorClass assigns a reload error a stable class for metrics:
// "missing" for an absent file, "permission" for an inaccessible one,
// "invalid" for anything that parses or matches incorrectly.
func certRotateErrorClass(err error) string {
	switch {
	case errors.Is(err, os.ErrNotExist):
		return "missing"
	case errors.Is(err, os.ErrPermission):
		return "permission"
	default:
		return "invalid"
	}
}
