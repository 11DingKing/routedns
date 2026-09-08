package rdns

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"expvar"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pion/dtls/v3"
	"github.com/stretchr/testify/require"
)

// writeRotatorCertPair writes a fresh self-signed certificate and matching
// key into dir under fixed names (server.crt/server.key) and returns the
// paths together with the leaf certificate's DER encoding, which identifies
// the generation. Calling it again with the same dir overwrites the files.
func writeRotatorCertPair(t *testing.T, dir string) (crtPath, keyPath string, leafDER []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "routedns-rotation-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)

	crtPath = filepath.Join(dir, "server.crt")
	keyPath = filepath.Join(dir, "server.key")
	cf, err := os.Create(crtPath)
	require.NoError(t, err)
	require.NoError(t, pem.Encode(cf, &pem.Block{Type: "CERTIFICATE", Bytes: der}))
	require.NoError(t, cf.Close())
	keyBytes, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	kf, err := os.OpenFile(keyPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	require.NoError(t, err)
	require.NoError(t, pem.Encode(kf, &pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes}))
	require.NoError(t, kf.Close())
	return crtPath, keyPath, der
}

// rotatorID yields a metrics-id unique per test so expvar counters don't
// collide between tests.
func rotatorID(t *testing.T) string {
	return strings.ReplaceAll(t.Name(), "/", "-")
}

func rotatorErrCount(r *CertRotator, class string) int64 {
	if v := r.errs.Get(class); v != nil {
		return v.(*expvar.Int).Value()
	}
	return 0
}

// The constructor loads the first generation eagerly and serves it via both
// the TLS and DTLS hooks.
func TestCertRotatorInitialLoad(t *testing.T) {
	dir := t.TempDir()
	crt, key, leafDER := writeRotatorCertPair(t, dir)

	r, err := NewCertRotator(rotatorID(t), crt, key, 0)
	require.NoError(t, err)
	require.Equal(t, int64(1), r.Generation())
	require.True(t, bytes.Equal(r.Certificate().Certificate[0], leafDER))

	cert, err := r.GetCertificate(nil)
	require.NoError(t, err)
	require.True(t, bytes.Equal(cert.Certificate[0], leafDER))

	dtlsCert, err := r.GetDTLSCertificate(nil)
	require.NoError(t, err)
	require.True(t, bytes.Equal(dtlsCert.Certificate[0], leafDER))
}

// A missing or unreadable pair at construction time fails startup, matching
// the static load behaviour.
func TestCertRotatorConstructionFailures(t *testing.T) {
	dir := t.TempDir()
	crt, key, _ := writeRotatorCertPair(t, dir)
	missing := filepath.Join(t.TempDir(), "absent")

	_, err := NewCertRotator(rotatorID(t)+"-missing", missing, missing, 0)
	require.Error(t, err)
	require.True(t, errors.Is(err, os.ErrNotExist), "expected a not-exist error, got %v", err)

	// Key of one pair with the certificate of another: mismatch must fail.
	dir2 := t.TempDir()
	crt2, key2, _ := writeRotatorCertPair(t, dir2)
	_, err = NewCertRotator(rotatorID(t)+"-mismatch", crt2, key, 0)
	require.Error(t, err)
	_, err = NewCertRotator(rotatorID(t)+"-mismatch2", crt, key2, 0)
	require.Error(t, err)

	_, err = NewCertRotator(rotatorID(t)+"-paths", "", "", 0)
	require.Error(t, err)
	require.Contains(t, err.Error(), "requires server-crt and server-key")

	_, err = NewCertRotator(rotatorID(t)+"-interval", crt, key, -time.Second)
	require.Error(t, err)
}

// A reload publishes a new generation only when both files read and validate
// as a matching pair; unchanged files leave the generation untouched.
func TestCertRotatorReloadPublishesNewGeneration(t *testing.T) {
	dir := t.TempDir()
	crt, key, leafA := writeRotatorCertPair(t, dir)
	r, err := NewCertRotator(rotatorID(t), crt, key, time.Hour)
	require.NoError(t, err)

	// Same content on disk: no new generation.
	r.reload()
	require.Equal(t, int64(1), r.Generation())
	require.True(t, bytes.Equal(r.Certificate().Certificate[0], leafA))

	// New pair: generation 2.
	_, _, leafB := writeRotatorCertPair(t, dir)
	r.reload()
	require.Equal(t, int64(2), r.Generation())
	require.True(t, bytes.Equal(r.Certificate().Certificate[0], leafB))
	// Successful reloads must not be counted as errors.
	require.Equal(t, int64(0), rotatorErrCount(r, "missing")+rotatorErrCount(r, "invalid")+rotatorErrCount(r, "permission"))
}

// Every failure mode must keep the last valid generation and report a
// deterministic error class; once valid files return, a later reload switches.
func TestCertRotatorReloadFailuresKeepGeneration(t *testing.T) {
	dir := t.TempDir()
	crt, key, _ := writeRotatorCertPair(t, dir)
	r, err := NewCertRotator(rotatorID(t), crt, key, time.Hour)
	require.NoError(t, err)

	// Valid second pair used as the source of mismatched files.
	dir2 := t.TempDir()
	crt2, key2, leafB := writeRotatorCertPair(t, dir2)

	// expectKeptGeneration reloads with the files in their current (bad)
	// state and asserts the served generation is unchanged and the error
	// counter for class advanced.
	expectKeptGeneration := func(t *testing.T, class string) {
		t.Helper()
		leafBefore := r.Certificate().Certificate[0]
		genBefore := r.Generation()
		before := rotatorErrCount(r, class)
		r.reload()
		require.True(t, bytes.Equal(r.Certificate().Certificate[0], leafBefore),
			"failed reload must keep the last valid generation")
		require.Equal(t, genBefore, r.Generation())
		require.Greater(t, rotatorErrCount(r, class), before, "error class %q must be counted", class)
	}

	t.Run("certificate/key mismatch", func(t *testing.T) {
		// Valid new certificate with the still-valid old key: both files
		// parse but do not match, so nothing may be published.
		crtPEM, err := os.ReadFile(crt2)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(crt, crtPEM, 0600))
		expectKeptGeneration(t, "invalid")

		// The matching key completes the new pair, which then publishes.
		keyPEM, err := os.ReadFile(key2)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(key, keyPEM, 0600))
		r.reload()
		require.Equal(t, int64(2), r.Generation())
		require.True(t, bytes.Equal(r.Certificate().Certificate[0], leafB))
	})
	t.Run("files missing", func(t *testing.T) {
		require.NoError(t, os.Remove(crt))
		require.NoError(t, os.Remove(key))
		expectKeptGeneration(t, "missing")
	})
	t.Run("garbage content", func(t *testing.T) {
		require.NoError(t, os.WriteFile(crt, []byte("not a certificate"), 0600))
		require.NoError(t, os.WriteFile(key, []byte("not a key"), 0600))
		expectKeptGeneration(t, "invalid")
	})
	t.Run("permission denied", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root bypasses file permissions")
		}
		// Restore a valid pair first so the generation is known.
		writeRotatorCertPair(t, dir)
		r.reload()
		genBefore := r.Generation()
		require.NoError(t, os.Chmod(crt, 0))
		t.Cleanup(func() { _ = os.Chmod(crt, 0600) })
		leafBefore := r.Certificate().Certificate[0]
		before := rotatorErrCount(r, "permission")
		r.reload()
		require.True(t, bytes.Equal(r.Certificate().Certificate[0], leafBefore))
		require.Equal(t, genBefore, r.Generation())
		require.Greater(t, rotatorErrCount(r, "permission"), before)
		require.NoError(t, os.Chmod(crt, 0600))
	})
	t.Run("recovery", func(t *testing.T) {
		_, _, leafD := writeRotatorCertPair(t, dir)
		r.reload()
		require.True(t, bytes.Equal(r.Certificate().Certificate[0], leafD),
			"valid files after a failure must publish on the next reload")
	})
}

// Start launches the watcher and Close stops it exactly once: after Close no
// further reloads happen, Close is idempotent, and Close without Start does
// not block.
func TestCertRotatorStartClose(t *testing.T) {
	dir := t.TempDir()

	// Close without Start must be a no-op that returns promptly.
	crt0, key0, _ := writeRotatorCertPair(t, t.TempDir())
	never, err := NewCertRotator(rotatorID(t)+"-never", crt0, key0, time.Hour)
	require.NoError(t, err)
	require.NoError(t, never.Close())
	require.NoError(t, never.Close())

	crt, key, _ := writeRotatorCertPair(t, dir)
	r, err := NewCertRotator(rotatorID(t), crt, key, 20*time.Millisecond)
	require.NoError(t, err)
	r.Start()
	r.Start() // idempotent

	// A changed pair is picked up by the watcher within a few intervals.
	_, _, leafB := writeRotatorCertPair(t, dir)
	require.Eventually(t, func() bool {
		return bytes.Equal(r.Certificate().Certificate[0], leafB)
	}, 2*time.Second, 10*time.Millisecond)

	require.NoError(t, r.Close())

	// After Close the watcher must not reload anything anymore.
	gen := r.Generation()
	_, _, leafC := writeRotatorCertPair(t, dir)
	time.Sleep(150 * time.Millisecond)
	require.Equal(t, gen, r.Generation(), "watcher kept reloading after Close")
	require.False(t, bytes.Equal(r.Certificate().Certificate[0], leafC))

	// Double Close is harmless.
	require.NoError(t, r.Close())
}

// End-to-end through crypto/tls: new handshakes use the new generation while
// broken files leave handshakes on the last valid one.
func TestCertRotatorTLSHandshakesUseGeneration(t *testing.T) {
	dir := t.TempDir()
	crt, key, leafA := writeRotatorCertPair(t, dir)
	r, err := NewCertRotator(rotatorID(t), crt, key, time.Hour)
	require.NoError(t, err)

	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	EnableCertRotation(tlsConfig, r)

	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	require.NoError(t, err)
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.(*tls.Conn).HandshakeContext(context.Background())
				_, _ = io.Copy(io.Discard, c)
			}(c)
		}
	}()

	dial := func(t *testing.T) []byte {
		t.Helper()
		conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		})
		require.NoError(t, err)
		t.Cleanup(func() { conn.Close() })
		require.NoError(t, conn.Handshake())
		return conn.ConnectionState().PeerCertificates[0].Raw
	}

	require.True(t, bytes.Equal(dial(t), leafA), "first handshake must use the startup generation")

	// Rotate: new handshakes present the new certificate.
	_, _, leafB := writeRotatorCertPair(t, dir)
	r.reload()
	require.Equal(t, int64(2), r.Generation())
	require.True(t, bytes.Equal(dial(t), leafB), "handshake after rotation must use the new generation")

	// Break both files: the last valid generation keeps serving.
	require.NoError(t, os.WriteFile(crt, []byte("garbage"), 0600))
	require.NoError(t, os.WriteFile(key, []byte("garbage"), 0600))
	r.reload()
	require.Equal(t, int64(2), r.Generation())
	require.True(t, bytes.Equal(dial(t), leafB), "handshake during file breakage must use the last valid generation")

	// Restore: handshakes switch again.
	_, _, leafD := writeRotatorCertPair(t, dir)
	r.reload()
	require.True(t, bytes.Equal(dial(t), leafD), "handshake after recovery must use the restored generation")
}

// Same end-to-end guarantee through pion/dtls: its GetCertificate hook only
// fires when Certificates is empty, which EnableDTLSCertRotation arranges.
func TestCertRotatorDTLSHandshakesUseGeneration(t *testing.T) {
	dir := t.TempDir()
	crt, key, leafA := writeRotatorCertPair(t, dir)
	r, err := NewCertRotator(rotatorID(t), crt, key, time.Hour)
	require.NoError(t, err)

	dtlsConfig := &dtls.Config{}
	EnableDTLSCertRotation(dtlsConfig, r)

	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	require.NoError(t, err)
	ln, err := dtls.Listen("udp", addr, dtlsConfig)
	require.NoError(t, err)
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(io.Discard, c)
			}(c)
		}
	}()

	// pion returns from Dial before the handshake finishes; sending app data
	// drives it to completion, after which ConnectionState reports the
	// negotiated certificate.
	dial := func(t *testing.T) [][]byte {
		t.Helper()
		c, err := dtls.Dial("udp", ln.Addr().(*net.UDPAddr), &dtls.Config{InsecureSkipVerify: true})
		require.NoError(t, err)
		t.Cleanup(func() { c.Close() })
		require.NoError(t, c.SetDeadline(time.Now().Add(5*time.Second)))
		_, err = c.Write([]byte("x"))
		require.NoError(t, err)
		var state dtls.State
		require.Eventually(t, func() bool {
			var ok bool
			state, ok = c.ConnectionState()
			return ok && len(state.PeerCertificates) > 0
		}, 3*time.Second, 20*time.Millisecond)
		return state.PeerCertificates
	}

	require.True(t, bytes.Equal(dial(t)[0], leafA))

	_, _, leafB := writeRotatorCertPair(t, dir)
	r.reload()
	require.Equal(t, int64(2), r.Generation())
	require.True(t, bytes.Equal(dial(t)[0], leafB), "DTLS handshake after rotation must use the new generation")

	require.NoError(t, os.WriteFile(crt, []byte("garbage"), 0600))
	require.NoError(t, os.WriteFile(key, []byte("garbage"), 0600))
	r.reload()
	require.True(t, bytes.Equal(dial(t)[0], leafB), "DTLS handshake during file breakage must use the last valid generation")

	_, _, leafD := writeRotatorCertPair(t, dir)
	r.reload()
	require.True(t, bytes.Equal(dial(t)[0], leafD), "DTLS handshake after recovery must use the restored generation")
}
