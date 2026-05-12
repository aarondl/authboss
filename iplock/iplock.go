// Package iplock implements per-IP rate limiting for authboss.
//
// It tracks failed authentication attempts grouped by client IP, and
// blocks an IP for a configurable duration once the failure count
// crosses a threshold inside a rolling window. Time is read through an
// injectable clock and the IP is read through an injectable extractor,
// so the limiter is fully deterministic in tests.
//
// The default IP extractor reads only r.RemoteAddr. It deliberately
// ignores X-Forwarded-For and X-Real-IP because trusting client-supplied
// headers would let any caller request a fresh bucket per request. To
// honour proxy headers, run authboss behind a reverse proxy that
// rewrites RemoteAddr, or set IPLock.IPExtractor to a function that
// validates the headers against a trusted-proxy list.
package iplock

import (
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/aarondl/authboss/v3"
)

// Default tunables applied when the corresponding Config.Modules.IPLock*
// field is unset.
const (
	DefaultIPLockAfter    = 10
	DefaultIPLockWindow   = 15 * time.Minute
	DefaultIPLockDuration = 1 * time.Hour

	cleanupInterval = 10 * time.Minute
)

func init() {
	authboss.RegisterModule("iplock", &IPLock{})
}

// IPLock is the per-IP rate limiter. It is safe for concurrent use.
//
// Construct with New for tests, or register the module via
// authboss.RegisterModule and let ab.Init wire it for production.
type IPLock struct {
	*authboss.Authboss

	// After is the failure count at which an IP becomes blocked.
	// Zero is replaced with Config.Modules.IPLockAfter, then with
	// DefaultIPLockAfter.
	After int
	// Window is the rolling window in which failures are counted.
	// Zero is replaced with Config.Modules.IPLockWindow, then with
	// DefaultIPLockWindow.
	Window time.Duration
	// Duration is the block length once the threshold is reached.
	// Zero is replaced with Config.Modules.IPLockDuration, then with
	// DefaultIPLockDuration.
	Duration time.Duration

	// Now returns the current time. Defaults to time.Now. Override in
	// tests to drive the limiter deterministically.
	Now func() time.Time

	// IPExtractor returns the client IP for a request. Defaults to
	// RemoteAddrIP, which uses r.RemoteAddr only. Override to honour
	// trusted proxy headers.
	IPExtractor func(*http.Request) string

	mu       sync.Mutex
	attempts map[string]*ipAttempt

	stopOnce sync.Once
	stopCh   chan struct{}
}

type ipAttempt struct {
	count        int
	firstSeen    time.Time
	blockedUntil time.Time
}

// New returns an IPLock pre-populated with safe defaults. Tests use this
// to exercise the limiter without standing up an Authboss instance. now
// and extractor may be nil to accept the package defaults.
func New(now func() time.Time, extractor func(*http.Request) string) *IPLock {
	i := &IPLock{Now: now, IPExtractor: extractor}
	i.applyDefaults()
	return i
}

// Init wires the module into authboss. Reads tunables from
// ab.Config.Modules, fills in defaults, registers event hooks on EventAuth
// and EventAuthFail, and starts the background cleanup goroutine.
func (i *IPLock) Init(ab *authboss.Authboss) error {
	i.Authboss = ab
	if i.After == 0 {
		i.After = ab.Config.Modules.IPLockAfter
	}
	if i.Window == 0 {
		i.Window = ab.Config.Modules.IPLockWindow
	}
	if i.Duration == 0 {
		i.Duration = ab.Config.Modules.IPLockDuration
	}
	i.applyDefaults()

	ab.Events.Before(authboss.EventAuth, i.BeforeAuth)
	ab.Events.After(authboss.EventAuth, i.AfterAuthSuccess)
	ab.Events.After(authboss.EventAuthFail, i.AfterAuthFail)

	go i.cleanupLoop()
	return nil
}

// Stop terminates the cleanup goroutine. Safe to call more than once and
// safe to call when no goroutine was started. Tests use this for clean
// shutdown.
func (i *IPLock) Stop() {
	i.stopOnce.Do(func() {
		if i.stopCh != nil {
			close(i.stopCh)
		}
	})
}

// BeforeAuth blocks the request when the client IP is currently rate-limited.
func (i *IPLock) BeforeAuth(w http.ResponseWriter, r *http.Request, handled bool) (bool, error) {
	if handled {
		return false, nil
	}
	if i.IsBlocked(i.IPExtractor(r)) {
		return i.respondBlocked(w)
	}
	return false, nil
}

// AfterAuthFail records a failed authentication attempt for the request's IP.
func (i *IPLock) AfterAuthFail(w http.ResponseWriter, r *http.Request, handled bool) (bool, error) {
	i.RecordFailure(i.IPExtractor(r))
	return false, nil
}

// AfterAuthSuccess clears all tracking for the request's IP.
func (i *IPLock) AfterAuthSuccess(w http.ResponseWriter, r *http.Request, handled bool) (bool, error) {
	i.Clear(i.IPExtractor(r))
	return false, nil
}

// Middleware returns an HTTP middleware that responds with 429 when the
// request's IP is blocked, and otherwise forwards to next.
func Middleware(i *IPLock) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if i.IsBlocked(i.IPExtractor(r)) {
				_, _ = i.respondBlocked(w)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// IsBlocked reports whether ip is currently blocked. Empty ip is never blocked.
func (i *IPLock) IsBlocked(ip string) bool {
	if ip == "" {
		return false
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	a, ok := i.attempts[ip]
	if !ok {
		return false
	}
	return i.Now().Before(a.blockedUntil)
}

// AttemptCount returns the failure count tracked for ip. Returns 0 when
// no failures are tracked.
func (i *IPLock) AttemptCount(ip string) int {
	i.mu.Lock()
	defer i.mu.Unlock()
	if a, ok := i.attempts[ip]; ok {
		return a.count
	}
	return 0
}

// RecordFailure increments the failure counter for ip. The IP becomes
// blocked once the count reaches After within Window. Failures observed
// after the window has elapsed reset the counter to 1. Empty ip is a no-op.
func (i *IPLock) RecordFailure(ip string) {
	if ip == "" {
		return
	}
	now := i.Now()
	i.mu.Lock()
	defer i.mu.Unlock()

	a, ok := i.attempts[ip]
	if !ok || now.Sub(a.firstSeen) > i.Window {
		i.attempts[ip] = &ipAttempt{count: 1, firstSeen: now}
		return
	}
	a.count++
	if a.count >= i.After {
		a.blockedUntil = now.Add(i.Duration)
	}
}

// Clear removes all tracking for ip. Empty ip is a no-op.
func (i *IPLock) Clear(ip string) {
	if ip == "" {
		return
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	delete(i.attempts, ip)
}

// Cleanup drops entries whose window has elapsed and whose block has
// expired. Currently-blocked entries are retained even when their window
// has passed, so a stale window cannot release a live block. Exposed so
// tests can drive cleanup without waiting on a real ticker.
func (i *IPLock) Cleanup() {
	now := i.Now()
	i.mu.Lock()
	defer i.mu.Unlock()
	for ip, a := range i.attempts {
		if now.Sub(a.firstSeen) > i.Window && !now.Before(a.blockedUntil) {
			delete(i.attempts, ip)
		}
	}
}

func (i *IPLock) cleanupLoop() {
	t := time.NewTicker(cleanupInterval)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			i.Cleanup()
		case <-i.stopCh:
			return
		}
	}
}

func (i *IPLock) applyDefaults() {
	if i.After == 0 {
		i.After = DefaultIPLockAfter
	}
	if i.Window == 0 {
		i.Window = DefaultIPLockWindow
	}
	if i.Duration == 0 {
		i.Duration = DefaultIPLockDuration
	}
	if i.Now == nil {
		i.Now = time.Now
	}
	if i.IPExtractor == nil {
		i.IPExtractor = RemoteAddrIP
	}
	if i.attempts == nil {
		i.attempts = make(map[string]*ipAttempt)
	}
	if i.stopCh == nil {
		i.stopCh = make(chan struct{})
	}
}

func (i *IPLock) respondBlocked(w http.ResponseWriter) (bool, error) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusTooManyRequests)
	_, err := w.Write([]byte("Too Many Requests\n"))
	return true, err
}

// RemoteAddrIP returns the host portion of r.RemoteAddr, with the port
// stripped. It is the safe-by-default extractor: it never reads
// client-supplied headers. Behind a reverse proxy that rewrites
// RemoteAddr (the common case), this returns the real client IP.
func RemoteAddrIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
