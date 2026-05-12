package iplock_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aarondl/authboss/v3/iplock"
)

// testClock is a manually-driven clock for deterministic time control.
type testClock struct{ now time.Time }

func newTestClock() *testClock              { return &testClock{now: time.Unix(0, 0).UTC()} }
func (c *testClock) Now() time.Time         { return c.now }
func (c *testClock) Advance(d time.Duration) { c.now = c.now.Add(d) }

// newTestLock returns an IPLock with small, fixed tunables so each rule
// can be asserted exactly. Window and Duration are picked so Duration >
// Window (required by TestCleanup_KeepsBlockedEvenWhenWindowPassed).
func newTestLock(clk *testClock) *iplock.IPLock {
	ipl := iplock.New(clk.Now, nil)
	ipl.After = 3
	ipl.Window = 1 * time.Minute
	ipl.Duration = 5 * time.Minute
	return ipl
}

// --- Counting and threshold ---

func TestRecordFailure_FirstAttempt_CountIsOneAndNotBlocked(t *testing.T) {
	ipl := newTestLock(newTestClock())
	ipl.RecordFailure("1.1.1.1")

	if got := ipl.AttemptCount("1.1.1.1"); got != 1 {
		t.Errorf("AttemptCount = %d, want 1", got)
	}
	if ipl.IsBlocked("1.1.1.1") {
		t.Error("IsBlocked = true after 1 failure, want false")
	}
}

func TestRecordFailure_BelowThreshold_NotBlocked(t *testing.T) {
	ipl := newTestLock(newTestClock())
	for n := 0; n < ipl.After-1; n++ {
		ipl.RecordFailure("1.1.1.1")
	}
	if ipl.IsBlocked("1.1.1.1") {
		t.Errorf("IsBlocked = true at threshold-1 (%d), want false", ipl.After-1)
	}
	if got, want := ipl.AttemptCount("1.1.1.1"), ipl.After-1; got != want {
		t.Errorf("AttemptCount = %d, want %d", got, want)
	}
}

func TestRecordFailure_AtThreshold_IsBlocked(t *testing.T) {
	ipl := newTestLock(newTestClock())
	for n := 0; n < ipl.After; n++ {
		ipl.RecordFailure("1.1.1.1")
	}
	if !ipl.IsBlocked("1.1.1.1") {
		t.Errorf("IsBlocked = false at threshold (%d), want true", ipl.After)
	}
}

// --- Time-based transitions ---

func TestBlock_ExpiresAfterDuration(t *testing.T) {
	clk := newTestClock()
	ipl := newTestLock(clk)
	for n := 0; n < ipl.After; n++ {
		ipl.RecordFailure("1.1.1.1")
	}
	if !ipl.IsBlocked("1.1.1.1") {
		t.Fatal("precondition: should be blocked")
	}

	clk.Advance(ipl.Duration + time.Nanosecond)
	if ipl.IsBlocked("1.1.1.1") {
		t.Error("IsBlocked = true after Duration elapsed, want false")
	}
}

func TestWindow_ResetsCountWhenElapsed(t *testing.T) {
	clk := newTestClock()
	ipl := newTestLock(clk)
	ipl.RecordFailure("1.1.1.1")
	if got := ipl.AttemptCount("1.1.1.1"); got != 1 {
		t.Fatalf("precondition AttemptCount = %d, want 1", got)
	}

	clk.Advance(ipl.Window + time.Nanosecond)
	ipl.RecordFailure("1.1.1.1")

	if got := ipl.AttemptCount("1.1.1.1"); got != 1 {
		t.Errorf("AttemptCount after window reset = %d, want 1", got)
	}
	if ipl.IsBlocked("1.1.1.1") {
		t.Error("IsBlocked = true after window reset with single new failure")
	}
}

// --- Manual clearing and isolation ---

func TestClear_RemovesAllTracking(t *testing.T) {
	ipl := newTestLock(newTestClock())
	ipl.RecordFailure("1.1.1.1")
	ipl.RecordFailure("1.1.1.1")
	ipl.Clear("1.1.1.1")

	if got := ipl.AttemptCount("1.1.1.1"); got != 0 {
		t.Errorf("AttemptCount after Clear = %d, want 0", got)
	}
	if ipl.IsBlocked("1.1.1.1") {
		t.Error("IsBlocked = true after Clear, want false")
	}
}

func TestIsolation_FailuresOnOneIPDoNotAffectAnother(t *testing.T) {
	ipl := newTestLock(newTestClock())
	for n := 0; n < ipl.After; n++ {
		ipl.RecordFailure("1.1.1.1")
	}
	if !ipl.IsBlocked("1.1.1.1") {
		t.Fatal("precondition: 1.1.1.1 should be blocked")
	}
	if ipl.IsBlocked("2.2.2.2") {
		t.Error("IsBlocked(2.2.2.2) = true, want false")
	}
	if got := ipl.AttemptCount("2.2.2.2"); got != 0 {
		t.Errorf("AttemptCount(2.2.2.2) = %d, want 0", got)
	}
}

// --- IP extraction ---

func TestRemoteAddrIP_StripsPort(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.0.0.1:54321"
	if got := iplock.RemoteAddrIP(r); got != "10.0.0.1" {
		t.Errorf("RemoteAddrIP = %q, want %q", got, "10.0.0.1")
	}
}

func TestRemoteAddrIP_HandlesIPv6(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "[2001:db8::1]:54321"
	if got := iplock.RemoteAddrIP(r); got != "2001:db8::1" {
		t.Errorf("RemoteAddrIP = %q, want %q", got, "2001:db8::1")
	}
}

func TestRemoteAddrIP_IgnoresXForwardedFor(t *testing.T) {
	// Default extractor must NOT trust client-supplied headers,
	// otherwise the limiter is trivially bypassable.
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.0.0.1:54321"
	r.Header.Set("X-Forwarded-For", "9.9.9.9")
	r.Header.Set("X-Real-IP", "8.8.8.8")
	if got := iplock.RemoteAddrIP(r); got != "10.0.0.1" {
		t.Errorf("RemoteAddrIP must ignore proxy headers; got %q, want %q", got, "10.0.0.1")
	}
}

func TestIPExtractor_CustomIsHonored(t *testing.T) {
	clk := newTestClock()
	ipl := iplock.New(clk.Now, func(r *http.Request) string {
		return r.Header.Get("X-Test-IP")
	})
	ipl.After = 2
	ipl.Window = time.Hour
	ipl.Duration = time.Hour

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Test-IP", "1.1.1.1")

	ipl.RecordFailure(ipl.IPExtractor(r))
	ipl.RecordFailure(ipl.IPExtractor(r))

	if !ipl.IsBlocked("1.1.1.1") {
		t.Error("custom IPExtractor not honored: 1.1.1.1 should be blocked after 2 failures")
	}
}

// --- Cleanup ---

func TestCleanup_DropsExpiredUnblockedEntries(t *testing.T) {
	clk := newTestClock()
	ipl := newTestLock(clk)
	ipl.RecordFailure("1.1.1.1")
	if got := ipl.AttemptCount("1.1.1.1"); got != 1 {
		t.Fatalf("precondition AttemptCount = %d, want 1", got)
	}

	clk.Advance(ipl.Window * 2)
	ipl.Cleanup()

	if got := ipl.AttemptCount("1.1.1.1"); got != 0 {
		t.Errorf("AttemptCount after Cleanup = %d, want 0", got)
	}
}

func TestCleanup_KeepsBlockedEvenWhenWindowPassed(t *testing.T) {
	// Critical safety property: a stale window must not release a live block.
	if newTestLock(newTestClock()).Duration <= newTestLock(newTestClock()).Window {
		t.Fatal("test setup error: Duration must exceed Window for this test to be meaningful")
	}
	clk := newTestClock()
	ipl := newTestLock(clk)
	for n := 0; n < ipl.After; n++ {
		ipl.RecordFailure("1.1.1.1")
	}

	clk.Advance(ipl.Window + time.Second) // past window, still inside Duration
	ipl.Cleanup()

	if !ipl.IsBlocked("1.1.1.1") {
		t.Error("Cleanup dropped a currently-blocked entry")
	}
}

// --- Middleware ---

func TestMiddleware_Returns429WhenBlocked(t *testing.T) {
	clk := newTestClock()
	ipl := newTestLock(clk)
	for n := 0; n < ipl.After; n++ {
		ipl.RecordFailure("1.1.1.1")
	}

	nextCalled := false
	h := iplock.Middleware(ipl)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "1.1.1.1:1234"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusTooManyRequests)
	}
	if nextCalled {
		t.Error("next handler called for blocked IP, want short-circuit")
	}
}

func TestMiddleware_PassesThroughWhenUnderLimit(t *testing.T) {
	ipl := newTestLock(newTestClock())

	nextCalled := false
	h := iplock.Middleware(ipl)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "1.1.1.1:1234"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if !nextCalled {
		t.Error("next handler not called for un-blocked IP")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}
