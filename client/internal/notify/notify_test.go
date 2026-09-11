package notify

import "testing"

func TestFirstThisSessionThrottlesPerReason(t *testing.T) {
	const sess = "notify-test-session-A"
	Clear(sess)
	t.Cleanup(func() { Clear(sess) })

	// First time for a reason → show it.
	if !FirstThisSession(sess, "unreachable") {
		t.Fatal("first occurrence should notify")
	}
	// Same reason again this session → suppressed (no spam during an outage).
	if FirstThisSession(sess, "unreachable") {
		t.Error("repeat of the same reason should be suppressed")
	}
	// A DIFFERENT reason is a new condition → show it once.
	if !FirstThisSession(sess, "unauthorized") {
		t.Error("a distinct reason should notify even after another was shown")
	}
	if FirstThisSession(sess, "unauthorized") {
		t.Error("repeat of the second reason should be suppressed")
	}
}

func TestFirstThisSessionIsPerSession(t *testing.T) {
	const a, b = "notify-test-session-B", "notify-test-session-C"
	Clear(a)
	Clear(b)
	t.Cleanup(func() { Clear(a); Clear(b) })

	if !FirstThisSession(a, "unreachable") {
		t.Fatal("session A first occurrence should notify")
	}
	// A separate session has its own state.
	if !FirstThisSession(b, "unreachable") {
		t.Error("session B should notify independently of session A")
	}
}

// An empty session ID can't be throttled (no key) → always notify, never silently
// swallow. (Fail toward informing the developer.)
func TestFirstThisSessionEmptySessionAlwaysNotifies(t *testing.T) {
	if !FirstThisSession("", "unreachable") {
		t.Error("empty session should always notify")
	}
	if !FirstThisSession("", "unreachable") {
		t.Error("empty session should still notify on repeat")
	}
}
