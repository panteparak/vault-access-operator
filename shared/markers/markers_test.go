package markers

import "testing"

// TestEnabled_DefaultOff pins the critical invariant that managed-marker
// tracking is OFF unless explicitly enabled. Every marker/conflict/discovery
// code path is gated on Enabled(); the default must be false so an operator
// that never sets --managed-markers needs no grant on the marker KV path.
func TestEnabled_DefaultOff(t *testing.T) {
	// Guard against test-ordering leakage: another test in this package could
	// have flipped the global. Restore to the documented default first.
	SetEnabled(false)
	if Enabled() {
		t.Fatal("markers.Enabled() must default to false")
	}
}

func TestSetEnabled_Roundtrip(t *testing.T) {
	t.Cleanup(func() { SetEnabled(false) })

	SetEnabled(true)
	if !Enabled() {
		t.Error("Enabled() should be true after SetEnabled(true)")
	}
	SetEnabled(false)
	if Enabled() {
		t.Error("Enabled() should be false after SetEnabled(false)")
	}
}
