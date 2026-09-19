package parser

import "testing"

const sampleStatL2TPSwitch = `l2tp:
  l2tp-switch:
    active: 1
    lns_rx_bytes: 1690
    lns_tx_bytes: 1639
`

func TestParseStatsL2TPSwitch(t *testing.T) {
	st, err := parseStats(sampleStatL2TPSwitch)
	if err != nil {
		t.Fatalf("parseStats: %v", err)
	}
	wantEq(t, "L2TP.Switch.Active", st.L2TP.Switch.Active, 1)
	wantEq(t, "L2TP.Switch.LNSRxBytes", st.L2TP.Switch.LNSRxBytes, 1690)
	wantEq(t, "L2TP.Switch.LNSTxBytes", st.L2TP.Switch.LNSTxBytes, 1639)
}

// sampleSwitchShow is a representative "accel-cmd l2tp switch show" capture.
const sampleSwitchShow = `targets:
  test1 -> 203.0.113.4:1701 [up] active=0 bytes_in=1639 bytes_out=1690
  test2 -> 203.0.113.5:1701 [down] active=0 bytes_in=0 bytes_out=0
calls:
  matched: 3
  placed: 3
  connected: 3
  active: 0
`

func TestParseSwitchShow(t *testing.T) {
	sw, err := parseSwitchShow(sampleSwitchShow)
	if err != nil {
		t.Fatalf("parseSwitchShow: %v", err)
	}
	if len(sw.Targets) != 2 {
		t.Fatalf("Targets = %d, want 2: %+v", len(sw.Targets), sw.Targets)
	}
	t1 := sw.Targets[0]
	if t1.Name != "test1" || t1.PeerAddr != "203.0.113.4" || t1.PeerPort != "1701" || !t1.Up {
		t.Errorf("Targets[0] = %+v, want test1 up at 203.0.113.4:1701", t1)
	}
	wantEq(t, "Targets[0].BytesIn", t1.BytesIn, 1639)
	wantEq(t, "Targets[0].BytesOut", t1.BytesOut, 1690)

	t2 := sw.Targets[1]
	if t2.Name != "test2" || t2.Up {
		t.Errorf("Targets[1] = %+v, want test2 down", t2)
	}

	wantEq(t, "Calls.Matched", sw.Calls.Matched, 3)
	wantEq(t, "Calls.Placed", sw.Calls.Placed, 3)
	wantEq(t, "Calls.Connected", sw.Calls.Connected, 3)
	wantEq(t, "Calls.Active", sw.Calls.Active, 0)
}

// TestParseSwitchShowEmpty verifies the shape accel-ppp emits when no
// l2tp-switch target is configured at all: an empty targets list and a
// zeroed calls block, not an error.
func TestParseSwitchShowEmpty(t *testing.T) {
	sw, err := parseSwitchShow("targets:\ncalls:\n  matched: 0\n  placed: 0\n  connected: 0\n  active: 0\n")
	if err != nil {
		t.Fatalf("parseSwitchShow: %v", err)
	}
	if len(sw.Targets) != 0 {
		t.Errorf("Targets = %d, want 0", len(sw.Targets))
	}
	wantEq(t, "Calls.Matched", sw.Calls.Matched, 0)
}

// TestParseSwitchShowIgnoresCallDetailLines verifies an interleaved per-call
// "call: ..." detail line under "targets:" (emitted only when a target has
// an active tunnel) doesn't get misparsed as a target or corrupt
// subsequent parsing.
func TestParseSwitchShowIgnoresCallDetailLines(t *testing.T) {
	in := `targets:
  test1 -> 203.0.113.4:1701 [up] active=1 bytes_in=100 bytes_out=200
  call: user1 tunnel 1-2 / 3-4
calls:
  matched: 1
  placed: 1
  connected: 1
  active: 1
`
	sw, err := parseSwitchShow(in)
	if err != nil {
		t.Fatalf("parseSwitchShow: %v", err)
	}
	if len(sw.Targets) != 1 {
		t.Fatalf("Targets = %d, want 1 (the \"call:\" line must not be parsed as a target): %+v", len(sw.Targets), sw.Targets)
	}
	wantEq(t, "Calls.Active", sw.Calls.Active, 1)
}

// TestParseSwitchShowOnDemandStatusWords verifies the two extra status words
// an on-demand target can report ("connecting", "idle") are parsed rather than
// the whole line being dropped.
func TestParseSwitchShowOnDemandStatusWords(t *testing.T) {
	in := `targets:
  connecting1 -> 203.0.113.5:1701 [connecting] active=0 bytes_in=0 bytes_out=0
  idle1 -> 203.0.113.6:1701 [idle] active=0 bytes_in=42 bytes_out=99
  active1 -> 203.0.113.7:1701 [up] active=2 bytes_in=100 bytes_out=200
calls:
  matched: 3
  placed: 3
  connected: 2
  active: 2
`
	sw, err := parseSwitchShow(in)
	if err != nil {
		t.Fatalf("parseSwitchShow: %v", err)
	}
	if len(sw.Targets) != 3 {
		t.Fatalf("Targets = %d, want 3 (connecting/idle lines must not be dropped): %+v", len(sw.Targets), sw.Targets)
	}

	byName := map[string]SwitchTarget{}
	for _, tg := range sw.Targets {
		byName[tg.Name] = tg
	}

	if tg := byName["connecting1"]; tg.Up {
		t.Errorf("connecting1.Up = true, want false ([connecting] is not [up])")
	}
	if tg := byName["idle1"]; tg.Up {
		t.Errorf("idle1.Up = true, want false ([idle] is not [up])")
	}
	if tg := byName["active1"]; !tg.Up {
		t.Errorf("active1.Up = false, want true ([up])")
	}
}
