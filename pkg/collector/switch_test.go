package collector

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

const sampleStatL2TPSwitch = `l2tp:
  tunnels:
    active: 1
  l2tp-switch:
    active: 1
    lns_rx_bytes: 1690
    lns_tx_bytes: 1639
`

const sampleSwitchShow = `targets:
  test1 -> 203.0.113.4:1701 [up] active=1 bytes_in=1639 bytes_out=1690
calls:
  matched: 3
  placed: 3
  connected: 3
  active: 1
`

// fakeSwitchCollector returns a collector backed by a fake accel-cmd that
// answers "l2tp switch show" with switchShowOutput (or fails when it is empty)
// and everything else with sampleStatL2TPSwitch.
func fakeSwitchCollector(t *testing.T, switchShowOutput string, opts ...Option) *AccelCollector {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell-script fake not supported on windows")
	}
	showBranch := "echo 'command unknown' >&2\nexit 1"
	if switchShowOutput != "" {
		showBranch = "cat <<'EOF'\n" + switchShowOutput + "EOF"
	}
	script := "#!/bin/sh\ncase \"$1 $2 $3\" in\n\"l2tp switch show\")\n" + showBranch + "\n;;\n*)\ncat <<'EOF'\n" + sampleStatL2TPSwitch + "EOF\n;;\nesac\n"
	path := filepath.Join(t.TempDir(), "accel-cmd")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake: %v", err)
	}
	return NewAccelCollector(path, time.Second, opts...)
}

func TestCollectL2TPSwitch(t *testing.T) {
	byName := gatherFamilies(t, fakeSwitchCollector(t, sampleSwitchShow, WithL2TPSwitch()))

	if m := byName["accel_l2tp_switch_active"]; m == nil || m.GetMetric()[0].GetGauge().GetValue() != 1 {
		t.Errorf("accel_l2tp_switch_active missing or wrong: %v", m)
	}
	if m := byName["accel_l2tp_switch_lns_rx_bytes_total"]; m == nil || m.GetMetric()[0].GetCounter().GetValue() != 1690 {
		t.Errorf("accel_l2tp_switch_lns_rx_bytes_total missing or wrong: %v", m)
	}

	target := byName["accel_l2tp_switch_target_up"]
	if target == nil || len(target.GetMetric()) != 1 {
		t.Fatalf("accel_l2tp_switch_target_up missing: %v", target)
	}
	if got := labelsOf(target.GetMetric()[0])["target"]; got != "test1" {
		t.Errorf("target label = %q, want test1", got)
	}
	if got := target.GetMetric()[0].GetGauge().GetValue(); got != 1 {
		t.Errorf("accel_l2tp_switch_target_up = %v, want 1", got)
	}

	if m := byName["accel_l2tp_switch_calls_matched_total"]; m == nil || m.GetMetric()[0].GetCounter().GetValue() != 3 {
		t.Errorf("accel_l2tp_switch_calls_matched_total missing or wrong: %v", m)
	}
}

// TestCollectL2TPSwitchOffByDefault guards that neither the show-stat
// aggregates nor the extra command are used unless the option is set.
func TestCollectL2TPSwitchOffByDefault(t *testing.T) {
	for name := range gatherFamilies(t, fakeSwitchCollector(t, sampleSwitchShow)) {
		if strings.HasPrefix(name, "accel_l2tp_switch_") {
			t.Errorf("%s present without WithL2TPSwitch", name)
		}
	}
}

// TestCollectL2TPSwitchShowUnavailable proves a failing "l2tp switch show"
// (e.g. an accel-ppp build without l2tp-switch) only drops the per-target
// series, without touching accel_up or failing the scrape.
func TestCollectL2TPSwitchShowUnavailable(t *testing.T) {
	byName := gatherFamilies(t, fakeSwitchCollector(t, "", WithL2TPSwitch()))

	if up := byName["accel_up"]; up == nil || up.GetMetric()[0].GetGauge().GetValue() != 1 {
		t.Errorf("accel_up missing or != 1: %v", up)
	}
	if mf := byName["accel_l2tp_switch_target_up"]; mf != nil {
		t.Errorf("accel_l2tp_switch_target_up present despite l2tp switch show failing: %v", mf)
	}
	if byName["accel_l2tp_switch_active"] == nil {
		t.Error("show-stat aggregate accel_l2tp_switch_active should survive a failing l2tp switch show")
	}
}
