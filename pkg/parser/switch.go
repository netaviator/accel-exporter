package parser

import (
	"bufio"
	"regexp"
	"strings"
	"time"
)

// L2TPSwitchStats is the aggregate l2tp-switch block of "show stat". It is only
// emitted by accel-ppp builds that have the l2tp-switch feature.
type L2TPSwitchStats struct {
	Active     float64
	LNSRxBytes float64
	LNSTxBytes float64
}

func parseL2TPSwitchSection(s *L2TPSwitchStats, key, value string) {
	f := atof(value)
	switch key {
	case "active":
		s.Active = f
	case "lns_rx_bytes":
		s.LNSRxBytes = f
	case "lns_tx_bytes":
		s.LNSTxBytes = f
	}
}

// SwitchStats is the per-target detail from "accel-cmd l2tp switch show". It is
// a separate command from "show stat" with its own text shape (arrow-separated
// target lines, occasional per-call detail lines, then a flat "calls:" block),
// so it has its own parser.
type SwitchStats struct {
	Targets []SwitchTarget
	Calls   SwitchCalls
}

// SwitchTarget is one configured l2tp-switch target and its live tunnel state.
type SwitchTarget struct {
	Name     string
	PeerAddr string
	PeerPort string
	// Up is true only for the "up" status word, i.e. the target is carrying
	// traffic. "down", "connecting" and "idle" are all false. On-demand targets
	// print "idle" both while an established tunnel lingers after its last call
	// and once it is fully closed, so the raw tunnel-established bit cannot be
	// recovered from this output during that window.
	Up       bool
	Active   float64
	BytesIn  float64
	BytesOut float64
}

// SwitchCalls are the aggregate call lifecycle counters across all targets:
// matched a rule, placed to a target, connected on the downstream leg, and
// currently active. matched >= placed >= connected always holds; a gap between
// them means calls are failing to place or connect, not that the switch is idle.
type SwitchCalls struct {
	Matched   float64
	Placed    float64
	Connected float64
	Active    float64
}

// targetLinePattern matches one "targets:" line, e.g.
// "test1 -> 203.0.113.5:1701 [up] active=0 bytes_in=1639 bytes_out=1690".
// The status word is up/down for persistent targets and up/connecting/idle for
// on-demand ones.
var targetLinePattern = regexp.MustCompile(
	`^(\S+) -> ([\d.]+):(\d+) \[(up|down|connecting|idle)\] active=(\d+) bytes_in=(\d+) bytes_out=(\d+)$`,
)

// CollectSwitchShow executes "accel-cmd l2tp switch show" and parses its
// output. With no target configured the output is an empty "targets:" list and
// a zeroed "calls:" block, not an error. An accel-ppp build without the
// l2tp-switch feature exits non-zero, which is returned as an error.
func CollectSwitchShow(accelCmdPath string, timeout time.Duration) (*SwitchStats, error) {
	out, err := runAccelCmd(accelCmdPath, timeout, "l2tp", "switch", "show")
	if err != nil {
		return nil, err
	}
	return parseSwitchShow(out)
}

// parseSwitchShow parses "accel-cmd l2tp switch show" output.
func parseSwitchShow(output string) (*SwitchStats, error) {
	stats := &SwitchStats{}

	scanner := bufio.NewScanner(strings.NewReader(output))
	var section string

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		if line == "targets:" || line == "calls:" {
			section = strings.TrimSuffix(line, ":")
			continue
		}

		switch section {
		case "targets":
			// Other lines under "targets:" (the per-call "call: ..." detail
			// lines) are not part of the metric surface.
			if m := targetLinePattern.FindStringSubmatch(line); m != nil {
				stats.Targets = append(stats.Targets, SwitchTarget{
					Name:     m[1],
					PeerAddr: m[2],
					PeerPort: m[3],
					Up:       m[4] == "up",
					Active:   atof(m[5]),
					BytesIn:  atof(m[6]),
					BytesOut: atof(m[7]),
				})
			}
		case "calls":
			parseSwitchCall(&stats.Calls, line)
		}
	}

	return stats, scanner.Err()
}

func parseSwitchCall(calls *SwitchCalls, line string) {
	key, value, found := strings.Cut(line, ":")
	if !found {
		return
	}
	f := atof(strings.TrimSpace(value))
	switch strings.TrimSpace(key) {
	case "matched":
		calls.Matched = f
	case "placed":
		calls.Placed = f
	case "connected":
		calls.Connected = f
	case "active":
		calls.Active = f
	}
}
