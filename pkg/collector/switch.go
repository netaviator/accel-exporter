package collector

import (
	"log"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/taihen/accel-exporter/pkg/parser"
)

// WithL2TPSwitch enables the optional l2tp-switch metrics. Off by default: the
// feature only exists in accel-ppp builds that ship l2tp-switch, and enabling
// it runs an extra "accel-cmd l2tp switch show" on every scrape.
func WithL2TPSwitch() Option {
	return func(c *AccelCollector) { c.l2tpSwitch = true }
}

// switchTargetLabels are the labels on every per-target metric. Cardinality is
// bounded by the number of configured targets, not by the number of subscribers.
var switchTargetLabels = []string{"target"}

var (
	switchActiveDesc     = newDesc("accel_l2tp_switch_active", "Number of currently active l2tp-switch relayed calls, across all targets.")
	switchLNSRxBytesDesc = newDesc("accel_l2tp_switch_lns_rx_bytes_total", "Total bytes received from l2tp-switch downstream targets.")
	switchLNSTxBytesDesc = newDesc("accel_l2tp_switch_lns_tx_bytes_total", "Total bytes sent to l2tp-switch downstream targets.")

	switchTargetUpDesc       = newDesc("accel_l2tp_switch_target_up", "Whether the l2tp-switch target is carrying traffic (1) or not (0). For an on-demand target this tracks active>0 rather than the raw tunnel state, because accel-cmd reports an idle-lingering tunnel and a closed one identically.", switchTargetLabels...)
	switchTargetActiveDesc   = newDesc("accel_l2tp_switch_target_active", "Number of currently active relayed calls on this l2tp-switch target.", switchTargetLabels...)
	switchTargetBytesInDesc  = newDesc("accel_l2tp_switch_target_bytes_in_total", "Total bytes received from this l2tp-switch target.", switchTargetLabels...)
	switchTargetBytesOutDesc = newDesc("accel_l2tp_switch_target_bytes_out_total", "Total bytes sent to this l2tp-switch target.", switchTargetLabels...)

	// Call counters are aggregate: "l2tp switch show" does not break
	// matched/placed/connected down per target.
	switchCallsMatchedDesc   = newDesc("accel_l2tp_switch_calls_matched_total", "Total incoming L2TP calls matched by an l2tp-switch rule.")
	switchCallsPlacedDesc    = newDesc("accel_l2tp_switch_calls_placed_total", "Total matched calls placed to a downstream target.")
	switchCallsConnectedDesc = newDesc("accel_l2tp_switch_calls_connected_total", "Total placed calls that connected on the downstream leg.")
	switchCallsActiveDesc    = newDesc("accel_l2tp_switch_calls_active", "Number of currently active l2tp-switch relayed calls (same value as accel_l2tp_switch_active, read from 'l2tp switch show' instead of 'show stat').")
)

var switchDescs = []*prometheus.Desc{
	switchActiveDesc, switchLNSRxBytesDesc, switchLNSTxBytesDesc,
	switchTargetUpDesc, switchTargetActiveDesc, switchTargetBytesInDesc, switchTargetBytesOutDesc,
	switchCallsMatchedDesc, switchCallsPlacedDesc, switchCallsConnectedDesc, switchCallsActiveDesc,
}

// collectL2TPSwitch emits the aggregate counters already parsed from "show
// stat", then the per-target and call detail from "l2tp switch show". A failure
// of the latter is logged and only drops those series for the scrape; it never
// affects accel_up or the rest of Collect.
func (c *AccelCollector) collectL2TPSwitch(ch chan<- prometheus.Metric, agg parser.L2TPSwitchStats) {
	ch <- prometheus.MustNewConstMetric(switchActiveDesc, prometheus.GaugeValue, agg.Active)
	ch <- prometheus.MustNewConstMetric(switchLNSRxBytesDesc, prometheus.CounterValue, agg.LNSRxBytes)
	ch <- prometheus.MustNewConstMetric(switchLNSTxBytesDesc, prometheus.CounterValue, agg.LNSTxBytes)

	sw, err := parser.CollectSwitchShow(c.accelCmdPath, c.timeout)
	if err != nil {
		log.Printf("l2tp switch show unavailable, per-target metrics dropped for this scrape: %v", err)
		return
	}

	for _, t := range sw.Targets {
		up := 0.0
		if t.Up {
			up = 1.0
		}
		ch <- prometheus.MustNewConstMetric(switchTargetUpDesc, prometheus.GaugeValue, up, t.Name)
		ch <- prometheus.MustNewConstMetric(switchTargetActiveDesc, prometheus.GaugeValue, t.Active, t.Name)
		ch <- prometheus.MustNewConstMetric(switchTargetBytesInDesc, prometheus.CounterValue, t.BytesIn, t.Name)
		ch <- prometheus.MustNewConstMetric(switchTargetBytesOutDesc, prometheus.CounterValue, t.BytesOut, t.Name)
	}

	ch <- prometheus.MustNewConstMetric(switchCallsMatchedDesc, prometheus.CounterValue, sw.Calls.Matched)
	ch <- prometheus.MustNewConstMetric(switchCallsPlacedDesc, prometheus.CounterValue, sw.Calls.Placed)
	ch <- prometheus.MustNewConstMetric(switchCallsConnectedDesc, prometheus.CounterValue, sw.Calls.Connected)
	ch <- prometheus.MustNewConstMetric(switchCallsActiveDesc, prometheus.GaugeValue, sw.Calls.Active)
}
