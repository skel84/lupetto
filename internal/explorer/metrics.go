package explorer

import (
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"lupetto/internal/explorer/vulnscan"
)

// TrackStates are the status document's track states; lupetto_track_state
// reports 1 for a track's state and 0 for the others.
var TrackStates = []string{"current", "not-built", "update-available", "config-changed", "fixes-available", "error"}

var (
	sideLabels             = []string{"package", "selector", "source"}
	metricVulnerabilities  = prometheus.NewDesc("lupetto_vulnerabilities", "Unique vulnerabilities (aliases merged) in the last successful Grype scan of the image.", append(sideLabels, "severity"), nil)
	metricScanTimestamp    = prometheus.NewDesc("lupetto_vulnerability_scan_timestamp_seconds", "Time of the last successful scan of the image.", sideLabels, nil)
	metricScanSuccess      = prometheus.NewDesc("lupetto_vulnerability_scan_success", "1 if the last scan attempt of the image succeeded, 0 if it failed.", sideLabels, nil)
	metricResultStale      = prometheus.NewDesc("lupetto_vulnerability_result_stale", "1 if the reported result is stale: the last attempt failed, the image changed, or the result is older than twice the scan interval.", sideLabels, nil)
	metricResultDBBuilt    = prometheus.NewDesc("lupetto_vulnerability_result_db_built_timestamp_seconds", "Build time of the vulnerability database the reported result used.", sideLabels, nil)
	metricDBBuilt          = prometheus.NewDesc("lupetto_vulnerability_db_built_timestamp_seconds", "Build time of the newest vulnerability database loaded.", nil, nil)
	metricTrackState       = prometheus.NewDesc("lupetto_track_state", "1 for the track's state in the last successful status check, 0 for the other states.", []string{"package", "selector", "state"}, nil)
	metricStatusTimestamp  = prometheus.NewDesc("lupetto_status_timestamp_seconds", "Time of the last successful status check.", nil, nil)
	metricProductsLoaded   = prometheus.NewDesc("lupetto_products_load_success", "1 if the last read of the products file succeeded, 0 if it failed.", nil, nil)
	metricProductsLoadTime = prometheus.NewDesc("lupetto_products_load_timestamp_seconds", "Time of the last read of the products file, successful or not.", nil, nil)
	vulnerabilityMetricSet = []*prometheus.Desc{metricVulnerabilities, metricScanTimestamp, metricScanSuccess, metricResultStale, metricResultDBBuilt, metricDBBuilt}
)

type metricsCollector struct{ server *Server }

func (c metricsCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- metricTrackState
	ch <- metricStatusTimestamp
	ch <- metricProductsLoaded
	ch <- metricProductsLoadTime
	if c.server.vulns != nil {
		for _, desc := range vulnerabilityMetricSet {
			ch <- desc
		}
	}
}

// Collect reads only cached status and stored scan results; a scrape never
// runs the CLI or a scan.
func (c metricsCollector) Collect(ch chan<- prometheus.Metric) {
	if at, err := c.server.productsLoadState(); !at.IsZero() {
		loaded := 1.0
		if err != "" {
			loaded = 0
		}
		ch <- prometheus.MustNewConstMetric(metricProductsLoaded, prometheus.GaugeValue, loaded)
		ch <- prometheus.MustNewConstMetric(metricProductsLoadTime, prometheus.GaugeValue, seconds(at))
	}
	status := c.server.status.snapshot()
	newest := map[string]string{}
	if document := status.Document; document != nil {
		ch <- prometheus.MustNewConstMetric(metricStatusTimestamp, prometheus.GaugeValue, seconds(document.ComputedAt))
		for _, track := range document.Tracks {
			for _, state := range TrackStates {
				value := 0.0
				if track.State == state {
					value = 1
				}
				ch <- prometheus.MustNewConstMetric(metricTrackState, prometheus.GaugeValue, value, track.Package, track.Selector, state)
			}
			if track.Newest != nil && track.Repository != "" {
				newest[track.Package+"\x00"+track.Selector] = track.Repository + "@" + track.Newest.Digest
			}
		}
	}
	v := c.server.vulns
	if v == nil {
		return
	}
	state := v.store.Snapshot()
	if state.DB != nil {
		ch <- prometheus.MustNewConstMetric(metricDBBuilt, prometheus.GaugeValue, seconds(state.DB.Built))
	}
	now := time.Now()
	for _, track := range state.Tracks {
		for _, source := range []string{vulnscan.SourceLupetto, vulnscan.SourceUpstream} {
			side := track.Side(source)
			if side == nil {
				continue
			}
			labels := []string{track.Package, track.Selector, source}
			reference := side.Reference
			if current, ok := newest[track.Package+"\x00"+track.Selector]; ok && source == vulnscan.SourceLupetto {
				reference = current
			}
			if !side.LastAttempt.IsZero() {
				success := 0.0
				if side.Success {
					success = 1
				}
				ch <- prometheus.MustNewConstMetric(metricScanSuccess, prometheus.GaugeValue, success, labels...)
			}
			result := side.Result
			if result == nil {
				// Never scanned successfully: no counts, never zeros.
				continue
			}
			stale := 0.0
			if side.Stale(reference, now, v.interval) {
				stale = 1
			}
			ch <- prometheus.MustNewConstMetric(metricResultStale, prometheus.GaugeValue, stale, labels...)
			ch <- prometheus.MustNewConstMetric(metricScanTimestamp, prometheus.GaugeValue, seconds(result.ScannedAt), labels...)
			ch <- prometheus.MustNewConstMetric(metricResultDBBuilt, prometheus.GaugeValue, seconds(result.DB.Built), labels...)
			for _, severity := range vulnscan.Severities {
				ch <- prometheus.MustNewConstMetric(metricVulnerabilities, prometheus.GaugeValue, float64(result.Counts.Get(severity)), append(labels, severity)...)
			}
		}
	}
}

func seconds(t time.Time) float64 { return float64(t.UnixNano()) / 1e9 }

func (s *Server) metricsHandler() http.Handler {
	registry := prometheus.NewRegistry()
	registry.MustRegister(metricsCollector{s}, collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	return promhttp.HandlerFor(registry, promhttp.HandlerOpts{ErrorHandling: promhttp.ContinueOnError})
}
