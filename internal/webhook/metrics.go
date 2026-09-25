package webhook

import (
	"github.com/prometheus/client_golang/prometheus"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
)

var (
	admissionDecisions = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "modelgate_admission_decisions_total",
			Help: "Admission decisions made by ModelGate, partitioned by bounded outcome and reason values.",
		},
		[]string{"outcome", "reason"},
	)
	admissionDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "modelgate_admission_duration_seconds",
			Help:    "End-to-end ModelGate admission-handler latency.",
			Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 15},
		},
		[]string{"outcome"},
	)
)

func init() {
	ctrlmetrics.Registry.MustRegister(admissionDecisions, admissionDuration)
}
