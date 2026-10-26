// admission-eval measures real API-server dry-run admission, including registry
// downloads and pinned cosign. It never creates persisted workload Pods.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"os"
	"os/signal"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/clientcmd"
)

type sample struct {
	Index        int     `json:"index"`
	Milliseconds float64 `json:"milliseconds"`
	Outcome      string  `json:"outcome"`
}

type report struct {
	Schema            int                           `json:"schema"`
	Started           time.Time                     `json:"startedUTC"`
	Go                string                        `json:"goVersion"`
	Context           string                        `json:"context"`
	Namespace         string                        `json:"namespace"`
	Image             string                        `json:"image"`
	Expected          string                        `json:"expected"`
	Concurrency       int                           `json:"concurrency"`
	Warmup            int                           `json:"warmup"`
	Seconds           float64                       `json:"seconds"`
	RequestsPerSecond float64                       `json:"completedRequestsPerSecond"`
	AllowedPerSecond  float64                       `json:"allowedRequestsPerSecond"`
	P50               float64                       `json:"p50Milliseconds"`
	P95               float64                       `json:"p95Milliseconds"`
	P99               float64                       `json:"p99Milliseconds"`
	Counts            map[string]int                `json:"outcomes"`
	LatencyByOutcome  map[string]map[string]float64 `json:"latencyMillisecondsByOutcome"`
	Samples           []sample                      `json:"samples"`
	Passed            bool                          `json:"passed"`
}

func outcome(err error) string {
	if err == nil {
		return "allowed"
	}
	s := err.Error()
	if strings.Contains(s, `admission webhook "validate-pods.modelgate.dev" denied the request`) {
		if strings.Contains(s, "admission capacity exhausted") {
			return "saturated"
		}
		return "policy_denied"
	}
	if strings.Contains(s, "failed calling webhook") {
		return "webhook_unavailable"
	}
	return "request_error"
}

func percentile(values []float64, p float64) float64 {
	if len(values) == 0 {
		return 0
	}
	return values[int(math.Ceil(p*float64(len(values))))-1]
}

func matches(expected, actual string) bool {
	if expected == "overload" {
		return actual == "allowed" || actual == "saturated"
	}
	if expected == "saturation" {
		return actual == "policy_denied" || actual == "saturated"
	}
	return expected == actual
}

func measure(ctx context.Context, client *kubernetes.Clientset, namespace, image string, index int) sample {
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("admission-eval-%d", index), Namespace: namespace}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "eval", Image: image}}}}
	started := time.Now()
	err := client.CoreV1().RESTClient().Post().Namespace(namespace).Resource("pods").
		VersionedParams(&metav1.CreateOptions{DryRun: []string{metav1.DryRunAll}}, scheme.ParameterCodec).
		Body(pod).MaxRetries(0).Do(ctx).Error()
	return sample{Index: index, Milliseconds: float64(time.Since(started).Microseconds()) / 1000, Outcome: outcome(err)}
}

func run() error {
	kubeconfig := flag.String("kubeconfig", "", "kubeconfig file; defaults to standard client loading")
	contextName := flag.String("context", "", "required explicit disposable-cluster context")
	namespace := flag.String("namespace", "modelgate-eval", "preconfigured evaluation namespace")
	image := flag.String("image", "", "exact signed/unsigned registry/repository@sha256 reference")
	expected := flag.String("expect", "allowed", "allowed, policy_denied, webhook_unavailable, overload or saturation")
	requests := flag.Int("requests", 100, "measured requests (1..10000)")
	workers := flag.Int("concurrency", 1, "closed-loop workers (1..64)")
	warmup := flag.Int("warmup", 5, "sequential warmup requests, checked but not timed in summary")
	output := flag.String("output", "", "required new JSON output path; never overwrites existing evidence")
	flag.Parse()
	if *contextName == "" || *output == "" || !strings.Contains(*image, "@sha256:") || *requests < 1 || *requests > 10000 || *workers < 1 || *workers > 64 || *warmup < 0 || *warmup > 100 {
		return fmt.Errorf("explicit context, immutable image, new output path and bounded request settings required")
	}
	if *expected != "allowed" && *expected != "policy_denied" && *expected != "webhook_unavailable" && *expected != "overload" && *expected != "saturation" {
		return fmt.Errorf("invalid expected outcome")
	}
	f, err := os.OpenFile(*output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	rules.ExplicitPath = *kubeconfig
	cfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, &clientcmd.ConfigOverrides{CurrentContext: *contextName}).ClientConfig()
	if err != nil {
		return err
	}
	// Keep client-side throttling out of the measurement. There are at most 64
	// in-flight requests; no retries or request queue is added by this harness.
	cfg.QPS = 10000
	cfg.Burst = 10000
	cfg.Timeout = 20 * time.Second
	cfg.UserAgent = "modelgate-admission-eval"
	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	request := func(index int) sample {
		return measure(ctx, client, *namespace, *image, index)
	}
	for i := 0; i < *warmup; i++ {
		s := request(-i - 1)
		if !matches(*expected, s.Outcome) {
			return fmt.Errorf("warmup outcome %s does not match %s", s.Outcome, *expected)
		}
	}
	r := report{Schema: 1, Started: time.Now().UTC(), Go: runtime.Version(), Context: *contextName, Namespace: *namespace, Image: *image, Expected: *expected, Concurrency: *workers, Warmup: *warmup, Counts: map[string]int{}, Samples: make([]sample, *requests), Passed: true}
	jobs := make(chan int)
	var wg sync.WaitGroup
	started := time.Now()
	for i := 0; i < *workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for index := range jobs {
				r.Samples[index] = request(index)
			}
		}()
	}
	for i := 0; i < *requests; i++ {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	r.Seconds = time.Since(started).Seconds()
	values := make([]float64, 0, *requests)
	groups := map[string][]float64{}
	for _, s := range r.Samples {
		r.Counts[s.Outcome]++
		values = append(values, s.Milliseconds)
		groups[s.Outcome] = append(groups[s.Outcome], s.Milliseconds)
		if !matches(*expected, s.Outcome) {
			r.Passed = false
		}
	}
	if *expected == "saturation" && r.Counts["saturated"] == 0 {
		r.Passed = false
	}
	sort.Float64s(values)
	r.P50 = percentile(values, .5)
	r.P95 = percentile(values, .95)
	r.P99 = percentile(values, .99)
	r.LatencyByOutcome = map[string]map[string]float64{}
	for name, group := range groups {
		sort.Float64s(group)
		r.LatencyByOutcome[name] = map[string]float64{"p50": percentile(group, .5), "p95": percentile(group, .95), "p99": percentile(group, .99)}
	}
	r.RequestsPerSecond = float64(*requests) / r.Seconds
	r.AllowedPerSecond = float64(r.Counts["allowed"]) / r.Seconds
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err = enc.Encode(r); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	fmt.Printf("%s: outcomes=%v p50=%.2fms p95=%.2fms p99=%.2fms completed=%.2f/s allowed=%.2f/s\n", *output, r.Counts, r.P50, r.P95, r.P99, r.RequestsPerSecond, r.AllowedPerSecond)
	if !r.Passed {
		return fmt.Errorf("observed unexpected outcomes; raw samples retained")
	}
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
