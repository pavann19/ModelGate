package policy

import (
	"context"
	"fmt"
	"log/slog"

	"sigs.k8s.io/controller-runtime/pkg/client"

	modelgatev1alpha1 "github.com/pavann19/modelgate/api/v1alpha1"
)

// ErrNoPolicy is returned when a namespace has no ModelGatePolicy at all.
// The MVP's static config allowed everything by default; the CRD-backed
// resolver deliberately fails closed instead -- a namespace with no policy
// object is denied, not silently permitted, since a missing policy is far
// more likely to be an operator oversight than an intentional "allow all".
var ErrNoPolicy = fmt.Errorf("policy: no ModelGatePolicy found for namespace")

// Resolution is the outcome of resolving a namespace's policy: either an
// explicit exemption (all checks skipped) or a Config to enforce.
type Resolution struct {
	// Exempt is true if the namespace's policy explicitly disables checks.
	Exempt bool
	// ExemptionReason documents why, for the audit log line the caller emits.
	ExemptionReason string
	// Config is nil when Exempt is true.
	Config *Config
}

// Resolver looks up the ModelGatePolicy for a namespace and converts it
// into the Config shape the admission handler enforces.
type Resolver struct {
	// Reader is used instead of a cached client so a policy created
	// moments ago (e.g. immediately before a pod in the same namespace)
	// is never missed due to informer cache lag -- correctness over the
	// small extra API server load this adds per admission request.
	Reader client.Reader
	Logger *slog.Logger
}

// NewResolver builds a Resolver with a non-nil default logger.
func NewResolver(reader client.Reader) *Resolver {
	return &Resolver{Reader: reader, Logger: slog.Default()}
}

// Resolve fetches the ModelGatePolicy for namespace. If more than one
// exists (not expected, but not prevented by the CRD's Namespaced scope
// alone), it picks the oldest by creation timestamp and logs a warning
// rather than picking arbitrarily and silently.
func (r *Resolver) Resolve(ctx context.Context, namespace string) (Resolution, error) {
	var list modelgatev1alpha1.ModelGatePolicyList
	if err := r.Reader.List(ctx, &list, client.InNamespace(namespace)); err != nil {
		return Resolution{}, fmt.Errorf("listing ModelGatePolicy in namespace %q: %w", namespace, err)
	}
	if len(list.Items) == 0 {
		return Resolution{}, fmt.Errorf("%w: namespace %q", ErrNoPolicy, namespace)
	}

	chosen := list.Items[0]
	if len(list.Items) > 1 {
		for _, p := range list.Items[1:] {
			if p.CreationTimestamp.Before(&chosen.CreationTimestamp) {
				chosen = p
			}
		}
		r.logger().Warn("multiple ModelGatePolicy objects found in namespace, using the oldest",
			"namespace", namespace, "count", len(list.Items), "chosen", chosen.Name)
	}

	if chosen.Spec.Exempt {
		r.logger().Warn("namespace is exempt from ModelGate checks",
			"namespace", namespace, "policy", chosen.Name, "reason", chosen.Spec.ExemptionReason)
		return Resolution{Exempt: true, ExemptionReason: chosen.Spec.ExemptionReason}, nil
	}

	allowList := make(map[string]string, len(chosen.Spec.ArtifactAllowList))
	for _, e := range chosen.Spec.ArtifactAllowList {
		allowList[e.ID] = e.SHA256
	}
	return Resolution{Config: &Config{
		CosignPublicKeyPEM: chosen.Spec.CosignPublicKeyPEM,
		ArtifactAllowList:  allowList,
	}}, nil
}

func (r *Resolver) logger() *slog.Logger {
	if r.Logger != nil {
		return r.Logger
	}
	return slog.Default()
}
