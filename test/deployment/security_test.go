package deployment

import (
	appsv1 "k8s.io/api/apps/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"os"
	"sigs.k8s.io/yaml"
	"strings"
	"testing"
)

func TestRawDeploymentSecurityBoundary(t *testing.T) {
	data, err := os.ReadFile("../../deploy/manifests/deployment.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var d appsv1.Deployment
	if err := yaml.Unmarshal([]byte(strings.Split(string(data), "---")[0]), &d); err != nil {
		t.Fatal(err)
	}
	p := d.Spec.Template.Spec
	if d.Spec.Replicas == nil || *d.Spec.Replicas < 2 || d.Spec.Strategy.RollingUpdate == nil || d.Spec.Strategy.RollingUpdate.MaxUnavailable.IntVal != 0 {
		t.Fatal("rollout must preserve available replicas")
	}
	if p.TerminationGracePeriodSeconds == nil || *p.TerminationGracePeriodSeconds < 40 || len(p.TopologySpreadConstraints) == 0 {
		t.Fatal("missing drain budget or node spread")
	}
	foundPolicy := false
	for _, v := range p.Volumes {
		if v.Name == "registry-policy" && v.Secret != nil && v.Secret.SecretName == "modelgate-registry-policy" {
			foundPolicy = true
		}
	}
	if !foundPolicy {
		t.Fatal("operator-owned registry policy mount missing")
	}
	for _, c := range p.Containers {
		if c.Lifecycle == nil || c.Lifecycle.PreStop == nil || c.Lifecycle.PreStop.Exec == nil || strings.Join(c.Lifecycle.PreStop.Exec.Command, " ") != "/webhook --prestop-delay=10s" {
			t.Fatal("missing bounded endpoint-withdrawal grace")
		}
		if c.StartupProbe == nil || c.ReadinessProbe == nil || c.LivenessProbe == nil || c.ReadinessProbe.HTTPGet == nil || c.ReadinessProbe.HTTPGet.Path != "/readyz" || c.LivenessProbe.HTTPGet == nil || c.LivenessProbe.HTTPGet.Path != "/healthz" {
			t.Fatal("startup, serving-readiness and process-liveness must be distinct")
		}
		if !strings.Contains(strings.Join(c.Args, " "), "--registry-policy-file=/etc/modelgate/registry-policy.json") {
			t.Fatal("destination policy not wired into production command")
		}
	}
	if p.SecurityContext == nil || p.SecurityContext.RunAsNonRoot == nil || !*p.SecurityContext.RunAsNonRoot || p.SecurityContext.SeccompProfile == nil {
		t.Fatal("missing pod hardening")
	}
	for _, c := range p.Containers {
		s := c.SecurityContext
		if s == nil || s.AllowPrivilegeEscalation == nil || *s.AllowPrivilegeEscalation || s.ReadOnlyRootFilesystem == nil || !*s.ReadOnlyRootFilesystem || s.Capabilities == nil || len(s.Capabilities.Drop) != 1 || s.Capabilities.Drop[0] != "ALL" {
			t.Fatal("container privilege boundary weakened")
		}
		if len(c.Resources.Limits) == 0 || len(c.Resources.Requests) == 0 {
			t.Fatal("missing resource bounds")
		}
	}
}
func TestRawRBACOnlyListsPolicies(t *testing.T) {
	data, err := os.ReadFile("../../deploy/manifests/rbac.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, doc := range strings.Split(string(data), "---") {
		var r rbacv1.ClusterRole
		if err := yaml.Unmarshal([]byte(doc), &r); err != nil {
			t.Fatal(err)
		}
		if r.Kind != "ClusterRole" {
			continue
		}
		found = true
		if len(r.Rules) != 1 {
			t.Fatal("unexpected RBAC scope")
		}
		x := r.Rules[0]
		if len(x.Verbs) != 1 || x.Verbs[0] != "list" || len(x.Resources) != 1 || x.Resources[0] != "modelgatepolicies" || len(x.APIGroups) != 1 || x.APIGroups[0] != "modelgate.dev" {
			t.Fatal("policy reader permissions expanded")
		}
	}
	if !found {
		t.Fatal("ClusterRole missing")
	}
}
