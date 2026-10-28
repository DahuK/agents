/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package openshellpolicy

import (
	"reflect"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	agentsv1alpha1 "github.com/openkruise/agents/api/v1alpha1"
)

// previewMapOptions returns the strict production options with the
// enforce-ready gate disabled: loss reporting and L4 shape are still
// exercised, but a lossy document is allowed to produce a preview artifact.
func previewMapOptions(namespace, name string, selector metav1.LabelSelector) MapOptions {
	opts := DefaultMapOptions(namespace, name, selector)
	opts.RequireEnforceable = false
	return opts
}

func TestMapToTrafficPolicy(t *testing.T) {
	policy := loadDemoPolicy(t)
	opts := previewMapOptions("sandbox-ns", "", metav1.LabelSelector{
		MatchLabels: map[string]string{"app": "sandbox"},
	})

	result, err := MapToTrafficPolicy(policy, opts)
	if err != nil {
		t.Fatalf("MapToTrafficPolicy: %v", err)
	}
	tp := result.Policy
	if tp.Namespace != "sandbox-ns" || tp.Name != "openshell-egress" {
		t.Errorf("metadata = %s/%s, want sandbox-ns/openshell-egress", tp.Namespace, tp.Name)
	}
	if tp.Spec.Selector.MatchLabels["app"] != "sandbox" {
		t.Errorf("selector = %+v, want app=sandbox", tp.Spec.Selector)
	}
	if tp.Spec.Egress == nil {
		t.Fatalf("egress direction missing")
	}

	// One allow rule per endpoint, in sorted policy-key order, plus the
	// reject-all tail preserving OpenShell's default-deny posture.
	wantFQDNs := []string{
		"api.openai.com",
		"api.github.com",
		"raw.githubusercontent.com",
		"metrics.internal",
		"registry.internal",
	}
	rules := tp.Spec.Egress.Rules
	if len(rules) != len(wantFQDNs)+1 {
		t.Fatalf("egress rules = %d, want %d", len(rules), len(wantFQDNs)+1)
	}
	for i, fqdn := range wantFQDNs {
		rule := rules[i]
		if rule.Action != agentsv1alpha1.RuleActionAllow {
			t.Errorf("rule %d action = %q, want allow", i, rule.Action)
		}
		if len(rule.To) != 1 || rule.To[0].FQDN != fqdn {
			t.Errorf("rule %d To = %+v, want FQDN %q", i, rule.To, fqdn)
		}
		if len(rule.Ports) != 1 || rule.Ports[0].Protocol != "TCP" || rule.Ports[0].Port == nil {
			t.Fatalf("rule %d Ports = %+v, want one TCP port", i, rule.Ports)
		}
	}
	if *rules[4].Ports[0].Port != 5000 {
		t.Errorf("registry port = %d, want 5000", *rules[4].Ports[0].Port)
	}
	tail := rules[len(rules)-1]
	if tail.Action != agentsv1alpha1.RuleActionReject || len(tail.To) != 0 || len(tail.Ports) != 0 {
		t.Errorf("tail rule = %+v, want reject-all", tail)
	}
}

func TestMapToTrafficPolicyLosses(t *testing.T) {
	policy := loadDemoPolicy(t)
	result, err := MapToTrafficPolicy(policy, previewMapOptions("ns", "egress", metav1.LabelSelector{}))
	if err != nil {
		t.Fatalf("MapToTrafficPolicy: %v", err)
	}

	wantFields := []string{
		"filesystem_policy",
		"landlock",
		"network_policies.codex.binaries",
		"network_policies.github_api_readonly.binaries",
		`network_policies.github_api_readonly.endpoints[api.github.com:443]`,
		`network_policies.github_raw_scoped.endpoints[raw.githubusercontent.com:443]`,
		`network_policies.metrics_sink.endpoints[metrics.internal:443].enforcement`,
		`network_policies.registry_mirror.endpoints[registry.internal:5000].protocol`,
	}
	if len(result.Losses) != len(wantFields) {
		t.Fatalf("losses = %d items (%+v), want %d", len(result.Losses), result.Losses, len(wantFields))
	}
	for _, field := range wantFields {
		found := false
		for _, loss := range result.Losses {
			if loss.Field == field && strings.TrimSpace(loss.Reason) != "" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected loss item with field %q and a non-empty reason", field)
		}
	}
}

func TestMapToTrafficPolicyRequiresEnforceable(t *testing.T) {
	policy := loadDemoPolicy(t)
	// The production default refuses to emit a projection that drops
	// filesystem, binary, audit, or non-REST semantics.
	_, err := MapToTrafficPolicy(policy, DefaultMapOptions("ns", "strict", metav1.LabelSelector{}))
	if err == nil {
		t.Fatal("MapToTrafficPolicy with strict defaults succeeded on a lossy policy")
	}
	if !strings.Contains(err.Error(), "not enforce-ready") {
		t.Errorf("error = %q, want a not-enforce-ready message", err)
	}

	// A policy inside the restricted contract maps without losses.
	doc := `version: 1
network_policies:
  api:
    endpoints:
      - { host: api.example.com, port: 443, protocol: rest, enforcement: enforce, access: full }
`
	restricted, parseErr := ParsePolicy([]byte(doc))
	if parseErr != nil {
		t.Fatalf("ParsePolicy: %v", parseErr)
	}
	result, err := MapToTrafficPolicy(restricted, DefaultMapOptions("ns", "strict", metav1.LabelSelector{}))
	if err != nil {
		t.Fatalf("MapToTrafficPolicy: %v", err)
	}
	if len(result.Losses) != 0 || len(result.Blockers) != 0 {
		t.Errorf("losses/blockers = %v/%v, want none for the restricted contract", result.Losses, result.Blockers)
	}
	if got := len(result.Policy.Spec.Egress.Rules); got != 2 {
		t.Errorf("rules = %d, want allow + default-deny tail", got)
	}
}

func TestMapToTrafficPolicyDeduplicatesEndpoints(t *testing.T) {
	// ParsePolicy rejects overlapping host:port pairs because the restrict
	// contract requires uniqueness. The projection still deduplicates
	// programmatically constructed policies so a caller cannot emit duplicate
	// L4 rules by bypassing the parser.
	policy := &Policy{NetworkPolicies: map[string]NetworkPolicy{
		"first": {
			Endpoints: []Endpoint{{Host: "api.example.com", Port: 443, Protocol: ProtocolREST, Enforcement: EnforcementEnforce, Access: AccessFull}},
		},
		"second": {
			Endpoints: []Endpoint{{Host: "api.example.com", Port: 443, Protocol: ProtocolREST, Enforcement: EnforcementEnforce, Access: AccessReadOnly}},
		},
	}}
	result, err := MapToTrafficPolicy(policy, previewMapOptions("ns", "dedup", metav1.LabelSelector{}))
	if err != nil {
		t.Fatalf("MapToTrafficPolicy: %v", err)
	}
	// One allow rule for the shared endpoint plus the reject tail; the second
	// occurrence still records its L7 loss.
	if got := len(result.Policy.Spec.Egress.Rules); got != 2 {
		t.Errorf("egress rules = %d, want 2 (allow + tail): %+v", got, result.Policy.Spec.Egress.Rules)
	}
	if got := len(result.Losses); got != 1 {
		t.Errorf("losses = %d, want 1 (read-only L7 loss): %+v", got, result.Losses)
	}
}

func TestMapToTrafficPolicyWithoutTail(t *testing.T) {
	policy, err := ParsePolicy([]byte("version: 1\nnetwork_policies:\n  codex:\n    name: codex\n    endpoints:\n      - { host: api.example.com, port: 443, protocol: rest, enforcement: enforce, access: full }\n"))
	if err != nil {
		t.Fatalf("ParsePolicy: %v", err)
	}
	result, err := MapToTrafficPolicy(policy, MapOptions{Namespace: "ns", Name: "no-tail"})
	if err != nil {
		t.Fatalf("MapToTrafficPolicy: %v", err)
	}
	rules := result.Policy.Spec.Egress.Rules
	if len(rules) != 1 || rules[0].Action != agentsv1alpha1.RuleActionAllow {
		t.Errorf("egress rules = %+v, want exactly one allow rule without the reject tail", rules)
	}
}

func TestMapToTrafficPolicyEmptyNetworkPoliciesWithTail(t *testing.T) {
	policy, err := ParsePolicy([]byte("version: 1\n"))
	if err != nil {
		t.Fatalf("ParsePolicy: %v", err)
	}
	result, err := MapToTrafficPolicy(policy, DefaultMapOptions("ns", "deny-all", metav1.LabelSelector{}))
	if err != nil {
		t.Fatalf("MapToTrafficPolicy: %v", err)
	}
	rules := result.Policy.Spec.Egress.Rules
	if len(rules) != 1 || rules[0].Action != agentsv1alpha1.RuleActionReject {
		t.Errorf("egress rules = %+v, want only the default-deny tail", rules)
	}
}

func TestMapToTrafficPolicyErrors(t *testing.T) {
	tests := []struct {
		name   string
		policy *Policy
		opts   MapOptions
		want   string
	}{
		{
			name:   "nil policy",
			policy: nil,
			opts:   MapOptions{Namespace: "ns"},
			want:   "policy is nil",
		},
		{
			name:   "missing namespace",
			policy: &Policy{Version: 1, NetworkPolicies: map[string]NetworkPolicy{"a": {}}},
			opts:   MapOptions{},
			want:   "namespace is required",
		},
		{
			name:   "empty network policies without the deny tail",
			policy: &Policy{Version: 1},
			opts:   MapOptions{Namespace: "ns"},
			want:   "empty network_policies requires the default-deny tail",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := MapToTrafficPolicy(tt.policy, tt.opts)
			if err == nil {
				t.Fatalf("MapToTrafficPolicy succeeded, want error containing %q", tt.want)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("MapToTrafficPolicy error = %q, want containing %q", err, tt.want)
			}
		})
	}
}

func TestMapToTrafficPolicyDeterministic(t *testing.T) {
	policy := loadDemoPolicy(t)
	first, err := MapToTrafficPolicy(policy, previewMapOptions("ns", "determinism", metav1.LabelSelector{}))
	if err != nil {
		t.Fatalf("MapToTrafficPolicy: %v", err)
	}
	second, err := MapToTrafficPolicy(policy, previewMapOptions("ns", "determinism", metav1.LabelSelector{}))
	if err != nil {
		t.Fatalf("MapToTrafficPolicy: %v", err)
	}
	if !reflect.DeepEqual(first.Policy.Spec.Egress, second.Policy.Spec.Egress) {
		t.Errorf("two mappings of the same policy differ:\n%+v\n%+v", first.Policy.Spec.Egress, second.Policy.Spec.Egress)
	}
	if !reflect.DeepEqual(first.Losses, second.Losses) {
		t.Errorf("two mappings of the same policy produced different losses:\n%+v\n%+v", first.Losses, second.Losses)
	}
}
