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
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	agentsv1alpha1 "github.com/openkruise/agents/api/v1alpha1"
)

func loadDemoDocument(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile("testdata/demo-policy.yaml")
	if err != nil {
		t.Fatalf("read testdata/demo-policy.yaml: %v", err)
	}
	return data
}

// previewProfileOptions disables the enforce-ready gate for loss accounting
// and document-fidelity tests.
func previewProfileOptions(namespace, name string, selector metav1.LabelSelector) ProfileMapOptions {
	opts := DefaultProfileMapOptions(namespace, name, selector)
	opts.RequireEnforceable = false
	return opts
}

func TestMapToSecurityProfile(t *testing.T) {
	result, err := MapToSecurityProfile(loadDemoDocument(t), previewProfileOptions("sandbox-ns", "", metav1.LabelSelector{
		MatchLabels: map[string]string{"app": "sandbox"},
	}))
	if err != nil {
		t.Fatalf("MapToSecurityProfile: %v", err)
	}
	profile := result.Profile
	if profile.Namespace != "sandbox-ns" || profile.Name != "openshell-l7" {
		t.Errorf("metadata = %s/%s, want sandbox-ns/openshell-l7", profile.Namespace, profile.Name)
	}
	if profile.Spec.Selector.MatchLabels["app"] != "sandbox" {
		t.Errorf("selector = %+v, want app=sandbox", profile.Spec.Selector)
	}
	if profile.Spec.Priority != nil {
		t.Errorf("priority = %d, want nil (CRD default applies) when unset", *profile.Spec.Priority)
	}

	if len(profile.Spec.Rules) != 1 {
		t.Fatalf("rules = %d, want exactly one", len(profile.Spec.Rules))
	}
	rule := profile.Spec.Rules[0]
	if rule.Name != "openshell" {
		t.Errorf("rule name = %q, want openshell", rule.Name)
	}
	// The document carries its own endpoint list, so the rule matches every
	// request and the data plane performs endpoint selection itself.
	if len(rule.Match) != 1 || !reflect.DeepEqual(rule.Match[0].Domains, []string{"*"}) {
		t.Errorf("match = %+v, want one catch-all domains entry", rule.Match)
	}
	action := rule.Actions.OpenShellPolicy
	if action == nil {
		t.Fatalf("actions.openShellPolicy missing")
	}
	if action.NextSteps != nil {
		t.Errorf("nextSteps = %+v, want nil without remediation pointers", action.NextSteps)
	}

	// The document travels whole: reparse the embedded JSON with the
	// canonical parser and check every section round-trips.
	if action.Policy == nil || len(action.Policy.Raw) == 0 {
		t.Fatalf("policy document missing from the action")
	}
	if !json.Valid(action.Policy.Raw) {
		t.Errorf("embedded document is not canonical JSON: %s", action.Policy.Raw)
	}
	reparsed, err := ParsePolicy(action.Policy.Raw)
	if err != nil {
		t.Fatalf("embedded document does not reparse: %v", err)
	}
	if want := loadDemoPolicy(t); !reflect.DeepEqual(reparsed.NetworkPolicies, want.NetworkPolicies) {
		t.Errorf("embedded network policies diverge from the source document:\n%+v\n%+v", reparsed.NetworkPolicies, want.NetworkPolicies)
	}
	if reparsed.FilesystemPolicy == nil || reparsed.Landlock == nil {
		t.Errorf("filesystem_policy and landlock sections must travel with the document")
	}
}

func TestMapToSecurityProfileSurvivesCRDMarshalling(t *testing.T) {
	// The API server round-trips the whole object as JSON; the embedded
	// document must survive as the same JSON object, which is exactly what
	// the data plane will receive.
	result, err := MapToSecurityProfile(loadDemoDocument(t), previewProfileOptions("ns", "wire", metav1.LabelSelector{}))
	if err != nil {
		t.Fatalf("MapToSecurityProfile: %v", err)
	}
	wire, err := json.Marshal(result.Profile)
	if err != nil {
		t.Fatalf("marshal profile: %v", err)
	}
	var decoded agentsv1alpha1.SecurityProfile
	if err := json.Unmarshal(wire, &decoded); err != nil {
		t.Fatalf("unmarshal profile: %v", err)
	}
	if len(decoded.Spec.Rules) != 1 {
		t.Fatalf("decoded rules = %d, want one", len(decoded.Spec.Rules))
	}
	action := decoded.Spec.Rules[0].Actions.OpenShellPolicy
	if action == nil || action.Policy == nil || len(action.Policy.Raw) == 0 {
		t.Fatalf("openShellPolicy action lost across the JSON round trip: %+v", decoded.Spec.Rules[0].Actions)
	}
	if _, err := ParsePolicy(action.Policy.Raw); err != nil {
		t.Fatalf("embedded document does not survive the JSON round trip: %v", err)
	}
}

func TestMapToSecurityProfileNextSteps(t *testing.T) {
	doc := loadDemoDocument(t)

	t.Run("both pointers", func(t *testing.T) {
		opts := previewProfileOptions("ns", "gov", metav1.LabelSelector{})
		opts.ProposalURL = "https://gov.example.com/submit-policy-analysis"
		opts.SkillPath = "/opt/openshell/skills/policy-advisor"
		result, err := MapToSecurityProfile(doc, opts)
		if err != nil {
			t.Fatalf("MapToSecurityProfile: %v", err)
		}
		next := result.Profile.Spec.Rules[0].Actions.OpenShellPolicy.NextSteps
		if next == nil {
			t.Fatalf("nextSteps missing")
		}
		if next.ProposalURL != opts.ProposalURL || next.SkillPath != opts.SkillPath {
			t.Errorf("nextSteps = %+v, want the governance pointers", next)
		}
	})

	t.Run("proposal only", func(t *testing.T) {
		opts := previewProfileOptions("ns", "gov", metav1.LabelSelector{})
		opts.ProposalURL = "https://gov.example.com/submit-policy-analysis"
		result, err := MapToSecurityProfile(doc, opts)
		if err != nil {
			t.Fatalf("MapToSecurityProfile: %v", err)
		}
		next := result.Profile.Spec.Rules[0].Actions.OpenShellPolicy.NextSteps
		if next == nil {
			t.Fatalf("nextSteps missing when only proposalURL is set")
		}
		if next.SkillPath != "" {
			t.Errorf("skillPath = %q, want empty", next.SkillPath)
		}
	})
}

func TestMapToSecurityProfileLosses(t *testing.T) {
	result, err := MapToSecurityProfile(loadDemoDocument(t), previewProfileOptions("ns", "losses", metav1.LabelSelector{}))
	if err != nil {
		t.Fatalf("MapToSecurityProfile: %v", err)
	}
	// Everything the L4 TrafficPolicy projection loses to L7 semantics is
	// enforced here; only in-guest semantics and protocol fidelity remain.
	wantFields := []string{
		"filesystem_policy",
		"landlock",
		"network_policies.codex.binaries",
		"network_policies.github_api_readonly.binaries",
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

func TestMapToSecurityProfileRequiresEnforceable(t *testing.T) {
	// The strict default refuses a document with in-guest, binary, audit, or
	// non-REST semantics instead of publishing a profile that implies
	// protection the data plane does not provide.
	_, err := MapToSecurityProfile(loadDemoDocument(t), DefaultProfileMapOptions("ns", "strict", metav1.LabelSelector{}))
	if err == nil {
		t.Fatal("MapToSecurityProfile with strict defaults succeeded on a lossy document")
	}
	if !strings.Contains(err.Error(), "not enforce-ready") {
		t.Errorf("error = %q, want a not-enforce-ready message", err)
	}
}

func TestMapToSecurityProfileUnsupportedFields(t *testing.T) {
	doc := []byte(`version: 1
process: { run_as: sandbox }
network_policies:
  api:
    endpoints:
      - { host: api.example.com, port: 443, protocol: rest, enforcement: enforce, access: full }
`)
	preview, err := MapToSecurityProfile(doc, previewProfileOptions("ns", "preview", metav1.LabelSelector{}))
	if err != nil {
		t.Fatalf("preview MapToSecurityProfile: %v", err)
	}
	if len(preview.Blockers) != 1 || !strings.Contains(preview.Blockers[0], `field "process" is not modeled`) {
		t.Errorf("blockers = %v, want the process blocker", preview.Blockers)
	}
	if _, err := MapToSecurityProfile(doc, DefaultProfileMapOptions("ns", "strict", metav1.LabelSelector{})); err == nil {
		t.Fatal("strict MapToSecurityProfile accepted a document with unsupported fields")
	}
}

func TestMapToSecurityProfileFilesystemOnly(t *testing.T) {
	// A filesystem-only document is a valid deny-all-network policy, but its
	// filesystem semantics cannot be enforced by this contract: strict mode
	// refuses, preview mode reports the loss.
	doc := []byte("version: 1\nfilesystem_policy:\n  read_only: [/usr]\n")
	if _, err := MapToSecurityProfile(doc, DefaultProfileMapOptions("ns", "fs-only", metav1.LabelSelector{})); err == nil {
		t.Fatal("strict MapToSecurityProfile accepted in-guest filesystem semantics")
	} else if !strings.Contains(err.Error(), "filesystem_policy") {
		t.Errorf("error = %q, want the filesystem_policy blocker", err)
	}

	result, err := MapToSecurityProfile(doc, previewProfileOptions("ns", "fs-only", metav1.LabelSelector{}))
	if err != nil {
		t.Fatalf("preview MapToSecurityProfile: %v", err)
	}
	rules := result.Profile.Spec.Rules
	if len(rules) != 1 {
		t.Fatalf("rules = %d, want the catch-all rule whose filter denies every host", len(rules))
	}
	if _, err := ParsePolicy(rules[0].Actions.OpenShellPolicy.Policy.Raw); err != nil {
		t.Fatalf("embedded document does not reparse: %v", err)
	}
	if len(result.Losses) != 1 || result.Losses[0].Field != "filesystem_policy" {
		t.Errorf("losses = %+v, want exactly the filesystem_policy loss", result.Losses)
	}
}

func TestMapToSecurityProfileEmptyDocumentIsDenyAll(t *testing.T) {
	// OpenShell accepts a versioned document with no network policies as a
	// deny-all policy; the profile is enforceable as written.
	result, err := MapToSecurityProfile([]byte("version: 1\n"), DefaultProfileMapOptions("ns", "deny-all", metav1.LabelSelector{}))
	if err != nil {
		t.Fatalf("MapToSecurityProfile: %v", err)
	}
	if len(result.Losses) != 0 || len(result.Blockers) != 0 {
		t.Errorf("losses/blockers = %v/%v, want none", result.Losses, result.Blockers)
	}
	if len(result.Profile.Spec.Rules) != 1 {
		t.Errorf("rules = %d, want the catch-all rule evaluated as deny-all", len(result.Profile.Spec.Rules))
	}
}

func TestMapToSecurityProfileJSONDocument(t *testing.T) {
	// The governance loop may hand the adapter JSON rather than YAML; both
	// are accepted (JSON is a YAML subset).
	doc := []byte(`{"version":1,"network_policies":{"api":{"endpoints":[{"host":"api.example.com","port":443,"protocol":"rest","enforcement":"enforce","access":"read-only"}]}}}`)
	result, err := MapToSecurityProfile(doc, DefaultProfileMapOptions("ns", "json-doc", metav1.LabelSelector{}))
	if err != nil {
		t.Fatalf("MapToSecurityProfile: %v", err)
	}
	reparsed, err := ParsePolicy(result.Profile.Spec.Rules[0].Actions.OpenShellPolicy.Policy.Raw)
	if err != nil {
		t.Fatalf("embedded JSON document does not reparse: %v", err)
	}
	endpoints := reparsed.NetworkPolicies["api"].Endpoints
	if len(endpoints) != 1 || endpoints[0].Host != "api.example.com" || endpoints[0].Access != AccessReadOnly {
		t.Errorf("reparsed endpoint = %+v, want api.example.com:443 read-only", endpoints)
	}
	if len(result.Losses) != 0 {
		t.Errorf("losses = %+v, want none for a pure REST policy", result.Losses)
	}
}

func TestMapToSecurityProfilePriority(t *testing.T) {
	opts := previewProfileOptions("ns", "priority", metav1.LabelSelector{})
	opts.Priority = 100
	result, err := MapToSecurityProfile(loadDemoDocument(t), opts)
	if err != nil {
		t.Fatalf("MapToSecurityProfile: %v", err)
	}
	if result.Profile.Spec.Priority == nil || *result.Profile.Spec.Priority != 100 {
		t.Errorf("priority = %+v, want 100", result.Profile.Spec.Priority)
	}
}

func TestMapToSecurityProfileErrors(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		opts ProfileMapOptions
		want string
	}{
		{
			name: "missing namespace",
			data: []byte("version: 1\nnetwork_policies:\n  a:\n    endpoints:\n      - { host: api.example.com, port: 443, protocol: rest, enforcement: enforce, access: full }"),
			opts: ProfileMapOptions{},
			want: "namespace is required",
		},
		{
			name: "policy without endpoints",
			data: []byte("version: 1\nnetwork_policies:\n  a:\n    endpoints: []\n"),
			opts: ProfileMapOptions{Namespace: "ns"},
			want: "has no endpoints",
		},
		{
			name: "unsupported schema version",
			data: []byte("version: 2\nnetwork_policies:\n  a:\n    endpoints:\n      - { host: api.example.com, port: 443 }\n"),
			opts: ProfileMapOptions{Namespace: "ns"},
			want: "unsupported policy version 2",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := MapToSecurityProfile(tt.data, tt.opts)
			if err == nil {
				t.Fatalf("MapToSecurityProfile succeeded, want error containing %q", tt.want)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("MapToSecurityProfile error = %q, want containing %q", err, tt.want)
			}
		})
	}
}

func TestMapToSecurityProfileDeterministic(t *testing.T) {
	opts := previewProfileOptions("ns", "determinism", metav1.LabelSelector{})
	first, err := MapToSecurityProfile(loadDemoDocument(t), opts)
	if err != nil {
		t.Fatalf("MapToSecurityProfile: %v", err)
	}
	second, err := MapToSecurityProfile(loadDemoDocument(t), opts)
	if err != nil {
		t.Fatalf("MapToSecurityProfile: %v", err)
	}
	if !reflect.DeepEqual(first.Profile.Spec, second.Profile.Spec) {
		t.Errorf("two projections of the same document differ:\n%+v\n%+v", first.Profile.Spec, second.Profile.Spec)
	}
	if !reflect.DeepEqual(first.Losses, second.Losses) {
		t.Errorf("two projections produced different losses:\n%+v\n%+v", first.Losses, second.Losses)
	}
}
