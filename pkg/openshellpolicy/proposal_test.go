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

	agentsv1alpha1 "github.com/openkruise/agents/api/v1alpha1"
)

const mergeBaseDoc = `version: 1
network_policies:
  api:
    endpoints:
      - host: api.example.com
        port: 443
        protocol: rest
        access: read-only
        rules:
          - allow: { method: GET, path: /v1/** }
  mirror:
    binaries:
      - path: /usr/bin/curl
    endpoints:
      - host: mirror.internal
        port: 5000
      - host: mirror-backup.internal
        port: 5000
`

func parseMergeBase(t *testing.T) *Policy {
	t.Helper()
	policy, err := ParsePolicy([]byte(mergeBaseDoc))
	if err != nil {
		t.Fatalf("ParsePolicy: %v", err)
	}
	return policy
}

func TestMarshalPolicyRoundTripsThroughParse(t *testing.T) {
	policy := loadDemoPolicy(t)
	data, err := MarshalPolicy(policy)
	if err != nil {
		t.Fatalf("MarshalPolicy: %v", err)
	}
	if !strings.Contains(string(data), `"allow":{"method":"GET","path":"/v1/**"}`) &&
		!strings.Contains(string(data), `"deny"`) {
		t.Errorf("canonical JSON lost the single-key rule wire form: %s", data)
	}
	reparsed, err := ParsePolicy(data)
	if err != nil {
		t.Fatalf("canonical JSON does not reparse: %v", err)
	}
	if !reflect.DeepEqual(reparsed.NetworkPolicies, policy.NetworkPolicies) {
		t.Errorf("round-tripped network policies diverge:\n%+v\n%+v", reparsed.NetworkPolicies, policy.NetworkPolicies)
	}
	if !reflect.DeepEqual(reparsed.FilesystemPolicy, policy.FilesystemPolicy) || !reflect.DeepEqual(reparsed.Landlock, policy.Landlock) {
		t.Errorf("round-tripped preserved sections diverge")
	}
}

func TestApplyMergeOperations(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(t *testing.T) []MergeOperation
		verify  func(t *testing.T, merged *Policy, data []byte)
		wantErr string
	}{
		{
			name: "add network rule",
			mutate: func(t *testing.T) []MergeOperation {
				return []MergeOperation{{
					AddNetworkRule: &AddNetworkRuleOp{
						RuleName: "github",
						Policy: NetworkPolicy{
							Endpoints: []Endpoint{{Host: "github.com", Port: 443, Access: AccessReadOnly}},
							Binaries:  []BinaryRef{{Path: "/usr/bin/git"}},
						},
					},
				}}
			},
			verify: func(t *testing.T, merged *Policy, data []byte) {
				np, ok := merged.NetworkPolicies["github"]
				if !ok {
					t.Fatalf("github policy missing after merge")
				}
				if len(np.Endpoints) != 1 || np.Endpoints[0].Host != "github.com" {
					t.Errorf("github endpoints = %+v", np.Endpoints)
				}
				if len(np.Binaries) != 1 || np.Binaries[0].Path != "/usr/bin/git" {
					t.Errorf("github binaries = %+v", np.Binaries)
				}
				if _, still := merged.NetworkPolicies["api"]; !still {
					t.Errorf("existing policies must survive the merge")
				}
			},
		},
		{
			name: "add network rule without endpoints",
			mutate: func(t *testing.T) []MergeOperation {
				return []MergeOperation{{
					AddNetworkRule: &AddNetworkRuleOp{RuleName: "empty"},
				}}
			},
			wantErr: "at least one endpoint is required",
		},
		{
			name: "remove network rule",
			mutate: func(t *testing.T) []MergeOperation {
				return []MergeOperation{{
					RemoveNetworkRule: &RemoveNetworkRuleOp{RuleName: "api"},
				}}
			},
			verify: func(t *testing.T, merged *Policy, data []byte) {
				if _, ok := merged.NetworkPolicies["api"]; ok {
					t.Errorf("api policy must be removed")
				}
				if _, ok := merged.NetworkPolicies["mirror"]; !ok {
					t.Errorf("mirror policy must survive")
				}
			},
		},
		{
			name: "remove missing network rule",
			mutate: func(t *testing.T) []MergeOperation {
				return []MergeOperation{{
					RemoveNetworkRule: &RemoveNetworkRuleOp{RuleName: "nope"},
				}}
			},
			wantErr: `network policy "nope" not found`,
		},
		{
			name: "remove endpoint case-insensitive",
			mutate: func(t *testing.T) []MergeOperation {
				return []MergeOperation{{
					RemoveNetworkEndpoint: &RemoveNetworkEndpointOp{RuleName: "mirror", Host: "MIRROR.Internal", Port: 5000},
				}}
			},
			verify: func(t *testing.T, merged *Policy, data []byte) {
				np := merged.NetworkPolicies["mirror"]
				if len(np.Endpoints) != 1 || np.Endpoints[0].Host != "mirror-backup.internal" {
					t.Errorf("mirror endpoints = %+v, want only the backup endpoint", np.Endpoints)
				}
			},
		},
		{
			name: "remove last endpoint fails validation",
			mutate: func(t *testing.T) []MergeOperation {
				return []MergeOperation{
					{RemoveNetworkEndpoint: &RemoveNetworkEndpointOp{RuleName: "mirror", Host: "mirror.internal", Port: 5000}},
					{RemoveNetworkEndpoint: &RemoveNetworkEndpointOp{RuleName: "mirror", Host: "mirror-backup.internal", Port: 5000}},
				}
			},
			wantErr: `network policy "mirror" has no endpoints`,
		},
		{
			name: "remove missing endpoint",
			mutate: func(t *testing.T) []MergeOperation {
				return []MergeOperation{{
					RemoveNetworkEndpoint: &RemoveNetworkEndpointOp{RuleName: "api", Host: "api.example.com", Port: 8443},
				}}
			},
			wantErr: "endpoint api.example.com:8443 not found",
		},
		{
			name: "add deny rules upper-cases methods",
			mutate: func(t *testing.T) []MergeOperation {
				return []MergeOperation{{
					AddDenyRules: &AddL7RulesOp{
						Target: L7RuleTarget{RuleName: "api", Host: "api.example.com", Port: 443},
						Rules:  []Rule{{Action: RuleActionReject, Method: "delete", Path: "/v1/admin"}},
					},
				}}
			},
			verify: func(t *testing.T, merged *Policy, data []byte) {
				ep := merged.NetworkPolicies["api"].Endpoints[0]
				if len(ep.Rules) != 2 {
					t.Fatalf("rules = %d, want the original allow plus the new deny", len(ep.Rules))
				}
				deny := ep.Rules[1]
				if deny.Action != RuleActionReject || deny.Method != "DELETE" || deny.Path != "/v1/admin" {
					t.Errorf("appended deny rule = %+v", deny)
				}
			},
		},
		{
			name: "add allow rules to missing endpoint",
			mutate: func(t *testing.T) []MergeOperation {
				return []MergeOperation{{
					AddAllowRules: &AddL7RulesOp{
						Target: L7RuleTarget{RuleName: "api", Host: "other.example.com", Port: 443},
						Rules:  []Rule{{Action: RuleActionAllow, Method: "GET"}},
					},
				}}
			},
			wantErr: "endpoint other.example.com:443 not found",
		},
		{
			name: "deny rules carrying an allow action",
			mutate: func(t *testing.T) []MergeOperation {
				return []MergeOperation{{
					AddDenyRules: &AddL7RulesOp{
						Target: L7RuleTarget{RuleName: "api", Host: "api.example.com", Port: 443},
						Rules:  []Rule{{Action: RuleActionAllow, Method: "GET"}},
					},
				}}
			},
			wantErr: `rule 0 has action "allow", want "deny"`,
		},
		{
			name: "remove bound binary",
			mutate: func(t *testing.T) []MergeOperation {
				return []MergeOperation{{
					RemoveNetworkBinary: &RemoveNetworkBinaryOp{RuleName: "mirror", BinaryPath: "/usr/bin/curl"},
				}}
			},
			verify: func(t *testing.T, merged *Policy, data []byte) {
				if binaries := merged.NetworkPolicies["mirror"].Binaries; len(binaries) != 0 {
					t.Errorf("binaries = %+v, want none", binaries)
				}
			},
		},
		{
			name: "remove missing binary",
			mutate: func(t *testing.T) []MergeOperation {
				return []MergeOperation{{
					RemoveNetworkBinary: &RemoveNetworkBinaryOp{RuleName: "mirror", BinaryPath: "/usr/bin/wget"},
				}}
			},
			wantErr: `binary "/usr/bin/wget" not bound`,
		},
		{
			name: "operations applied in order",
			mutate: func(t *testing.T) []MergeOperation {
				return []MergeOperation{
					{AddNetworkRule: &AddNetworkRuleOp{RuleName: "tmp", Policy: NetworkPolicy{
						Endpoints: []Endpoint{{Host: "tmp.example.com", Port: 443}},
					}}},
					{RemoveNetworkRule: &RemoveNetworkRuleOp{RuleName: "tmp"}},
				}
			},
			verify: func(t *testing.T, merged *Policy, data []byte) {
				if _, ok := merged.NetworkPolicies["tmp"]; ok {
					t.Errorf("tmp policy must be added then removed")
				}
			},
		},
		{
			name: "operation with no branch set",
			mutate: func(t *testing.T) []MergeOperation {
				return []MergeOperation{{}}
			},
			wantErr: "exactly one of",
		},
		{
			name: "operation with two branches set",
			mutate: func(t *testing.T) []MergeOperation {
				return []MergeOperation{{
					RemoveNetworkRule:     &RemoveNetworkRuleOp{RuleName: "api"},
					RemoveNetworkEndpoint: &RemoveNetworkEndpointOp{RuleName: "api", Host: "api.example.com", Port: 443},
				}}
			},
			wantErr: "exactly one of",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			base := parseMergeBase(t)
			ops := tt.mutate(t)
			merged, data, err := ApplyMergeOperations(base, ops)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("ApplyMergeOperations succeeded, want error containing %q", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("error = %q, want containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ApplyMergeOperations: %v", err)
			}
			if merged == nil || data == nil {
				t.Fatalf("merged policy or canonical JSON missing")
			}
			tt.verify(t, merged, data)
		})
	}
}

func TestApplyMergeOperationsRefusesUnsupportedFields(t *testing.T) {
	// Rewriting through the trimmed model would drop process/network_middlewares
	// or other fields the contract does not model, so the merge must refuse
	// instead of publishing a silently reduced document.
	policy, err := ParsePolicy([]byte(mergeBaseDoc + "process: { run_as: sandbox }\n"))
	if err != nil {
		t.Fatalf("ParsePolicy: %v", err)
	}
	_, _, err = ApplyMergeOperations(policy, []MergeOperation{{
		AddNetworkRule: &AddNetworkRuleOp{
			RuleName: "extra",
			Policy:   NetworkPolicy{Endpoints: []Endpoint{{Host: "extra.example.com", Port: 443}}},
		},
	}})
	if err == nil {
		t.Fatal("ApplyMergeOperations succeeded, want the unsupported-field refusal")
	}
	if !strings.Contains(err.Error(), "refusing to rewrite the authoritative document") || !strings.Contains(err.Error(), "process") {
		t.Errorf("error = %q, want the unsupported-field refusal naming process", err)
	}
}

func TestApplyMergeOperationsRejectsExistingRuleName(t *testing.T) {
	base := parseMergeBase(t)
	_, _, err := ApplyMergeOperations(base, []MergeOperation{{
		AddNetworkRule: &AddNetworkRuleOp{
			RuleName: "api",
			Policy:   NetworkPolicy{Endpoints: []Endpoint{{Host: "other.example.com", Port: 443}}},
		},
	}})
	if err == nil {
		t.Fatal("ApplyMergeOperations overwrote an existing network policy")
	}
	if !strings.Contains(err.Error(), "network policy already exists") {
		t.Errorf("error = %q, want the name-collision refusal", err)
	}
	if _, ok := base.NetworkPolicies["api"]; !ok {
		t.Errorf("baseline api policy was mutated by the rejected merge")
	}
}

func TestApplyMergeOperationsRequiresInput(t *testing.T) {
	base := parseMergeBase(t)
	if _, _, err := ApplyMergeOperations(nil, []MergeOperation{{RemoveNetworkRule: &RemoveNetworkRuleOp{RuleName: "api"}}}); err == nil {
		t.Errorf("nil policy must be rejected")
	}
	if _, _, err := ApplyMergeOperations(base, nil); err == nil {
		t.Errorf("empty operations must be rejected")
	}
}

func TestApplyMergeOperationsDoesNotMutateBaseline(t *testing.T) {
	base := parseMergeBase(t)
	before := base.NetworkPolicies["api"].Endpoints[0].Rules
	_, _, err := ApplyMergeOperations(base, []MergeOperation{{
		AddDenyRules: &AddL7RulesOp{
			Target: L7RuleTarget{RuleName: "api", Host: "api.example.com", Port: 443},
			Rules:  []Rule{{Action: RuleActionReject, Method: "POST"}},
		},
	}})
	if err != nil {
		t.Fatalf("ApplyMergeOperations: %v", err)
	}
	if len(before) != 1 || before[0].Action != RuleActionAllow {
		t.Errorf("baseline policy was mutated by the merge: %+v", before)
	}
}

func TestApplyMergeOperationsKeepsPreservedSections(t *testing.T) {
	base, err := ParsePolicy([]byte(mergeBaseDoc + "filesystem_policy:\n  read_only: [/usr]\nlandlock:\n  best_effort: true\n"))
	if err != nil {
		t.Fatalf("ParsePolicy: %v", err)
	}
	merged, _, err := ApplyMergeOperations(base, []MergeOperation{{
		AddNetworkRule: &AddNetworkRuleOp{RuleName: "extra", Policy: NetworkPolicy{
			Endpoints: []Endpoint{{Host: "extra.example.com", Port: 443}},
		}},
	}})
	if err != nil {
		t.Fatalf("ApplyMergeOperations: %v", err)
	}
	if merged.FilesystemPolicy == nil || merged.Landlock == nil {
		t.Errorf("filesystem_policy and landlock must survive the merge")
	}
	if got := merged.FilesystemPolicy["read_only"]; !reflect.DeepEqual(got, []interface{}{"/usr"}) {
		t.Errorf("filesystem_policy.read_only = %#v, want [/usr]", got)
	}
}

func TestConvertMergeOperations(t *testing.T) {
	ops := []agentsv1alpha1.PolicyMergeOperation{
		{
			AddNetworkRule: &agentsv1alpha1.NetworkRuleAdd{
				RuleName: "github",
				Endpoints: []agentsv1alpha1.PolicyEndpoint{{
					Host: "github.com", Port: 443, Access: "read-only",
					Rules: []agentsv1alpha1.PolicyL7Rule{{Action: "allow", Method: "get", Path: "/**"}},
				}},
				Binaries: []agentsv1alpha1.PolicyBinaryRef{{Path: "/usr/bin/git"}},
			},
		},
		{
			AddDenyRules: &agentsv1alpha1.L7RulesAppend{
				Target: agentsv1alpha1.L7RuleTarget{RuleName: "api", Host: "api.example.com", Port: 443},
				Rules:  []agentsv1alpha1.PolicyL7Rule{{Action: "deny", Method: "post", Path: "/v1/admin"}},
			},
		},
		{
			RemoveNetworkBinary: &agentsv1alpha1.NetworkBinaryRemove{RuleName: "mirror", BinaryPath: "/usr/bin/curl"},
		},
	}
	converted, err := ConvertMergeOperations(ops)
	if err != nil {
		t.Fatalf("ConvertMergeOperations: %v", err)
	}
	if len(converted) != 3 {
		t.Fatalf("converted = %d ops, want 3", len(converted))
	}
	add := converted[0].AddNetworkRule
	if add == nil || add.Policy.Endpoints[0].Rules[0].Method != "GET" {
		t.Errorf("add rule methods must be upper-cased: %+v", add)
	}
	deny := converted[1].AddDenyRules
	if deny == nil || deny.Rules[0].Action != RuleActionReject || deny.Rules[0].Method != "POST" {
		t.Errorf("deny rules = %+v", deny)
	}
	if converted[2].RemoveNetworkBinary == nil {
		t.Errorf("remove binary op lost in conversion")
	}

	// The converted operations merge cleanly onto the base document.
	merged, data, err := ApplyMergeOperations(parseMergeBase(t), converted)
	if err != nil {
		t.Fatalf("ApplyMergeOperations(converted): %v", err)
	}
	if len(merged.NetworkPolicies["github"].Endpoints) != 1 {
		t.Errorf("github policy missing after merge: %s", data)
	}
}

func TestConvertMergeOperationsErrors(t *testing.T) {
	tests := []struct {
		name string
		ops  []agentsv1alpha1.PolicyMergeOperation
		want string
	}{
		{
			name: "empty batch",
			ops:  nil,
			want: "at least one operation is required",
		},
		{
			name: "no branch set",
			ops:  []agentsv1alpha1.PolicyMergeOperation{{}},
			want: "exactly one operation must be set",
		},
		{
			name: "action does not match kind",
			ops: []agentsv1alpha1.PolicyMergeOperation{{
				AddAllowRules: &agentsv1alpha1.L7RulesAppend{
					Target: agentsv1alpha1.L7RuleTarget{RuleName: "api", Host: "api.example.com", Port: 443},
					Rules:  []agentsv1alpha1.PolicyL7Rule{{Action: "deny"}},
				},
			}},
			want: `action "deny" does not match the operation kind`,
		},
		{
			name: "empty rule list",
			ops: []agentsv1alpha1.PolicyMergeOperation{{
				AddDenyRules: &agentsv1alpha1.L7RulesAppend{
					Target: agentsv1alpha1.L7RuleTarget{RuleName: "api", Host: "api.example.com", Port: 443},
				},
			}},
			want: "at least one rule is required",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ConvertMergeOperations(tt.ops)
			if err == nil {
				t.Fatalf("ConvertMergeOperations succeeded, want error containing %q", tt.want)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %q, want containing %q", err, tt.want)
			}
		})
	}
}

func TestPolicyHash(t *testing.T) {
	base := parseMergeBase(t)
	first, err := PolicyHash(base)
	if err != nil {
		t.Fatalf("PolicyHash: %v", err)
	}
	if !strings.HasPrefix(first, "sha256:") || len(first) != len("sha256:")+64 {
		t.Errorf("hash = %q, want sha256-prefixed 64-hex digest", first)
	}
	second, err := PolicyHash(base)
	if err != nil {
		t.Fatalf("PolicyHash: %v", err)
	}
	if first != second {
		t.Errorf("hashing is not deterministic: %q vs %q", first, second)
	}
	merged, _, err := ApplyMergeOperations(base, []MergeOperation{{
		AddNetworkRule: &AddNetworkRuleOp{RuleName: "extra", Policy: NetworkPolicy{
			Endpoints: []Endpoint{{Host: "extra.example.com", Port: 443}},
		}},
	}})
	if err != nil {
		t.Fatalf("ApplyMergeOperations: %v", err)
	}
	other, err := PolicyHash(merged)
	if err != nil {
		t.Fatalf("PolicyHash: %v", err)
	}
	if other == first {
		t.Errorf("hash collision between different policies")
	}
}
