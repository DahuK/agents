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
	"encoding/hex"
	"os"
	"reflect"
	"strings"
	"testing"
)

func loadDemoPolicy(t *testing.T) *Policy {
	t.Helper()
	data, err := os.ReadFile("testdata/demo-policy.yaml")
	if err != nil {
		t.Fatalf("read testdata/demo-policy.yaml: %v", err)
	}
	policy, err := ParsePolicy(data)
	if err != nil {
		t.Fatalf("ParsePolicy: %v", err)
	}
	return policy
}

func TestVersionBaselinePinsUpstreamCommit(t *testing.T) {
	if UpstreamSource != "github.com/NVIDIA/OpenShell" {
		t.Errorf("UpstreamSource = %q, want the canonical OpenShell repository", UpstreamSource)
	}
	if len(VersionBaseline) != 40 {
		t.Fatalf("VersionBaseline = %q, want a full 40-character commit hash", VersionBaseline)
	}
	if _, err := hex.DecodeString(VersionBaseline); err != nil {
		t.Errorf("VersionBaseline = %q, want lowercase hex: %v", VersionBaseline, err)
	}
	if strings.ToLower(VersionBaseline) != VersionBaseline {
		t.Errorf("VersionBaseline = %q, want lowercase hex", VersionBaseline)
	}
}

func TestParsePolicy(t *testing.T) {
	policy := loadDemoPolicy(t)

	if policy.Version != 1 {
		t.Errorf("Version = %d, want 1", policy.Version)
	}
	if policy.FilesystemPolicy == nil || policy.Landlock == nil {
		t.Errorf("filesystem_policy and landlock sections must be preserved for loss accounting")
	}
	if len(policy.UnsupportedFields) != 0 {
		t.Errorf("UnsupportedFields = %v, want none for the demo document", policy.UnsupportedFields)
	}
	wantKeys := []string{"codex", "github_api_readonly", "github_raw_scoped", "metrics_sink", "registry_mirror"}
	if got := policy.PolicyNames(); !reflect.DeepEqual(got, wantKeys) {
		t.Errorf("PolicyNames() = %v, want %v", got, wantKeys)
	}

	tests := []struct {
		key         string
		name        string
		host        string
		port        int32
		protocol    string
		enforcement string
		access      string
		rules       int
		binaries    int
	}{
		{key: "codex", name: "codex", host: "api.openai.com", port: 443, protocol: "rest", enforcement: "enforce", access: "full", binaries: 2},
		{key: "github_api_readonly", name: "github-api-readonly", host: "api.github.com", port: 443, protocol: "rest", enforcement: "enforce", access: "read-only", binaries: 1},
		{key: "github_raw_scoped", name: "github-raw-scoped", host: "raw.githubusercontent.com", port: 443, protocol: "rest", enforcement: "enforce", rules: 2},
		{key: "metrics_sink", name: "metrics-sink", host: "metrics.internal", port: 443, protocol: "rest", enforcement: "audit", access: "full"},
		{key: "registry_mirror", name: "registry-mirror", host: "registry.internal", port: 5000, protocol: "http", enforcement: "enforce", access: "full"},
	}
	for _, tt := range tests {
		np, ok := policy.NetworkPolicies[tt.key]
		if !ok {
			t.Errorf("network policy %q missing", tt.key)
			continue
		}
		if np.Name != tt.name {
			t.Errorf("policy %q Name = %q, want %q", tt.key, np.Name, tt.name)
		}
		if len(np.Endpoints) != 1 {
			t.Errorf("policy %q has %d endpoints, want 1", tt.key, len(np.Endpoints))
			continue
		}
		ep := np.Endpoints[0]
		if ep.Host != tt.host || ep.Port != tt.port {
			t.Errorf("policy %q endpoint = %s:%d, want %s:%d", tt.key, ep.Host, ep.Port, tt.host, tt.port)
		}
		if ep.Protocol != tt.protocol {
			t.Errorf("policy %q Protocol = %q, want %q", tt.key, ep.Protocol, tt.protocol)
		}
		if ep.Enforcement != tt.enforcement {
			t.Errorf("policy %q Enforcement = %q, want %q", tt.key, ep.Enforcement, tt.enforcement)
		}
		if ep.Access != tt.access {
			t.Errorf("policy %q Access = %q, want %q", tt.key, ep.Access, tt.access)
		}
		if len(ep.Rules) != tt.rules {
			t.Errorf("policy %q has %d rules, want %d", tt.key, len(ep.Rules), tt.rules)
		}
		if len(np.Binaries) != tt.binaries {
			t.Errorf("policy %q has %d binaries, want %d", tt.key, len(np.Binaries), tt.binaries)
		}
	}

	raw := policy.NetworkPolicies["github_raw_scoped"].Endpoints[0].Rules
	wantRules := []Rule{
		{Action: RuleActionAllow, Method: "GET", Path: "/github/rest-api-description/main/README.md"},
		{Action: RuleActionReject, Method: "GET", Path: "/github/rest-api-description/main/secrets/**"},
	}
	if !reflect.DeepEqual(raw, wantRules) {
		t.Errorf("github_raw_scoped rules = %+v, want %+v", raw, wantRules)
	}
}

func TestParsePolicyEmptyNetworkPoliciesIsDefaultDeny(t *testing.T) {
	// OpenShell accepts an explicitly versioned document without network
	// policies as a valid deny-all policy; it is not a parse error.
	policy, err := ParsePolicy([]byte("version: 1\n"))
	if err != nil {
		t.Fatalf("ParsePolicy: %v", err)
	}
	if policy.Version != 1 || len(policy.NetworkPolicies) != 0 {
		t.Errorf("policy = %+v, want a version-1 document with no network policies", policy)
	}
	if blockers := EnforceBlockers(policy); len(blockers) != 0 {
		t.Errorf("blockers = %v, want none: an empty policy is enforceable as deny-all", blockers)
	}
}

func TestParsePolicyReadWriteAccess(t *testing.T) {
	policy, err := ParsePolicy([]byte("version: 1\nnetwork_policies:\n  api:\n    endpoints:\n      - { host: a.com, port: 443, protocol: rest, enforcement: enforce, access: read-write }\n"))
	if err != nil {
		t.Fatalf("ParsePolicy: %v", err)
	}
	if got := policy.NetworkPolicies["api"].Endpoints[0].Access; got != AccessReadWrite {
		t.Errorf("access = %q, want %q", got, AccessReadWrite)
	}
}

func TestParsePolicyUnsupportedFields(t *testing.T) {
	doc := `version: 1
process: { run_as: sandbox }
network_middlewares: []
network_policies:
  api:
    endpoints:
      - host: api.example.com
        port: 443
        protocol: rest
        enforcement: enforce
        access: full
        ports: [443]
        tls: auto
        rules:
          - allow: { method: GET, path: /v1, headers: { x: y } }
    binaries:
      - path: /usr/bin/curl
        sha256: abc
`
	policy, err := ParsePolicy([]byte(doc))
	if err != nil {
		t.Fatalf("ParsePolicy: %v", err)
	}
	want := []string{
		"network_middlewares",
		"network_policies.api.binaries[0].sha256",
		"network_policies.api.endpoints[0].ports",
		"network_policies.api.endpoints[0].rules[0].allow.headers",
		"network_policies.api.endpoints[0].tls",
		"process",
	}
	if !reflect.DeepEqual(policy.UnsupportedFields, want) {
		t.Errorf("UnsupportedFields = %v, want %v", policy.UnsupportedFields, want)
	}
	blockers := EnforceBlockers(policy)
	// One blocker per unsupported field, plus the binary-binding blocker.
	if len(blockers) != len(want)+1 {
		t.Errorf("blockers = %v, want one per unsupported field plus binaries", blockers)
	}
}

func TestParsePolicyRejectsOverlappingEndpoints(t *testing.T) {
	tests := []struct {
		name string
		doc  string
		want string
	}{
		{
			name: "same host and port in two policies",
			doc: `version: 1
network_policies:
  first:
    endpoints:
      - { host: api.example.com, port: 443, protocol: rest, enforcement: enforce, access: full }
  second:
    endpoints:
      - { host: API.EXAMPLE.COM, port: 443, protocol: rest, enforcement: enforce, access: read-only }
`,
			want: `network policies "first" and "second" overlap on endpoint api.example.com:443`,
		},
		{
			name: "duplicate endpoint in one policy",
			doc: `version: 1
network_policies:
  first:
    endpoints:
      - { host: api.example.com, port: 443, protocol: rest, enforcement: enforce, access: full }
      - { host: api.example.com, port: 443, protocol: rest, enforcement: enforce, access: read-only }
`,
			want: `network policy "first" declares endpoint api.example.com:443 more than once`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParsePolicy([]byte(tt.doc))
			if err == nil {
				t.Fatalf("ParsePolicy succeeded, want error containing %q", tt.want)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("ParsePolicy error = %q, want containing %q", err, tt.want)
			}
		})
	}
}

func TestParsePolicyErrors(t *testing.T) {
	tests := []struct {
		name string
		doc  string
		want string
	}{
		{
			name: "truly empty document",
			doc:  "",
			want: "document contains no policy sections",
		},
		{
			name: "unsupported schema version",
			doc:  "version: 2\nnetwork_policies:\n  codex:\n    endpoints:\n      - { host: a.com, port: 443 }\n",
			want: "unsupported policy version 2",
		},
		{
			name: "network policy without endpoints",
			doc:  "version: 1\nnetwork_policies:\n  codex: {}\n",
			want: `network policy "codex" has no endpoints`,
		},
		{
			name: "endpoint without host",
			doc:  "version: 1\nnetwork_policies:\n  codex:\n    endpoints:\n      - port: 443\n",
			want: `endpoint 0: host is required`,
		},
		{
			name: "endpoint port out of range",
			doc:  "version: 1\nnetwork_policies:\n  codex:\n    endpoints:\n      - host: a.com\n        port: 70000\n",
			want: "port 70000 out of range",
		},
		{
			name: "unknown access",
			doc:  "version: 1\nnetwork_policies:\n  codex:\n    endpoints:\n      - host: a.com\n        port: 443\n        access: sometimes\n",
			want: `unknown access "sometimes"`,
		},
		{
			name: "unknown enforcement",
			doc:  "version: 1\nnetwork_policies:\n  codex:\n    endpoints:\n      - host: a.com\n        port: 443\n        enforcement: maybe\n",
			want: `unknown enforcement "maybe"`,
		},
		{
			name: "malformed yaml",
			doc:  "network_policies: [\n",
			want: "parse openshell policy",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParsePolicy([]byte(tt.doc))
			if err == nil {
				t.Fatalf("ParsePolicy succeeded, want error containing %q", tt.want)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("ParsePolicy error = %q, want containing %q", err, tt.want)
			}
		})
	}
}

func TestRuleUnmarshalJSON(t *testing.T) {
	tests := []struct {
		name    string
		data    string
		want    Rule
		wantErr string
	}{
		{
			name: "allow rule",
			data: `{"allow": {"method": "GET", "path": "/x"}}`,
			want: Rule{Action: RuleActionAllow, Method: "GET", Path: "/x"},
		},
		{
			name: "deny rule lower-case method",
			data: `{"deny": {"method": "put", "path": "/y"}}`,
			want: Rule{Action: RuleActionReject, Method: "PUT", Path: "/y"},
		},
		{
			name:    "two actions",
			data:    `{"allow": {"path": "/x"}, "deny": {"path": "/y"}}`,
			wantErr: "exactly one of allow/deny",
		},
		{
			name:    "unknown action",
			data:    `{"maybe": {"path": "/x"}}`,
			wantErr: `unknown rule action "maybe"`,
		},
		{
			name:    "not an object",
			data:    `["allow"]`,
			wantErr: "cannot unmarshal",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var rule Rule
			err := rule.UnmarshalJSON([]byte(tt.data))
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("unmarshal succeeded, want error containing %q", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("unmarshal error = %q, want containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if !reflect.DeepEqual(rule, tt.want) {
				t.Errorf("rule = %+v, want %+v", rule, tt.want)
			}
		})
	}
}
