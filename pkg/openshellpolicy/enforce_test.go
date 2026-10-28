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
	"strings"
	"testing"
)

func TestEnforceBlockers(t *testing.T) {
	tests := []struct {
		name string
		doc  string
		want []string
	}{
		{
			name: "enforceable rest policy",
			doc: `version: 1
network_policies:
  api:
    endpoints:
      - { host: api.example.com, port: 443, protocol: rest, enforcement: enforce, access: full }
      - { host: api.example.com, port: 8443, protocol: rest, enforcement: enforce, rules: [{ allow: { method: GET, path: /v1/** } }] }
`,
		},
		{
			name: "missing version",
			doc: `network_policies:
  api:
    endpoints:
      - { host: api.example.com, port: 443, protocol: rest, enforcement: enforce, access: full }
`,
			want: []string{"version must be 1"},
		},
		{
			name: "filesystem policy",
			doc: `version: 1
filesystem_policy: { read_only: [/usr] }
network_policies:
  api:
    endpoints:
      - { host: api.example.com, port: 443, protocol: rest, enforcement: enforce, access: full }
`,
			want: []string{"filesystem_policy requires native in-guest LSM enforcement"},
		},
		{
			name: "landlock",
			doc: `version: 1
landlock: { compatibility: best_effort }
network_policies:
  api:
    endpoints:
      - { host: api.example.com, port: 443, protocol: rest, enforcement: enforce, access: full }
`,
			want: []string{"landlock requires native in-guest LSM enforcement"},
		},
		{
			name: "binary binding",
			doc: `version: 1
network_policies:
  api:
    binaries: [{ path: /usr/bin/curl }]
    endpoints:
      - { host: api.example.com, port: 443, protocol: rest, enforcement: enforce, access: full }
`,
			want: []string{"network_policies.api.binaries requires per-binary identity"},
		},
		{
			name: "non-rest protocol",
			doc: `version: 1
network_policies:
  api:
    endpoints:
      - { host: api.example.com, port: 443, protocol: http, enforcement: enforce, access: full }
`,
			want: []string{`network_policies.api.endpoints[api.example.com:443].protocol must be explicitly "rest"`},
		},
		{
			name: "omitted enforcement means audit",
			doc: `version: 1
network_policies:
  api:
    endpoints:
      - { host: api.example.com, port: 443, protocol: rest, access: full }
`,
			want: []string{`network_policies.api.endpoints[api.example.com:443].enforcement must be explicitly "enforce"`},
		},
		{
			name: "partial wildcard path",
			doc: `version: 1
network_policies:
  api:
    endpoints:
      - { host: api.example.com, port: 443, protocol: rest, enforcement: enforce, rules: [{ allow: { method: GET, path: /v1/* } }] }
`,
			want: []string{`rules[0].path "/v1/*" is neither empty, an exact path, nor a /** prefix match`},
		},
		{
			name: "unsupported document field",
			doc: `version: 1
process: { run_as: sandbox }
network_policies:
  api:
    endpoints:
      - { host: api.example.com, port: 443, protocol: rest, enforcement: enforce, access: full }
`,
			want: []string{`field "process" is not modeled`},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy, err := ParsePolicy([]byte(tt.doc))
			if err != nil {
				t.Fatalf("ParsePolicy: %v", err)
			}
			blockers := EnforceBlockers(policy)
			if len(blockers) != len(tt.want) {
				t.Fatalf("blockers = %v, want %d matching %v", blockers, len(tt.want), tt.want)
			}
			for i, want := range tt.want {
				if !strings.Contains(blockers[i], want) {
					t.Errorf("blockers[%d] = %q, want containing %q", i, blockers[i], want)
				}
			}
		})
	}
}

func TestEnforceBlockersNilPolicy(t *testing.T) {
	if got := EnforceBlockers(nil); len(got) != 1 || !strings.Contains(got[0], "policy is nil") {
		t.Errorf("EnforceBlockers(nil) = %v, want a nil-policy blocker", got)
	}
}
