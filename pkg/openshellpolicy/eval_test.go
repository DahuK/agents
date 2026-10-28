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
	"strings"
	"testing"
)

func TestEvaluate(t *testing.T) {
	policy := loadDemoPolicy(t)

	tests := []struct {
		name          string
		req           Request
		wantAllowed   bool
		wantAuditOnly bool
		wantPolicy    string
		wantDetail    string
		wantLayer     string
		wantMissing   string
	}{
		{
			name:        "full access GET",
			req:         Request{Host: "api.openai.com", Port: 443, Method: "GET", Path: "/v1/responses"},
			wantAllowed: true,
		},
		{
			name:        "full access write method",
			req:         Request{Host: "api.openai.com", Port: 443, Method: "POST", Path: "/v1/responses"},
			wantAllowed: true,
		},
		{
			name:        "read-only endpoint admits GET",
			req:         Request{Host: "api.github.com", Port: 443, Method: "GET", Path: "/repos/o/r"},
			wantAllowed: true,
		},
		{
			name:        "read-only endpoint denies PUT",
			req:         Request{Host: "api.github.com", Port: 443, Method: "PUT", Path: "/repos/o/r/contents/f", Binary: "/usr/bin/curl"},
			wantPolicy:  "github-api-readonly",
			wantDetail:  "endpoint is read-only",
			wantLayer:   "l7",
			wantMissing: "rest_allow",
		},
		{
			name:        "unknown host is denied at the network layer",
			req:         Request{Host: "evil.example.com", Port: 443, Method: "GET", Path: "/"},
			wantDetail:  "network connections not allowed by policy",
			wantLayer:   "network",
			wantMissing: "network_allow",
		},
		{
			name:        "known host wrong port is denied at the network layer",
			req:         Request{Host: "api.github.com", Port: 8443, Method: "GET", Path: "/"},
			wantDetail:  "network connections not allowed by policy",
			wantLayer:   "network",
			wantMissing: "network_allow",
		},
		{
			name:        "exact allow rule admits the scoped path",
			req:         Request{Host: "raw.githubusercontent.com", Port: 443, Method: "GET", Path: "/github/rest-api-description/main/README.md"},
			wantAllowed: true,
		},
		{
			name:        "missing allow rule denies the unscoped path",
			req:         Request{Host: "raw.githubusercontent.com", Port: 443, Method: "GET", Path: "/github/other/main/README.md"},
			wantPolicy:  "github-raw-scoped",
			wantDetail:  "no matching rest allow rule",
			wantLayer:   "l7",
			wantMissing: "rest_allow",
		},
		{
			name:        "explicit deny rule wins over an allow-rule miss",
			req:         Request{Host: "raw.githubusercontent.com", Port: 443, Method: "GET", Path: "/github/rest-api-description/main/secrets/token"},
			wantPolicy:  "github-raw-scoped",
			wantDetail:  "denied by explicit rest deny rule",
			wantLayer:   "l7",
			wantMissing: "rest_deny",
		},
		{
			name:          "audit endpoint forwards and flags audit-only",
			req:           Request{Host: "metrics.internal", Port: 443, Method: "POST", Path: "/v1/ingest"},
			wantAllowed:   true,
			wantAuditOnly: true,
		},
		{
			name:        "non-rest protocol endpoint is refused, not approximated",
			req:         Request{Host: "registry.internal", Port: 5000, Method: "GET", Path: "/v2/"},
			wantPolicy:  "registry-mirror",
			wantDetail:  `endpoint protocol "http" is not supported by the restricted REST enforcement contract`,
			wantLayer:   "l7",
			wantMissing: "rest_allow",
		},
		{
			name:        "request normalization folds host case, trailing dot, and method",
			req:         Request{Host: "API.GitHub.COM.", Port: 443, Method: "get", Path: "/repos/o/r"},
			wantAllowed: true,
		},
		{
			name:        "read-only endpoint admits HEAD",
			req:         Request{Host: "api.github.com", Port: 443, Method: "HEAD", Path: "/repos/o/r"},
			wantAllowed: true,
		},
		{
			name:        "read-only endpoint admits OPTIONS",
			req:         Request{Host: "api.github.com", Port: 443, Method: "OPTIONS", Path: "/repos/o/r"},
			wantAllowed: true,
		},
		{
			name:        "read-only endpoint denies TRACE",
			req:         Request{Host: "api.github.com", Port: 443, Method: "TRACE", Path: "/repos/o/r"},
			wantPolicy:  "github-api-readonly",
			wantDetail:  "endpoint is read-only",
			wantLayer:   "l7",
			wantMissing: "rest_allow",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision := Evaluate(policy, tt.req)
			if decision.Allowed != tt.wantAllowed {
				t.Fatalf("Allowed = %v, want %v (decision %+v)", decision.Allowed, tt.wantAllowed, decision)
			}
			if decision.AuditOnly != tt.wantAuditOnly {
				t.Errorf("AuditOnly = %v, want %v", decision.AuditOnly, tt.wantAuditOnly)
			}
			if tt.wantAllowed {
				if decision.Denial != nil {
					t.Errorf("Denial set on an allowed decision: %+v", decision.Denial)
				}
				return
			}
			if decision.Denial == nil {
				t.Fatalf("Denial missing on a denied decision")
			}
			if decision.Denial.HTTPStatus != 403 {
				t.Errorf("HTTPStatus = %d, want 403", decision.Denial.HTTPStatus)
			}
			body := decision.Denial.Body
			if body.Error != "policy_denied" {
				t.Errorf("Error = %q, want policy_denied", body.Error)
			}
			if body.Policy != tt.wantPolicy {
				t.Errorf("Policy = %q, want %q", body.Policy, tt.wantPolicy)
			}
			if body.Detail != tt.wantDetail {
				t.Errorf("Detail = %q, want %q", body.Detail, tt.wantDetail)
			}
			if body.Layer != tt.wantLayer {
				t.Errorf("Layer = %q, want %q", body.Layer, tt.wantLayer)
			}
			if body.RuleMissing == nil {
				t.Fatalf("RuleMissing missing")
			}
			if body.RuleMissing.Type != tt.wantMissing {
				t.Errorf("RuleMissing.Type = %q, want %q", body.RuleMissing.Type, tt.wantMissing)
			}
			if body.RuleMissing.Method != tt.req.Method {
				t.Errorf("RuleMissing.Method = %q, want %q", body.RuleMissing.Method, tt.req.Method)
			}
			if body.RuleMissing.Path != tt.req.Path {
				t.Errorf("RuleMissing.Path = %q, want %q", body.RuleMissing.Path, tt.req.Path)
			}
		})
	}
}

func TestEvaluateNilPolicyFailsClosed(t *testing.T) {
	decision := Evaluate(nil, Request{Host: "api.github.com", Port: 443, Method: "GET", Path: "/"})
	if decision.Allowed {
		t.Fatal("nil policy admitted a request, want default-deny")
	}
	if decision.Denial == nil || decision.Denial.Body.Layer != "network" {
		t.Fatalf("expected network-layer denial, got %+v", decision)
	}
}

func TestEvaluateNextSteps(t *testing.T) {
	policy := loadDemoPolicy(t)
	req := Request{Host: "api.github.com", Port: 443, Method: "PUT", Path: "/repos/o/r/contents/f"}
	opts := NextStepsOptions{
		ProposalURL: "http://gateway.openshell.svc/v1/proposals",
		SkillPath:   "/etc/openshell/skills/policy_advisor.md",
	}

	decision := EvaluateWithNextSteps(policy, req, opts)
	if decision.Allowed {
		t.Fatal("PUT on a read-only endpoint must be denied")
	}
	steps := decision.Denial.Body.NextSteps
	if len(steps) != 2 {
		t.Fatalf("NextSteps has %d entries, want 2 (read_skill, submit_proposal): %+v", len(steps), steps)
	}
	if steps[0].Action != "read_skill" || steps[0].Path != opts.SkillPath {
		t.Errorf("steps[0] = %+v, want read_skill pointing at the advisor skill", steps[0])
	}
	if steps[1].Action != "submit_proposal" || steps[1].URL != opts.ProposalURL || steps[1].BodyType != "PolicyMergeOperation" {
		t.Errorf("steps[1] = %+v, want submit_proposal pointing at the proposal endpoint", steps[1])
	}

	// The default (no options) must serialize an empty list, not null, so
	// agent-side JSON parsing of OpenShell-shaped bodies stays uniform.
	defaultDecision := Evaluate(policy, req)
	encoded, err := json.Marshal(defaultDecision.Denial.Body)
	if err != nil {
		t.Fatalf("marshal deny body: %v", err)
	}
	if !strings.Contains(string(encoded), `"next_steps":[]`) {
		t.Errorf("deny body JSON = %s, want \"next_steps\":[]", encoded)
	}
}

func TestEvaluateAccessPresetsAndEnforcementDefaults(t *testing.T) {
	policy := &Policy{NetworkPolicies: map[string]NetworkPolicy{
		"rw": {
			Endpoints: []Endpoint{{Host: "rw.example.com", Port: 443, Protocol: ProtocolREST, Enforcement: EnforcementEnforce, Access: AccessReadWrite}},
		},
		"audit": {
			Endpoints: []Endpoint{{Host: "audit.example.com", Port: 443, Protocol: ProtocolREST, Access: AccessFull}},
		},
		"bare": {
			Endpoints: []Endpoint{{Host: "bare.example.com", Port: 443, Protocol: ProtocolREST, Enforcement: EnforcementEnforce}},
		},
	}}

	allowed := []Request{
		{Host: "rw.example.com", Port: 443, Method: "GET", Path: "/v1"},
		{Host: "rw.example.com", Port: 443, Method: "HEAD", Path: "/v1"},
		{Host: "rw.example.com", Port: 443, Method: "OPTIONS", Path: "/v1"},
		{Host: "rw.example.com", Port: 443, Method: "POST", Path: "/v1"},
		{Host: "rw.example.com", Port: 443, Method: "PUT", Path: "/v1"},
		{Host: "rw.example.com", Port: 443, Method: "PATCH", Path: "/v1"},
	}
	for _, req := range allowed {
		if decision := Evaluate(policy, req); !decision.Allowed {
			t.Errorf("%s %s: denied, want allowed (%+v)", req.Method, req.Path, decision.Denial)
		}
	}

	denied := []Request{
		{Host: "rw.example.com", Port: 443, Method: "DELETE", Path: "/v1"},
		{Host: "rw.example.com", Port: 443, Method: "TRACE", Path: "/v1"},
		{Host: "bare.example.com", Port: 443, Method: "GET", Path: "/"},
	}
	for _, req := range denied {
		decision := Evaluate(policy, req)
		if decision.Allowed {
			t.Errorf("%s %s: allowed, want denied by the restricted preset", req.Method, req.Path)
		}
	}
	if d := Evaluate(policy, denied[2]); d.Denial == nil || d.Denial.Body.Detail != "endpoint has no access preset and no allow rule" {
		t.Errorf("bare endpoint denial = %+v, want the no-preset message", d.Denial)
	}

	// OpenShell treats an omitted enforcement value as audit; the evaluator
	// must forward and flag it instead of denying traffic that upstream would
	// observe.
	decision := Evaluate(policy, Request{Host: "audit.example.com", Port: 443, Method: "POST", Path: "/v1"})
	if !decision.Allowed || !decision.AuditOnly || decision.Denial != nil {
		t.Errorf("audit decision = %+v, want allowed with AuditOnly", decision)
	}
}

func TestEvaluateRejectsNonCanonicalPaths(t *testing.T) {
	policy := loadDemoPolicy(t)
	paths := []string{
		"/safe/../admin",
		"/safe/./admin",
		"/safe//admin",
		"/safe/%2e%2e/admin",
		"/safe%2fadmin",
		"/safe%2Fadmin",
		"/safe%5cadmin",
		"/safe%252fadmin",
		"/safe#fragment",
		`/safe\admin`,
	}
	for _, path := range paths {
		decision := Evaluate(policy, Request{Host: "raw.githubusercontent.com", Port: 443, Method: "GET", Path: path})
		if decision.Allowed {
			t.Errorf("path %q was allowed, want denial", path)
			continue
		}
		if decision.Denial.Body.Detail != "request path is not canonical; dot segments, duplicate slashes, and encoded separators are rejected" {
			t.Errorf("path %q denial = %q, want the canonical-path message", path, decision.Denial.Body.Detail)
		}
	}

	// A decoded but otherwise canonical path is matched after unescaping, so
	// ordinary percent-encoded characters keep working.
	if decision := Evaluate(policy, Request{Host: "api.github.com", Port: 443, Method: "GET", Path: "/repos/o/r%20x"}); !decision.Allowed {
		t.Errorf("percent-encoded ordinary character was denied: %+v", decision.Denial)
	}
}
