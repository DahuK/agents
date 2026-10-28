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
	"strconv"
	"strings"
	"testing"
)

// artifactDoc exercises every shape the restricted contract can compile:
// presets, explicit rules overriding a preset, and an endpoint that allows
// nothing.
const artifactDoc = `version: 1
network_policies:
  read:
    endpoints:
      - host: Read.Example.COM
        port: 443
        protocol: rest
        enforcement: enforce
        access: read-only
  write:
    endpoints:
      - host: write.example.com
        port: 443
        protocol: rest
        enforcement: enforce
        access: read-write
  any:
    endpoints:
      - host: any.example.com
        port: 8443
        protocol: rest
        enforcement: enforce
        access: full
  explicit:
    endpoints:
      - host: explicit.example.com
        port: 443
        protocol: rest
        enforcement: enforce
        access: full
        rules:
          - allow: { method: get, path: /v1/** }
          - deny: { method: POST, path: /v1/admin }
  closed:
    endpoints:
      - host: closed.example.com
        port: 443
        protocol: rest
        enforcement: enforce
`

func TestCompileDecisionArtifactExpandsRestrictedContract(t *testing.T) {
	policy, err := ParsePolicy([]byte(artifactDoc))
	if err != nil {
		t.Fatalf("ParsePolicy: %v", err)
	}
	identities := Identities{
		Contract:                  ContractEndpointRESTv1,
		SourceDigest:              "sha256:source",
		CandidateSemanticIdentity: "sha256:candidate",
	}

	artifact, err := CompileDecisionArtifact(policy, identities)
	if err != nil {
		t.Fatalf("CompileDecisionArtifact: %v", err)
	}
	if artifact.SchemaVersion != DecisionArtifactSchemaVersion {
		t.Errorf("schema version = %q, want %q", artifact.SchemaVersion, DecisionArtifactSchemaVersion)
	}
	if artifact.Contract != ContractEndpointRESTv1 {
		t.Errorf("contract = %q, want %q", artifact.Contract, ContractEndpointRESTv1)
	}
	if artifact.OpenShellVersion != VersionBaseline {
		t.Errorf("openshell version = %q, want the pinned baseline", artifact.OpenShellVersion)
	}
	if artifact.SourceDigest != identities.SourceDigest {
		t.Errorf("source digest = %q, want the supplied source digest", artifact.SourceDigest)
	}
	if artifact.SemanticIdentity != identities.CandidateSemanticIdentity {
		t.Errorf("semantic identity = %q, want the candidate identity", artifact.SemanticIdentity)
	}

	// Endpoints are sorted by host then port so the artifact is stable.
	wantOrder := []string{
		"any.example.com:8443",
		"closed.example.com:443",
		"explicit.example.com:443",
		"read.example.com:443",
		"write.example.com:443",
	}
	gotOrder := make([]string, 0, len(artifact.Endpoints))
	for _, endpoint := range artifact.Endpoints {
		gotOrder = append(gotOrder, endpoint.Host+":"+strconv.Itoa(int(endpoint.Port)))
		if endpoint.Protocol != ProtocolREST || endpoint.Enforcement != EnforcementEnforce {
			t.Errorf("endpoint %s = %+v, want explicit rest/enforce", endpoint.Host, endpoint)
		}
	}
	if !reflect.DeepEqual(gotOrder, wantOrder) {
		t.Errorf("endpoint order = %v, want %v", gotOrder, wantOrder)
	}

	// Hostnames are normalized so a rule never depends on author casing.
	read := requireArtifactEndpoint(t, artifact, "read.example.com")
	if want := []ArtifactRule{{Method: "GET"}, {Method: "HEAD"}, {Method: "OPTIONS"}}; !reflect.DeepEqual(read.Allow, want) {
		t.Errorf("read-only allow = %+v, want %+v", read.Allow, want)
	}
	if read.Deny != nil {
		t.Errorf("read-only deny = %+v, want none", read.Deny)
	}

	write := requireArtifactEndpoint(t, artifact, "write.example.com")
	wantWrite := []ArtifactRule{
		{Method: "GET"}, {Method: "HEAD"}, {Method: "OPTIONS"},
		{Method: "POST"}, {Method: "PUT"}, {Method: "PATCH"},
	}
	if !reflect.DeepEqual(write.Allow, wantWrite) {
		t.Errorf("read-write allow = %+v, want %+v", write.Allow, wantWrite)
	}

	any := requireArtifactEndpoint(t, artifact, "any.example.com")
	if want := []ArtifactRule{{Method: "*"}}; !reflect.DeepEqual(any.Allow, want) {
		t.Errorf("full-access allow = %+v, want %+v", any.Allow, want)
	}

	// Explicit rules govern exclusively: the full-access preset must not be
	// expanded in addition to the authored allow rule.
	explicit := requireArtifactEndpoint(t, artifact, "explicit.example.com")
	wantAllow := []ArtifactRule{{Method: "GET", Path: "/v1/**"}}
	if !reflect.DeepEqual(explicit.Allow, wantAllow) {
		t.Errorf("explicit allow = %+v, want %+v", explicit.Allow, wantAllow)
	}
	wantDeny := []ArtifactRule{{Method: "POST", Path: "/v1/admin"}}
	if !reflect.DeepEqual(explicit.Deny, wantDeny) {
		t.Errorf("explicit deny = %+v, want %+v", explicit.Deny, wantDeny)
	}

	// An endpoint with neither a preset nor a rule allows nothing.
	closed := requireArtifactEndpoint(t, artifact, "closed.example.com")
	if len(closed.Allow) != 0 || len(closed.Deny) != 0 {
		t.Errorf("closed endpoint = %+v, want deny-all", closed)
	}
}

func TestCompileDecisionArtifactRefusesUnenforceablePolicies(t *testing.T) {
	tests := []struct {
		name string
		doc  string
		want string
	}{
		{
			name: "binaries",
			doc: `version: 1
network_policies:
  curl:
    binaries:
      - path: /usr/bin/curl
    endpoints:
      - host: api.example.com
        port: 443
        protocol: rest
        enforcement: enforce
        access: full
`,
			want: "binaries",
		},
		{
			name: "audit enforcement",
			doc: `version: 1
network_policies:
  api:
    endpoints:
      - host: api.example.com
        port: 443
        protocol: rest
        enforcement: audit
        access: full
`,
			want: "enforcement",
		},
		{
			name: "non-REST protocol",
			doc: `version: 1
network_policies:
  api:
    endpoints:
      - host: api.example.com
        port: 443
        protocol: grpc
        enforcement: enforce
`,
			want: "protocol",
		},
	}

	identities := Identities{Contract: ContractEndpointRESTv1}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			policy, err := ParsePolicy([]byte(tc.doc))
			if err != nil {
				t.Fatalf("ParsePolicy: %v", err)
			}
			artifact, err := CompileDecisionArtifact(policy, identities)
			if err == nil {
				t.Fatalf("CompileDecisionArtifact succeeded, want a refusal; artifact = %+v", artifact)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to name %q", err, tc.want)
			}
		})
	}
}

func TestCompileDecisionArtifactRequiresKnownContract(t *testing.T) {
	policy, err := ParsePolicy([]byte(artifactDoc))
	if err != nil {
		t.Fatalf("ParsePolicy: %v", err)
	}
	for _, contract := range []ContractID{"", ContractID("endpoint-rest-v9")} {
		artifact, err := CompileDecisionArtifact(policy, Identities{Contract: contract})
		if err == nil {
			t.Fatalf("contract %q: CompileDecisionArtifact succeeded, want a refusal", contract)
		}
		if artifact != nil {
			t.Errorf("contract %q: artifact = %+v, want nil", contract, artifact)
		}
		if !strings.Contains(err.Error(), "decision artifact schema") {
			t.Errorf("contract %q: error = %q, want the schema refusal", contract, err)
		}
	}

	if _, err := CompileDecisionArtifact(nil, Identities{Contract: ContractEndpointRESTv1}); err == nil {
		t.Errorf("nil policy: CompileDecisionArtifact succeeded, want an error")
	}
}

func requireArtifactEndpoint(t *testing.T, artifact *DecisionArtifact, host string) ArtifactEndpoint {
	t.Helper()
	for _, endpoint := range artifact.Endpoints {
		if endpoint.Host == host {
			return endpoint
		}
	}
	t.Fatalf("artifact has no endpoint %q: %+v", host, artifact.Endpoints)
	return ArtifactEndpoint{}
}
