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
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"
)

const prepareRESTDoc = `version: 1
network_policies:
  api:
    endpoints:
      - host: api.example.com
        port: 443
        protocol: rest
        enforcement: enforce
        access: full
`

// prepareUnmodeledDoc carries sections the restricted contract cannot
// execute. A merge must preserve every one of them.
const prepareUnmodeledDoc = `version: 1
process:
  run_as: sandbox
filesystem_policy:
  read_only: [/usr]
network_policies:
  api:
    description: do not drop me
    endpoints:
      - host: api.example.com
        port: 443
        protocol: rest
        enforcement: enforce
        access: full
        tls:
          verify: true
`

func TestPrepareCandidatePreservesUnmodeledSections(t *testing.T) {
	ops := []MergeOperation{
		{AddNetworkRule: &AddNetworkRuleOp{
			RuleName: "github",
			Policy: NetworkPolicy{Endpoints: []Endpoint{{
				Host:        "github.com",
				Port:        443,
				Protocol:    ProtocolREST,
				Enforcement: EnforcementEnforce,
				Access:      AccessFull,
			}}},
		}},
		{AddAllowRules: &AddL7RulesOp{
			Target: L7RuleTarget{RuleName: "api", Host: "api.example.com", Port: 443},
			Rules:  []Rule{{Action: RuleActionAllow, Method: "GET", Path: "/v2/**"}},
		}},
	}

	prepared, err := PrepareCandidate(PrepareRequest{Source: []byte(prepareUnmodeledDoc), Operations: ops})
	if err != nil {
		t.Fatalf("PrepareCandidate: %v", err)
	}

	// The candidate is a complete document: sections outside the trimmed
	// model survive the rewrite with their content intact.
	for _, fragment := range []string{
		`"process"`, `"run_as"`, `"sandbox"`,
		`"filesystem_policy"`, `"/usr"`,
		`"description"`, `"do not drop me"`,
		`"tls"`, `"verify"`,
		`"/v2/**"`,
	} {
		if !bytes.Contains(prepared.Document, []byte(fragment)) {
			t.Errorf("candidate document dropped %s: %s", fragment, prepared.Document)
		}
	}
	if _, ok := prepared.Policy.NetworkPolicies["github"]; !ok {
		t.Errorf("github policy missing from the parsed candidate")
	}
	if _, ok := prepared.Policy.NetworkPolicies["api"]; !ok {
		t.Errorf("baseline api policy must survive the merge")
	}
	if prepared.Changed != true {
		t.Errorf("Changed = false, want true for a candidate that adds a policy")
	}

	// Preservation is not endorsement: the restricted contract still cannot
	// execute the candidate, so it has no decision artifact.
	if prepared.Supported {
		t.Errorf("Supported = true, want false for a document with unmodeled sections")
	}
	if prepared.Artifact != nil {
		t.Errorf("Artifact = %+v, want nil for an unsupported candidate", prepared.Artifact)
	}
	if prepared.Identities.ArtifactDigest != "" {
		t.Errorf("ArtifactDigest = %q, want empty for an unsupported candidate", prepared.Identities.ArtifactDigest)
	}
	joined := strings.Join(prepared.Unsupported, "; ")
	for _, want := range []string{
		`field "process" is not modeled`,
		"filesystem_policy",
		`network_policies.api.description`,
		`network_policies.api.endpoints[0].tls`,
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("unsupported blockers = %q, want %q", joined, want)
		}
	}
	if len(prepared.Warnings) == 0 || !strings.Contains(strings.Join(prepared.Warnings, " "), "not enforceable") {
		t.Errorf("warnings = %v, want an explicit preview-only warning", prepared.Warnings)
	}
}

func TestPrepareCandidateSeparatesIdentities(t *testing.T) {
	// Two encodings of the same policy: distinct bytes, identical semantics.
	yamlSource := prepareRESTDoc
	jsonSource := `{"version":1,"network_policies":{"api":{"endpoints":[` +
		`{"protocol":"rest","port":443,"access":"full","enforcement":"enforce","host":"api.example.com"}]}}}`

	fromYAML, err := PrepareCandidate(PrepareRequest{Source: []byte(yamlSource)})
	if err != nil {
		t.Fatalf("PrepareCandidate(yaml): %v", err)
	}
	fromJSON, err := PrepareCandidate(PrepareRequest{Source: []byte(jsonSource)})
	if err != nil {
		t.Fatalf("PrepareCandidate(json): %v", err)
	}

	if fromYAML.Identities.SourceDigest == fromJSON.Identities.SourceDigest {
		t.Errorf("distinct source bytes share a source digest %q", fromYAML.Identities.SourceDigest)
	}
	if fromYAML.Identities.SourceSemanticIdentity != fromJSON.Identities.SourceSemanticIdentity {
		t.Errorf("equivalent documents diverge semantically: %q vs %q",
			fromYAML.Identities.SourceSemanticIdentity, fromJSON.Identities.SourceSemanticIdentity)
	}
	if !bytes.Equal(fromYAML.Document, fromJSON.Document) {
		t.Errorf("canonical documents differ:\n%s\n%s", fromYAML.Document, fromJSON.Document)
	}
	if fromYAML.Changed {
		t.Errorf("Changed = true, want false when no operations are supplied")
	}
	if fromYAML.Identities.CandidateSemanticIdentity != fromYAML.Identities.SourceSemanticIdentity {
		t.Errorf("a no-op candidate must keep the source semantic identity")
	}
	if fromYAML.Identities.Contract != ContractEndpointRESTv1 {
		t.Errorf("contract = %q, want %q", fromYAML.Identities.Contract, ContractEndpointRESTv1)
	}
	if fromYAML.Identities.OpenShellVersion != VersionBaseline {
		t.Errorf("openshell version = %q, want the pinned baseline", fromYAML.Identities.OpenShellVersion)
	}
	assertPrefixedDigest(t, "SourceDigest", fromYAML.Identities.SourceDigest)
	assertPrefixedDigest(t, "SourceSemanticIdentity", fromYAML.Identities.SourceSemanticIdentity)
	assertPrefixedDigest(t, "ArtifactDigest", fromYAML.Identities.ArtifactDigest)

	artifact, err := CompileDecisionArtifact(fromYAML.Policy, fromYAML.Identities)
	if err != nil {
		t.Fatalf("CompileDecisionArtifact: %v", err)
	}
	if artifact.SchemaVersion != DecisionArtifactSchemaVersion {
		t.Errorf("schema version = %q, want %q", artifact.SchemaVersion, DecisionArtifactSchemaVersion)
	}
	if fromYAML.Identities.ArtifactDigest == fromYAML.Identities.CandidateSemanticIdentity {
		t.Errorf("artifact digest must be independent of the semantic identity")
	}
	// The artifact binds the exact source bytes, so semantically equal
	// documents with different source bytes produce different artifacts even
	// though their semantic identities match.
	if fromYAML.Identities.ArtifactDigest == fromJSON.Identities.ArtifactDigest {
		t.Errorf("artifacts did not bind their distinct source digests")
	}

	// A changed candidate gets a new semantic identity and artifact digest.
	changed, err := PrepareCandidate(PrepareRequest{Source: []byte(yamlSource), Operations: []MergeOperation{
		{AddAllowRules: &AddL7RulesOp{
			Target: L7RuleTarget{RuleName: "api", Host: "api.example.com", Port: 443},
			Rules:  []Rule{{Action: RuleActionAllow, Method: "GET", Path: "/v1/**"}},
		}},
	}})
	if err != nil {
		t.Fatalf("PrepareCandidate(changed): %v", err)
	}
	if !changed.Changed {
		t.Errorf("Changed = false, want true after adding a rule")
	}
	if changed.Identities.SourceSemanticIdentity != fromYAML.Identities.SourceSemanticIdentity {
		t.Errorf("source identity changed with the candidate")
	}
	if changed.Identities.CandidateSemanticIdentity == fromYAML.Identities.CandidateSemanticIdentity {
		t.Errorf("candidate identity did not change")
	}
	if changed.Identities.ArtifactDigest == fromYAML.Identities.ArtifactDigest {
		t.Errorf("artifact digest did not change with the candidate")
	}

	// The artifact is deterministic: re-preparing the same request reproduces
	// its digest byte for byte.
	repeated, err := PrepareCandidate(PrepareRequest{Source: []byte(yamlSource), Operations: []MergeOperation{
		{AddAllowRules: &AddL7RulesOp{
			Target: L7RuleTarget{RuleName: "api", Host: "api.example.com", Port: 443},
			Rules:  []Rule{{Action: RuleActionAllow, Method: "GET", Path: "/v1/**"}},
		}},
	}})
	if err != nil {
		t.Fatalf("PrepareCandidate(repeated): %v", err)
	}
	if repeated.Identities.ArtifactDigest != changed.Identities.ArtifactDigest {
		t.Errorf("artifact digest is not reproducible: %q vs %q",
			repeated.Identities.ArtifactDigest, changed.Identities.ArtifactDigest)
	}
}

func assertPrefixedDigest(t *testing.T, name, digest string) {
	t.Helper()
	if !strings.HasPrefix(digest, "sha256:") || len(digest) != len("sha256:")+64 {
		t.Errorf("%s = %q, want a sha256:<64 hex> digest", name, digest)
	}
}

func TestPrepareCandidateOperationBatchIsAtomic(t *testing.T) {
	ops := []MergeOperation{
		{AddNetworkRule: &AddNetworkRuleOp{
			RuleName: "github",
			Policy: NetworkPolicy{Endpoints: []Endpoint{{
				Host:        "github.com",
				Port:        443,
				Protocol:    ProtocolREST,
				Enforcement: EnforcementEnforce,
				Access:      AccessFull,
			}}},
		}},
		{RemoveNetworkRule: &RemoveNetworkRuleOp{RuleName: "missing"}},
	}

	prepared, err := PrepareCandidate(PrepareRequest{Source: []byte(prepareRESTDoc), Operations: ops})
	if err == nil {
		t.Fatalf("PrepareCandidate succeeded, want a merge conflict on the second operation")
	}
	if prepared != nil {
		t.Fatalf("prepared = %+v, want nil: a failing batch must not yield a partial candidate", prepared)
	}
	var prepareErr *PrepareError
	if !errors.As(err, &prepareErr) {
		t.Fatalf("error %v is not a *PrepareError", err)
	}
	if prepareErr.Kind != ErrorMergeConflict {
		t.Errorf("kind = %q, want %q", prepareErr.Kind, ErrorMergeConflict)
	}
	if prepareErr.OpIndex != 1 {
		t.Errorf("op index = %d, want 1", prepareErr.OpIndex)
	}
	if !strings.Contains(prepareErr.Error(), "merge operation 1") {
		t.Errorf("error = %q, want the failing operation index", prepareErr.Error())
	}
}

func TestPrepareCandidateFailureTaxonomy(t *testing.T) {
	oversize := bytes.Repeat([]byte("a"), MaxPolicyDocumentBytes+1)

	deep := "1"
	for i := 0; i <= MaxPolicyDocumentDepth+1; i++ {
		deep = `{"a":` + deep + `}`
	}

	tests := []struct {
		name    string
		req     PrepareRequest
		kind    PrepareErrorKind
		opIndex int
	}{
		{
			name: "empty source",
			req:  PrepareRequest{},
			kind: ErrorSyntax,
		},
		{
			name: "oversize source",
			req:  PrepareRequest{Source: oversize},
			kind: ErrorLimitExceeded,
		},
		{
			name: "too many operations",
			req: PrepareRequest{
				Source:     []byte(prepareRESTDoc),
				Operations: make([]MergeOperation, MaxMergeOperations+1),
			},
			kind: ErrorLimitExceeded,
		},
		{
			name: "unsupported contract",
			req:  PrepareRequest{Source: []byte(prepareRESTDoc), Contract: ContractID("endpoint-rest-v2")},
			kind: ErrorUnsupportedContract,
		},
		{
			name: "duplicate keys",
			req: PrepareRequest{Source: []byte(`version: 1
version: 1
network_policies: {}
`)},
			kind: ErrorDuplicateField,
		},
		{
			name: "unsupported version",
			req:  PrepareRequest{Source: []byte("version: 2\nnetwork_policies: {}\n")},
			kind: ErrorVersion,
		},
		{
			name: "invalid policy",
			req:  PrepareRequest{Source: []byte("version: 1\nnetwork_policies:\n  api:\n    endpoints: []\n")},
			kind: ErrorInvalidPolicy,
		},
		{
			name: "excessive nesting",
			req:  PrepareRequest{Source: []byte(`{"version":1,"network_policies":{},"process":` + deep + `}`)},
			kind: ErrorLimitExceeded,
		},
		{
			name: "failing merge",
			req: PrepareRequest{Source: []byte(prepareRESTDoc), Operations: []MergeOperation{
				{RemoveNetworkRule: &RemoveNetworkRuleOp{RuleName: "missing"}},
			}},
			kind:    ErrorMergeConflict,
			opIndex: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			prepared, err := PrepareCandidate(tc.req)
			if prepared != nil {
				t.Fatalf("prepared = %+v, want nil on failure", prepared)
			}
			if err == nil {
				t.Fatalf("PrepareCandidate returned no error")
			}
			var prepareErr *PrepareError
			if !errors.As(err, &prepareErr) {
				t.Fatalf("error %v is not a *PrepareError", err)
			}
			if prepareErr.Kind != tc.kind {
				t.Errorf("kind = %q, want %q (error: %v)", prepareErr.Kind, tc.kind, err)
			}
			// Only merge conflicts carry an operation index.
			wantIndex := -1
			if tc.kind == ErrorMergeConflict {
				wantIndex = tc.opIndex
			}
			if prepareErr.OpIndex != wantIndex {
				t.Errorf("op index = %d, want %d", prepareErr.OpIndex, wantIndex)
			}
		})
	}
}

func TestPrepareCandidateRejectsOversizeCandidate(t *testing.T) {
	// Each operation is small, but together they expand the document past the
	// budget. The limit must apply to the candidate, not only to the source.
	longHost := strings.Repeat("h", 5<<10)
	ops := make([]MergeOperation, 0, MaxMergeOperations)
	for i := 0; i < MaxMergeOperations; i++ {
		ops = append(ops, MergeOperation{AddNetworkRule: &AddNetworkRuleOp{
			RuleName: fmt.Sprintf("added-%d", i),
			Policy: NetworkPolicy{Endpoints: []Endpoint{{
				Host:        longHost,
				Port:        443,
				Protocol:    ProtocolREST,
				Enforcement: EnforcementEnforce,
				Access:      AccessFull,
			}}},
		}})
	}

	prepared, err := PrepareCandidate(PrepareRequest{Source: []byte(prepareRESTDoc), Operations: ops})
	if prepared != nil {
		t.Fatalf("prepared = %+v, want nil for an oversized candidate", prepared)
	}
	var prepareErr *PrepareError
	if !errors.As(err, &prepareErr) || prepareErr.Kind != ErrorLimitExceeded {
		t.Fatalf("error = %v, want a limit_exceeded failure", err)
	}
	if !strings.Contains(err.Error(), "candidate document") {
		t.Errorf("error = %q, want it to name the candidate budget", err)
	}
}

func TestPrepareCandidateRejectsDuplicatePolicyNames(t *testing.T) {
	ops := []MergeOperation{
		{AddNetworkRule: &AddNetworkRuleOp{
			RuleName: "api",
			Policy: NetworkPolicy{Endpoints: []Endpoint{{
				Host:        "other.example.com",
				Port:        443,
				Protocol:    ProtocolREST,
				Enforcement: EnforcementEnforce,
				Access:      AccessFull,
			}}},
		}},
	}

	_, err := PrepareCandidate(PrepareRequest{Source: []byte(prepareRESTDoc), Operations: ops})
	var prepareErr *PrepareError
	if !errors.As(err, &prepareErr) || prepareErr.Kind != ErrorMergeConflict {
		t.Fatalf("error = %v, want a merge conflict for a duplicate policy name", err)
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("error = %q, want the duplicate-policy refusal", err)
	}
}
