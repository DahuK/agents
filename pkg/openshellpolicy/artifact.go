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
	"fmt"
	"sort"
	"strings"
)

// DecisionArtifactSchemaVersion is the wire schema of DecisionArtifact. A
// consumer that does not know this value must reject the artifact instead of
// interpreting the authored policy language itself.
const DecisionArtifactSchemaVersion = "v1"

// DecisionArtifact is the finite, immutable output of compiling a candidate
// under an execution contract. It contains only concrete host/port endpoints
// and expanded method/path rules, so the data plane never re-implements
// OpenShell's authored presets, defaults, or merge semantics.
type DecisionArtifact struct {
	// SchemaVersion is DecisionArtifactSchemaVersion.
	SchemaVersion string `json:"schemaVersion"`
	// Contract is the execution contract this artifact implements.
	Contract ContractID `json:"contract"`
	// OpenShellVersion is the upstream semantic baseline that produced it.
	OpenShellVersion string `json:"openshellVersion"`
	// SourceDigest identifies the exact source document bytes.
	SourceDigest string `json:"sourceDigest"`
	// SemanticIdentity identifies the canonical candidate document.
	SemanticIdentity string `json:"semanticIdentity"`
	// Endpoints is the executable rule set, sorted by host and port.
	Endpoints []ArtifactEndpoint `json:"endpoints"`
}

// ArtifactEndpoint is one executable endpoint under endpoint-rest-v1.
type ArtifactEndpoint struct {
	// Policy is the authored network policy key, kept for attribution.
	Policy string `json:"policy"`
	// Host is the lower-cased destination hostname.
	Host string `json:"host"`
	// Port is the destination port.
	Port int32 `json:"port"`
	// Protocol is always "rest"; other protocols are rejected.
	Protocol string `json:"protocol"`
	// Enforcement is always "enforce"; audit endpoints are rejected.
	Enforcement string `json:"enforcement"`
	// Allow rules are evaluated after every deny rule.
	Allow []ArtifactRule `json:"allow,omitempty"`
	// Deny rules reject a matching request regardless of allow rules.
	Deny []ArtifactRule `json:"deny,omitempty"`
}

// ArtifactRule is one fully expanded method/path rule. Method "*" matches any
// method; Path is empty (any path), an exact path, or a "/**" prefix.
type ArtifactRule struct {
	Method string `json:"method"`
	Path   string `json:"path,omitempty"`
}

// CompileDecisionArtifact turns a parsed candidate into the immutable artifact
// a policy-enforcement point can execute. It refuses any document that the
// restricted contract cannot fully express, so an artifact is never a lossy
// approximation.
func CompileDecisionArtifact(policy *Policy, identities Identities) (*DecisionArtifact, error) {
	if policy == nil {
		return nil, fmt.Errorf("policy is nil")
	}
	if identities.Contract != ContractEndpointRESTv1 {
		return nil, fmt.Errorf("contract %q has no decision artifact schema", identities.Contract)
	}
	if blockers := EnforceBlockers(policy); len(blockers) > 0 {
		return nil, fmt.Errorf("policy is not enforceable by contract %s: %s",
			identities.Contract, strings.Join(blockers, "; "))
	}
	artifact := &DecisionArtifact{
		SchemaVersion:    DecisionArtifactSchemaVersion,
		Contract:         identities.Contract,
		OpenShellVersion: VersionBaseline,
		SourceDigest:     identities.SourceDigest,
		SemanticIdentity: identities.CandidateSemanticIdentity,
		Endpoints:        make([]ArtifactEndpoint, 0, len(policy.NetworkPolicies)),
	}
	for _, name := range policy.PolicyNames() {
		np := policy.NetworkPolicies[name]
		for i := range np.Endpoints {
			endpoint := np.Endpoints[i]
			allow, deny := artifactEndpointRules(endpoint)
			artifact.Endpoints = append(artifact.Endpoints, ArtifactEndpoint{
				Policy:      name,
				Host:        strings.ToLower(endpoint.Host),
				Port:        endpoint.Port,
				Protocol:    ProtocolREST,
				Enforcement: EnforcementEnforce,
				Allow:       allow,
				Deny:        deny,
			})
		}
	}
	sort.Slice(artifact.Endpoints, func(i, j int) bool {
		left, right := artifact.Endpoints[i], artifact.Endpoints[j]
		if left.Host != right.Host {
			return left.Host < right.Host
		}
		return left.Port < right.Port
	})
	return artifact, nil
}

// artifactEndpointRules expands the endpoint into concrete rules. Explicit
// rules govern the endpoint exclusively, mirroring the evaluator: presets are
// only expanded when the author wrote no rules at all. An endpoint with
// neither rules nor a preset compiles to an explicit deny-all endpoint.
func artifactEndpointRules(endpoint Endpoint) (allow, deny []ArtifactRule) {
	for _, rule := range endpoint.Rules {
		compiled := ArtifactRule{Method: artifactMethod(rule.Method), Path: rule.Path}
		if rule.Action == RuleActionReject {
			deny = append(deny, compiled)
			continue
		}
		allow = append(allow, compiled)
	}
	if len(endpoint.Rules) > 0 {
		return allow, deny
	}
	for _, method := range presetMethods(endpoint.Access) {
		allow = append(allow, ArtifactRule{Method: method})
	}
	return allow, deny
}

// presetMethods expands an access preset into concrete methods. The sets match
// the evaluator and upstream Rust exactly: read-only is GET/HEAD/OPTIONS and
// read-write adds POST/PUT/PATCH. TRACE is never part of a preset.
func presetMethods(access string) []string {
	switch access {
	case AccessFull:
		return []string{"*"}
	case AccessReadOnly:
		return []string{"GET", "HEAD", "OPTIONS"}
	case AccessReadWrite:
		return []string{"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH"}
	default:
		return nil
	}
}

func artifactMethod(method string) string {
	if method == "" {
		return "*"
	}
	return strings.ToUpper(method)
}
