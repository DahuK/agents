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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	yamlv3 "gopkg.in/yaml.v3"
	"sigs.k8s.io/yaml"
)

// ContractID names a versioned execution contract. A contract is the set of
// authored semantics a data plane promises to execute; documents outside it
// are still parseable and previewable, but cannot produce a decision artifact.
type ContractID string

// ContractEndpointRESTv1 is the only execution contract implemented by this
// package: explicit REST endpoints in explicit enforce mode, unique host:port
// pairs, and exact or "/**" path rules.
const ContractEndpointRESTv1 ContractID = "endpoint-rest-v1"

// Input budgets. They bound attacker-controlled documents and operation
// batches before any merge work happens, so an oversized request fails fast
// instead of consuming controller memory or time.
const (
	// MaxPolicyDocumentBytes caps the raw source and candidate documents.
	MaxPolicyDocumentBytes = 256 << 10
	// MaxPolicyDocumentDepth caps container nesting.
	MaxPolicyDocumentDepth = 32
	// MaxMergeOperations caps one atomic operation batch.
	MaxMergeOperations = 64
	// MaxPolicyEndpoints caps endpoints per network policy.
	MaxPolicyEndpoints = 256
	// MaxEndpointRules caps L7 rules per endpoint.
	MaxEndpointRules = 256
)

// PrepareErrorKind classifies a PrepareCandidate failure so callers can react
// without parsing error strings. The names follow the route's error taxonomy.
type PrepareErrorKind string

// PrepareCandidate error kinds.
const (
	// ErrorSyntax is an unparsable document.
	ErrorSyntax PrepareErrorKind = "syntax"
	// ErrorDuplicateField is a document with duplicate mapping keys.
	ErrorDuplicateField PrepareErrorKind = "duplicate_field"
	// ErrorVersion is an unsupported policy schema version.
	ErrorVersion PrepareErrorKind = "version"
	// ErrorInvalidPolicy is a structurally valid but invalid policy.
	ErrorInvalidPolicy PrepareErrorKind = "invalid_policy"
	// ErrorLimitExceeded is a document or operation batch over budget.
	ErrorLimitExceeded PrepareErrorKind = "limit_exceeded"
	// ErrorUnsupportedContract is a contract this build does not implement.
	ErrorUnsupportedContract PrepareErrorKind = "unsupported_contract"
	// ErrorMergeConflict is an operation that cannot apply to the document.
	ErrorMergeConflict PrepareErrorKind = "merge_conflict"
	// ErrorInternal is a bug or an encoding failure.
	ErrorInternal PrepareErrorKind = "internal"
)

// PrepareError carries the failure class, the failing operation index (or -1),
// and the underlying cause.
type PrepareError struct {
	Kind    PrepareErrorKind
	OpIndex int
	Err     error
}

// Error implements error.
func (e *PrepareError) Error() string {
	if e.OpIndex >= 0 {
		return fmt.Sprintf("prepare candidate: %s: merge operation %d: %v", e.Kind, e.OpIndex, e.Err)
	}
	return fmt.Sprintf("prepare candidate: %s: %v", e.Kind, e.Err)
}

// Unwrap exposes the underlying cause.
func (e *PrepareError) Unwrap() error { return e.Err }

func prepareError(kind PrepareErrorKind, format string, args ...any) *PrepareError {
	return &PrepareError{Kind: kind, OpIndex: -1, Err: fmt.Errorf(format, args...)}
}

// PrepareRequest is the single input to candidate preparation: the complete
// source document, an optional atomic operation batch, and the target
// execution contract.
type PrepareRequest struct {
	Source     []byte
	Operations []MergeOperation
	Contract   ContractID
}

// Identities separates the three hashes the governance loop must never
// conflate: the exact source bytes, the canonical source/candidate documents,
// and the compiled decision artifact.
type Identities struct {
	// SourceDigest is the sha256 of the exact source bytes as supplied.
	SourceDigest string
	// SourceSemanticIdentity is the sha256 of the canonical source document.
	SourceSemanticIdentity string
	// CandidateSemanticIdentity is the sha256 of the canonical candidate.
	CandidateSemanticIdentity string
	// ArtifactDigest is the sha256 of the compiled decision artifact. Empty
	// when the candidate is not enforceable under the requested contract.
	ArtifactDigest string
	// Contract is the execution contract the candidate was evaluated against.
	Contract ContractID
	// OpenShellVersion is the upstream semantic baseline this package pins.
	OpenShellVersion string
}

// Candidate is the complete result of PrepareCandidate. Document is always
// the full canonical candidate: sections and fields outside this package's
// model are preserved byte-for-byte in meaning rather than dropped.
type Candidate struct {
	// Document is the canonical full candidate document (JSON).
	Document []byte
	// Changed reports whether the operations changed the document.
	Changed bool
	// Warnings are non-fatal observations, including preview-only status.
	Warnings []string
	// Unsupported lists every reason the candidate cannot be enforced by the
	// requested contract. Empty means Supported.
	Unsupported []string
	// Supported reports whether a decision artifact was produced.
	Supported bool
	// Baseline is the parsed source document (used for risk comparison).
	Baseline *Policy
	// Policy is the parsed candidate document.
	Policy *Policy
	// Identities are the hashes described above.
	Identities Identities
	// Artifact is the compiled finite decision artifact, nil when unsupported.
	Artifact *DecisionArtifact
}

// PrepareCandidate applies an optional atomic operation batch to a complete
// OpenShell policy document without trimming it, then evaluates the result
// against the requested execution contract.
//
// The source document is decoded strictly: duplicate keys, oversize input,
// excessive nesting, and unsupported versions fail before any operation runs.
// Operations are applied in order to a private copy, so a failing batch
// produces no candidate and never a partially merged document.
func PrepareCandidate(req PrepareRequest) (*Candidate, error) {
	contract := req.Contract
	if contract == "" {
		contract = ContractEndpointRESTv1
	}
	if contract != ContractEndpointRESTv1 {
		return nil, prepareError(ErrorUnsupportedContract, "contract %q is not implemented by this build", contract)
	}
	if len(req.Source) == 0 {
		return nil, prepareError(ErrorSyntax, "source document is empty")
	}
	if len(req.Source) > MaxPolicyDocumentBytes {
		return nil, prepareError(ErrorLimitExceeded,
			"source document is %d bytes, limit is %d", len(req.Source), MaxPolicyDocumentBytes)
	}
	if len(req.Operations) > MaxMergeOperations {
		return nil, prepareError(ErrorLimitExceeded,
			"%d operations supplied, limit is %d", len(req.Operations), MaxMergeOperations)
	}

	sourceRoot, err := decodePolicyDocument(req.Source)
	if err != nil {
		return nil, err
	}
	sourceDocument, err := canonicalDocument(sourceRoot)
	if err != nil {
		return nil, prepareError(ErrorInternal, "canonicalize source: %v", err)
	}
	baseline, err := parsePreparedPolicy(sourceDocument)
	if err != nil {
		return nil, err
	}

	merged := cloneMap(sourceRoot)
	for i := range req.Operations {
		if err := applyRawOperation(merged, &req.Operations[i]); err != nil {
			return nil, &PrepareError{Kind: ErrorMergeConflict, OpIndex: i, Err: err}
		}
	}
	candidateDocument, err := canonicalDocument(merged)
	if err != nil {
		return nil, prepareError(ErrorInternal, "canonicalize candidate: %v", err)
	}
	// The operation batch is bounded, but it can still expand the document
	// (for example by adding many endpoints), so the budget applies to the
	// candidate as well as to the source.
	if len(candidateDocument) > MaxPolicyDocumentBytes {
		return nil, prepareError(ErrorLimitExceeded,
			"candidate document is %d bytes, limit is %d", len(candidateDocument), MaxPolicyDocumentBytes)
	}
	candidate, err := parsePreparedPolicy(candidateDocument)
	if err != nil {
		if len(req.Operations) == 0 {
			return nil, err
		}
		return nil, &PrepareError{
			Kind:    ErrorMergeConflict,
			OpIndex: len(req.Operations) - 1,
			Err:     fmt.Errorf("candidate policy is invalid: %w", err),
		}
	}
	if err := checkPreparedLimits(candidate); err != nil {
		return nil, err
	}

	unsupported := EnforceBlockers(candidate)
	identities := Identities{
		SourceDigest:              digestBytes(req.Source),
		SourceSemanticIdentity:    digestBytes(sourceDocument),
		CandidateSemanticIdentity: digestBytes(candidateDocument),
		Contract:                  contract,
		OpenShellVersion:          VersionBaseline,
	}
	result := &Candidate{
		Document:    candidateDocument,
		Changed:     !bytes.Equal(sourceDocument, candidateDocument),
		Unsupported: unsupported,
		Supported:   len(unsupported) == 0,
		Baseline:    baseline,
		Policy:      candidate,
		Identities:  identities,
	}
	if len(req.Operations) == 0 {
		result.Warnings = append(result.Warnings, "no operations supplied; candidate is the canonicalized source document")
	}
	if !result.Supported {
		result.Warnings = append(result.Warnings, fmt.Sprintf(
			"candidate is not enforceable by contract %s: %s", contract, strings.Join(unsupported, "; ")))
		return result, nil
	}

	artifact, err := CompileDecisionArtifact(candidate, identities)
	if err != nil {
		return nil, prepareError(ErrorInternal, "compile decision artifact: %v", err)
	}
	artifactDocument, err := json.Marshal(artifact)
	if err != nil {
		return nil, prepareError(ErrorInternal, "encode decision artifact: %v", err)
	}
	result.Identities.ArtifactDigest = digestBytes(artifactDocument)
	result.Artifact = artifact
	return result, nil
}

// decodePolicyDocument enforces the document budget and returns the full
// document as generic JSON values, with numbers kept as json.Number so the
// canonical encoding preserves their authored precision.
func decodePolicyDocument(data []byte) (map[string]any, error) {
	// yaml.v3 rejects duplicate mapping keys; sigs.k8s.io/yaml keeps the last
	// one silently, so the strict probe runs before the conversion.
	var probe any
	if err := yamlv3.Unmarshal(data, &probe); err != nil {
		kind := ErrorSyntax
		if strings.Contains(err.Error(), "already defined") {
			kind = ErrorDuplicateField
		}
		return nil, prepareError(kind, "%v", err)
	}
	jsonData, err := yaml.YAMLToJSON(data)
	if err != nil {
		return nil, prepareError(ErrorSyntax, "%v", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(jsonData))
	decoder.UseNumber()
	var raw any
	if err := decoder.Decode(&raw); err != nil {
		return nil, prepareError(ErrorSyntax, "%v", err)
	}
	root, ok := raw.(map[string]any)
	if !ok {
		return nil, prepareError(ErrorInvalidPolicy, "document must be a mapping, got %T", raw)
	}
	if err := checkDocumentDepth(root, 0); err != nil {
		return nil, prepareError(ErrorLimitExceeded, "%v", err)
	}
	return root, nil
}

func checkDocumentDepth(value any, depth int) error {
	if depth > MaxPolicyDocumentDepth {
		return fmt.Errorf("document nesting exceeds %d levels", MaxPolicyDocumentDepth)
	}
	switch typed := value.(type) {
	case map[string]any:
		for _, child := range typed {
			if err := checkDocumentDepth(child, depth+1); err != nil {
				return err
			}
		}
	case []any:
		for _, child := range typed {
			if err := checkDocumentDepth(child, depth+1); err != nil {
				return err
			}
		}
	}
	return nil
}

func parsePreparedPolicy(data []byte) (*Policy, error) {
	policy, err := ParsePolicy(data)
	if err == nil {
		return policy, nil
	}
	kind := ErrorInvalidPolicy
	if strings.Contains(err.Error(), "unsupported policy version") {
		kind = ErrorVersion
	}
	return nil, prepareError(kind, "%v", err)
}

func checkPreparedLimits(policy *Policy) error {
	for _, name := range policy.PolicyNames() {
		np := policy.NetworkPolicies[name]
		if len(np.Endpoints) > MaxPolicyEndpoints {
			return prepareError(ErrorLimitExceeded,
				"network policy %q has %d endpoints, limit is %d", name, len(np.Endpoints), MaxPolicyEndpoints)
		}
		for i := range np.Endpoints {
			if len(np.Endpoints[i].Rules) > MaxEndpointRules {
				return prepareError(ErrorLimitExceeded,
					"network policy %q endpoint %s:%d has %d rules, limit is %d",
					name, np.Endpoints[i].Host, np.Endpoints[i].Port, len(np.Endpoints[i].Rules), MaxEndpointRules)
			}
		}
	}
	return nil
}

func canonicalDocument(root map[string]any) ([]byte, error) {
	return json.Marshal(root)
}

func digestBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func cloneMap(root map[string]any) map[string]any {
	return cloneValue(root).(map[string]any)
}

func cloneValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		cloned := make(map[string]any, len(typed))
		for key, child := range typed {
			cloned[key] = cloneValue(child)
		}
		return cloned
	case []any:
		cloned := make([]any, len(typed))
		for i := range typed {
			cloned[i] = cloneValue(typed[i])
		}
		return cloned
	default:
		return value
	}
}

func applyRawOperation(root map[string]any, op *MergeOperation) error {
	set := 0
	for _, present := range []bool{
		op.AddNetworkRule != nil,
		op.RemoveNetworkRule != nil,
		op.RemoveNetworkEndpoint != nil,
		op.AddDenyRules != nil,
		op.AddAllowRules != nil,
		op.RemoveNetworkBinary != nil,
	} {
		if present {
			set++
		}
	}
	if set != 1 {
		return fmt.Errorf("exactly one of addNetworkRule, removeNetworkRule, removeNetworkEndpoint, addDenyRules, addAllowRules, removeNetworkBinary must be set, got %d", set)
	}
	switch {
	case op.AddNetworkRule != nil:
		return rawAddNetworkRule(root, op.AddNetworkRule)
	case op.RemoveNetworkRule != nil:
		return rawRemoveNetworkRule(root, op.RemoveNetworkRule)
	case op.RemoveNetworkEndpoint != nil:
		return rawRemoveNetworkEndpoint(root, op.RemoveNetworkEndpoint)
	case op.AddDenyRules != nil:
		return rawAddL7Rules(root, op.AddDenyRules, RuleActionReject)
	case op.AddAllowRules != nil:
		return rawAddL7Rules(root, op.AddAllowRules, RuleActionAllow)
	default:
		return rawRemoveNetworkBinary(root, op.RemoveNetworkBinary)
	}
}

func networkPoliciesMap(root map[string]any, create bool) (map[string]any, error) {
	raw, ok := root["network_policies"]
	if !ok || raw == nil {
		if !create {
			return map[string]any{}, nil
		}
		created := map[string]any{}
		root["network_policies"] = created
		return created, nil
	}
	policies, ok := raw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("network_policies must be a mapping")
	}
	return policies, nil
}

func lookupRawPolicy(root map[string]any, name string) (map[string]any, bool, error) {
	policies, err := networkPoliciesMap(root, false)
	if err != nil {
		return nil, false, err
	}
	raw, ok := policies[name]
	if !ok {
		return nil, false, nil
	}
	entry, ok := raw.(map[string]any)
	if !ok {
		return nil, false, fmt.Errorf("network policy %q must be a mapping", name)
	}
	return entry, true, nil
}

func rawAddNetworkRule(root map[string]any, op *AddNetworkRuleOp) error {
	if op.RuleName == "" {
		return fmt.Errorf("addNetworkRule: ruleName is required")
	}
	if len(op.Policy.Endpoints) == 0 {
		return fmt.Errorf("addNetworkRule %q: at least one endpoint is required", op.RuleName)
	}
	policies, err := networkPoliciesMap(root, true)
	if err != nil {
		return err
	}
	if _, exists := policies[op.RuleName]; exists {
		return fmt.Errorf("addNetworkRule %q: network policy already exists; remove it first or choose a new name", op.RuleName)
	}
	entry := map[string]any{}
	if op.Policy.Name != "" {
		entry["name"] = op.Policy.Name
	}
	endpoints := make([]any, 0, len(op.Policy.Endpoints))
	for _, endpoint := range op.Policy.Endpoints {
		raw, err := rawEndpointValue(endpoint)
		if err != nil {
			return fmt.Errorf("addNetworkRule %q: %w", op.RuleName, err)
		}
		endpoints = append(endpoints, raw)
	}
	entry["endpoints"] = endpoints
	if len(op.Policy.Binaries) > 0 {
		binaries := make([]any, 0, len(op.Policy.Binaries))
		for _, binary := range op.Policy.Binaries {
			binaries = append(binaries, map[string]any{"path": binary.Path})
		}
		entry["binaries"] = binaries
	}
	policies[op.RuleName] = entry
	return nil
}

func rawEndpointValue(endpoint Endpoint) (map[string]any, error) {
	if endpoint.Host == "" {
		return nil, fmt.Errorf("endpoint host is required")
	}
	if endpoint.Port < 1 || endpoint.Port > 65535 {
		return nil, fmt.Errorf("endpoint %s port %d out of range", endpoint.Host, endpoint.Port)
	}
	raw := map[string]any{"host": endpoint.Host, "port": int64(endpoint.Port)}
	if endpoint.Protocol != "" {
		raw["protocol"] = endpoint.Protocol
	}
	if endpoint.Enforcement != "" {
		raw["enforcement"] = endpoint.Enforcement
	}
	if endpoint.Access != "" {
		raw["access"] = endpoint.Access
	}
	if len(endpoint.Rules) > 0 {
		rules := make([]any, 0, len(endpoint.Rules))
		for _, rule := range endpoint.Rules {
			if rule.Action != RuleActionAllow && rule.Action != RuleActionReject {
				return nil, fmt.Errorf("rule has unknown action %q", rule.Action)
			}
			rules = append(rules, rawRuleValue(rule))
		}
		raw["rules"] = rules
	}
	return raw, nil
}

func rawRemoveNetworkRule(root map[string]any, op *RemoveNetworkRuleOp) error {
	entry, found, err := lookupRawPolicy(root, op.RuleName)
	if err != nil {
		return err
	}
	if !found || entry == nil {
		return fmt.Errorf("removeNetworkRule: network policy %q not found", op.RuleName)
	}
	policies, err := networkPoliciesMap(root, false)
	if err != nil {
		return err
	}
	delete(policies, op.RuleName)
	return nil
}

func rawRemoveNetworkEndpoint(root map[string]any, op *RemoveNetworkEndpointOp) error {
	entry, found, err := lookupRawPolicy(root, op.RuleName)
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("removeNetworkEndpoint: network policy %q not found", op.RuleName)
	}
	endpoints, err := rawEndpoints(entry)
	if err != nil {
		return err
	}
	for i := range endpoints {
		if rawEndpointMatches(endpoints[i], op.Host, op.Port) {
			endpoints = append(endpoints[:i], endpoints[i+1:]...)
			entry["endpoints"] = endpoints
			return nil
		}
	}
	return fmt.Errorf("removeNetworkEndpoint: endpoint %s:%d not found in network policy %q", op.Host, op.Port, op.RuleName)
}

func rawAddL7Rules(root map[string]any, op *AddL7RulesOp, want RuleAction) error {
	kind := "addDenyRules"
	if want == RuleActionAllow {
		kind = "addAllowRules"
	}
	if len(op.Rules) == 0 {
		return fmt.Errorf("%s: at least one rule is required", kind)
	}
	entry, found, err := lookupRawPolicy(root, op.Target.RuleName)
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("%s: network policy %q not found", kind, op.Target.RuleName)
	}
	endpoints, err := rawEndpoints(entry)
	if err != nil {
		return err
	}
	index := -1
	for i := range endpoints {
		if rawEndpointMatches(endpoints[i], op.Target.Host, op.Target.Port) {
			index = i
			break
		}
	}
	if index < 0 {
		return fmt.Errorf("%s: endpoint %s:%d not found in network policy %q",
			kind, op.Target.Host, op.Target.Port, op.Target.RuleName)
	}
	endpoint, ok := endpoints[index].(map[string]any)
	if !ok {
		return fmt.Errorf("%s: endpoint %s:%d must be a mapping", kind, op.Target.Host, op.Target.Port)
	}
	rules, err := rawRules(endpoint)
	if err != nil {
		return fmt.Errorf("%s: %w", kind, err)
	}
	for i, rule := range op.Rules {
		if rule.Action != want {
			return fmt.Errorf("%s: rule %d has action %q, want %q", kind, i, rule.Action, want)
		}
		rules = append(rules, rawRuleValue(rule))
	}
	endpoint["rules"] = rules
	endpoints[index] = endpoint
	entry["endpoints"] = endpoints
	return nil
}

func rawRemoveNetworkBinary(root map[string]any, op *RemoveNetworkBinaryOp) error {
	entry, found, err := lookupRawPolicy(root, op.RuleName)
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("removeNetworkBinary: network policy %q not found", op.RuleName)
	}
	raw, ok := entry["binaries"]
	if !ok || raw == nil {
		return fmt.Errorf("removeNetworkBinary: binary %q not bound in network policy %q", op.BinaryPath, op.RuleName)
	}
	binaries, ok := raw.([]any)
	if !ok {
		return fmt.Errorf("network policy %q binaries must be a list", op.RuleName)
	}
	for i := range binaries {
		binary, ok := binaries[i].(map[string]any)
		if !ok {
			continue
		}
		if path, _ := binary["path"].(string); path == op.BinaryPath {
			binaries = append(binaries[:i], binaries[i+1:]...)
			entry["binaries"] = binaries
			return nil
		}
	}
	return fmt.Errorf("removeNetworkBinary: binary %q not bound in network policy %q", op.BinaryPath, op.RuleName)
}

func rawEndpoints(entry map[string]any) ([]any, error) {
	raw, ok := entry["endpoints"]
	if !ok || raw == nil {
		return nil, nil
	}
	endpoints, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("network policy endpoints must be a list")
	}
	return endpoints, nil
}

func rawRules(endpoint map[string]any) ([]any, error) {
	raw, ok := endpoint["rules"]
	if !ok || raw == nil {
		return nil, nil
	}
	rules, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("endpoint rules must be a list")
	}
	return rules, nil
}

func rawEndpointMatches(value any, host string, port int32) bool {
	endpoint, ok := value.(map[string]any)
	if !ok {
		return false
	}
	rawHost, _ := endpoint["host"].(string)
	if !strings.EqualFold(rawHost, host) {
		return false
	}
	rawPort, ok := rawPortValue(endpoint["port"])
	return ok && rawPort == port
}

func rawPortValue(value any) (int32, bool) {
	switch typed := value.(type) {
	case json.Number:
		parsed, err := typed.Int64()
		if err != nil || parsed < 1 || parsed > 65535 {
			return 0, false
		}
		return int32(parsed), true
	case int:
		if typed < 1 || typed > 65535 {
			return 0, false
		}
		return int32(typed), true
	case int32:
		if typed < 1 || typed > 65535 {
			return 0, false
		}
		return typed, true
	case int64:
		if typed < 1 || typed > 65535 {
			return 0, false
		}
		return int32(typed), true
	case float64:
		if typed < 1 || typed > 65535 {
			return 0, false
		}
		port := int32(typed)
		if float64(port) != typed {
			return 0, false
		}
		return port, true
	default:
		return 0, false
	}
}

func rawRuleValue(rule Rule) map[string]any {
	body := map[string]any{}
	if rule.Method != "" {
		body["method"] = strings.ToUpper(rule.Method)
	}
	if rule.Path != "" {
		body["path"] = rule.Path
	}
	return map[string]any{string(rule.Action): body}
}
