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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	agentsv1alpha1 "github.com/openkruise/agents/api/v1alpha1"
)

// l7RuleBody is the wire body of a rule in OpenShell's single-key form.
type l7RuleBody struct {
	Method string `json:"method,omitempty"`
	Path   string `json:"path,omitempty"`
}

// MarshalJSON emits OpenShell's single-key rule wire form
// ({"allow": {"method": "GET", "path": "/x"}}), the inverse of
// UnmarshalJSON. Merged documents serialized with MarshalPolicy keep the
// exact rule shape the data plane parses.
func (r Rule) MarshalJSON() ([]byte, error) {
	if r.Action != RuleActionAllow && r.Action != RuleActionReject {
		return nil, fmt.Errorf("rule has unknown action %q", r.Action)
	}
	return json.Marshal(map[string]l7RuleBody{
		string(r.Action): {Method: r.Method, Path: r.Path},
	})
}

// MarshalPolicy serializes a Policy to canonical JSON: compact, map keys
// sorted, rules in OpenShell's single-key wire form. The output re-parses
// with ParsePolicy, so it is the exact document the data plane can enforce.
func MarshalPolicy(policy *Policy) ([]byte, error) {
	return json.Marshal(policy)
}

// PolicyHash returns the "sha256:<hex>" digest of the canonical JSON
// serialization. Proposals record the baseline and candidate hashes at
// admission; the apply step refuses to merge when the live document no
// longer hashes to the baseline, mirroring OpenShell's review token.
func PolicyHash(policy *Policy) (string, error) {
	data, err := MarshalPolicy(policy)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// MergeOperation is one OpenShell PolicyMergeOperation mapped onto the
// parsed policy model. Exactly one operation field is set.
type MergeOperation struct {
	AddNetworkRule        *AddNetworkRuleOp
	RemoveNetworkRule     *RemoveNetworkRuleOp
	RemoveNetworkEndpoint *RemoveNetworkEndpointOp
	AddDenyRules          *AddL7RulesOp
	AddAllowRules         *AddL7RulesOp
	RemoveNetworkBinary   *RemoveNetworkBinaryOp
}

// AddNetworkRuleOp adds a new network_policies entry. A name that already
// exists is rejected rather than replaced.
type AddNetworkRuleOp struct {
	RuleName string
	Policy   NetworkPolicy
}

// RemoveNetworkRuleOp deletes a whole network_policies entry.
type RemoveNetworkRuleOp struct {
	RuleName string
}

// RemoveNetworkEndpointOp deletes one endpoint from a network policy.
type RemoveNetworkEndpointOp struct {
	RuleName string
	Host     string
	Port     int32
}

// AddL7RulesOp appends deny or allow rules to an existing endpoint.
type AddL7RulesOp struct {
	Target L7RuleTarget
	Rules  []Rule
}

// L7RuleTarget identifies the endpoint rules append to, scoped by the
// endpoint's host:port within the named policy.
type L7RuleTarget struct {
	RuleName string
	Host     string
	Port     int32
}

// RemoveNetworkBinaryOp removes a binary binding from a network policy.
type RemoveNetworkBinaryOp struct {
	RuleName   string
	BinaryPath string
}

// ApplyMergeOperations is the model-level compatibility entry point for
// callers that only hold a parsed Policy. MarshalPolicy serializes the trimmed
// model, so fields the model cannot represent would be dropped on rewrite;
// this function refuses those documents instead of silently reducing them.
// PrepareCandidate is the authoritative entry point because it merges the
// complete document.
func ApplyMergeOperations(policy *Policy, ops []MergeOperation) (*Policy, []byte, error) {
	if policy == nil {
		return nil, nil, fmt.Errorf("merge operations: policy is required")
	}
	if len(ops) == 0 {
		return nil, nil, fmt.Errorf("merge operations: at least one operation is required")
	}
	if len(policy.UnsupportedFields) > 0 {
		return nil, nil, fmt.Errorf(
			"merge operations: policy contains fields this contract does not model (%s); refusing to rewrite the authoritative document",
			strings.Join(policy.UnsupportedFields, ", "))
	}
	data, err := MarshalPolicy(policy)
	if err != nil {
		return nil, nil, fmt.Errorf("merge operations: %w", err)
	}
	prepared, err := PrepareCandidate(PrepareRequest{
		Source:     data,
		Operations: ops,
		Contract:   ContractEndpointRESTv1,
	})
	if err != nil {
		var prepareErr *PrepareError
		if errors.As(err, &prepareErr) && prepareErr.OpIndex >= 0 {
			return nil, nil, fmt.Errorf("merge operation %d: %w", prepareErr.OpIndex, prepareErr.Err)
		}
		return nil, nil, err
	}
	return prepared.Policy, prepared.Document, nil
}

// ConvertMergeOperations converts the PolicyProposal API wire form into
// model operations. Rule actions must match their operation kind: deny rules
// ride addDenyRules, allow rules ride addAllowRules.
func ConvertMergeOperations(ops []agentsv1alpha1.PolicyMergeOperation) ([]MergeOperation, error) {
	if len(ops) == 0 {
		return nil, fmt.Errorf("operations: at least one operation is required")
	}
	converted := make([]MergeOperation, 0, len(ops))
	for i := range ops {
		op := &ops[i]
		var model MergeOperation
		switch {
		case op.AddNetworkRule != nil:
			add := &AddNetworkRuleOp{RuleName: op.AddNetworkRule.RuleName}
			for _, ep := range op.AddNetworkRule.Endpoints {
				add.Policy.Endpoints = append(add.Policy.Endpoints, convertEndpoint(ep))
			}
			for _, b := range op.AddNetworkRule.Binaries {
				add.Policy.Binaries = append(add.Policy.Binaries, BinaryRef{Path: b.Path})
			}
			model.AddNetworkRule = add
		case op.RemoveNetworkRule != nil:
			model.RemoveNetworkRule = &RemoveNetworkRuleOp{RuleName: op.RemoveNetworkRule.RuleName}
		case op.RemoveNetworkEndpoint != nil:
			model.RemoveNetworkEndpoint = &RemoveNetworkEndpointOp{
				RuleName: op.RemoveNetworkEndpoint.RuleName,
				Host:     op.RemoveNetworkEndpoint.Host,
				Port:     op.RemoveNetworkEndpoint.Port,
			}
		case op.AddDenyRules != nil:
			rules, err := convertL7Rules(op.AddDenyRules.Rules, RuleActionReject)
			if err != nil {
				return nil, fmt.Errorf("operations[%d].addDenyRules: %w", i, err)
			}
			model.AddDenyRules = &AddL7RulesOp{Target: convertL7RuleTarget(op.AddDenyRules.Target), Rules: rules}
		case op.AddAllowRules != nil:
			rules, err := convertL7Rules(op.AddAllowRules.Rules, RuleActionAllow)
			if err != nil {
				return nil, fmt.Errorf("operations[%d].addAllowRules: %w", i, err)
			}
			model.AddAllowRules = &AddL7RulesOp{Target: convertL7RuleTarget(op.AddAllowRules.Target), Rules: rules}
		case op.RemoveNetworkBinary != nil:
			model.RemoveNetworkBinary = &RemoveNetworkBinaryOp{
				RuleName:   op.RemoveNetworkBinary.RuleName,
				BinaryPath: op.RemoveNetworkBinary.BinaryPath,
			}
		default:
			return nil, fmt.Errorf("operations[%d]: exactly one operation must be set", i)
		}
		converted = append(converted, model)
	}
	return converted, nil
}

func convertEndpoint(ep agentsv1alpha1.PolicyEndpoint) Endpoint {
	converted := Endpoint{
		Host:        ep.Host,
		Port:        ep.Port,
		Protocol:    ep.Protocol,
		Enforcement: ep.Enforcement,
		Access:      ep.Access,
	}
	for _, r := range ep.Rules {
		converted.Rules = append(converted.Rules, Rule{
			Action: RuleAction(r.Action),
			Method: strings.ToUpper(r.Method),
			Path:   r.Path,
		})
	}
	return converted
}

func convertL7Rules(rules []agentsv1alpha1.PolicyL7Rule, want RuleAction) ([]Rule, error) {
	if len(rules) == 0 {
		return nil, fmt.Errorf("at least one rule is required")
	}
	out := make([]Rule, 0, len(rules))
	for i, r := range rules {
		action := RuleAction(r.Action)
		if action != want {
			return nil, fmt.Errorf("rules[%d]: action %q does not match the operation kind (want %q)", i, r.Action, want)
		}
		out = append(out, Rule{Action: action, Method: strings.ToUpper(r.Method), Path: r.Path})
	}
	return out, nil
}

func convertL7RuleTarget(target agentsv1alpha1.L7RuleTarget) L7RuleTarget {
	return L7RuleTarget{RuleName: target.RuleName, Host: target.Host, Port: target.Port}
}
