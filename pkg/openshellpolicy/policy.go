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

// Package openshellpolicy parses OpenShell sandbox policies and provides the
// bridge pieces needed to reuse OpenShell's policy governance on top of
// OpenKruise Agents sandboxes without changing their runtime or guest
// architecture: an L7 request evaluator that mirrors OpenShell's REST decision
// semantics, a coarse mapper that projects an OpenShell policy onto a
// TrafficPolicy CR while recording everything the L4 egress layer cannot
// express, and a projector that embeds the approved document verbatim into a
// SecurityProfile rule for the L7 enforcement data plane.
//
// The package is deliberately dependency-light and policy-neutral with respect
// to the repository's layering: it may be consumed by the controller and the
// sandbox-manager layers, and must not depend on either.
//
// Semantic scope (see docs/proposals/20261023-openshell-policy-governance_zh.md):
//   - network_policies endpoints with protocol "rest" are evaluated at L7
//     (method/path), matching OpenShell's sandbox-policy.rego allow_request
//     and deny_request behavior for the subset this data plane observes;
//   - per-binary endpoint binding, filesystem_policy, and landlock are parsed
//     but recorded as loss items: without OpenShell's in-sandbox supervisor
//     there is no syscall-level binary identity or LSM hook to enforce them;
//   - evaluation is default-deny: a request is allowed only when it matches an
//     endpoint and the endpoint's rules or access level admit it.
package openshellpolicy

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"sigs.k8s.io/yaml"
)

// Access levels for a REST endpoint, mirroring OpenShell's access presets.
const (
	// AccessFull allows every HTTP method on the endpoint.
	AccessFull = "full"
	// AccessReadOnly allows GET, HEAD, and OPTIONS, matching OpenShell's
	// read-only preset. TRACE is deliberately excluded: OpenShell's preset
	// does not include it.
	AccessReadOnly = "read-only"
	// AccessReadWrite allows GET, HEAD, OPTIONS, POST, PUT, and PATCH,
	// matching OpenShell's read-write preset.
	AccessReadWrite = "read-write"
)

// Enforcement modes for an endpoint.
const (
	// EnforcementEnforce denies requests that are not admitted.
	EnforcementEnforce = "enforce"
	// EnforcementAudit admits traffic and only observes it.
	EnforcementAudit = "audit"
)

// ProtocolREST is the only L7 protocol evaluated by this package.
const ProtocolREST = "rest"

// UpstreamSource identifies the upstream project whose policy schema and
// request-decision semantics this package mirrors.
const UpstreamSource = "github.com/NVIDIA/OpenShell"

// VersionBaseline pins the upstream OpenShell revision whose sandbox-policy
// schema, access presets, and L7 evaluator semantics this package was
// validated against. It is a semantic pin, not a build dependency: bump it in
// the same change that re-verifies parse, merge, and request decisions against
// the new revision, instead of silently following upstream HEAD.
const VersionBaseline = "c4688aa8715ea75d6c39fe468361dbbc16c691fa"

// NetworkPolicy is one named entry of the policy's network_policies map.
type NetworkPolicy struct {
	// Name is the display name of the policy. When empty the map key is used.
	Name string `json:"name,omitempty"`
	// Endpoints lists the L4/L7 endpoints the policy governs.
	Endpoints []Endpoint `json:"endpoints"`
	// Binaries restricts which binaries may use the endpoints. Parsed for
	// fidelity; not enforceable at this data plane (recorded as a loss item).
	Binaries []BinaryRef `json:"binaries,omitempty"`
}

// Endpoint is one governed host:port with L7 REST semantics.
type Endpoint struct {
	// Host is the destination hostname. Matching is case-insensitive.
	Host string `json:"host"`
	// Port is the destination port.
	Port int32 `json:"port"`
	// Protocol is the L7 protocol; only "rest" is evaluated at L7. Other
	// protocols are parsed and mapped to plain L4 rules.
	Protocol string `json:"protocol,omitempty"`
	// Enforcement is "enforce" or "audit". An omitted value means audit,
	// matching OpenShell's L7 configuration default; enforce-ready
	// publication requires an explicit "enforce".
	Enforcement string `json:"enforcement,omitempty"`
	// Access is "full", "read-only", or "read-write". An omitted value means
	// no preset.
	Access string `json:"access,omitempty"`
	// Rules are the ordered L7 allow/deny rules. Deny rules take precedence
	// over allow rules, mirroring OpenShell's deny_request evaluation.
	Rules []Rule `json:"rules,omitempty"`
}

// BinaryRef references a binary that may use an endpoint.
type BinaryRef struct {
	// Path is the absolute path or glob of the permitted binary.
	Path string `json:"path"`
}

// RuleAction is an L7 rule outcome.
type RuleAction string

// Rule actions.
const (
	// RuleActionAllow admits a matching request.
	RuleActionAllow RuleAction = "allow"
	// RuleActionReject denies a matching request.
	RuleActionReject RuleAction = "deny"
)

// Rule is one L7 REST rule in OpenShell's wire form: {"allow": {...}} or
// {"deny": {...}} with method and path fields.
type Rule struct {
	// Action is the rule outcome.
	Action RuleAction `json:"action"`
	// Method is the HTTP method, or "*" for any method. Empty matches any
	// method.
	Method string `json:"method,omitempty"`
	// Path is the request path: exact match, a prefix match when it ends with
	// "/**", or any path when empty.
	Path string `json:"path,omitempty"`
}

// UnmarshalJSON decodes OpenShell's single-key rule form
// ({"allow": {"method": "GET", "path": "/x"}}) into Rule. sigs.k8s.io/yaml
// routes YAML through this decoder, so both formats work.
func (r *Rule) UnmarshalJSON(data []byte) error {
	var wire map[string]struct {
		Method string `json:"method"`
		Path   string `json:"path"`
	}
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	if len(wire) != 1 {
		return fmt.Errorf("rule must have exactly one of allow/deny, got %d keys", len(wire))
	}
	for key, body := range wire {
		switch RuleAction(key) {
		case RuleActionAllow:
			r.Action = RuleActionAllow
		case RuleActionReject:
			r.Action = RuleActionReject
		default:
			return fmt.Errorf("unknown rule action %q", key)
		}
		r.Method = strings.ToUpper(body.Method)
		r.Path = body.Path
	}
	return nil
}

// Policy is the parsed OpenShell sandbox policy, restricted to the fields
// this integration consumes. Fields outside that model are enumerated in
// UnsupportedFields: they stay parseable for previewing, but callers that
// rewrite the authoritative document through this trimmed model must refuse
// instead of silently dropping them.
type Policy struct {
	// Version is the OpenShell policy schema version.
	Version int `json:"version,omitempty"`
	// UnsupportedFields lists every document field this package does not
	// model, keyed by its location (for example
	// "network_policies.api.endpoints[0].ports"). It is derived at parse time
	// and never serialized.
	UnsupportedFields []string `json:"-"`
	// FilesystemPolicy is preserved as raw data; never enforced here.
	FilesystemPolicy map[string]interface{} `json:"filesystem_policy,omitempty"`
	// Landlock is preserved as raw data; never enforced here.
	Landlock map[string]interface{} `json:"landlock,omitempty"`
	// NetworkPolicies is the governed network policy map.
	NetworkPolicies map[string]NetworkPolicy `json:"network_policies"`
}

// PolicyNames returns the network policy map keys in sorted order.
func (p *Policy) PolicyNames() []string {
	names := make([]string, 0, len(p.NetworkPolicies))
	for name := range p.NetworkPolicies {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// ParsePolicy decodes an OpenShell sandbox policy document (YAML or JSON) and
// validates the fields the evaluator and mapper consume. Documents declaring
// an unsupported schema version are rejected; fields this package does not
// model are recorded in UnsupportedFields so enforce callers can refuse to
// rewrite the authoritative document through the trimmed model.
//
// Filesystem and landlock sections are preserved as raw data and flagged by
// the mappers as loss items. A document with an empty network_policies map is
// a valid default-deny policy when its version is declared.
func ParsePolicy(data []byte) (*Policy, error) {
	policy := &Policy{}
	if err := yaml.Unmarshal(data, policy); err != nil {
		return nil, fmt.Errorf("parse openshell policy: %w", err)
	}
	if policy.Version > 1 {
		return nil, fmt.Errorf("parse openshell policy: unsupported policy version %d (version 1 is the only supported schema)", policy.Version)
	}
	if policy.Version == 0 && len(policy.NetworkPolicies) == 0 && policy.FilesystemPolicy == nil && policy.Landlock == nil {
		return nil, fmt.Errorf("parse openshell policy: document contains no policy sections")
	}
	unsupported, err := scanUnsupportedFields(data)
	if err != nil {
		return nil, fmt.Errorf("parse openshell policy: %w", err)
	}
	policy.UnsupportedFields = unsupported

	// Endpoint matching must be unambiguous: this data plane decides by one
	// endpoint, while OpenShell unions every matching endpoint and applies a
	// deny from any of them. Overlapping host:port entries are rejected
	// instead of being silently approximated.
	seen := make(map[string]string)
	// Sorted order keeps overlap errors deterministic: map iteration order
	// would otherwise name the two policies in random order.
	for _, name := range policy.PolicyNames() {
		np := policy.NetworkPolicies[name]
		if len(np.Endpoints) == 0 {
			return nil, fmt.Errorf("network policy %q has no endpoints", name)
		}
		for i := range np.Endpoints {
			if err := validateEndpoint(name, i, np.Endpoints[i]); err != nil {
				return nil, err
			}
			key := endpointKey(np.Endpoints[i].Host, np.Endpoints[i].Port)
			if previous, ok := seen[key]; ok {
				host := strings.ToLower(np.Endpoints[i].Host)
				if previous == name {
					return nil, fmt.Errorf("network policy %q declares endpoint %s:%d more than once", name, host, np.Endpoints[i].Port)
				}
				return nil, fmt.Errorf("network policies %q and %q overlap on endpoint %s:%d; this data plane requires unique host:port endpoints", previous, name, host, np.Endpoints[i].Port)
			}
			seen[key] = name
		}
	}
	return policy, nil
}

// scanUnsupportedFields walks the raw document and lists every field outside
// the trimmed model. Rewriting a document through MarshalPolicy would drop
// these fields, so enforce callers must treat a non-empty result as a hard
// blocker rather than a warning.
func scanUnsupportedFields(data []byte) ([]string, error) {
	jsonData, err := yaml.YAMLToJSON(data)
	if err != nil {
		return nil, err
	}
	var root map[string]json.RawMessage
	if err := json.Unmarshal(jsonData, &root); err != nil {
		return nil, err
	}
	var unsupported []string
	record := func(path string) { unsupported = append(unsupported, path) }

	for key := range root {
		switch key {
		case "version", "filesystem_policy", "landlock", "network_policies":
		default:
			record(key)
		}
	}

	var networks map[string]json.RawMessage
	if raw, ok := root["network_policies"]; ok {
		if err := json.Unmarshal(raw, &networks); err != nil {
			return nil, err
		}
	}
	for name, rawPolicy := range networks {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(rawPolicy, &fields); err != nil {
			return nil, fmt.Errorf("network policy %q: %w", name, err)
		}
		for key := range fields {
			switch key {
			case "name", "endpoints", "binaries":
			default:
				record("network_policies." + name + "." + key)
			}
		}

		var endpoints []map[string]json.RawMessage
		if raw, ok := fields["endpoints"]; ok {
			if err := json.Unmarshal(raw, &endpoints); err != nil {
				return nil, fmt.Errorf("network policy %q endpoints: %w", name, err)
			}
		}
		for i, endpoint := range endpoints {
			prefix := fmt.Sprintf("network_policies.%s.endpoints[%d]", name, i)
			for key := range endpoint {
				switch key {
				case "host", "port", "protocol", "enforcement", "access", "rules":
				default:
					record(prefix + "." + key)
				}
			}
			var rules []map[string]json.RawMessage
			if raw, ok := endpoint["rules"]; ok {
				if err := json.Unmarshal(raw, &rules); err != nil {
					return nil, fmt.Errorf("%s.rules: %w", prefix, err)
				}
			}
			for j, rule := range rules {
				for action, rawBody := range rule {
					if action != "allow" && action != "deny" {
						record(fmt.Sprintf("%s.rules[%d].%s", prefix, j, action))
						continue
					}
					var body map[string]json.RawMessage
					if err := json.Unmarshal(rawBody, &body); err != nil {
						return nil, fmt.Errorf("%s.rules[%d].%s: %w", prefix, j, action, err)
					}
					for key := range body {
						switch key {
						case "method", "path":
						default:
							record(fmt.Sprintf("%s.rules[%d].%s.%s", prefix, j, action, key))
						}
					}
				}
			}
		}

		var binaries []map[string]json.RawMessage
		if raw, ok := fields["binaries"]; ok {
			if err := json.Unmarshal(raw, &binaries); err != nil {
				return nil, fmt.Errorf("network policy %q binaries: %w", name, err)
			}
		}
		for i, binary := range binaries {
			for key := range binary {
				if key != "path" {
					record(fmt.Sprintf("network_policies.%s.binaries[%d].%s", name, i, key))
				}
			}
		}
	}
	sort.Strings(unsupported)
	return unsupported, nil
}

func validateEndpoint(policyName string, index int, ep Endpoint) error {
	if ep.Host == "" {
		return fmt.Errorf("network policy %q endpoint %d: host is required", policyName, index)
	}
	if ep.Port < 1 || ep.Port > 65535 {
		return fmt.Errorf("network policy %q endpoint %d: port %d out of range", policyName, index, ep.Port)
	}
	switch ep.Enforcement {
	case "", EnforcementEnforce, EnforcementAudit:
	default:
		return fmt.Errorf("network policy %q endpoint %d: unknown enforcement %q", policyName, index, ep.Enforcement)
	}
	switch ep.Access {
	case "", AccessFull, AccessReadOnly, AccessReadWrite:
	default:
		return fmt.Errorf("network policy %q endpoint %d: unknown access %q", policyName, index, ep.Access)
	}
	return nil
}
