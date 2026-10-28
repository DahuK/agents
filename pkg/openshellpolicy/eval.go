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
	"net/url"
	"strings"
)

// Request is one egress L7 request as observed by the enforcement data plane.
// Host, Port, Method, and Path are required; Binary is echoed into denial
// bodies for diagnostics only (per-binary enforcement is a loss item).
type Request struct {
	Host   string
	Port   int32
	Method string
	Path   string
	Binary string
}

// DenyBody is the structured denial body mirroring OpenShell's L7 deny wire
// shape ("error": "policy_denied", rule_missing, next_steps) so agent-side
// revise-and-propose loops written against OpenShell keep working.
type DenyBody struct {
	Error       string       `json:"error"`
	Policy      string       `json:"policy"`
	Rule        string       `json:"rule"`
	Detail      string       `json:"detail"`
	Layer       string       `json:"layer"`
	Protocol    string       `json:"protocol,omitempty"`
	Method      string       `json:"method,omitempty"`
	Path        string       `json:"path,omitempty"`
	Host        string       `json:"host,omitempty"`
	Port        *int32       `json:"port,omitempty"`
	Binary      string       `json:"binary,omitempty"`
	RuleMissing *RuleMissing `json:"rule_missing,omitempty"`
	NextSteps   []NextStep   `json:"next_steps"`
}

// RuleMissing describes the exact rule that would have admitted the request,
// mirroring OpenShell's rule_missing object in deny bodies.
type RuleMissing struct {
	Type   string `json:"type"`
	Layer  string `json:"layer"`
	Method string `json:"method,omitempty"`
	Path   string `json:"path,omitempty"`
	Host   string `json:"host,omitempty"`
	Port   *int32 `json:"port,omitempty"`
	Binary string `json:"binary,omitempty"`
}

// NextStep is one machine-readable remediation pointer in a denial body,
// mirroring OpenShell's next_steps entries.
type NextStep struct {
	Action   string `json:"action"`
	Method   string `json:"method,omitempty"`
	URL      string `json:"url,omitempty"`
	Path     string `json:"path,omitempty"`
	BodyType string `json:"body_type,omitempty"`
}

// Denial carries a structured denial plus the machine-readable reason.
type Denial struct {
	// HTTPStatus is the status the data plane should return (403).
	HTTPStatus int
	// Reason is the machine-readable deny reason, suitable for activity logs.
	Reason string
	// Body is the structured JSON body returned to the client.
	Body DenyBody
}

// Decision is the outcome of evaluating one request against a policy.
type Decision struct {
	// Allowed reports whether the request is admitted.
	Allowed bool
	// AuditOnly is true when the request matched an endpoint in audit mode;
	// the data plane must forward the traffic and record the observation.
	AuditOnly bool
	// Denial is set when Allowed is false.
	Denial *Denial
}

// NextStepsOptions controls the next_steps entries embedded in denial bodies.
// The zero value produces an empty list; the wiring layer sets ProposalURL to
// the OpenShell gateway SubmitPolicyAnalysis endpoint exposed to agents.
type NextStepsOptions struct {
	// ProposalURL is the endpoint agents POST policy proposals to.
	ProposalURL string
	// SkillPath is the on-filesystem advisor skill location, when the runtime
	// installs one.
	SkillPath string
}

// Evaluate decides whether req is admitted by policy. It is pure and
// default-deny: a nil policy denies every request.
func Evaluate(policy *Policy, req Request) Decision {
	return EvaluateWithNextSteps(policy, req, NextStepsOptions{})
}

// EvaluateWithNextSteps behaves like Evaluate and embeds the given next_steps
// options in denial bodies.
func EvaluateWithNextSteps(policy *Policy, req Request, opts NextStepsOptions) Decision {
	req.normalize()
	if policy == nil {
		return deny(req, "", "no active sandbox policy", "network", "network_allow", opts)
	}

	name, np, ep, ok := matchEndpoint(policy, req)
	if !ok {
		return deny(req, "", "network connections not allowed by policy", "network", "network_allow", opts)
	}
	policyName := np.Name
	if policyName == "" {
		policyName = name
	}

	// Only REST is implemented. Approximating another protocol with REST
	// method/path rules could admit traffic the author intended to restrict,
	// so the evaluator refuses instead of guessing.
	if ep.Protocol != "" && ep.Protocol != ProtocolREST {
		return deny(req, policyName, fmt.Sprintf("endpoint protocol %q is not supported by the restricted REST enforcement contract", ep.Protocol), "l7", "rest_allow", opts)
	}

	// OpenShell treats an omitted enforcement value as audit in its L7
	// configuration. Matching that default here keeps evaluation faithful;
	// enforce-ready publication rejects omitted or audit endpoints instead
	// of silently turning them into enforcement.
	switch ep.Enforcement {
	case "", EnforcementAudit:
		return Decision{Allowed: true, AuditOnly: true}
	}

	matchPath, canonical := canonicalRequestPath(req.Path)
	if !canonical {
		return deny(req, policyName, "request path is not canonical; dot segments, duplicate slashes, and encoded separators are rejected", "l7", "rest_allow", opts)
	}

	for _, rule := range ep.Rules {
		if rule.Action == RuleActionReject && ruleMatches(rule, req, matchPath) {
			return deny(req, policyName, "denied by explicit rest deny rule", "l7", "rest_deny", opts)
		}
	}
	for _, rule := range ep.Rules {
		if rule.Action == RuleActionAllow && ruleMatches(rule, req, matchPath) {
			return Decision{Allowed: true}
		}
	}
	if len(ep.Rules) > 0 {
		return deny(req, policyName, "no matching rest allow rule", "l7", "rest_allow", opts)
	}
	switch ep.Access {
	case AccessFull:
		return Decision{Allowed: true}
	case AccessReadOnly:
		if isReadMethod(req.Method) {
			return Decision{Allowed: true}
		}
		return deny(req, policyName, "endpoint is read-only", "l7", "rest_allow", opts)
	case AccessReadWrite:
		if isReadWriteMethod(req.Method) {
			return Decision{Allowed: true}
		}
		return deny(req, policyName, "endpoint is read-write; DELETE and CONNECT are not admitted by the preset", "l7", "rest_allow", opts)
	default:
		// Upstream expands access presets into allow rules and keeps
		// allow_request = false by default. An endpoint with neither a preset
		// nor a rule denies every L7 request; treating it as allow would be a
		// silent widening.
		return deny(req, policyName, "endpoint has no access preset and no allow rule", "l7", "rest_allow", opts)
	}
}

// matchEndpoint finds the first endpoint (in sorted policy-key order) that
// matches req's host and port, mirroring OpenShell's deterministic
// matched_network_policy = min(matching policy names). It returns the map key
// alongside the policy so callers can resolve the display name without
// shared mutable state.
func matchEndpoint(policy *Policy, req Request) (string, NetworkPolicy, Endpoint, bool) {
	for _, name := range policy.PolicyNames() {
		np := policy.NetworkPolicies[name]
		for _, ep := range np.Endpoints {
			if strings.EqualFold(ep.Host, req.Host) && ep.Port == req.Port {
				return name, np, ep, true
			}
		}
	}
	return "", NetworkPolicy{}, Endpoint{}, false
}

func ruleMatches(rule Rule, req Request, path string) bool {
	if rule.Method != "" && rule.Method != "*" && rule.Method != req.Method {
		return false
	}
	if rule.Path == "" {
		return true
	}
	if strings.HasSuffix(rule.Path, "/**") {
		return strings.HasPrefix(path, strings.TrimSuffix(rule.Path, "**"))
	}
	return rule.Path == path
}

// isReadMethod matches OpenShell's read-only access preset: GET, HEAD, and
// OPTIONS. TRACE is not part of the preset.
func isReadMethod(method string) bool {
	switch method {
	case "GET", "HEAD", "OPTIONS":
		return true
	default:
		return false
	}
}

// isReadWriteMethod matches OpenShell's read-write access preset: the read
// methods plus POST, PUT, and PATCH. DELETE and CONNECT are not part of it.
func isReadWriteMethod(method string) bool {
	if isReadMethod(method) {
		return true
	}
	switch method {
	case "POST", "PUT", "PATCH":
		return true
	default:
		return false
	}
}

// canonicalRequestPath returns the decoded path used for rule matching. It
// rejects rather than normalizes whenever the target could be reinterpreted
// upstream: control bytes, non-canonical dot segments, duplicate slashes,
// fragments, backslashes, and percent-encoded separators or double encoding.
// First-phase enforcement refuses such requests instead of guessing which
// path the upstream will actually serve.
func canonicalRequestPath(raw string) (string, bool) {
	if raw == "" {
		raw = "/"
	}
	for i := 0; i < len(raw); i++ {
		if raw[i] < 0x20 || raw[i] >= 0x7f {
			return "", false
		}
	}
	if !strings.HasPrefix(raw, "/") || strings.ContainsAny(raw, "#\\") {
		return "", false
	}
	lower := strings.ToLower(raw)
	if strings.Contains(lower, "%2f") || strings.Contains(lower, "%5c") || strings.Contains(lower, "%25") {
		return "", false
	}
	path := raw
	if index := strings.IndexByte(path, '?'); index >= 0 {
		path = path[:index]
	}
	decoded, err := url.PathUnescape(path)
	if err != nil {
		return "", false
	}
	// A percent sign surviving one decode is double encoding; reject it
	// rather than iterating decoders the upstream may not share.
	if strings.Contains(decoded, "%") {
		return "", false
	}
	if decoded == "" || !strings.HasPrefix(decoded, "/") || strings.Contains(decoded, "//") {
		return "", false
	}
	for _, segment := range strings.Split(decoded, "/")[1:] {
		if segment == "." || segment == ".." {
			return "", false
		}
	}
	return decoded, true
}

func (r *Request) normalize() {
	r.Host = strings.TrimRight(strings.ToLower(strings.TrimSpace(r.Host)), ".")
	r.Method = strings.ToUpper(strings.TrimSpace(r.Method))
	if r.Path == "" {
		r.Path = "/"
	}
	r.Binary = strings.TrimSpace(r.Binary)
}

func deny(req Request, policyName, detail, layer, missingType string, opts NextStepsOptions) Decision {
	var port *int32
	if req.Port != 0 {
		p := req.Port
		port = &p
	}
	missing := &RuleMissing{
		Type:   missingType,
		Layer:  layer,
		Method: req.Method,
		Path:   req.Path,
		Host:   req.Host,
		Port:   port,
		Binary: req.Binary,
	}
	body := DenyBody{
		Error:       "policy_denied",
		Policy:      policyName,
		Rule:        fmt.Sprintf("%s %s", req.Method, req.Path),
		Detail:      detail,
		Layer:       layer,
		Protocol:    ProtocolREST,
		Method:      req.Method,
		Path:        req.Path,
		Host:        req.Host,
		Port:        port,
		Binary:      req.Binary,
		RuleMissing: missing,
		NextSteps:   nextSteps(opts),
	}
	if layer == "network" {
		body.Protocol = ""
	}
	return Decision{
		Allowed: false,
		Denial: &Denial{
			HTTPStatus: 403,
			Reason:     detail,
			Body:       body,
		},
	}
}

func nextSteps(opts NextStepsOptions) []NextStep {
	steps := make([]NextStep, 0, 2)
	if opts.SkillPath != "" {
		steps = append(steps, NextStep{
			Action: "read_skill",
			Path:   opts.SkillPath,
		})
	}
	if opts.ProposalURL != "" {
		steps = append(steps, NextStep{
			Action:   "submit_proposal",
			Method:   "POST",
			URL:      opts.ProposalURL,
			BodyType: "PolicyMergeOperation",
		})
	}
	return steps
}
