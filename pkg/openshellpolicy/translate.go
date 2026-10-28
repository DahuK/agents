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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	agentsv1alpha1 "github.com/openkruise/agents/api/v1alpha1"
)

// MapOptions controls the TrafficPolicy produced by MapToTrafficPolicy.
type MapOptions struct {
	// Namespace is the namespace of the generated TrafficPolicy. Required.
	Namespace string
	// Name is the resource name. Defaults to "openshell-egress".
	Name string
	// Selector selects the sandbox pods the policy applies to.
	Selector metav1.LabelSelector
	// Priority is the TrafficPolicy evaluation priority. Defaults to the CRD's
	// default (1000) when zero.
	Priority int32
	// TailDefaultDeny appends a final reject-all egress rule. Defaults to
	// true when the struct is built with DefaultMapOptions; a zero-value
	// MapOptions omits the tail rule.
	TailDefaultDeny bool
	// RequireEnforceable refuses to return a projection when any OpenShell
	// semantic would be lost or the document is not enforceable as written.
	// DefaultMapOptions sets it; preview callers may clear it explicitly.
	RequireEnforceable bool
}

// DefaultMapOptions returns MapOptions with repository-conventional defaults
// applied.
func DefaultMapOptions(namespace, name string, selector metav1.LabelSelector) MapOptions {
	return MapOptions{
		Namespace:          namespace,
		Name:               name,
		Selector:           selector,
		TailDefaultDeny:    true,
		RequireEnforceable: true,
	}
}

// LossItem records one OpenShell policy semantic that the TrafficPolicy
// projection cannot express, following the loss-accounting pattern of
// OpenShell's own driver-mxc policy mapper: what the target runtime cannot
// enforce is surfaced, never silently dropped.
type LossItem struct {
	// Field locates the loss in the source policy, e.g.
	// "network_policies.github-api-readonly.binaries".
	Field string `json:"field"`
	// Reason explains what is not enforced and where it must be enforced
	// instead.
	Reason string `json:"reason"`
}

// MapResult is the outcome of mapping an OpenShell policy onto kruise API
// resources.
type MapResult struct {
	// Policy is the generated TrafficPolicy.
	Policy *agentsv1alpha1.TrafficPolicy
	// Losses lists every semantic that the L4 egress projection dropped.
	Losses []LossItem
	// Blockers lists reasons the source document is not enforceable by the
	// restricted contract (see EnforceBlockers).
	Blockers []string
}

// MapToTrafficPolicy projects an OpenShell sandbox policy onto an egress
// TrafficPolicy: each enforce/audit endpoint becomes one allow rule with an
// FQDN peer and a TCP port, deduplicated and emitted in sorted order for
// deterministic output. With TailDefaultDeny the rule list ends with a
// reject-all rule, preserving OpenShell's default-deny posture.
//
// L7 method/path semantics, per-binary binding, filesystem_policy, and
// landlock cannot be expressed at this layer; each occurrence is recorded in
// Losses so callers can decide whether to additionally run the L7 evaluator
// in their data plane.
func MapToTrafficPolicy(policy *Policy, opts MapOptions) (MapResult, error) {
	if policy == nil {
		return MapResult{}, fmt.Errorf("map openshell policy: policy is nil")
	}
	if opts.Namespace == "" {
		return MapResult{}, fmt.Errorf("map openshell policy: namespace is required")
	}
	if len(policy.NetworkPolicies) == 0 && !opts.TailDefaultDeny {
		return MapResult{}, fmt.Errorf("map openshell policy: empty network_policies requires the default-deny tail (set TailDefaultDeny)")
	}
	name := opts.Name
	if name == "" {
		name = "openshell-egress"
	}

	type endpointKey struct {
		host string
		port int32
	}
	seen := make(map[endpointKey]struct{})
	var rules []agentsv1alpha1.TrafficPolicyRule
	var losses []LossItem

	if policy.FilesystemPolicy != nil {
		losses = append(losses, LossItem{
			Field:  "filesystem_policy",
			Reason: "filesystem policy requires in-guest LSM enforcement (OpenShell supervisor/landlock); not expressible in TrafficPolicy",
		})
	}
	if policy.Landlock != nil {
		losses = append(losses, LossItem{
			Field:  "landlock",
			Reason: "landlock compatibility settings require a landlock-capable in-guest runtime; not expressible in TrafficPolicy",
		})
	}

	for _, policyName := range policy.PolicyNames() {
		np := policy.NetworkPolicies[policyName]
		if len(np.Binaries) > 0 {
			losses = append(losses, LossItem{
				Field:  fmt.Sprintf("network_policies.%s.binaries", policyName),
				Reason: "per-binary endpoint binding is not enforceable at the pod egress layer; the rule applies to all processes in the sandbox pod",
			})
		}
		endpoints := make([]Endpoint, len(np.Endpoints))
		copy(endpoints, np.Endpoints)
		sort.SliceStable(endpoints, func(i, j int) bool {
			if endpoints[i].Host != endpoints[j].Host {
				return endpoints[i].Host < endpoints[j].Host
			}
			return endpoints[i].Port < endpoints[j].Port
		})
		for _, ep := range endpoints {
			// Only rule emission is deduplicated; loss accounting below still
			// runs for every occurrence so duplicate endpoints cannot silently
			// drop their L7 semantics from the projection.
			key := endpointKey{host: ep.Host, port: ep.Port}
			if _, ok := seen[key]; !ok {
				seen[key] = struct{}{}
				port := ep.Port
				rules = append(rules, agentsv1alpha1.TrafficPolicyRule{
					Action: agentsv1alpha1.RuleActionAllow,
					To: []agentsv1alpha1.TrafficPolicyPeer{
						{FQDN: ep.Host},
					},
					Ports: []agentsv1alpha1.TrafficPolicyPort{
						{Protocol: "TCP", Port: &port},
					},
				})
			}
			field := fmt.Sprintf("network_policies.%s.endpoints[%s:%d]", policyName, ep.Host, ep.Port)
			if ep.Protocol != "" && ep.Protocol != ProtocolREST {
				losses = append(losses, LossItem{
					Field:  field + ".protocol",
					Reason: fmt.Sprintf("protocol %q is mapped to a plain L4 host:port rule; protocol-specific L7 semantics are not enforced", ep.Protocol),
				})
			}
			if ep.Enforcement == "" || ep.Enforcement == EnforcementAudit {
				losses = append(losses, LossItem{
					Field:  field + ".enforcement",
					Reason: "audit or omitted enforcement degrades to allow at the L4 layer; L7 observation requires the evaluator data plane",
				})
			}
			if len(ep.Rules) > 0 || ep.Access == "" || ep.Access == AccessReadOnly || ep.Access == AccessReadWrite {
				losses = append(losses, LossItem{
					Field:  field,
					Reason: "L7 method/path restriction requires the L7 evaluator in the data plane; the TrafficPolicy rule admits all methods to the host:port",
				})
			}
		}
	}

	if opts.TailDefaultDeny {
		rules = append(rules, agentsv1alpha1.TrafficPolicyRule{
			Action: agentsv1alpha1.RuleActionReject,
		})
	}

	trafficPolicy := &agentsv1alpha1.TrafficPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: opts.Namespace,
			Name:      name,
		},
		Spec: agentsv1alpha1.TrafficPolicySpec{
			Priority: opts.Priority,
			Selector: opts.Selector,
			Egress: &agentsv1alpha1.TrafficPolicyDirection{
				Rules: rules,
			},
		},
	}
	result := MapResult{Policy: trafficPolicy, Losses: losses, Blockers: EnforceBlockers(policy)}
	if opts.RequireEnforceable {
		if reasons := projectionBlockers(losses, result.Blockers); len(reasons) > 0 {
			return MapResult{}, fmt.Errorf("map openshell policy: projection is not enforce-ready: %s", strings.Join(reasons, "; "))
		}
	}
	return result, nil
}

// projectionBlockers combines loss fields and hard blockers into one list.
func projectionBlockers(losses []LossItem, blockers []string) []string {
	reasons := make([]string, 0, len(losses)+len(blockers))
	for _, loss := range losses {
		reasons = append(reasons, fmt.Sprintf("%s: %s", loss.Field, loss.Reason))
	}
	reasons = append(reasons, blockers...)
	return reasons
}
