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
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/yaml"

	agentsv1alpha1 "github.com/openkruise/agents/api/v1alpha1"
)

// ProfileMapOptions controls the SecurityProfile produced by
// MapToSecurityProfile.
type ProfileMapOptions struct {
	// Namespace is the namespace of the generated SecurityProfile. Required.
	Namespace string
	// Name is the resource name. Defaults to "openshell-l7".
	Name string
	// Selector selects the sandbox pods the profile applies to.
	Selector metav1.LabelSelector
	// Priority is the profile's evaluation priority. Defaults to the CRD's
	// default (1000) when zero.
	Priority int32
	// RuleName is the name of the single rule carrying the OpenShellPolicy
	// action. Defaults to "openshell".
	RuleName string
	// ProposalURL is the OpenShell governance-cluster endpoint embedded in
	// denial bodies' next_steps, so denied agents can submit policy
	// proposals. Optional.
	ProposalURL string
	// SkillPath is the on-filesystem policy-advisor skill location embedded
	// in denial bodies' next_steps. Optional.
	SkillPath string
	// RequireEnforceable refuses to emit the profile when any semantic would
	// be lost or the document is not enforceable as written.
	// DefaultProfileMapOptions sets it; preview callers may clear it.
	RequireEnforceable bool
}

// DefaultProfileMapOptions returns ProfileMapOptions with
// repository-conventional defaults applied.
func DefaultProfileMapOptions(namespace, name string, selector metav1.LabelSelector) ProfileMapOptions {
	return ProfileMapOptions{
		Namespace:          namespace,
		Name:               name,
		Selector:           selector,
		RuleName:           "openshell",
		RequireEnforceable: true,
	}
}

// ProfileMapResult is the outcome of mapping an OpenShell policy onto a
// SecurityProfile.
type ProfileMapResult struct {
	// Profile is the generated SecurityProfile.
	Profile *agentsv1alpha1.SecurityProfile
	// Losses lists every semantic the projection dropped.
	Losses []LossItem
	// Blockers lists reasons the document is not enforceable by the
	// restricted contract (see EnforceBlockers).
	Blockers []string
}

// MapToSecurityProfile projects an approved OpenShell sandbox policy document
// onto a SecurityProfile carrying one openShellPolicy action for the L7
// enforcement data plane (agentio EPE).
//
// The document travels whole, not projected: it is validated with ParsePolicy,
// converted to canonical JSON, and embedded verbatim, so the data plane
// evaluates exactly what the OpenShell governance cluster approved — including
// sections the CRD does not model, which the API server preserves. The single
// rule matches every domain because the OpenShell document carries its own
// endpoint list: the data plane's openshellpolicy filter performs endpoint
// selection itself, preserving OpenShell's default-deny posture for hosts the
// policy does not list.
//
// A filesystem-only policy still produces a profile whose filter denies all
// network traffic (OpenShell's default-deny semantics for a document without
// network_policies), but with RequireEnforceable (the default) the projection
// is refused: the filesystem_policy section itself cannot be enforced here,
// and publishing the profile would imply protection that does not exist.
// Preview callers may clear RequireEnforceable and read Losses instead.
func MapToSecurityProfile(data []byte, opts ProfileMapOptions) (ProfileMapResult, error) {
	if opts.Namespace == "" {
		return ProfileMapResult{}, fmt.Errorf("map openshell policy: namespace is required")
	}
	policy, err := ParsePolicy(data)
	if err != nil {
		return ProfileMapResult{}, fmt.Errorf("map openshell policy: %w", err)
	}
	jsonDoc, err := yaml.YAMLToJSON(data)
	if err != nil {
		return ProfileMapResult{}, fmt.Errorf("map openshell policy: %w", err)
	}
	name := opts.Name
	if name == "" {
		name = "openshell-l7"
	}
	ruleName := opts.RuleName
	if ruleName == "" {
		ruleName = "openshell"
	}

	action := &agentsv1alpha1.OpenShellPolicyAction{
		Policy: &runtime.RawExtension{Raw: jsonDoc},
	}
	if opts.ProposalURL != "" || opts.SkillPath != "" {
		action.NextSteps = &agentsv1alpha1.OpenShellNextStepsConfig{
			ProposalURL: opts.ProposalURL,
			SkillPath:   opts.SkillPath,
		}
	}

	spec := agentsv1alpha1.SecurityProfileSpec{
		Selector: opts.Selector,
		Rules: []agentsv1alpha1.SecurityRule{{
			Name: ruleName,
			Match: []agentsv1alpha1.RuleMatch{
				{Domains: []string{"*"}},
			},
			Actions: agentsv1alpha1.SecurityRuleActions{
				OpenShellPolicy: action,
			},
		}},
	}
	if opts.Priority > 0 {
		priority := opts.Priority
		spec.Priority = &priority
	}

	losses := profileLosses(policy)
	blockers := EnforceBlockers(policy)
	if opts.RequireEnforceable {
		if reasons := projectionBlockers(losses, blockers); len(reasons) > 0 {
			return ProfileMapResult{}, fmt.Errorf("map openshell policy: profile is not enforce-ready: %s", strings.Join(reasons, "; "))
		}
	}

	return ProfileMapResult{
		Profile: &agentsv1alpha1.SecurityProfile{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: opts.Namespace,
				Name:      name,
			},
			Spec: spec,
		},
		Losses:   losses,
		Blockers: blockers,
	}, nil
}

// profileLosses records the semantics the SecurityProfile projection cannot
// enforce. Unlike the TrafficPolicy projection, L7 method/path rules, access
// levels, and audit enforcement are enforced by the data plane's evaluator;
// only in-guest semantics and protocol fidelity are lost.
func profileLosses(policy *Policy) []LossItem {
	var losses []LossItem
	if policy.FilesystemPolicy != nil {
		losses = append(losses, LossItem{
			Field:  "filesystem_policy",
			Reason: "filesystem policy requires in-guest LSM enforcement (OpenShell supervisor/landlock); not expressible in SecurityProfile",
		})
	}
	if policy.Landlock != nil {
		losses = append(losses, LossItem{
			Field:  "landlock",
			Reason: "landlock compatibility settings require a landlock-capable in-guest runtime; not expressible in SecurityProfile",
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
		for _, ep := range np.Endpoints {
			if ep.Protocol != "" && ep.Protocol != ProtocolREST {
				losses = append(losses, LossItem{
					Field:  fmt.Sprintf("network_policies.%s.endpoints[%s:%d].protocol", policyName, ep.Host, ep.Port),
					Reason: fmt.Sprintf("protocol %q is evaluated with REST semantics by the L7 data plane; protocol-specific semantics are approximated", ep.Protocol),
				})
			}
		}
	}
	return losses
}
