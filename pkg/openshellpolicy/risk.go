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
	"net"
	"strconv"
	"strings"

	agentsv1alpha1 "github.com/openkruise/agents/api/v1alpha1"
)

// OpenShell prover finding categories (openshell-prover/src/finding.rs).
// Findings are categorical, not severity-graded: the reviewer reads the
// category name and the structured evidence and decides. The auto-approval
// gate in OpenShell is binary — empty finding delta is a candidate; any
// finding demands human review.
const (
	// RiskLinkLocalReach flags new reach to a link-local range
	// (169.254.0.0/16, fe80::/10). Cloud metadata endpoints serve
	// credentials from these ranges regardless of the sandbox's own
	// credential state.
	RiskLinkLocalReach = "link_local_reach"
	// RiskCredentialReachExpansion flags a binary gaining credentialed
	// reach to a (host, port) it could not reach before.
	RiskCredentialReachExpansion = "credential_reach_expansion"
	// RiskCapabilityExpansion flags a new HTTP method on a (binary, host,
	// port) that already had credentialed reach.
	RiskCapabilityExpansion = "capability_expansion"
	// RiskL7BypassCredentialed flags a binary using a wire protocol the L7
	// proxy cannot inspect gaining reach to a host where a credential is in
	// scope.
	RiskL7BypassCredentialed = "l7_bypass_credentialed"
)

// CheckProposalRisk compares the reachability of the current and candidate
// policies and records one finding per prover category that flags the delta.
//
// Only link_local_reach is runnable today: it is unconditional and needs no
// credential state. The three credential-scoped categories are returned as
// unchecked entries with the reason they cannot run — a proposal never
// silently passes a check that was not executed, mirroring the prover's
// explicit Unsupported reporting for policy shapes outside its model.
func CheckProposalRisk(current, candidate *Policy) ([]agentsv1alpha1.PolicyFinding, []agentsv1alpha1.PolicyUncheckedCheck) {
	var findings []agentsv1alpha1.PolicyFinding

	currentReach := reachIndex(current)
	var evidence []agentsv1alpha1.PolicyFindingPath
	for _, name := range candidate.PolicyNames() {
		np := candidate.NetworkPolicies[name]
		binaries := binaryPaths(np)
		for _, ep := range np.Endpoints {
			if currentReach[endpointKey(ep.Host, ep.Port)] {
				continue
			}
			if isLinkLocalHost(ep.Host) {
				evidence = append(evidence, agentsv1alpha1.PolicyFindingPath{
					Binary: binaries,
					Host:   ep.Host,
					Port:   ep.Port,
					Policy: name,
				})
			}
		}
	}
	if len(evidence) > 0 {
		findings = append(findings, agentsv1alpha1.PolicyFinding{
			Query:       RiskLinkLocalReach,
			Title:       "New reach to a link-local address",
			Description: "The proposal adds an endpoint in a link-local range (169.254.0.0/16, fe80::/10). Cloud metadata services serve credentials from these ranges regardless of the sandbox's own credential state.",
			Evidence:    evidence,
			Remediation: []string{
				"Remove the link-local endpoint from the proposal.",
				"Route metadata access through a governed egress proxy instead.",
			},
		})
	}

	unchecked := []agentsv1alpha1.PolicyUncheckedCheck{
		{
			Category: RiskCredentialReachExpansion,
			Reason:   "requires OpenShell's provider-credential scope model, which this data plane does not track yet",
		},
		{
			Category: RiskCapabilityExpansion,
			Reason:   "requires credentialed-reach tracking per (binary, host, port), which this data plane does not track yet",
		},
		{
			Category: RiskL7BypassCredentialed,
			Reason:   "requires per-protocol L7 inspection capability and credential scope, which this data plane does not track yet",
		},
	}
	return findings, unchecked
}

// reachIndex indexes every endpoint a policy admits, keyed by lowercased
// host and port. Reach is reach: duplicate endpoints across policies
// collapse into one key.
func reachIndex(policy *Policy) map[string]bool {
	reach := make(map[string]bool)
	if policy == nil {
		return reach
	}
	for _, np := range policy.NetworkPolicies {
		for _, ep := range np.Endpoints {
			reach[endpointKey(ep.Host, ep.Port)] = true
		}
	}
	return reach
}

func endpointKey(host string, port int32) string {
	return strings.ToLower(host) + ":" + strconv.FormatInt(int64(port), 10)
}

func binaryPaths(np NetworkPolicy) string {
	if len(np.Binaries) == 0 {
		return ""
	}
	paths := make([]string, 0, len(np.Binaries))
	for _, b := range np.Binaries {
		paths = append(paths, b.Path)
	}
	return strings.Join(paths, ",")
}

// isLinkLocalHost reports whether host is a link-local unicast or multicast
// address. Hostnames are not resolved: only literal link-local IPs are
// flagged, exactly the ranges OpenShell's prover checks.
func isLinkLocalHost(host string) bool {
	ip := net.ParseIP(strings.TrimSpace(host))
	if ip == nil {
		return false
	}
	return ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast()
}
