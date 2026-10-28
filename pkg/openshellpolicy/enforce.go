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
	"strconv"
	"strings"
)

// EnforceBlockers lists every reason policy cannot be published for
// enforcement by this integration's restricted REST/L7 contract. An empty
// result means the document can be enforced as written.
//
// The contract is deliberately narrow: only explicit REST endpoints with
// explicit enforce mode, unique host:port pairs, and method/path rules the
// evaluator implements are publishable. Per-binary binding, filesystem,
// landlock, process, middleware, and protocol-specific semantics require
// OpenShell's native in-guest runtime and are rejected rather than
// approximated or silently dropped.
func EnforceBlockers(policy *Policy) []string {
	if policy == nil {
		return []string{"policy is nil"}
	}
	var blockers []string
	if policy.Version != 1 {
		blockers = append(blockers, "version must be 1, got "+strconv.Itoa(policy.Version))
	}
	for _, field := range policy.UnsupportedFields {
		blockers = append(blockers, fmt.Sprintf("field %q is not modeled by the restricted enforcement contract", field))
	}
	if policy.FilesystemPolicy != nil {
		blockers = append(blockers, "filesystem_policy requires native in-guest LSM enforcement and cannot be published by this contract")
	}
	if policy.Landlock != nil {
		blockers = append(blockers, "landlock requires native in-guest LSM enforcement and cannot be published by this contract")
	}
	for _, name := range policy.PolicyNames() {
		np := policy.NetworkPolicies[name]
		if len(np.Binaries) > 0 {
			blockers = append(blockers, fmt.Sprintf(
				"network_policies.%s.binaries requires per-binary identity and cannot be enforced at the pod egress layer", name))
		}
		for i := range np.Endpoints {
			ep := np.Endpoints[i]
			field := fmt.Sprintf("network_policies.%s.endpoints[%s:%d]", name, ep.Host, ep.Port)
			if ep.Protocol != ProtocolREST {
				blockers = append(blockers, fmt.Sprintf(
					"%s.protocol must be explicitly %q; protocol-specific semantics are not implemented", field, ProtocolREST))
			}
			if ep.Enforcement != EnforcementEnforce {
				blockers = append(blockers, fmt.Sprintf(
					"%s.enforcement must be explicitly %q; OpenShell treats an omitted value as audit", field, EnforcementEnforce))
			}
			for j := range ep.Rules {
				if !supportedRulePath(ep.Rules[j].Path) {
					blockers = append(blockers, fmt.Sprintf(
						"%s.rules[%d].path %q is neither empty, an exact path, nor a /** prefix match",
						field, j, ep.Rules[j].Path))
				}
			}
		}
	}
	return blockers
}

// supportedRulePath accepts the path forms the evaluator implements: empty
// (any path), an exact path, or a prefix ending in "/**". Every other pattern
// is rejected so a partial match can never be mistaken for full OpenShell
// semantics.
func supportedRulePath(path string) bool {
	if path == "" {
		return true
	}
	if !strings.HasPrefix(path, "/") {
		return false
	}
	if strings.HasSuffix(path, "/**") {
		return !strings.Contains(strings.TrimSuffix(path, "/**"), "*")
	}
	return !strings.Contains(path, "*")
}
