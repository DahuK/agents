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

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// PolicyDecisionAction is an operator ruling on a proposal.
// +kubebuilder:validation:Enum=approve;reject
type PolicyDecisionAction string

const (
	// PolicyDecisionActionApprove merges the proposal into the target policy.
	PolicyDecisionActionApprove PolicyDecisionAction = "approve"
	// PolicyDecisionActionReject closes the proposal without merging.
	PolicyDecisionActionReject PolicyDecisionAction = "reject"
)

// PolicyProposalPhase is the lifecycle phase of a proposal.
type PolicyProposalPhase string

const (
	// PolicyProposalPhasePending means the proposal was admitted: operations
	// validated, risk checks recorded, awaiting an operator decision.
	PolicyProposalPhasePending PolicyProposalPhase = "Pending"
	// PolicyProposalPhaseApplied means the merged document was written back
	// into the target SecurityProfile.
	PolicyProposalPhaseApplied PolicyProposalPhase = "Applied"
	// PolicyProposalPhaseRejected means the operator rejected the proposal;
	// the rejection reason is surfaced for the submitting agent.
	PolicyProposalPhaseRejected PolicyProposalPhase = "Rejected"
	// PolicyProposalPhaseFailed means the proposal could not be applied for
	// reasons other than a rejection: invalid operations, missing target, or
	// a stale baseline document.
	PolicyProposalPhaseFailed PolicyProposalPhase = "Failed"
)

// PolicyProposalSpec describes an agent-submitted amendment to the OpenShell
// policy embedded in a SecurityProfile. The wire shapes mirror OpenShell's
// PolicyMergeOperation protobuf so proposals authored against the OpenShell
// governance loop (deny -> propose -> approve) map onto this resource without
// translation.
type PolicyProposalSpec struct {
	// SecurityProfileRef names the SecurityProfile in the proposal's
	// namespace whose embedded OpenShell document the operations amend.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	SecurityProfileRef string `json:"securityProfileRef"`

	// Operations is the ordered batch of merge operations to apply to the
	// embedded document. Exactly one operation must be set per entry.
	// +listType=atomic
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=32
	Operations []PolicyMergeOperation `json:"operations"`

	// Rationale is the submitting agent's explanation of why the rules are
	// needed. Surfaced to the reviewer with the risk findings.
	// +optional
	// +kubebuilder:validation:MaxLength=4096
	Rationale string `json:"rationale,omitempty"`

	// Principal identifies the submitter, e.g. the sandbox ID or the traffic
	// token subject the proposal was filed on behalf of.
	// +optional
	// +kubebuilder:validation:MaxLength=256
	Principal string `json:"principal,omitempty"`
}

// PolicyProposalDecision is the operator's ruling on a proposal.
type PolicyProposalDecision struct {
	// Action approves or rejects the proposal.
	Action PolicyDecisionAction `json:"action"`

	// Reason accompanies the ruling. For rejections it is surfaced back to
	// the submitting agent so it can revise the proposal, mirroring
	// OpenShell's rejection_reason.
	// +optional
	// +kubebuilder:validation:MaxLength=2048
	Reason string `json:"reason,omitempty"`

	// DecidedBy records who ruled, e.g. the operator's username.
	// +optional
	// +kubebuilder:validation:MaxLength=256
	DecidedBy string `json:"decidedBy,omitempty"`
}

// PolicyMergeOperation is one OpenShell PolicyMergeOperation. Exactly one of
// the six operations must be set; the controller rejects anything else.
type PolicyMergeOperation struct {
	// AddNetworkRule adds a new whole network_policies entry. Adding an
	// existing name is rejected: OpenShell merges same-named entries, and this
	// controller does not approximate that merge.
	// +optional
	AddNetworkRule *NetworkRuleAdd `json:"addNetworkRule,omitempty"`

	// RemoveNetworkRule deletes a whole network_policies entry.
	// +optional
	RemoveNetworkRule *NetworkRuleRemove `json:"removeNetworkRule,omitempty"`

	// RemoveNetworkEndpoint deletes one endpoint from a network policy.
	// +optional
	RemoveNetworkEndpoint *NetworkEndpointRemove `json:"removeNetworkEndpoint,omitempty"`

	// AddDenyRules appends deny rules to an existing endpoint.
	// +optional
	AddDenyRules *L7RulesAppend `json:"addDenyRules,omitempty"`

	// AddAllowRules appends allow rules to an existing endpoint.
	// +optional
	AddAllowRules *L7RulesAppend `json:"addAllowRules,omitempty"`

	// RemoveNetworkBinary removes a binary binding from a network policy.
	// +optional
	RemoveNetworkBinary *NetworkBinaryRemove `json:"removeNetworkBinary,omitempty"`
}

// NetworkRuleAdd carries a whole network_policies entry.
type NetworkRuleAdd struct {
	// RuleName is the network_policies map key.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	RuleName string `json:"ruleName"`

	// Endpoints is the entry's host:port endpoint list.
	// +listType=atomic
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=64
	Endpoints []PolicyEndpoint `json:"endpoints"`

	// Binaries restricts which binaries may use the endpoints. Parsed for
	// document fidelity; enforcement arrives with the per-binary phase.
	// +optional
	// +listType=atomic
	// +kubebuilder:validation:MaxItems=64
	Binaries []PolicyBinaryRef `json:"binaries,omitempty"`
}

// NetworkRuleRemove deletes a whole network_policies entry.
type NetworkRuleRemove struct {
	// RuleName is the network_policies map key to delete.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	RuleName string `json:"ruleName"`
}

// NetworkEndpointRemove deletes one endpoint from a network policy.
type NetworkEndpointRemove struct {
	// RuleName is the network_policies map key.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	RuleName string `json:"ruleName"`

	// Host of the endpoint to remove. Matched case-insensitively.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Host string `json:"host"`

	// Port of the endpoint to remove.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	Port int32 `json:"port"`
}

// L7RulesAppend appends L7 rules to an existing endpoint.
type L7RulesAppend struct {
	// Target identifies the endpoint the rules append to. OpenShell's target
	// also scopes by ports/binaries/path; this projection scopes by the
	// endpoint's host:port within the named policy.
	Target L7RuleTarget `json:"target"`

	// Rules are the L7 rules to append.
	// +listType=atomic
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=256
	Rules []PolicyL7Rule `json:"rules"`
}

// L7RuleTarget identifies the endpoint L7 rules append to.
type L7RuleTarget struct {
	// RuleName is the network_policies map key.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	RuleName string `json:"ruleName"`

	// Host of the target endpoint.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Host string `json:"host"`

	// Port of the target endpoint.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	Port int32 `json:"port"`
}

// NetworkBinaryRemove removes a binary binding from a network policy.
type NetworkBinaryRemove struct {
	// RuleName is the network_policies map key.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	RuleName string `json:"ruleName"`

	// BinaryPath is the bound binary path to remove.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=4096
	BinaryPath string `json:"binaryPath"`
}

// PolicyEndpoint mirrors the OpenShell NetworkEndpoint wire shape.
type PolicyEndpoint struct {
	// Host is the destination hostname.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Host string `json:"host"`

	// Port is the destination port.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	Port int32 `json:"port"`

	// Protocol is the L7 protocol. Only "rest" is evaluated by the
	// restricted enforcement contract; other protocols are rejected for
	// enforce-ready publication rather than approximated.
	// +optional
	// +kubebuilder:validation:MaxLength=32
	Protocol string `json:"protocol,omitempty"`

	// Enforcement is "enforce" or "audit". The restricted enforcement
	// contract requires an explicit "enforce": OpenShell treats an omitted
	// value as audit, and the two must not be silently conflated.
	// +optional
	// +kubebuilder:validation:Enum=enforce;audit
	Enforcement string `json:"enforcement,omitempty"`

	// Access is "full", "read-only", or "read-write", mirroring
	// OpenShell's access presets. An omitted value means no preset.
	// +optional
	// +kubebuilder:validation:Enum=full;read-only;read-write
	Access string `json:"access,omitempty"`

	// Rules are the ordered L7 allow/deny rules; deny rules take precedence.
	// +optional
	// +listType=atomic
	// +kubebuilder:validation:MaxItems=256
	Rules []PolicyL7Rule `json:"rules,omitempty"`
}

// PolicyBinaryRef references a binary that may use an endpoint.
type PolicyBinaryRef struct {
	// Path is the absolute path or glob of the permitted binary.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=4096
	Path string `json:"path"`
}

// PolicyL7Rule is one L7 rule in the flattened OKA wire form. The embedded
// document keeps OpenShell's single-key {"allow"|"deny": {...}} form; this
// type is the authoring surface for proposals.
type PolicyL7Rule struct {
	// Action is the rule outcome.
	// +kubebuilder:validation:Enum=allow;deny
	Action string `json:"action"`

	// Method is the HTTP method, "*" for any method; empty matches any.
	// +optional
	// +kubebuilder:validation:MaxLength=16
	Method string `json:"method,omitempty"`

	// Path is the request path: exact match, a prefix match when it ends with
	// "/**", or any path when empty.
	// +optional
	// +kubebuilder:validation:MaxLength=2048
	Path string `json:"path,omitempty"`
}

// PolicyFinding is one risk-check finding, mirroring OpenShell's prover
// finding categories. Findings are categorical, not severity-graded: the
// reviewer reads the category and evidence and decides.
type PolicyFinding struct {
	// Query is the finding category, one of OpenShell's prover categories
	// (link_local_reach, credential_reach_expansion, capability_expansion,
	// l7_bypass_credentialed).
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=64
	Query string `json:"query"`

	// Title is a one-line summary for the review card.
	// +optional
	// +kubebuilder:validation:MaxLength=256
	Title string `json:"title,omitempty"`

	// Description explains what the category means in this context.
	// +optional
	Description string `json:"description,omitempty"`

	// Evidence lists the concrete paths through which the property was
	// observed.
	// +optional
	// +listType=atomic
	// +kubebuilder:validation:MaxItems=256
	Evidence []PolicyFindingPath `json:"evidence,omitempty"`

	// Remediation suggests how to avoid the finding.
	// +optional
	// +listType=atomic
	// +kubebuilder:validation:MaxItems=16
	Remediation []string `json:"remediation,omitempty"`
}

// PolicyFindingPath is the concrete evidence of one finding.
type PolicyFindingPath struct {
	// Binary is the executable gaining the property, when the policy binds
	// binaries.
	// +optional
	// +kubebuilder:validation:MaxLength=4096
	Binary string `json:"binary,omitempty"`

	// Host of the endpoint the finding refers to.
	// +optional
	// +kubebuilder:validation:MaxLength=253
	Host string `json:"host,omitempty"`

	// Port of the endpoint the finding refers to.
	// +optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	Port int32 `json:"port,omitempty"`

	// Method is the HTTP method the finding refers to; populated only for
	// capability_expansion evidence.
	// +optional
	// +kubebuilder:validation:MaxLength=16
	Method string `json:"method,omitempty"`

	// Policy is the network_policies map key the endpoint belongs to.
	// +optional
	// +kubebuilder:validation:MaxLength=63
	Policy string `json:"policy,omitempty"`
}

// PolicyUncheckedCheck names a risk category this data plane cannot evaluate
// yet. Unchecked categories are always recorded explicitly — a proposal never
// silently passes a check that was not run.
type PolicyUncheckedCheck struct {
	// Category is the OpenShell prover finding category that was not checked.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=64
	Category string `json:"category"`

	// Reason explains what the check requires that is not modeled yet.
	// +optional
	Reason string `json:"reason,omitempty"`
}

// PolicyProposalStatus is the most recently observed status of a proposal.
type PolicyProposalStatus struct {
	// Decision records the operator's ruling. "okactl policy approve/reject"
	// writes it through the status subresource; the controller applies it
	// exactly once. It lives in status, not spec, so a ruling does not bump
	// metadata.generation: the generation tracks the agent-authored proposal
	// content, and admission (which pins the baseline the ruling is validated
	// against) is re-run only when that content changes — mirroring
	// OpenShell's review token.
	// +optional
	Decision *PolicyProposalDecision `json:"decision,omitempty"`

	// Phase is the proposal lifecycle phase.
	// +optional
	Phase PolicyProposalPhase `json:"phase,omitempty"`

	// Findings are the risk-check results recorded at admission. Empty means
	// no runnable check flagged the proposal.
	// +optional
	// +listType=atomic
	// +kubebuilder:validation:MaxItems=64
	Findings []PolicyFinding `json:"findings,omitempty"`

	// Unchecked lists the risk categories that could not be evaluated. The
	// three credential-scoped OpenShell categories are always listed until
	// the credential model lands.
	// +optional
	// +listType=atomic
	// +kubebuilder:validation:MaxItems=16
	Unchecked []PolicyUncheckedCheck `json:"unchecked,omitempty"`

	// CurrentPolicyHash is the sha256 of the canonical JSON of the target
	// document observed at admission. At apply time the live document must
	// still hash to this value, mirroring OpenShell's review token: a
	// proposal built against a stale baseline fails instead of merging into
	// an unknown document.
	// +optional
	// +kubebuilder:validation:MaxLength=71
	CurrentPolicyHash string `json:"currentPolicyHash,omitempty"`

	// CandidatePolicyHash is the sha256 of the canonical JSON of the merged
	// candidate document computed at admission.
	// +optional
	// +kubebuilder:validation:MaxLength=71
	CandidatePolicyHash string `json:"candidatePolicyHash,omitempty"`

	// AppliedRevision is the OpenShell policy revision the approval produced
	// on the target SecurityProfile.
	// +optional
	AppliedRevision int64 `json:"appliedRevision,omitempty"`

	// ApplicationError records why a prover-clean proposal could not be
	// applied: invalid operations, missing target, or a stale baseline. Kept
	// separate from the operator's rejection reason, mirroring OpenShell's
	// PolicyChunk split.
	// +optional
	ApplicationError string `json:"applicationError,omitempty"`

	// RejectionReason is the operator-supplied reason, surfaced back to the
	// submitting agent so it can revise the proposal.
	// +optional
	RejectionReason string `json:"rejectionReason,omitempty"`

	// DecidedBy records who approved or rejected the proposal.
	// +optional
	DecidedBy string `json:"decidedBy,omitempty"`

	// DecidedTime is when the decision was recorded.
	// +optional
	DecidedTime *metav1.Time `json:"decidedTime,omitempty"`

	// AppliedTime is when the merged document was written to the profile.
	// +optional
	AppliedTime *metav1.Time `json:"appliedTime,omitempty"`

	// ObservedGeneration is the generation most recently admitted.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
}

// +kubebuilder:object:root=true
// +genclient
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Profile",type=string,JSONPath=`.spec.securityProfileRef`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Decision",type=string,JSONPath=`.status.decision.action`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
// +kubebuilder:resource:scope=Namespaced

// PolicyProposal is an agent-submitted amendment to the OpenShell policy
// embedded in a SecurityProfile, following OpenShell's policy advisor loop:
// the agent's overreach is denied with next_steps, it files a narrowed
// proposal, risk checks are recorded, and an operator ruling merges the
// approved document back into the profile.
type PolicyProposal struct {
	metav1.TypeMeta `json:",inline"`
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +optional
	Spec PolicyProposalSpec `json:"spec,omitempty"`
	// +optional
	Status PolicyProposalStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// PolicyProposalList contains a list of PolicyProposal.
type PolicyProposalList struct {
	metav1.TypeMeta `json:",inline"`
	// +optional
	metav1.ListMeta `json:"metadata,omitempty"`
	// +required
	Items []PolicyProposal `json:"items"`
}

func init() {
	SchemeBuilder.Register(&PolicyProposal{}, &PolicyProposalList{})
}
