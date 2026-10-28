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

package policyproposal

import (
	"context"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	agentsv1alpha1 "github.com/openkruise/agents/api/v1alpha1"
	"github.com/openkruise/agents/pkg/openshellpolicy"
)

const (
	testNamespace = "test-ns"
	profileName   = "profile"
)

const controllerBaseDoc = `version: 1
network_policies:
  api:
    name: api
    endpoints:
      - host: api.example.com
        port: 443
        protocol: rest
        enforcement: enforce
        access: full
`

func newTestScheme() *runtime.Scheme {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = agentsv1alpha1.AddToScheme(scheme)
	return scheme
}

func newTestReconciler(objs ...client.Object) (*PolicyProposalReconciler, client.Client) {
	scheme := newTestScheme()
	fc := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(objs...).
		WithStatusSubresource(&agentsv1alpha1.PolicyProposal{}).
		Build()
	return &PolicyProposalReconciler{
		Client:   fc,
		Scheme:   scheme,
		Recorder: record.NewFakeRecorder(64),
	}, fc
}

func targetProfile(t *testing.T) *agentsv1alpha1.SecurityProfile {
	t.Helper()
	result, err := openshellpolicy.MapToSecurityProfile(
		[]byte(controllerBaseDoc),
		openshellpolicy.DefaultProfileMapOptions(testNamespace, profileName, metav1.LabelSelector{}),
	)
	if err != nil {
		t.Fatalf("MapToSecurityProfile: %v", err)
	}
	return result.Profile
}

// addRuleOps builds an operation inside the restricted REST/enforce
// contract: explicit rest, explicit enforce, and no per-binary binding.
func addRuleOps(ruleName, host string, port int32) []agentsv1alpha1.PolicyMergeOperation {
	return []agentsv1alpha1.PolicyMergeOperation{{
		AddNetworkRule: &agentsv1alpha1.NetworkRuleAdd{
			RuleName: ruleName,
			Endpoints: []agentsv1alpha1.PolicyEndpoint{{
				Host:        host,
				Port:        port,
				Protocol:    "rest",
				Enforcement: "enforce",
				Access:      "full",
			}},
		},
	}}
}

// addBinaryRuleOps builds an operation the restricted contract cannot
// enforce: per-binary binding requires in-guest identity.
func addBinaryRuleOps(ruleName, host string, port int32) []agentsv1alpha1.PolicyMergeOperation {
	ops := addRuleOps(ruleName, host, port)
	ops[0].AddNetworkRule.Binaries = []agentsv1alpha1.PolicyBinaryRef{{Path: "/usr/bin/curl"}}
	return ops
}

func newProposal(name, profileRef string, ops []agentsv1alpha1.PolicyMergeOperation) *agentsv1alpha1.PolicyProposal {
	return &agentsv1alpha1.PolicyProposal{
		ObjectMeta: metav1.ObjectMeta{
			Name:       name,
			Namespace:  testNamespace,
			UID:        types.UID("uid-" + name),
			Generation: 1,
		},
		Spec: agentsv1alpha1.PolicyProposalSpec{
			SecurityProfileRef: profileRef,
			Operations:         ops,
			Rationale:          "agent needs the rule",
			Principal:          "sandbox-1",
		},
	}
}

func reconcileProposal(t *testing.T, r *PolicyProposalReconciler, name string) {
	t.Helper()
	_, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: testNamespace, Name: name},
	})
	if err != nil {
		t.Fatalf("reconcile %s: %v", name, err)
	}
}

func fetchProposal(t *testing.T, c client.Client, name string) *agentsv1alpha1.PolicyProposal {
	t.Helper()
	proposal := &agentsv1alpha1.PolicyProposal{}
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: testNamespace, Name: name}, proposal); err != nil {
		t.Fatalf("get proposal %s: %v", name, err)
	}
	return proposal
}

// decideProposal records the operator ruling through the status subresource,
// the way "okactl policy approve/reject" does. A ruling never touches the
// spec, so metadata.generation still tracks only agent-authored content.
func decideProposal(t *testing.T, c client.Client, name string, decision *agentsv1alpha1.PolicyProposalDecision) {
	t.Helper()
	updated := fetchProposal(t, c, name).DeepCopy()
	updated.Status.Decision = decision
	if err := c.Status().Update(context.Background(), updated); err != nil {
		t.Fatalf("status update decision on %s: %v", name, err)
	}
}

func fetchProfile(t *testing.T, c client.Client) *agentsv1alpha1.SecurityProfile {
	t.Helper()
	profile := &agentsv1alpha1.SecurityProfile{}
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: testNamespace, Name: profileName}, profile); err != nil {
		t.Fatalf("get securityProfile: %v", err)
	}
	return profile
}

// fetchProfilePolicyRaw returns the profile's embedded OpenShell document
// exactly as published, without round-tripping it through the trimmed model.
func fetchProfilePolicyRaw(t *testing.T, c client.Client) []byte {
	t.Helper()
	profile := fetchProfile(t, c)
	for i := range profile.Spec.Rules {
		if a := profile.Spec.Rules[i].Actions.OpenShellPolicy; a != nil {
			return a.Policy.Raw
		}
	}
	t.Fatalf("securityProfile %s carries no openShellPolicy action", profileName)
	return nil
}

// fetchProfileDoc parses the profile's embedded OpenShell document.
func fetchProfileDoc(t *testing.T, c client.Client) *openshellpolicy.Policy {
	t.Helper()
	parsed, err := openshellpolicy.ParsePolicy(fetchProfilePolicyRaw(t, c))
	if err != nil {
		t.Fatalf("embedded policy does not parse: %v", err)
	}
	return parsed
}

func TestAdmitRecordsChecksAndHashes(t *testing.T) {
	r, c := newTestReconciler(targetProfile(t), newProposal("add-github", profileName, addRuleOps("github", "github.com", 443)))

	reconcileProposal(t, r, "add-github")

	proposal := fetchProposal(t, c, "add-github")
	if proposal.Status.Phase != agentsv1alpha1.PolicyProposalPhasePending {
		t.Fatalf("phase = %q, want Pending", proposal.Status.Phase)
	}
	if len(proposal.Status.Findings) != 0 {
		t.Errorf("findings = %+v, want none for a clean proposal", proposal.Status.Findings)
	}
	if len(proposal.Status.Unchecked) != 3 {
		t.Errorf("unchecked = %d entries, want the three credential-scoped categories", len(proposal.Status.Unchecked))
	}
	if !strings.HasPrefix(proposal.Status.CurrentPolicyHash, "sha256:") || !strings.HasPrefix(proposal.Status.CandidatePolicyHash, "sha256:") {
		t.Errorf("hashes = %q / %q, want sha256-prefixed", proposal.Status.CurrentPolicyHash, proposal.Status.CandidatePolicyHash)
	}
	if proposal.Status.CurrentPolicyHash == proposal.Status.CandidatePolicyHash {
		t.Errorf("candidate hash must differ from the baseline hash")
	}
	if proposal.Status.ObservedGeneration != proposal.Generation {
		t.Errorf("observedGeneration = %d, want %d", proposal.Status.ObservedGeneration, proposal.Generation)
	}

	// Admission computes but never applies: the profile document is untouched.
	doc := fetchProfileDoc(t, c)
	if _, ok := doc.NetworkPolicies["github"]; ok {
		t.Errorf("github policy must not be applied before a decision")
	}
	if _, ok := doc.NetworkPolicies["api"]; !ok {
		t.Errorf("baseline api policy must survive admission")
	}
}

func TestAdmitRecordsLinkLocalFinding(t *testing.T) {
	r, c := newTestReconciler(targetProfile(t), newProposal("metadata", profileName, addRuleOps("metadata", "169.254.169.254", 80)))

	reconcileProposal(t, r, "metadata")

	proposal := fetchProposal(t, c, "metadata")
	// A finding records risk for the reviewer; it does not decide for them.
	if proposal.Status.Phase != agentsv1alpha1.PolicyProposalPhasePending {
		t.Fatalf("phase = %q, want Pending: findings inform the ruling", proposal.Status.Phase)
	}
	if len(proposal.Status.Findings) != 1 {
		t.Fatalf("findings = %+v, want the link_local_reach finding", proposal.Status.Findings)
	}
	finding := proposal.Status.Findings[0]
	if finding.Query != openshellpolicy.RiskLinkLocalReach {
		t.Errorf("query = %q, want %q", finding.Query, openshellpolicy.RiskLinkLocalReach)
	}
	if len(finding.Evidence) != 1 || finding.Evidence[0].Host != "169.254.169.254" {
		t.Errorf("evidence = %+v, want the metadata endpoint", finding.Evidence)
	}
}

func TestApproveAppliesAndBumpsRevision(t *testing.T) {
	r, c := newTestReconciler(targetProfile(t), newProposal("add-github", profileName, addRuleOps("github", "github.com", 443)))

	reconcileProposal(t, r, "add-github")
	admitted := fetchProposal(t, c, "add-github")

	decideProposal(t, c, "add-github", &agentsv1alpha1.PolicyProposalDecision{
		Action:    agentsv1alpha1.PolicyDecisionActionApprove,
		DecidedBy: "alice",
	})
	reconcileProposal(t, r, "add-github")

	proposal := fetchProposal(t, c, "add-github")
	if proposal.Status.Phase != agentsv1alpha1.PolicyProposalPhaseApplied {
		t.Fatalf("phase = %q, want Applied", proposal.Status.Phase)
	}
	if proposal.Status.AppliedRevision != 1 {
		t.Errorf("appliedRevision = %d, want 1", proposal.Status.AppliedRevision)
	}
	if proposal.Status.DecidedBy != "alice" || proposal.Status.DecidedTime == nil || proposal.Status.AppliedTime == nil {
		t.Errorf("decision bookkeeping missing: %+v", proposal.Status)
	}

	profile := fetchProfile(t, c)
	if got := profile.Annotations[OpenShellPolicyRevisionAnnotation]; got != "1" {
		t.Errorf("revision annotation = %q, want 1", got)
	}
	credential := profile.Annotations[OpenShellPolicyApplyAnnotation]
	if !strings.Contains(credential, string(proposal.UID)) || !strings.Contains(credential, admitted.Status.CandidatePolicyHash) {
		t.Errorf("apply credential = %q, want the proposal UID and admitted candidate hash", credential)
	}
	doc := fetchProfileDoc(t, c)
	github, ok := doc.NetworkPolicies["github"]
	if !ok {
		t.Fatalf("github policy missing after approval")
	}
	if len(github.Endpoints) != 1 || github.Endpoints[0].Host != "github.com" || github.Endpoints[0].Port != 443 {
		t.Errorf("github endpoints = %+v", github.Endpoints)
	}
	if github.Endpoints[0].Protocol != "rest" || github.Endpoints[0].Enforcement != "enforce" {
		t.Errorf("github endpoint = %+v, want explicit rest/enforce", github.Endpoints[0])
	}
	if _, ok := doc.NetworkPolicies["api"]; !ok {
		t.Errorf("baseline api policy must survive the merge")
	}
	// The applied document is exactly the candidate admitted for review:
	// re-preparing the live document must reproduce the admitted full-document
	// identity, so unknown fields are covered by the check too.
	live, err := openshellpolicy.PrepareCandidate(openshellpolicy.PrepareRequest{Source: fetchProfilePolicyRaw(t, c)})
	if err != nil {
		t.Fatalf("PrepareCandidate(live): %v", err)
	}
	if live.Identities.CandidateSemanticIdentity != admitted.Status.CandidatePolicyHash {
		t.Errorf("live identity %s != admitted candidate identity %s",
			live.Identities.CandidateSemanticIdentity, admitted.Status.CandidatePolicyHash)
	}

	// A second proposal, filed and approved after the first landed, bumps the
	// revision again.
	second := newProposal("add-pypi", profileName, addRuleOps("pypi", "pypi.org", 443))
	if err := c.Create(context.Background(), second); err != nil {
		t.Fatalf("create second proposal: %v", err)
	}
	reconcileProposal(t, r, "add-pypi")
	decideProposal(t, c, "add-pypi", &agentsv1alpha1.PolicyProposalDecision{
		Action:    agentsv1alpha1.PolicyDecisionActionApprove,
		DecidedBy: "alice",
	})
	reconcileProposal(t, r, "add-pypi")

	if proposal := fetchProposal(t, c, "add-pypi"); proposal.Status.AppliedRevision != 2 {
		t.Errorf("second appliedRevision = %d, want 2", proposal.Status.AppliedRevision)
	}
	if got := fetchProfile(t, c).Annotations[OpenShellPolicyRevisionAnnotation]; got != "2" {
		t.Errorf("revision annotation = %q, want 2", got)
	}
	if doc := fetchProfileDoc(t, c); len(doc.NetworkPolicies) != 3 {
		t.Errorf("policies = %v, want api, github, and pypi", doc.NetworkPolicies)
	}
}

func TestApproveFailsOnStaleBaseline(t *testing.T) {
	r, c := newTestReconciler(
		targetProfile(t),
		newProposal("first", profileName, addRuleOps("github", "github.com", 443)),
		newProposal("second", profileName, addRuleOps("pypi", "pypi.org", 443)),
	)

	// Both proposals are admitted against the same baseline document.
	reconcileProposal(t, r, "first")
	reconcileProposal(t, r, "second")

	// The first approval lands and changes the document.
	decideProposal(t, c, "first", &agentsv1alpha1.PolicyProposalDecision{
		Action: agentsv1alpha1.PolicyDecisionActionApprove,
	})
	reconcileProposal(t, r, "first")

	// The second was reviewed against the pre-merge baseline: applying it now
	// would merge into a document nobody reviewed, so it fails instead.
	decideProposal(t, c, "second", &agentsv1alpha1.PolicyProposalDecision{
		Action: agentsv1alpha1.PolicyDecisionActionApprove,
	})
	reconcileProposal(t, r, "second")

	proposal := fetchProposal(t, c, "second")
	if proposal.Status.Phase != agentsv1alpha1.PolicyProposalPhaseFailed {
		t.Fatalf("phase = %q, want Failed", proposal.Status.Phase)
	}
	if !strings.Contains(proposal.Status.ApplicationError, "target policy changed since admission") {
		t.Errorf("applicationError = %q, want the stale-baseline message", proposal.Status.ApplicationError)
	}
	if proposal.Status.RejectionReason != "" {
		t.Errorf("a failed apply is not a rejection: rejectionReason = %q", proposal.Status.RejectionReason)
	}

	doc := fetchProfileDoc(t, c)
	if _, ok := doc.NetworkPolicies["pypi"]; ok {
		t.Errorf("the stale proposal must not be merged")
	}
	if _, ok := doc.NetworkPolicies["github"]; !ok {
		t.Errorf("the first, validly approved proposal must remain applied")
	}
}

func TestRejectClosesProposal(t *testing.T) {
	r, c := newTestReconciler(targetProfile(t), newProposal("add-github", profileName, addRuleOps("github", "github.com", 443)))

	reconcileProposal(t, r, "add-github")
	decideProposal(t, c, "add-github", &agentsv1alpha1.PolicyProposalDecision{
		Action:    agentsv1alpha1.PolicyDecisionActionReject,
		Reason:    "scope too broad for this workload",
		DecidedBy: "bob",
	})
	reconcileProposal(t, r, "add-github")

	proposal := fetchProposal(t, c, "add-github")
	if proposal.Status.Phase != agentsv1alpha1.PolicyProposalPhaseRejected {
		t.Fatalf("phase = %q, want Rejected", proposal.Status.Phase)
	}
	if proposal.Status.RejectionReason != "scope too broad for this workload" {
		t.Errorf("rejectionReason = %q", proposal.Status.RejectionReason)
	}
	if proposal.Status.DecidedBy != "bob" || proposal.Status.DecidedTime == nil {
		t.Errorf("decision bookkeeping missing: %+v", proposal.Status)
	}
	if doc := fetchProfileDoc(t, c); len(doc.NetworkPolicies) != 1 {
		t.Errorf("policies = %v, want the untouched baseline only", doc.NetworkPolicies)
	}
	if got := fetchProfile(t, c).Annotations[OpenShellPolicyRevisionAnnotation]; got != "" {
		t.Errorf("revision annotation = %q, want none after a rejection", got)
	}
}

func TestTerminalPhaseIsImmutable(t *testing.T) {
	done := newProposal("done", profileName, addRuleOps("github", "github.com", 443))
	done.Status = agentsv1alpha1.PolicyProposalStatus{
		Phase:           agentsv1alpha1.PolicyProposalPhaseApplied,
		Decision:        &agentsv1alpha1.PolicyProposalDecision{Action: agentsv1alpha1.PolicyDecisionActionApprove},
		AppliedRevision: 7,
		DecidedBy:       "alice",
	}
	r, c := newTestReconciler(targetProfile(t), done)

	reconcileProposal(t, r, "done")

	proposal := fetchProposal(t, c, "done")
	if proposal.Status.Phase != agentsv1alpha1.PolicyProposalPhaseApplied || proposal.Status.AppliedRevision != 7 {
		t.Errorf("terminal proposal was re-processed: %+v", proposal.Status)
	}
	if doc := fetchProfileDoc(t, c); len(doc.NetworkPolicies) != 1 {
		t.Errorf("policies = %v, want the untouched baseline only", doc.NetworkPolicies)
	}
}

func TestAdmitFailsOnMissingTarget(t *testing.T) {
	r, c := newTestReconciler(targetProfile(t), newProposal("orphan", "missing", addRuleOps("github", "github.com", 443)))

	reconcileProposal(t, r, "orphan")

	proposal := fetchProposal(t, c, "orphan")
	if proposal.Status.Phase != agentsv1alpha1.PolicyProposalPhaseFailed {
		t.Fatalf("phase = %q, want Failed", proposal.Status.Phase)
	}
	if !strings.Contains(proposal.Status.ApplicationError, `securityProfile "missing" not found`) {
		t.Errorf("applicationError = %q, want the missing-target message", proposal.Status.ApplicationError)
	}
}

func TestAdmitFailsOnProfileWithoutOpenShellAction(t *testing.T) {
	plain := &agentsv1alpha1.SecurityProfile{
		ObjectMeta: metav1.ObjectMeta{Name: profileName, Namespace: testNamespace},
		Spec: agentsv1alpha1.SecurityProfileSpec{
			Rules: []agentsv1alpha1.SecurityRule{{Name: "noop"}},
		},
	}
	r, c := newTestReconciler(plain, newProposal("add-github", profileName, addRuleOps("github", "github.com", 443)))

	reconcileProposal(t, r, "add-github")

	proposal := fetchProposal(t, c, "add-github")
	if proposal.Status.Phase != agentsv1alpha1.PolicyProposalPhaseFailed {
		t.Fatalf("phase = %q, want Failed", proposal.Status.Phase)
	}
	if !strings.Contains(proposal.Status.ApplicationError, "exactly one openShellPolicy action") {
		t.Errorf("applicationError = %q, want the missing-action message", proposal.Status.ApplicationError)
	}
}

func TestAdmitFailsOnInvalidOperations(t *testing.T) {
	ops := []agentsv1alpha1.PolicyMergeOperation{{
		RemoveNetworkRule: &agentsv1alpha1.NetworkRuleRemove{RuleName: "nope"},
	}}
	r, c := newTestReconciler(targetProfile(t), newProposal("bad-ops", profileName, ops))

	reconcileProposal(t, r, "bad-ops")

	proposal := fetchProposal(t, c, "bad-ops")
	if proposal.Status.Phase != agentsv1alpha1.PolicyProposalPhaseFailed {
		t.Fatalf("phase = %q, want Failed", proposal.Status.Phase)
	}
	if !strings.Contains(proposal.Status.ApplicationError, `network policy "nope" not found`) {
		t.Errorf("applicationError = %q, want the unknown-rule message", proposal.Status.ApplicationError)
	}
}

func TestReAdmitsWhenProposalIsEdited(t *testing.T) {
	r, c := newTestReconciler(targetProfile(t), newProposal("edited", profileName, addRuleOps("github", "github.com", 443)))

	reconcileProposal(t, r, "edited")
	if proposal := fetchProposal(t, c, "edited"); len(proposal.Status.Findings) != 0 {
		t.Fatalf("clean proposal admitted with findings: %+v", proposal.Status.Findings)
	}

	// The submitting agent edits the operations after admission. The fake
	// client does not manage metadata.generation, so the edit sets it the way
	// a real API server would.
	updated := fetchProposal(t, c, "edited").DeepCopy()
	updated.Spec.Operations = addRuleOps("metadata", "169.254.169.254", 80)
	updated.Generation = 2
	if err := c.Update(context.Background(), updated); err != nil {
		t.Fatalf("update proposal: %v", err)
	}

	reconcileProposal(t, r, "edited")

	proposal := fetchProposal(t, c, "edited")
	if proposal.Status.Phase != agentsv1alpha1.PolicyProposalPhasePending {
		t.Fatalf("phase = %q, want Pending after re-admission", proposal.Status.Phase)
	}
	if proposal.Status.ObservedGeneration != 2 {
		t.Errorf("observedGeneration = %d, want 2", proposal.Status.ObservedGeneration)
	}
	if len(proposal.Status.Findings) != 1 || proposal.Status.Findings[0].Query != openshellpolicy.RiskLinkLocalReach {
		t.Errorf("findings = %+v, want the link_local_reach finding for the edited operations", proposal.Status.Findings)
	}
}

func TestAdmitRejectsNonEnforceableCandidate(t *testing.T) {
	r, c := newTestReconciler(targetProfile(t), newProposal("add-binary", profileName, addBinaryRuleOps("curl", "api.example.com", 8443)))

	reconcileProposal(t, r, "add-binary")

	proposal := fetchProposal(t, c, "add-binary")
	if proposal.Status.Phase != agentsv1alpha1.PolicyProposalPhaseFailed {
		t.Fatalf("phase = %q, want Failed: binary binding is outside the restricted contract", proposal.Status.Phase)
	}
	if !strings.Contains(proposal.Status.ApplicationError, "not enforceable by the restricted REST/L7 contract") ||
		!strings.Contains(proposal.Status.ApplicationError, "binaries") {
		t.Errorf("applicationError = %q, want the binary-binding refusal", proposal.Status.ApplicationError)
	}
	if doc := fetchProfileDoc(t, c); len(doc.NetworkPolicies) != 1 {
		t.Errorf("policies = %v, want the untouched baseline", doc.NetworkPolicies)
	}
}

func TestAdmitAllowsUnenforceableCandidateWhenGateDisabled(t *testing.T) {
	r, c := newTestReconciler(targetProfile(t), newProposal("add-binary", profileName, addBinaryRuleOps("curl", "api.example.com", 8443)))
	r.AllowUnenforceable = true

	reconcileProposal(t, r, "add-binary")

	proposal := fetchProposal(t, c, "add-binary")
	if proposal.Status.Phase != agentsv1alpha1.PolicyProposalPhasePending {
		t.Fatalf("phase = %q, want Pending with the gate disabled: %s", proposal.Status.Phase, proposal.Status.ApplicationError)
	}
	select {
	case event := <-r.Recorder.(*record.FakeRecorder).Events:
		if !strings.Contains(event, "UnenforceablePolicy") || !strings.Contains(event, "binaries") {
			t.Errorf("event = %q, want the unenforceable-policy warning naming the blockers", event)
		}
	default:
		t.Error("admission recorded no warning for the unenforceable candidate")
	}

	// Preview-only mode still lets an operator publish the document, which is
	// exactly why the flag defaults to on.
	decideProposal(t, c, "add-binary", &agentsv1alpha1.PolicyProposalDecision{
		Action:    agentsv1alpha1.PolicyDecisionActionApprove,
		DecidedBy: "alice",
	})
	reconcileProposal(t, r, "add-binary")

	proposal = fetchProposal(t, c, "add-binary")
	if proposal.Status.Phase != agentsv1alpha1.PolicyProposalPhaseApplied {
		t.Fatalf("phase = %q, want Applied: %s", proposal.Status.Phase, proposal.Status.ApplicationError)
	}
	curl, ok := fetchProfileDoc(t, c).NetworkPolicies["curl"]
	if !ok || len(curl.Binaries) != 1 || curl.Binaries[0].Path != "/usr/bin/curl" {
		t.Errorf("curl policy = %+v, want the binary binding published as written", curl)
	}
}

func TestApproveRechecksGateAfterPreviewAdmission(t *testing.T) {
	r, c := newTestReconciler(targetProfile(t), newProposal("add-binary", profileName, addBinaryRuleOps("curl", "api.example.com", 8443)))
	r.AllowUnenforceable = true
	reconcileProposal(t, r, "add-binary")

	// The controller is restarted with the gate on after a preview admission.
	// Approval must not launder the preview-only candidate into production.
	r.AllowUnenforceable = false
	decideProposal(t, c, "add-binary", &agentsv1alpha1.PolicyProposalDecision{
		Action:    agentsv1alpha1.PolicyDecisionActionApprove,
		DecidedBy: "alice",
	})
	reconcileProposal(t, r, "add-binary")

	proposal := fetchProposal(t, c, "add-binary")
	if proposal.Status.Phase != agentsv1alpha1.PolicyProposalPhaseFailed {
		t.Fatalf("phase = %q, want Failed after the apply-time gate re-check", proposal.Status.Phase)
	}
	if !strings.Contains(proposal.Status.ApplicationError, "not enforceable by the restricted REST/L7 contract") {
		t.Errorf("applicationError = %q, want the gate refusal", proposal.Status.ApplicationError)
	}
	if doc := fetchProfileDoc(t, c); len(doc.NetworkPolicies) != 1 {
		t.Errorf("policies = %v, want the untouched baseline", doc.NetworkPolicies)
	}
}

func TestAdmitRejectsUnenforceableTargetDocument(t *testing.T) {
	// The authoritative document carries a section the restricted contract
	// cannot execute. The merge preserves it instead of deleting it, but the
	// enforce gate must still refuse: publishing would leave the data plane
	// enforcing less than the approved document states.
	opts := openshellpolicy.DefaultProfileMapOptions(testNamespace, profileName, metav1.LabelSelector{})
	opts.RequireEnforceable = false
	mapped, err := openshellpolicy.MapToSecurityProfile([]byte(controllerBaseDoc+"process: { run_as: sandbox }\n"), opts)
	if err != nil {
		t.Fatalf("MapToSecurityProfile: %v", err)
	}
	r, c := newTestReconciler(mapped.Profile, newProposal("edit", profileName, addRuleOps("github", "github.com", 443)))

	reconcileProposal(t, r, "edit")

	proposal := fetchProposal(t, c, "edit")
	if proposal.Status.Phase != agentsv1alpha1.PolicyProposalPhaseFailed {
		t.Fatalf("phase = %q, want Failed", proposal.Status.Phase)
	}
	if !strings.Contains(proposal.Status.ApplicationError, `field "process" is not modeled`) {
		t.Errorf("applicationError = %q, want the gate refusal naming the unmodeled section", proposal.Status.ApplicationError)
	}
}

func TestPreviewMergePreservesUnmodeledSections(t *testing.T) {
	// A preview deployment admits documents the restricted contract cannot
	// execute. The merge must still be lossless: dropping "process" would
	// silently change the policy the operator approved.
	opts := openshellpolicy.DefaultProfileMapOptions(testNamespace, profileName, metav1.LabelSelector{})
	opts.RequireEnforceable = false
	mapped, err := openshellpolicy.MapToSecurityProfile([]byte(controllerBaseDoc+"process: { run_as: sandbox }\n"), opts)
	if err != nil {
		t.Fatalf("MapToSecurityProfile: %v", err)
	}
	r, c := newTestReconciler(mapped.Profile, newProposal("edit", profileName, addRuleOps("github", "github.com", 443)))
	r.AllowUnenforceable = true

	reconcileProposal(t, r, "edit")
	if proposal := fetchProposal(t, c, "edit"); proposal.Status.Phase != agentsv1alpha1.PolicyProposalPhasePending {
		t.Fatalf("phase = %q, want Pending with the gate disabled: %s", proposal.Status.Phase, proposal.Status.ApplicationError)
	}
	decideProposal(t, c, "edit", &agentsv1alpha1.PolicyProposalDecision{
		Action:    agentsv1alpha1.PolicyDecisionActionApprove,
		DecidedBy: "alice",
	})
	reconcileProposal(t, r, "edit")

	proposal := fetchProposal(t, c, "edit")
	if proposal.Status.Phase != agentsv1alpha1.PolicyProposalPhaseApplied {
		t.Fatalf("phase = %q, want Applied: %s", proposal.Status.Phase, proposal.Status.ApplicationError)
	}
	doc := fetchProfileDoc(t, c)
	if len(doc.UnsupportedFields) != 1 || doc.UnsupportedFields[0] != "process" {
		t.Fatalf("unsupported fields = %v, want the preserved top-level process section", doc.UnsupportedFields)
	}
	if _, ok := doc.NetworkPolicies["github"]; !ok {
		t.Errorf("approved operation is missing from the published document")
	}
}

func TestStaleDecisionDoesNotSurviveReAdmission(t *testing.T) {
	r, c := newTestReconciler(targetProfile(t), newProposal("edited", profileName, addRuleOps("github", "github.com", 443)))

	reconcileProposal(t, r, "edited")

	// The operator approves the admitted candidate...
	decideProposal(t, c, "edited", &agentsv1alpha1.PolicyProposalDecision{
		Action:    agentsv1alpha1.PolicyDecisionActionApprove,
		DecidedBy: "alice",
	})

	// ...but before the controller applies it, the agent replaces the
	// operations. The API server bumps generation; the old ruling must not
	// apply to content the reviewer never saw.
	updated := fetchProposal(t, c, "edited").DeepCopy()
	updated.Spec.Operations = addRuleOps("pypi", "pypi.org", 443)
	updated.Generation = 2
	if err := c.Update(context.Background(), updated); err != nil {
		t.Fatalf("update proposal: %v", err)
	}

	reconcileProposal(t, r, "edited")

	proposal := fetchProposal(t, c, "edited")
	if proposal.Status.Phase != agentsv1alpha1.PolicyProposalPhasePending {
		t.Fatalf("phase = %q, want Pending after re-admission", proposal.Status.Phase)
	}
	if proposal.Status.ObservedGeneration != 2 {
		t.Errorf("observedGeneration = %d, want 2", proposal.Status.ObservedGeneration)
	}
	if proposal.Status.Decision != nil || proposal.Status.DecidedBy != "" {
		t.Errorf("stale decision survived re-admission: %+v", proposal.Status.Decision)
	}

	// Without a fresh ruling, a later reconcile must not apply anything.
	reconcileProposal(t, r, "edited")
	if proposal := fetchProposal(t, c, "edited"); proposal.Status.Phase != agentsv1alpha1.PolicyProposalPhasePending {
		t.Errorf("phase = %q, want Pending without a fresh decision", proposal.Status.Phase)
	}
	doc := fetchProfileDoc(t, c)
	if _, ok := doc.NetworkPolicies["pypi"]; ok {
		t.Errorf("the unapproved pypi policy was applied")
	}
	if _, ok := doc.NetworkPolicies["github"]; ok {
		t.Errorf("the superseded github operation was applied")
	}
}

func TestApproveRecoversFromLostStatusWrite(t *testing.T) {
	r, c := newTestReconciler(targetProfile(t), newProposal("add-github", profileName, addRuleOps("github", "github.com", 443)))

	reconcileProposal(t, r, "add-github")
	decideProposal(t, c, "add-github", &agentsv1alpha1.PolicyProposalDecision{
		Action:    agentsv1alpha1.PolicyDecisionActionApprove,
		DecidedBy: "alice",
	})
	reconcileProposal(t, r, "add-github")

	// Simulate the controller dying after it wrote the profile but before the
	// status write landed: the proposal is still Pending and unapplied, while
	// the profile carries the apply credential.
	lost := fetchProposal(t, c, "add-github").DeepCopy()
	lost.Status.Phase = agentsv1alpha1.PolicyProposalPhasePending
	lost.Status.AppliedRevision = 0
	lost.Status.AppliedTime = nil
	if err := c.Status().Update(context.Background(), lost); err != nil {
		t.Fatalf("rewind status: %v", err)
	}

	reconcileProposal(t, r, "add-github")

	proposal := fetchProposal(t, c, "add-github")
	if proposal.Status.Phase != agentsv1alpha1.PolicyProposalPhaseApplied {
		t.Fatalf("phase = %q, want Applied after recovery", proposal.Status.Phase)
	}
	if proposal.Status.AppliedRevision != 1 {
		t.Errorf("appliedRevision = %d, want the committed revision 1, not a double bump", proposal.Status.AppliedRevision)
	}
	if got := fetchProfile(t, c).Annotations[OpenShellPolicyRevisionAnnotation]; got != "1" {
		t.Errorf("revision annotation = %q, want 1 (the merge must not run twice)", got)
	}
	if doc := fetchProfileDoc(t, c); len(doc.NetworkPolicies) != 2 {
		t.Errorf("policies = %v, want the applied github policy and the baseline", doc.NetworkPolicies)
	}
}
