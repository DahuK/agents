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
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/log"

	agentsv1alpha1 "github.com/openkruise/agents/api/v1alpha1"
	"github.com/openkruise/agents/pkg/discovery"
	"github.com/openkruise/agents/pkg/openshellpolicy"
)

var (
	concurrentReconciles = 2
	controllerName       = "policyproposal-controller"
	controllerKind       = agentsv1alpha1.SchemeGroupVersion.WithKind("PolicyProposal")
)

// OpenShellPolicyRevisionAnnotation counts, on a SecurityProfile, every
// approved proposal merged into the embedded OpenShell document. Revision 1
// is the document as originally projected; each approval increments it.
const OpenShellPolicyRevisionAnnotation = "agents.kruise.io/openshell-policy-revision"

// OpenShellPolicyApplyAnnotation records the last proposal application in the
// same write that changed the document. It is the recovery credential for the
// profile-updated/status-write-failed window: without it a retry would
// misread its own write as a stale baseline and report Failed even though the
// authorization is already effective.
const OpenShellPolicyApplyAnnotation = "agents.kruise.io/openshell-policy-apply"

// policyApplyCredential is the value of OpenShellPolicyApplyAnnotation.
type policyApplyCredential struct {
	ProposalUID   string `json:"proposalUID"`
	CandidateHash string `json:"candidateHash"`
	Revision      int64  `json:"revision"`
}

func readApplyCredential(profile *agentsv1alpha1.SecurityProfile) (policyApplyCredential, bool) {
	raw := profile.Annotations[OpenShellPolicyApplyAnnotation]
	if raw == "" {
		return policyApplyCredential{}, false
	}
	var credential policyApplyCredential
	if err := json.Unmarshal([]byte(raw), &credential); err != nil {
		return policyApplyCredential{}, false
	}
	return credential, true
}

func writeApplyCredential(profile *agentsv1alpha1.SecurityProfile, proposal *agentsv1alpha1.PolicyProposal, revision int64) error {
	data, err := json.Marshal(policyApplyCredential{
		ProposalUID:   string(proposal.UID),
		CandidateHash: proposal.Status.CandidatePolicyHash,
		Revision:      revision,
	})
	if err != nil {
		return fmt.Errorf("encode apply credential: %w", err)
	}
	if profile.Annotations == nil {
		profile.Annotations = make(map[string]string, 2)
	}
	profile.Annotations[OpenShellPolicyApplyAnnotation] = string(data)
	return nil
}

// PolicyProposalReconciler reconciles a PolicyProposal: it admits proposals
// (validating operations and recording risk findings), applies operator
// rulings, and writes approved merges back into the target SecurityProfile's
// embedded OpenShell document.
type PolicyProposalReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder record.EventRecorder
	// AllowUnenforceable admits proposals whose documents the restricted
	// REST/L7 contract cannot execute. It is a preview-only escape hatch:
	// approval then publishes a document the data plane does not enforce.
	// The zero value keeps the gate enabled, so a reconciler constructed
	// without options never becomes permissive by accident.
	AllowUnenforceable bool
}

// Options configures the PolicyProposal controller.
type Options struct {
	// AllowUnenforceable disables the restricted REST/L7 publication gate.
	// Only set it for preview deployments that must admit unenforceable
	// documents; production keeps the gate on.
	AllowUnenforceable bool
}

func Add(mgr ctrl.Manager, opts Options) error {
	if !discovery.DiscoverGVK(controllerKind) {
		return nil
	}
	if err := (&PolicyProposalReconciler{
		Client:             mgr.GetClient(),
		Scheme:             mgr.GetScheme(),
		Recorder:           mgr.GetEventRecorderFor(controllerName),
		AllowUnenforceable: opts.AllowUnenforceable,
	}).SetupWithManager(mgr); err != nil {
		return err
	}
	ctrl.Log.Info("Started PolicyProposalReconciler successfully",
		"openshellVersionBaseline", openshellpolicy.VersionBaseline,
		"enforceBlocksEnabled", !opts.AllowUnenforceable)
	return nil
}

// +kubebuilder:rbac:groups=agents.kruise.io,resources=policyproposals,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=agents.kruise.io,resources=policyproposals/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=agents.kruise.io,resources=securityprofiles,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=core,resources=events,verbs=create;patch

func (r *PolicyProposalReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := log.FromContext(ctx)
	proposal := &agentsv1alpha1.PolicyProposal{}
	if err := r.Get(ctx, req.NamespacedName, proposal); err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	// Terminal phases are immutable outcomes.
	switch proposal.Status.Phase {
	case agentsv1alpha1.PolicyProposalPhaseApplied, agentsv1alpha1.PolicyProposalPhaseRejected, agentsv1alpha1.PolicyProposalPhaseFailed:
		return ctrl.Result{}, nil
	}

	// (Re-)admit when first seen or when the spec changed after admission, so
	// the reviewer always sees checks for the exact operations being decided
	// on and the apply step validates against the baseline the reviewer saw.
	if proposal.Status.Phase == "" || proposal.Generation != proposal.Status.ObservedGeneration {
		if result, err := r.admit(ctx, proposal); err != nil {
			return result, err
		}
	}
	if proposal.Status.Phase != agentsv1alpha1.PolicyProposalPhasePending {
		return ctrl.Result{}, nil
	}
	if proposal.Status.Decision == nil {
		return ctrl.Result{}, nil
	}
	switch proposal.Status.Decision.Action {
	case agentsv1alpha1.PolicyDecisionActionReject:
		return r.reject(ctx, proposal)
	case agentsv1alpha1.PolicyDecisionActionApprove:
		return r.approve(ctx, proposal)
	default:
		log.Info("Unknown decision action", "action", proposal.Status.Decision.Action)
		return ctrl.Result{}, nil
	}
}

// admit validates the proposal against the target document and records the
// risk findings, the unchecked categories, and the baseline hashes. The
// merged candidate is computed but not applied: applying waits for an
// operator decision.
func (r *PolicyProposalReconciler) admit(ctx context.Context, proposal *agentsv1alpha1.PolicyProposal) (ctrl.Result, error) {
	_, action, err := r.targetAction(ctx, proposal)
	if err != nil {
		return r.fail(ctx, proposal, err.Error())
	}
	ops, err := openshellpolicy.ConvertMergeOperations(proposal.Spec.Operations)
	if err != nil {
		return r.fail(ctx, proposal, fmt.Sprintf("invalid operations: %v", err))
	}
	prepared, err := openshellpolicy.PrepareCandidate(openshellpolicy.PrepareRequest{
		Source:     action.Policy.Raw,
		Operations: ops,
		Contract:   openshellpolicy.ContractEndpointRESTv1,
	})
	if err != nil {
		return r.fail(ctx, proposal, err.Error())
	}
	if len(prepared.Unsupported) > 0 {
		message := fmt.Sprintf("policy is not enforceable by the restricted REST/L7 contract: %s", strings.Join(prepared.Unsupported, "; "))
		if !r.AllowUnenforceable {
			return r.fail(ctx, proposal, message)
		}
		// Preview-only mode: admission succeeds, but the data plane cannot
		// execute the candidate. Warn so the gap is never silent.
		r.Recorder.Eventf(proposal, corev1.EventTypeWarning, "UnenforceablePolicy",
			"Admitted with the enforcement gate disabled: %s", message)
	}
	findings, unchecked := openshellpolicy.CheckProposalRisk(prepared.Baseline, prepared.Policy)

	newStatus := *proposal.Status.DeepCopy()
	newStatus.Phase = agentsv1alpha1.PolicyProposalPhasePending
	// A new generation is a new proposal: the previous ruling must never
	// carry over into a decision on content the reviewer never saw.
	newStatus.Decision = nil
	newStatus.DecidedBy = ""
	newStatus.DecidedTime = nil
	newStatus.RejectionReason = ""
	newStatus.AppliedRevision = 0
	newStatus.AppliedTime = nil
	newStatus.ApplicationError = ""
	newStatus.Findings = findings
	newStatus.Unchecked = unchecked
	newStatus.CurrentPolicyHash = prepared.Identities.SourceSemanticIdentity
	newStatus.CandidatePolicyHash = prepared.Identities.CandidateSemanticIdentity
	newStatus.ObservedGeneration = proposal.Generation
	if err := r.updateStatus(ctx, proposal, newStatus); err != nil {
		return ctrl.Result{}, err
	}
	r.Recorder.Eventf(proposal, corev1.EventTypeNormal, "Admitted",
		"Proposal admitted: %d finding(s), %d unchecked categor(ies)", len(findings), len(unchecked))
	return ctrl.Result{}, nil
}

// approve merges the approved operations into the target SecurityProfile and
// bumps the profile's OpenShell policy revision.
func (r *PolicyProposalReconciler) approve(ctx context.Context, proposal *agentsv1alpha1.PolicyProposal) (ctrl.Result, error) {
	decision := proposal.Status.Decision
	profile, action, err := r.targetAction(ctx, proposal)
	if err != nil {
		return r.fail(ctx, proposal, err.Error())
	}

	// Recovery path: the previous attempt changed the profile but lost the
	// status write. The apply credential proves this proposal already
	// committed, so reporting a stale baseline would be false.
	if credential, ok := readApplyCredential(profile); ok &&
		proposal.UID != "" &&
		credential.ProposalUID == string(proposal.UID) &&
		credential.CandidateHash == proposal.Status.CandidatePolicyHash {
		return r.markApplied(ctx, proposal, decision, credential.Revision)
	}

	ops, err := openshellpolicy.ConvertMergeOperations(proposal.Spec.Operations)
	if err != nil {
		return r.fail(ctx, proposal, fmt.Sprintf("invalid operations: %v", err))
	}
	prepared, err := openshellpolicy.PrepareCandidate(openshellpolicy.PrepareRequest{
		Source:     action.Policy.Raw,
		Operations: ops,
		Contract:   openshellpolicy.ContractEndpointRESTv1,
	})
	if err != nil {
		return r.fail(ctx, proposal, err.Error())
	}
	// Review-token semantics: the decision was made against the baseline
	// recorded at admission. Comparing the full-document identity also
	// detects changes to fields this controller does not model.
	if prepared.Identities.SourceSemanticIdentity != proposal.Status.CurrentPolicyHash {
		return r.fail(ctx, proposal, fmt.Sprintf(
			"target policy changed since admission (now %s, admitted against %s); resubmit the proposal against the current policy",
			prepared.Identities.SourceSemanticIdentity, proposal.Status.CurrentPolicyHash))
	}
	// The applied document must be byte-for-byte the candidate the reviewer
	// approved, not merely a document produced by the same operations.
	if proposal.Status.CandidatePolicyHash != "" &&
		prepared.Identities.CandidateSemanticIdentity != proposal.Status.CandidatePolicyHash {
		return r.fail(ctx, proposal, fmt.Sprintf(
			"recomputed candidate %s does not match the admitted candidate %s; resubmit the proposal",
			prepared.Identities.CandidateSemanticIdentity, proposal.Status.CandidatePolicyHash))
	}
	// Re-check the gate at apply time: a proposal admitted while the gate was
	// disabled must not be published after the controller restarts with the
	// gate enabled.
	if len(prepared.Unsupported) > 0 && !r.AllowUnenforceable {
		return r.fail(ctx, proposal, fmt.Sprintf(
			"policy is not enforceable by the restricted REST/L7 contract: %s", strings.Join(prepared.Unsupported, "; ")))
	}

	revision := bumpRevision(profile)
	action.Policy.Raw = prepared.Document
	if err := writeApplyCredential(profile, proposal, revision); err != nil {
		return ctrl.Result{}, err
	}
	if err := r.Update(ctx, profile); err != nil {
		return ctrl.Result{}, err
	}
	return r.markApplied(ctx, proposal, decision, revision)
}

// markApplied records the applied revision after the profile write (or after
// recovering a committed apply credential). It is idempotent: terminal phases
// never reach it because Reconcile returns early.
func (r *PolicyProposalReconciler) markApplied(ctx context.Context, proposal *agentsv1alpha1.PolicyProposal, decision *agentsv1alpha1.PolicyProposalDecision, revision int64) (ctrl.Result, error) {
	now := metav1.Now()
	newStatus := *proposal.Status.DeepCopy()
	newStatus.Phase = agentsv1alpha1.PolicyProposalPhaseApplied
	newStatus.AppliedRevision = revision
	newStatus.AppliedTime = &now
	newStatus.DecidedBy = decision.DecidedBy
	newStatus.DecidedTime = &now
	newStatus.ApplicationError = ""
	if err := r.updateStatus(ctx, proposal, newStatus); err != nil {
		return ctrl.Result{}, err
	}
	r.Recorder.Eventf(proposal, corev1.EventTypeNormal, "Applied",
		"Merged into securityProfile %s at OpenShell policy revision %d", proposal.Spec.SecurityProfileRef, revision)
	return ctrl.Result{}, nil
}

// reject closes the proposal without merging; the reason is surfaced for
// the submitting agent, mirroring OpenShell's rejection_reason.
func (r *PolicyProposalReconciler) reject(ctx context.Context, proposal *agentsv1alpha1.PolicyProposal) (ctrl.Result, error) {
	decision := proposal.Status.Decision
	now := metav1.Now()
	newStatus := *proposal.Status.DeepCopy()
	newStatus.Phase = agentsv1alpha1.PolicyProposalPhaseRejected
	newStatus.RejectionReason = decision.Reason
	newStatus.DecidedBy = decision.DecidedBy
	newStatus.DecidedTime = &now
	if err := r.updateStatus(ctx, proposal, newStatus); err != nil {
		return ctrl.Result{}, err
	}
	r.Recorder.Eventf(proposal, corev1.EventTypeNormal, "Rejected",
		"Proposal rejected: %s", decision.Reason)
	return ctrl.Result{}, nil
}

// targetAction fetches the proposal's target SecurityProfile and returns the
// profile together with its single openShellPolicy action.
func (r *PolicyProposalReconciler) targetAction(ctx context.Context, proposal *agentsv1alpha1.PolicyProposal) (*agentsv1alpha1.SecurityProfile, *agentsv1alpha1.OpenShellPolicyAction, error) {
	profile := &agentsv1alpha1.SecurityProfile{}
	key := client.ObjectKey{Namespace: proposal.Namespace, Name: proposal.Spec.SecurityProfileRef}
	if err := r.Get(ctx, key, profile); err != nil {
		if errors.IsNotFound(err) {
			return nil, nil, fmt.Errorf("securityProfile %q not found", proposal.Spec.SecurityProfileRef)
		}
		return nil, nil, err
	}
	var action *agentsv1alpha1.OpenShellPolicyAction
	count := 0
	for i := range profile.Spec.Rules {
		if a := profile.Spec.Rules[i].Actions.OpenShellPolicy; a != nil {
			action = a
			count++
		}
	}
	if count != 1 {
		return nil, nil, fmt.Errorf("securityProfile %q must carry exactly one openShellPolicy action, found %d", profile.Name, count)
	}
	return profile, action, nil
}

// bumpRevision increments the profile's OpenShell policy revision annotation
// and returns the new revision. An absent or unparsable annotation restarts
// counting at 1.
func bumpRevision(profile *agentsv1alpha1.SecurityProfile) int64 {
	revision := int64(1)
	if parsed, err := strconv.ParseInt(profile.Annotations[OpenShellPolicyRevisionAnnotation], 10, 64); err == nil && parsed > 0 {
		revision = parsed + 1
	}
	if profile.Annotations == nil {
		profile.Annotations = make(map[string]string, 1)
	}
	profile.Annotations[OpenShellPolicyRevisionAnnotation] = strconv.FormatInt(revision, 10)
	return revision
}

// fail moves the proposal to the Failed phase with an application error,
// kept separate from an operator rejection: a prover-clean proposal can
// still fail to apply.
func (r *PolicyProposalReconciler) fail(ctx context.Context, proposal *agentsv1alpha1.PolicyProposal, message string) (ctrl.Result, error) {
	newStatus := *proposal.Status.DeepCopy()
	newStatus.Phase = agentsv1alpha1.PolicyProposalPhaseFailed
	newStatus.ApplicationError = message
	if err := r.updateStatus(ctx, proposal, newStatus); err != nil {
		return ctrl.Result{}, err
	}
	r.Recorder.Eventf(proposal, corev1.EventTypeWarning, "ApplicationFailed", "%s", message)
	return ctrl.Result{}, nil
}

func (r *PolicyProposalReconciler) updateStatus(ctx context.Context, proposal *agentsv1alpha1.PolicyProposal, newStatus agentsv1alpha1.PolicyProposalStatus) error {
	if reflect.DeepEqual(proposal.Status, newStatus) {
		return nil
	}
	updated := proposal.DeepCopy()
	updated.Status = newStatus
	if err := r.Status().Patch(ctx, updated, client.MergeFromWithOptions(proposal, client.MergeFromWithOptimisticLock{})); err != nil {
		return err
	}
	proposal.Status = newStatus
	return nil
}

func (r *PolicyProposalReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		WithOptions(controller.Options{MaxConcurrentReconciles: concurrentReconciles}).
		For(&agentsv1alpha1.PolicyProposal{}).
		Complete(r)
}
