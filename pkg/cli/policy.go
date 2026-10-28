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

package cli

import (
	"context"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	agentsv1alpha1 "github.com/openkruise/agents/api/v1alpha1"
	apiv1alpha1 "github.com/openkruise/agents/client/clientset/versioned/typed/api/v1alpha1"
)

// NewPolicyCommand returns the "policy" command with its subcommands.
//
// These commands drive the OpenShell policy governance loop: an agent whose
// overreach was denied with next_steps files a PolicyProposal, the controller
// admits it with risk findings recorded, and an operator rules on it here.
func NewPolicyCommand(globalOpts *GlobalOptions) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "policy",
		Short: "Review and rule on OpenShell policy proposals",
		Long: `Review and rule on OpenShell policy proposals.

Admitted proposals carry the risk checks the controller recorded at
admission. "okactl policy get" shows them; "approve"/"reject" record the
operator ruling the controller applies.`,
	}
	cmd.AddCommand(newPolicyListCommand(globalOpts))
	cmd.AddCommand(newPolicyGetCommand(globalOpts))
	cmd.AddCommand(newPolicyApproveCommand(globalOpts))
	cmd.AddCommand(newPolicyRejectCommand(globalOpts))
	return cmd
}

func newPolicyListCommand(globalOpts *GlobalOptions) *cobra.Command {
	var profile string
	cmd := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List OpenShell policy proposals",
		Long: `List OpenShell policy proposals in a namespace.

Shows the target profile, lifecycle phase, recorded ruling, and the number
of risk findings awaiting review.`,
		Example: `  # List all proposals in the current namespace
  okactl policy list

  # List proposals targeting one SecurityProfile
  okactl policy list --profile openshell-l7`,
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := globalOpts.AgentsClient()
			if err != nil {
				return err
			}
			return runPolicyListWithClient(client, globalOpts, profile)
		},
	}
	cmd.Flags().StringVar(&profile, "profile", "", "Only show proposals targeting this SecurityProfile")
	return cmd
}

func newPolicyGetCommand(globalOpts *GlobalOptions) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "get NAME",
		Short: "Show one policy proposal in review detail",
		Long: `Show one policy proposal in review detail.

Displays the submitted operations, the rationale, the risk findings and
unchecked categories recorded at admission, the baseline and candidate
policy hashes, and the ruling (if any).`,
		Example: `  # Review a proposal before ruling on it
  okactl policy get add-github`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := globalOpts.AgentsClient()
			if err != nil {
				return err
			}
			return runPolicyGetWithClient(client, globalOpts, args[0])
		},
	}
	return cmd
}

func newPolicyApproveCommand(globalOpts *GlobalOptions) *cobra.Command {
	var reason, decidedBy string
	cmd := &cobra.Command{
		Use:   "approve NAME",
		Short: "Approve a policy proposal",
		Long: `Approve a policy proposal.

Records the ruling on the proposal's status. The controller merges the
approved operations into the target SecurityProfile's embedded OpenShell
document and bumps its policy revision, failing instead if the baseline
document changed since admission.`,
		Example: `  # Approve a proposal after reviewing its findings
  okactl policy approve add-github --by alice

  # Approve with a note
  okactl policy approve add-github --by alice --reason "narrowed to read-only"`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := globalOpts.AgentsClient()
			if err != nil {
				return err
			}
			return runPolicyDecideWithClient(client, globalOpts, args[0], &agentsv1alpha1.PolicyProposalDecision{
				Action:    agentsv1alpha1.PolicyDecisionActionApprove,
				Reason:    reason,
				DecidedBy: decidedBy,
			})
		},
	}
	cmd.Flags().StringVar(&reason, "reason", "", "Optional note recorded with the approval")
	cmd.Flags().StringVar(&decidedBy, "by", "", "Identity recorded as the decider (e.g. your username)")
	return cmd
}

func newPolicyRejectCommand(globalOpts *GlobalOptions) *cobra.Command {
	var reason, decidedBy string
	cmd := &cobra.Command{
		Use:   "reject NAME",
		Short: "Reject a policy proposal",
		Long: `Reject a policy proposal.

Records the ruling together with a reason that is surfaced back to the
submitting agent, mirroring OpenShell's rejection_reason, so it can file a
narrowed proposal.`,
		Example: `  # Reject with the reason the agent will see
  okactl policy reject add-github --by alice --reason "scope too broad for this workload"`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if reason == "" {
				return fmt.Errorf("--reason is required: the submitting agent sees it when revising the proposal")
			}
			client, err := globalOpts.AgentsClient()
			if err != nil {
				return err
			}
			return runPolicyDecideWithClient(client, globalOpts, args[0], &agentsv1alpha1.PolicyProposalDecision{
				Action:    agentsv1alpha1.PolicyDecisionActionReject,
				Reason:    reason,
				DecidedBy: decidedBy,
			})
		},
	}
	cmd.Flags().StringVar(&reason, "reason", "", "Reason surfaced back to the submitting agent (required)")
	cmd.Flags().StringVar(&decidedBy, "by", "", "Identity recorded as the decider (e.g. your username)")
	return cmd
}

func runPolicyListWithClient(client apiv1alpha1.ApiV1alpha1Interface, globalOpts *GlobalOptions, profile string) error {
	ctx := context.TODO()
	ns := globalOpts.Namespace

	list, err := client.PolicyProposals(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("failed to list policyproposals: %w", err)
	}

	fmt.Printf("%-40s %-30s %-10s %-9s %s\n", "NAME", "PROFILE", "PHASE", "DECISION", "FINDINGS")
	for i := range list.Items {
		proposal := &list.Items[i]
		if profile != "" && proposal.Spec.SecurityProfileRef != profile {
			continue
		}
		phase := string(proposal.Status.Phase)
		if phase == "" {
			phase = "-"
		}
		decision := "-"
		if proposal.Status.Decision != nil {
			decision = string(proposal.Status.Decision.Action)
		}
		fmt.Printf("%-40s %-30s %-10s %-9s %d\n",
			proposal.Name, proposal.Spec.SecurityProfileRef, phase, decision, len(proposal.Status.Findings))
	}
	return nil
}

func runPolicyGetWithClient(client apiv1alpha1.ApiV1alpha1Interface, globalOpts *GlobalOptions, name string) error {
	ctx := context.TODO()
	ns := globalOpts.Namespace

	proposal, err := client.PolicyProposals(ns).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("failed to get policyproposal %q: %w", name, err)
	}
	printPolicyProposal(proposal)
	return nil
}

// runPolicyDecideWithClient records an operator ruling through the status
// subresource, the single write path the controller consumes. Rulings are
// refused on terminal proposals: a decided proposal is history, and revision
// happens through a newly filed proposal.
func runPolicyDecideWithClient(client apiv1alpha1.ApiV1alpha1Interface, globalOpts *GlobalOptions, name string, decision *agentsv1alpha1.PolicyProposalDecision) error {
	ctx := context.TODO()
	ns := globalOpts.Namespace

	proposal, err := client.PolicyProposals(ns).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("failed to get policyproposal %q: %w", name, err)
	}
	switch proposal.Status.Phase {
	case agentsv1alpha1.PolicyProposalPhaseApplied, agentsv1alpha1.PolicyProposalPhaseRejected, agentsv1alpha1.PolicyProposalPhaseFailed:
		return fmt.Errorf("policyproposal %q is already %s; file a new proposal instead", name, proposal.Status.Phase)
	}
	// Surface the recorded risk, so a ruling is never cast blind to it.
	if len(proposal.Status.Findings) > 0 {
		queries := make([]string, 0, len(proposal.Status.Findings))
		for _, f := range proposal.Status.Findings {
			queries = append(queries, f.Query)
		}
		fmt.Printf("Warning: proposal carries %d finding(s): %s\n", len(proposal.Status.Findings), strings.Join(queries, ", "))
	}

	proposal.Status.Decision = decision
	if _, err := client.PolicyProposals(ns).UpdateStatus(ctx, proposal, metav1.UpdateOptions{}); err != nil {
		return fmt.Errorf("failed to record decision on policyproposal %q: %w", name, err)
	}

	switch decision.Action {
	case agentsv1alpha1.PolicyDecisionActionApprove:
		fmt.Printf("Policyproposal %q approved; the controller merges it into securityProfile %q.\n", name, proposal.Spec.SecurityProfileRef)
	case agentsv1alpha1.PolicyDecisionActionReject:
		fmt.Printf("Policyproposal %q rejected; the reason is surfaced to the submitter.\n", name)
	}
	return nil
}

func printPolicyProposal(proposal *agentsv1alpha1.PolicyProposal) {
	phase := string(proposal.Status.Phase)
	if phase == "" {
		phase = "Pending (not yet admitted)"
	}
	fmt.Printf("Name:       %s\n", proposal.Name)
	fmt.Printf("Namespace:  %s\n", proposal.Namespace)
	fmt.Printf("Profile:    %s\n", proposal.Spec.SecurityProfileRef)
	fmt.Printf("Phase:      %s\n", phase)
	if proposal.Spec.Principal != "" {
		fmt.Printf("Principal:  %s\n", proposal.Spec.Principal)
	}
	if proposal.Spec.Rationale != "" {
		fmt.Printf("Rationale:  %s\n", proposal.Spec.Rationale)
	}

	fmt.Printf("\nOperations:\n")
	for i, op := range proposal.Spec.Operations {
		fmt.Printf("  %d. %s\n", i+1, describePolicyMergeOperation(op))
	}

	if len(proposal.Status.Findings) > 0 {
		fmt.Printf("\nFindings (recorded at admission):\n")
		for _, f := range proposal.Status.Findings {
			title := f.Query
			if f.Title != "" {
				title = fmt.Sprintf("%s: %s", f.Query, f.Title)
			}
			fmt.Printf("  - %s\n", title)
			for _, ev := range f.Evidence {
				fmt.Printf("      evidence: %s\n", describeFindingPath(ev))
			}
			for _, rem := range f.Remediation {
				fmt.Printf("      remediation: %s\n", rem)
			}
		}
	} else {
		fmt.Printf("\nFindings: none recorded\n")
	}

	if len(proposal.Status.Unchecked) > 0 {
		fmt.Printf("\nUnchecked (not evaluated by this data plane):\n")
		for _, u := range proposal.Status.Unchecked {
			fmt.Printf("  - %s: %s\n", u.Category, u.Reason)
		}
	}

	if proposal.Status.CurrentPolicyHash != "" {
		fmt.Printf("\nBaseline hash: %s\n", proposal.Status.CurrentPolicyHash)
		fmt.Printf("Candidate hash: %s\n", proposal.Status.CandidatePolicyHash)
	}

	fmt.Printf("\nDecision: ")
	switch {
	case proposal.Status.Decision == nil:
		fmt.Printf("none (awaiting ruling)\n")
	default:
		fmt.Printf("%s", proposal.Status.Decision.Action)
		if proposal.Status.Decision.DecidedBy != "" {
			fmt.Printf(" by %s", proposal.Status.Decision.DecidedBy)
		}
		if proposal.Status.Decision.Reason != "" {
			fmt.Printf(" (%s)", proposal.Status.Decision.Reason)
		}
		fmt.Println()
	}
	if proposal.Status.RejectionReason != "" {
		fmt.Printf("Rejection reason: %s\n", proposal.Status.RejectionReason)
	}
	if proposal.Status.ApplicationError != "" {
		fmt.Printf("Application error: %s\n", proposal.Status.ApplicationError)
	}
	if proposal.Status.AppliedRevision != 0 {
		fmt.Printf("Applied revision: %d\n", proposal.Status.AppliedRevision)
	}
}

// describePolicyMergeOperation renders one merge operation for a human
// reviewer, one line per operation regardless of kind.
func describePolicyMergeOperation(op agentsv1alpha1.PolicyMergeOperation) string {
	switch {
	case op.AddNetworkRule != nil:
		add := op.AddNetworkRule
		endpoints := make([]string, 0, len(add.Endpoints))
		for _, ep := range add.Endpoints {
			s := fmt.Sprintf("%s:%d", ep.Host, ep.Port)
			if ep.Access != "" {
				s = fmt.Sprintf("%s (%s)", s, ep.Access)
			}
			endpoints = append(endpoints, s)
		}
		scope := "any binary"
		if paths := policyBinaryPaths(add.Binaries); len(paths) > 0 {
			scope = fmt.Sprintf("binaries: %s", strings.Join(paths, ", "))
		}
		return fmt.Sprintf("add network rule %q: %s [%s]", add.RuleName, strings.Join(endpoints, ", "), scope)
	case op.RemoveNetworkRule != nil:
		return fmt.Sprintf("remove network rule %q", op.RemoveNetworkRule.RuleName)
	case op.RemoveNetworkEndpoint != nil:
		rm := op.RemoveNetworkEndpoint
		return fmt.Sprintf("remove endpoint %s:%d from network rule %q", rm.Host, rm.Port, rm.RuleName)
	case op.AddDenyRules != nil:
		return describeL7RulesAppend("deny", op.AddDenyRules)
	case op.AddAllowRules != nil:
		return describeL7RulesAppend("allow", op.AddAllowRules)
	case op.RemoveNetworkBinary != nil:
		rm := op.RemoveNetworkBinary
		return fmt.Sprintf("remove binary %q from network rule %q", rm.BinaryPath, rm.RuleName)
	default:
		return "invalid operation (no branch set)"
	}
}

func describeL7RulesAppend(kind string, app *agentsv1alpha1.L7RulesAppend) string {
	rules := make([]string, 0, len(app.Rules))
	for _, r := range app.Rules {
		s := string(r.Action)
		if r.Method != "" {
			s = fmt.Sprintf("%s %s", s, r.Method)
		}
		if r.Path != "" {
			s = fmt.Sprintf("%s %s", s, r.Path)
		}
		rules = append(rules, s)
	}
	return fmt.Sprintf("add %s rules to %s:%d in network rule %q: %s",
		kind, app.Target.Host, app.Target.Port, app.Target.RuleName, strings.Join(rules, ", "))
}

func policyBinaryPaths(binaries []agentsv1alpha1.PolicyBinaryRef) []string {
	paths := make([]string, 0, len(binaries))
	for _, b := range binaries {
		paths = append(paths, b.Path)
	}
	return paths
}

func describeFindingPath(ev agentsv1alpha1.PolicyFindingPath) string {
	var parts []string
	if ev.Host != "" || ev.Port != 0 {
		parts = append(parts, fmt.Sprintf("%s:%d", ev.Host, ev.Port))
	}
	if ev.Method != "" {
		parts = append(parts, ev.Method)
	}
	if ev.Binary != "" {
		parts = append(parts, fmt.Sprintf("via binary %s", ev.Binary))
	}
	if ev.Policy != "" {
		parts = append(parts, fmt.Sprintf("(policy %s)", ev.Policy))
	}
	if len(parts) == 0 {
		return "(no evidence recorded)"
	}
	return strings.Join(parts, " ")
}
