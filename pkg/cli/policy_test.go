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
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"

	agentsv1alpha1 "github.com/openkruise/agents/api/v1alpha1"
	"github.com/openkruise/agents/client/clientset/versioned/fake"
)

// captureStdout collects everything fn prints while it runs.
func capturePolicyStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	old := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = old }()

	fn()
	w.Close()
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	return buf.String()
}

func newCLIProposal(name, profile string, phase agentsv1alpha1.PolicyProposalPhase) *agentsv1alpha1.PolicyProposal {
	return &agentsv1alpha1.PolicyProposal{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "default",
		},
		Spec: agentsv1alpha1.PolicyProposalSpec{
			SecurityProfileRef: profile,
			Principal:          "sandbox-1",
			Rationale:          "agent needs git",
			Operations: []agentsv1alpha1.PolicyMergeOperation{{
				AddNetworkRule: &agentsv1alpha1.NetworkRuleAdd{
					RuleName: "github",
					Endpoints: []agentsv1alpha1.PolicyEndpoint{{
						Host:   "github.com",
						Port:   443,
						Access: "read-only",
					}},
					Binaries: []agentsv1alpha1.PolicyBinaryRef{{Path: "/usr/bin/git"}},
				},
			}},
		},
		Status: agentsv1alpha1.PolicyProposalStatus{
			Phase: phase,
			Findings: []agentsv1alpha1.PolicyFinding{{
				Query: "link_local_reach",
				Title: "New reach into the link-local range",
				Evidence: []agentsv1alpha1.PolicyFindingPath{{
					Host:   "169.254.169.254",
					Port:   80,
					Binary: "/usr/bin/curl",
					Policy: "metadata",
				}},
				Remediation: []string{"Bind the endpoint to a specific binary."},
			}},
			Unchecked: []agentsv1alpha1.PolicyUncheckedCheck{{
				Category: "credential_reach_expansion",
				Reason:   "credential reach is not modeled yet",
			}},
			CurrentPolicyHash:   "sha256:current",
			CandidatePolicyHash: "sha256:candidate",
		},
	}
}

func TestPolicyListWithClient(t *testing.T) {
	cs := fake.NewSimpleClientset(
		newCLIProposal("add-github", "profile-a", agentsv1alpha1.PolicyProposalPhasePending),
		newCLIProposal("add-pypi", "profile-b", agentsv1alpha1.PolicyProposalPhaseApplied),
	)
	globalOpts := &GlobalOptions{Namespace: "default"}

	out := capturePolicyStdout(t, func() {
		err := runPolicyListWithClient(cs.ApiV1alpha1(), globalOpts, "")
		assert.NoError(t, err)
	})
	assert.Contains(t, out, "add-github")
	assert.Contains(t, out, "profile-a")
	assert.Contains(t, out, "Pending")
	assert.Contains(t, out, "add-pypi")
	assert.Contains(t, out, "Applied")

	out = capturePolicyStdout(t, func() {
		err := runPolicyListWithClient(cs.ApiV1alpha1(), globalOpts, "profile-a")
		assert.NoError(t, err)
	})
	assert.Contains(t, out, "add-github")
	assert.NotContains(t, out, "add-pypi")
}

func TestPolicyGetWithClient(t *testing.T) {
	cs := fake.NewSimpleClientset(newCLIProposal("add-github", "profile-a", agentsv1alpha1.PolicyProposalPhasePending))
	globalOpts := &GlobalOptions{Namespace: "default"}

	out := capturePolicyStdout(t, func() {
		err := runPolicyGetWithClient(cs.ApiV1alpha1(), globalOpts, "add-github")
		assert.NoError(t, err)
	})
	assert.Contains(t, out, "Name:       add-github")
	assert.Contains(t, out, "Profile:    profile-a")
	assert.Contains(t, out, "Rationale:  agent needs git")
	assert.Contains(t, out, `add network rule "github": github.com:443 (read-only) [binaries: /usr/bin/git]`)
	assert.Contains(t, out, "link_local_reach: New reach into the link-local range")
	assert.Contains(t, out, "evidence: 169.254.169.254:80 via binary /usr/bin/curl (policy metadata)")
	assert.Contains(t, out, "credential_reach_expansion: credential reach is not modeled yet")
	assert.Contains(t, out, "Baseline hash: sha256:current")
	assert.Contains(t, out, "Candidate hash: sha256:candidate")
	assert.Contains(t, out, "Decision: none (awaiting ruling)")
}

func TestPolicyGetWithClientNotFound(t *testing.T) {
	cs := fake.NewSimpleClientset()
	globalOpts := &GlobalOptions{Namespace: "default"}

	err := runPolicyGetWithClient(cs.ApiV1alpha1(), globalOpts, "missing")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), `failed to get policyproposal "missing"`)
}

func TestPolicyApproveWithClient(t *testing.T) {
	cs := fake.NewSimpleClientset(newCLIProposal("add-github", "profile-a", agentsv1alpha1.PolicyProposalPhasePending))
	globalOpts := &GlobalOptions{Namespace: "default"}

	out := capturePolicyStdout(t, func() {
		err := runPolicyDecideWithClient(cs.ApiV1alpha1(), globalOpts, "add-github", &agentsv1alpha1.PolicyProposalDecision{
			Action:    agentsv1alpha1.PolicyDecisionActionApprove,
			Reason:    "narrowed scope",
			DecidedBy: "alice",
		})
		assert.NoError(t, err)
	})
	// The recorded findings are surfaced before the ruling is written.
	assert.Contains(t, out, "Warning: proposal carries 1 finding(s): link_local_reach")
	assert.Contains(t, out, `approved; the controller merges it into securityProfile "profile-a"`)

	proposal, err := cs.ApiV1alpha1().PolicyProposals("default").Get(context.TODO(), "add-github", metav1.GetOptions{})
	assert.NoError(t, err)
	assert.NotNil(t, proposal.Status.Decision)
	assert.Equal(t, agentsv1alpha1.PolicyDecisionActionApprove, proposal.Status.Decision.Action)
	assert.Equal(t, "narrowed scope", proposal.Status.Decision.Reason)
	assert.Equal(t, "alice", proposal.Status.Decision.DecidedBy)
}

func TestPolicyRejectWithClient(t *testing.T) {
	cs := fake.NewSimpleClientset(newCLIProposal("add-github", "profile-a", agentsv1alpha1.PolicyProposalPhasePending))
	globalOpts := &GlobalOptions{Namespace: "default"}

	out := capturePolicyStdout(t, func() {
		err := runPolicyDecideWithClient(cs.ApiV1alpha1(), globalOpts, "add-github", &agentsv1alpha1.PolicyProposalDecision{
			Action:    agentsv1alpha1.PolicyDecisionActionReject,
			Reason:    "scope too broad",
			DecidedBy: "bob",
		})
		assert.NoError(t, err)
	})
	assert.Contains(t, out, `rejected; the reason is surfaced to the submitter`)

	proposal, err := cs.ApiV1alpha1().PolicyProposals("default").Get(context.TODO(), "add-github", metav1.GetOptions{})
	assert.NoError(t, err)
	assert.NotNil(t, proposal.Status.Decision)
	assert.Equal(t, agentsv1alpha1.PolicyDecisionActionReject, proposal.Status.Decision.Action)
	assert.Equal(t, "scope too broad", proposal.Status.Decision.Reason)
}

func TestPolicyDecideRefusesTerminalPhases(t *testing.T) {
	for _, phase := range []agentsv1alpha1.PolicyProposalPhase{
		agentsv1alpha1.PolicyProposalPhaseApplied,
		agentsv1alpha1.PolicyProposalPhaseRejected,
		agentsv1alpha1.PolicyProposalPhaseFailed,
	} {
		cs := fake.NewSimpleClientset(newCLIProposal("add-github", "profile-a", phase))
		globalOpts := &GlobalOptions{Namespace: "default"}

		err := runPolicyDecideWithClient(cs.ApiV1alpha1(), globalOpts, "add-github", &agentsv1alpha1.PolicyProposalDecision{
			Action: agentsv1alpha1.PolicyDecisionActionApprove,
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), fmt.Sprintf("already %s", phase))
	}
}

func TestPolicyRejectRequiresReason(t *testing.T) {
	cmd := newPolicyRejectCommand(&GlobalOptions{Namespace: "default"})
	cmd.SetArgs([]string{"add-github"})
	err := cmd.Execute()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "--reason is required")
}

func TestPolicyCommandsInvalidConfig(t *testing.T) {
	origFn := inClusterConfigFn
	defer func() { inClusterConfigFn = origFn }()
	inClusterConfigFn = func() (*rest.Config, error) {
		return nil, fmt.Errorf("not in cluster")
	}

	tests := []struct {
		name string
		args []string
	}{
		{name: "list", args: []string{"list"}},
		{name: "get", args: []string{"get", "add-github"}},
		{name: "approve", args: []string{"approve", "add-github"}},
		{name: "reject", args: []string{"reject", "add-github", "--reason", "no"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := NewPolicyCommand(&GlobalOptions{
				KubeConfig: "/nonexistent/config",
				Namespace:  "default",
			})
			cmd.SetArgs(tt.args)
			err := cmd.Execute()
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "failed to build kubeconfig")
		})
	}
}

func TestDescribePolicyMergeOperation(t *testing.T) {
	tests := []struct {
		name string
		op   agentsv1alpha1.PolicyMergeOperation
		want string
	}{
		{
			name: "add network rule",
			op: agentsv1alpha1.PolicyMergeOperation{
				AddNetworkRule: &agentsv1alpha1.NetworkRuleAdd{
					RuleName:  "github",
					Endpoints: []agentsv1alpha1.PolicyEndpoint{{Host: "github.com", Port: 443}},
					Binaries:  []agentsv1alpha1.PolicyBinaryRef{{Path: "/usr/bin/git"}},
				},
			},
			want: `add network rule "github": github.com:443 [binaries: /usr/bin/git]`,
		},
		{
			name: "add network rule without binaries",
			op: agentsv1alpha1.PolicyMergeOperation{
				AddNetworkRule: &agentsv1alpha1.NetworkRuleAdd{
					RuleName:  "open",
					Endpoints: []agentsv1alpha1.PolicyEndpoint{{Host: "api.example.com", Port: 443, Access: "read-only"}},
				},
			},
			want: `add network rule "open": api.example.com:443 (read-only) [any binary]`,
		},
		{
			name: "remove network rule",
			op: agentsv1alpha1.PolicyMergeOperation{
				RemoveNetworkRule: &agentsv1alpha1.NetworkRuleRemove{RuleName: "api"},
			},
			want: `remove network rule "api"`,
		},
		{
			name: "remove endpoint",
			op: agentsv1alpha1.PolicyMergeOperation{
				RemoveNetworkEndpoint: &agentsv1alpha1.NetworkEndpointRemove{RuleName: "api", Host: "api.example.com", Port: 443},
			},
			want: `remove endpoint api.example.com:443 from network rule "api"`,
		},
		{
			name: "add deny rules",
			op: agentsv1alpha1.PolicyMergeOperation{
				AddDenyRules: &agentsv1alpha1.L7RulesAppend{
					Target: agentsv1alpha1.L7RuleTarget{RuleName: "api", Host: "api.example.com", Port: 443},
					Rules:  []agentsv1alpha1.PolicyL7Rule{{Action: "deny", Method: "DELETE", Path: "/v1/admin"}},
				},
			},
			want: `add deny rules to api.example.com:443 in network rule "api": deny DELETE /v1/admin`,
		},
		{
			name: "add allow rules",
			op: agentsv1alpha1.PolicyMergeOperation{
				AddAllowRules: &agentsv1alpha1.L7RulesAppend{
					Target: agentsv1alpha1.L7RuleTarget{RuleName: "api", Host: "api.example.com", Port: 443},
					Rules:  []agentsv1alpha1.PolicyL7Rule{{Action: "allow", Method: "GET"}},
				},
			},
			want: `add allow rules to api.example.com:443 in network rule "api": allow GET`,
		},
		{
			name: "remove binary",
			op: agentsv1alpha1.PolicyMergeOperation{
				RemoveNetworkBinary: &agentsv1alpha1.NetworkBinaryRemove{RuleName: "mirror", BinaryPath: "/usr/bin/curl"},
			},
			want: `remove binary "/usr/bin/curl" from network rule "mirror"`,
		},
		{
			name: "no branch set",
			op:   agentsv1alpha1.PolicyMergeOperation{},
			want: "invalid operation (no branch set)",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, describePolicyMergeOperation(tt.op))
		})
	}
}
