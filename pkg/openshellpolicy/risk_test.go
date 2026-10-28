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
	"strings"
	"testing"

	agentsv1alpha1 "github.com/openkruise/agents/api/v1alpha1"
)

func parseRiskDoc(t *testing.T, doc string) *Policy {
	t.Helper()
	policy, err := ParsePolicy([]byte(doc))
	if err != nil {
		t.Fatalf("ParsePolicy: %v", err)
	}
	return policy
}

const riskCurrentDoc = `version: 1
network_policies:
  api:
    endpoints:
      - host: api.example.com
        port: 443
`

func uncheckedCategories(unchecked []agentsv1alpha1.PolicyUncheckedCheck) []string {
	categories := make([]string, 0, len(unchecked))
	for _, u := range unchecked {
		categories = append(categories, u.Category)
	}
	return categories
}

func TestCheckProposalRiskLinkLocal(t *testing.T) {
	current := parseRiskDoc(t, riskCurrentDoc)
	candidate := parseRiskDoc(t, `version: 1
network_policies:
  api:
    endpoints:
      - host: api.example.com
        port: 443
  metadata:
    binaries:
      - path: /usr/bin/curl
    endpoints:
      - host: 169.254.169.254
        port: 80
`)
	findings, unchecked := CheckProposalRisk(current, candidate)
	if len(findings) != 1 {
		t.Fatalf("findings = %+v, want exactly the link_local_reach finding", findings)
	}
	finding := findings[0]
	if finding.Query != RiskLinkLocalReach {
		t.Errorf("query = %q, want %q", finding.Query, RiskLinkLocalReach)
	}
	if len(finding.Evidence) != 1 {
		t.Fatalf("evidence = %+v, want the metadata endpoint", finding.Evidence)
	}
	ev := finding.Evidence[0]
	if ev.Host != "169.254.169.254" || ev.Port != 80 || ev.Policy != "metadata" {
		t.Errorf("evidence = %+v, want the metadata endpoint in the metadata policy", ev)
	}
	if ev.Binary != "/usr/bin/curl" {
		t.Errorf("evidence binary = %q, want the bound binary path", ev.Binary)
	}
	if finding.Title == "" || len(finding.Remediation) == 0 {
		t.Errorf("finding must carry a title and remediation: %+v", finding)
	}

	// The credential-scoped categories are always reported unchecked.
	want := []string{RiskCredentialReachExpansion, RiskCapabilityExpansion, RiskL7BypassCredentialed}
	got := uncheckedCategories(unchecked)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("unchecked = %v, want %v", got, want)
	}
	for _, u := range unchecked {
		if strings.TrimSpace(u.Reason) == "" {
			t.Errorf("unchecked category %q must carry a reason", u.Category)
		}
	}
}

func TestCheckProposalRiskDeltaOnly(t *testing.T) {
	// A link-local endpoint already admitted in the baseline is not re-flagged:
	// findings track the delta between baseline and candidate.
	docs := `version: 1
network_policies:
  metadata:
    endpoints:
      - host: 169.254.169.254
        port: 80
`
	findings, _ := CheckProposalRisk(parseRiskDoc(t, docs), parseRiskDoc(t, docs))
	if len(findings) != 0 {
		t.Errorf("findings = %+v, want none for an unchanged baseline", findings)
	}
}

func TestCheckProposalRiskIPv6LinkLocal(t *testing.T) {
	current := parseRiskDoc(t, riskCurrentDoc)
	candidate := parseRiskDoc(t, `version: 1
network_policies:
  api:
    endpoints:
      - host: api.example.com
        port: 443
  v6:
    endpoints:
      - host: fe80::1
        port: 8080
`)
	findings, _ := CheckProposalRisk(current, candidate)
	if len(findings) != 1 || findings[0].Query != RiskLinkLocalReach {
		t.Fatalf("findings = %+v, want one link_local_reach finding for fe80::/10", findings)
	}
	if findings[0].Evidence[0].Host != "fe80::1" {
		t.Errorf("evidence host = %q, want fe80::1", findings[0].Evidence[0].Host)
	}
}

func TestCheckProposalRiskCleanProposal(t *testing.T) {
	current := parseRiskDoc(t, riskCurrentDoc)
	candidate := parseRiskDoc(t, `version: 1
network_policies:
  api:
    endpoints:
      - host: api.example.com
        port: 443
      - host: api.example.com
        port: 8443
        access: read-only
      - host: cdn.example.com
        port: 443
  metadata-hostname:
    endpoints:
      - host: metadata.google.internal
        port: 80
`)
	findings, _ := CheckProposalRisk(current, candidate)
	if len(findings) != 0 {
		t.Fatalf("findings = %+v, want none: only literal link-local IPs are flagged, and no new reach touches them", findings)
	}
}

func TestCheckProposalRiskNilBaseline(t *testing.T) {
	// A profile without a parseable network section (filesystem-only) still
	// yields a reach index; every candidate endpoint is new reach.
	candidate := parseRiskDoc(t, `version: 1
network_policies:
  metadata:
    endpoints:
      - host: 169.254.169.254
        port: 80
`)
	findings, _ := CheckProposalRisk(nil, candidate)
	if len(findings) != 1 || findings[0].Query != RiskLinkLocalReach {
		t.Fatalf("findings = %+v, want one link_local_reach finding against a nil baseline", findings)
	}
}
