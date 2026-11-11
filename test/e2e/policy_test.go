// SPDX-License-Identifier: BSD-3-Clause

//go:build e2e

package e2e

import (
	"fmt"
	"testing"

	"github.com/go-openapi/testify/v2/assert"
	"github.com/go-openapi/testify/v2/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	nbv1alpha1 "github.com/netbirdio/kubernetes-operator/api/v1alpha1"
	"github.com/netbirdio/netbird/shared/management/http/api"
)

// TestPolicy grants access with a Policy and checks it the way a user would see
// it: a peer outside the cluster reaches a network resource in a group no other
// policy covers only while a Policy from the peer's group to that group is
// enabled, and deleting the Policy deletes it on the server.
func TestPolicy(t *testing.T) {
	t.Parallel()
	e := requireEnv(t)
	fx := e.requireNetworkFixtures(t)
	ns := e.createNamespace(t, "policy")
	router := e.createRouter(t, ns, 1)
	svc := e.createBackend(t, ns, "web")

	group := &nbv1alpha1.Group{
		ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: ns},
		Spec:       nbv1alpha1.GroupSpec{Name: "e2e-" + ns},
	}
	require.NoError(t, e.k8s.Create(t.Context(), group))
	e.waitReady(t, group)
	groupRef := nbv1alpha1.GroupReference{LocalRef: &corev1.LocalObjectReference{Name: group.Name}}

	res := resourceFor(ns, router, svc)
	res.Spec.Groups = []nbv1alpha1.GroupReference{groupRef}
	require.NoError(t, e.k8s.Create(t.Context(), res))
	e.waitReady(t, res)
	url := fmt.Sprintf("http://%s/hostname", resourceFQDN(svc.Name, ns))
	requireUnreachable(t, fx.laptop, url)

	policy := &nbv1alpha1.Policy{
		ObjectMeta: metav1.ObjectMeta{Name: "clients-to-web", Namespace: ns},
		Spec: nbv1alpha1.PolicySpec{
			Name:              "e2e-clients-to-" + ns,
			SourceGroups:      []nbv1alpha1.GroupReference{{Name: new(clientsGroup)}},
			DestinationGroups: []nbv1alpha1.GroupReference{groupRef},
			Protocol:          "tcp",
			Ports:             []int32{backendServicePort},
		},
	}
	require.NoError(t, e.k8s.Create(t.Context(), policy))
	e.waitReady(t, policy)
	policyID := policy.Status.PolicyID

	nbPolicy, err := e.nb.Policies.Get(t.Context(), policyID)
	require.NoError(t, err)
	assert.EqualT(t, policy.Spec.Name, nbPolicy.Name, "policy name")
	assert.TrueT(t, nbPolicy.Enabled, "policy enabled")
	require.Len(t, nbPolicy.Rules, 1, "policy rules")
	rule := nbPolicy.Rules[0]
	assert.EqualT(t, api.PolicyRuleProtocolTcp, rule.Protocol, "rule protocol")
	require.NotNil(t, rule.Ports, "rule ports")
	assert.Equal(t, []string{fmt.Sprint(backendServicePort)}, *rule.Ports, "rule ports")
	require.NotNil(t, rule.Sources, "rule sources")
	assert.Equal(t, []string{fx.clientsGroupID}, groupIDs(*rule.Sources), "rule sources")
	require.NotNil(t, rule.Destinations, "rule destinations")
	assert.Equal(t, []string{group.Status.GroupID}, groupIDs(*rule.Destinations), "rule destinations")
	requireReachable(t, fx.laptop, url, svc.Name+"-")

	// Disabling the policy has to cut the peer off without the policy being
	// recreated.
	require.NoError(t, e.k8s.Get(t.Context(), client.ObjectKeyFromObject(policy), policy))
	policy.Spec.Enabled = new(false)
	require.NoError(t, e.k8s.Update(t.Context(), policy))
	e.waitReady(t, policy)
	assert.EqualT(t, policyID, policy.Status.PolicyID, "disabling the policy recreated it")
	requireUnreachable(t, fx.laptop, url)

	require.NoError(t, e.k8s.Delete(t.Context(), policy))
	e.waitGone(t, policy)
	requireGone(t, "policy", policyID, e.nb.Policies.Get)
}
