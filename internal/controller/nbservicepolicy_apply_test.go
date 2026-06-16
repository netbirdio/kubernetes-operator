// SPDX-License-Identifier: BSD-3-Clause

package controller

import (
	"context"
	"testing"

	"github.com/go-openapi/testify/v2/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gwv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/netbirdio/netbird/shared/management/http/api"

	nbv1alpha1 "github.com/netbirdio/kubernetes-operator/api/v1alpha1"
)

func targetRef(kind, name string) gwv1.LocalPolicyTargetReference {
	return gwv1.LocalPolicyTargetReference{
		Group: gatewayAPIGroup,
		Kind:  gwv1.Kind(kind),
		Name:  gwv1.ObjectName(name),
	}
}

func TestPolicyTargetsRoute(t *testing.T) {
	t.Parallel()

	p := &nbv1alpha1.NBServicePolicy{Spec: nbv1alpha1.NBServicePolicySpec{
		TargetRefs: []gwv1.LocalPolicyTargetReference{targetRef("HTTPRoute", "nextcloud")},
	}}
	require.True(t, policyTargetsRoute(p, "nextcloud"))
	require.False(t, policyTargetsRoute(p, "searxng"))

	wrongKind := &nbv1alpha1.NBServicePolicy{Spec: nbv1alpha1.NBServicePolicySpec{
		TargetRefs: []gwv1.LocalPolicyTargetReference{targetRef("Gateway", "nextcloud")},
	}}
	require.False(t, policyTargetsRoute(wrongKind, "nextcloud"))
}

func TestApplyServicePolicy(t *testing.T) {
	t.Parallel()

	mode := nbv1alpha1.CrowdsecModeEnforce
	p := nbv1alpha1.NBServicePolicy{Spec: nbv1alpha1.NBServicePolicySpec{
		Private:      new(true),
		AccessGroups: []string{"All", "admins"},
		CrowdsecMode: &mode,
		AccessRestrictions: &nbv1alpha1.AccessRestrictions{
			BlockedCountries: []string{"RU", "KP"},
			AllowedCidrs:     []string{"10.0.0.0/8"},
		},
	}}

	req := api.ServiceRequest{}
	applyServicePolicies([]nbv1alpha1.NBServicePolicy{p}, &req)

	require.NotNil(t, req.Private)
	require.True(t, *req.Private)
	require.Equal(t, []string{"All", "admins"}, *req.AccessGroups)
	require.NotNil(t, req.AccessRestrictions)
	require.Equal(t, api.AccessRestrictionsCrowdsecModeEnforce, *req.AccessRestrictions.CrowdsecMode)
	require.Equal(t, []string{"RU", "KP"}, *req.AccessRestrictions.BlockedCountries)
	require.Equal(t, []string{"10.0.0.0/8"}, *req.AccessRestrictions.AllowedCidrs)
	require.Nil(t, req.AccessRestrictions.AllowedCountries)
}

func TestApplyServicePolicy_NoPolicies(t *testing.T) {
	t.Parallel()
	req := api.ServiceRequest{PassHostHeader: new(false)}
	applyServicePolicies(nil, &req)
	require.Nil(t, req.Private)
	require.Nil(t, req.AccessGroups)
	require.Nil(t, req.AccessRestrictions)
	require.False(t, *req.PassHostHeader)
}

func TestApplyServicePolicies_OldestWins(t *testing.T) {
	t.Parallel()

	// servicePoliciesFor yields newest-first; applying in that order means the
	// oldest is applied last and wins the conflicting field.
	newest := nbv1alpha1.NBServicePolicy{Spec: nbv1alpha1.NBServicePolicySpec{Private: new(false)}}
	oldest := nbv1alpha1.NBServicePolicy{Spec: nbv1alpha1.NBServicePolicySpec{
		Private:      new(true),
		AccessGroups: []string{"All"},
	}}

	req := api.ServiceRequest{}
	applyServicePolicies([]nbv1alpha1.NBServicePolicy{newest, oldest}, &req)

	require.True(t, *req.Private)                        // oldest wins the conflict
	require.Equal(t, []string{"All"}, *req.AccessGroups) // non-conflicting field still applied
}

func TestRoutesForServicePolicy(t *testing.T) {
	t.Parallel()

	p := &nbv1alpha1.NBServicePolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: "nextcloud"},
		Spec: nbv1alpha1.NBServicePolicySpec{TargetRefs: []gwv1.LocalPolicyTargetReference{
			targetRef("HTTPRoute", "nextcloud"),
			targetRef("Gateway", "ignored"),
		}},
	}
	reqs := routesForServicePolicy(context.Background(), p)
	require.Len(t, reqs, 1)
	require.Equal(t, "nextcloud", reqs[0].Name)
	require.Equal(t, "nextcloud", reqs[0].Namespace)
}
