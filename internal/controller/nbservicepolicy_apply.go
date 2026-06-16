// SPDX-License-Identifier: BSD-3-Clause

package controller

import (
	"context"
	"sort"

	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gwv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/netbirdio/netbird/shared/management/http/api"

	nbv1alpha1 "github.com/netbirdio/kubernetes-operator/api/v1alpha1"
)

// gatewayAPIGroup is the API group of the HTTPRoute targets an NBServicePolicy
// may attach to.
const gatewayAPIGroup = "gateway.networking.k8s.io"

// servicePoliciesFor returns the NBServicePolicies attached to hr, ordered
// newest-first. Applying them in that order (see applyServicePolicies) lets the
// oldest policy win per-field conflicts, matching the GEP-713 precedence rule.
func (r *HTTPRouteReconciler) servicePoliciesFor(ctx context.Context, hr *gwv1.HTTPRoute) ([]nbv1alpha1.NBServicePolicy, error) {
	var list nbv1alpha1.NBServicePolicyList
	if err := r.List(ctx, &list, client.InNamespace(hr.Namespace)); err != nil {
		return nil, err
	}
	var out []nbv1alpha1.NBServicePolicy
	for i := range list.Items {
		if policyTargetsRoute(&list.Items[i], hr.Name) {
			out = append(out, list.Items[i])
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		ti, tj := out[i].CreationTimestamp, out[j].CreationTimestamp
		if ti.Equal(&tj) {
			return out[i].Name > out[j].Name // deterministic tie-break
		}
		return ti.After(tj.Time) // newest first
	})
	return out, nil
}

// policyTargetsRoute reports whether p attaches to the HTTPRoute named name.
// Targets are same-namespace (LocalPolicyTargetReference), which the caller
// guarantees by listing policies in the route's namespace.
func policyTargetsRoute(p *nbv1alpha1.NBServicePolicy, name string) bool {
	for _, t := range p.Spec.TargetRefs {
		if string(t.Group) == gatewayAPIGroup && string(t.Kind) == "HTTPRoute" && string(t.Name) == name {
			return true
		}
	}
	return false
}

// applyServicePolicies folds attached policies into req. Policies are expected
// newest-first, so the oldest is applied last and wins per-field conflicts.
func applyServicePolicies(policies []nbv1alpha1.NBServicePolicy, req *api.ServiceRequest) {
	for i := range policies {
		applyServicePolicy(&policies[i].Spec, req)
	}
}

func applyServicePolicy(s *nbv1alpha1.NBServicePolicySpec, req *api.ServiceRequest) {
	if s.Private != nil {
		req.Private = s.Private
	}
	if s.PassHostHeader != nil {
		req.PassHostHeader = s.PassHostHeader
	}
	if s.RewriteRedirects != nil {
		req.RewriteRedirects = s.RewriteRedirects
	}
	if len(s.AccessGroups) > 0 {
		groups := append([]string(nil), s.AccessGroups...)
		req.AccessGroups = &groups
	}
	if ar := accessRestrictionsFor(s); ar != nil {
		req.AccessRestrictions = ar
	}
}

// accessRestrictionsFor maps the CRD's restriction fields onto the NetBird API
// type, or returns nil when none are set. Values are validated at admission by
// the CRD's CEL rules, so no re-validation is needed here.
func accessRestrictionsFor(s *nbv1alpha1.NBServicePolicySpec) *api.AccessRestrictions {
	if s.CrowdsecMode == nil && s.AccessRestrictions == nil {
		return nil
	}
	var ar api.AccessRestrictions
	if s.CrowdsecMode != nil {
		mode := api.AccessRestrictionsCrowdsecMode(*s.CrowdsecMode)
		ar.CrowdsecMode = &mode
	}
	if r := s.AccessRestrictions; r != nil {
		if len(r.AllowedCidrs) > 0 {
			v := append([]string(nil), r.AllowedCidrs...)
			ar.AllowedCidrs = &v
		}
		if len(r.BlockedCidrs) > 0 {
			v := append([]string(nil), r.BlockedCidrs...)
			ar.BlockedCidrs = &v
		}
		if len(r.AllowedCountries) > 0 {
			v := append([]string(nil), r.AllowedCountries...)
			ar.AllowedCountries = &v
		}
		if len(r.BlockedCountries) > 0 {
			v := append([]string(nil), r.BlockedCountries...)
			ar.BlockedCountries = &v
		}
	}
	return &ar
}

// routesForServicePolicy maps an NBServicePolicy event to reconcile requests
// for every HTTPRoute it targets, so an attached route re-reconciles when the
// policy changes.
func routesForServicePolicy(_ context.Context, obj client.Object) []reconcile.Request {
	p, ok := obj.(*nbv1alpha1.NBServicePolicy)
	if !ok {
		return nil
	}
	var reqs []reconcile.Request
	for _, t := range p.Spec.TargetRefs {
		if string(t.Group) == gatewayAPIGroup && string(t.Kind) == "HTTPRoute" {
			reqs = append(reqs, reconcile.Request{
				NamespacedName: types.NamespacedName{Namespace: p.Namespace, Name: string(t.Name)},
			})
		}
	}
	return reqs
}
