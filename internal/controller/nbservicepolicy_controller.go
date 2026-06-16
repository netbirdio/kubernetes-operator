// SPDX-License-Identifier: BSD-3-Clause

package controller

import (
	"context"

	"github.com/fluxcd/pkg/runtime/conditions"
	"github.com/fluxcd/pkg/runtime/patch"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gwv1 "sigs.k8s.io/gateway-api/apis/v1"

	nbv1alpha1 "github.com/netbirdio/kubernetes-operator/api/v1alpha1"
)

// TargetNotFoundReason marks a policy whose targetRefs resolve to no HTTPRoute.
const TargetNotFoundReason = "TargetNotFound"

// NBServicePolicyReconciler manages NBServicePolicy status. The policy's effect
// is applied by the HTTPRoute reconciler (which watches these objects); this
// controller records readiness — advancing observedGeneration and setting the
// Ready condition (False/TargetNotFound when no target resolves) — so kstatus
// and Flux observe real status instead of hanging at InProgress.
type NBServicePolicyReconciler struct {
	client.Client
}

// +kubebuilder:rbac:groups=netbird.io,resources=nbservicepolicies,verbs=get;list;watch
// +kubebuilder:rbac:groups=netbird.io,resources=nbservicepolicies/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=gateway.networking.k8s.io,resources=httproutes,verbs=get;list;watch

func (r *NBServicePolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := ctrl.Log.WithName("NBServicePolicy").WithValues("namespace", req.Namespace, "name", req.Name)

	policy := &nbv1alpha1.NBServicePolicy{}
	if err := r.Get(ctx, req.NamespacedName, policy); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if !policy.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, nil
	}

	resolved, err := r.hasResolvableTarget(ctx, policy)
	if err != nil {
		return ctrl.Result{}, err
	}

	sp := patch.NewSerialPatcher(policy, r.Client)
	if resolved {
		conditions.MarkTrue(policy, nbv1alpha1.ReadyCondition, nbv1alpha1.ReconciledReason, "")
		if conflict, cErr := r.conflictingPolicy(ctx, policy); cErr == nil && conflict != "" {
			logger.Info("multiple NBServicePolicies target the same route; oldest wins per field",
				"conflictsWith", conflict)
		}
	} else {
		conditions.MarkFalse(policy, nbv1alpha1.ReadyCondition, TargetNotFoundReason,
			"no target HTTPRoute found in namespace %s", policy.Namespace)
	}
	if err := sp.Patch(ctx, policy, patch.WithStatusObservedGeneration{}); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

// hasResolvableTarget reports whether at least one targetRef resolves to an
// existing HTTPRoute in the policy's namespace.
func (r *NBServicePolicyReconciler) hasResolvableTarget(ctx context.Context, policy *nbv1alpha1.NBServicePolicy) (bool, error) {
	for _, t := range policy.Spec.TargetRefs {
		if string(t.Group) != gatewayAPIGroup || string(t.Kind) != "HTTPRoute" {
			continue
		}
		hr := &gwv1.HTTPRoute{}
		err := r.Get(ctx, client.ObjectKey{Namespace: policy.Namespace, Name: string(t.Name)}, hr)
		if err == nil {
			return true, nil
		}
		if !kerrors.IsNotFound(err) {
			return false, err
		}
	}
	return false, nil
}

// conflictingPolicy returns the name of a strictly older sibling policy that
// targets one of the same routes (and would therefore win the oldest-wins
// merge), or "" when there is no conflict.
func (r *NBServicePolicyReconciler) conflictingPolicy(ctx context.Context, policy *nbv1alpha1.NBServicePolicy) (string, error) {
	var list nbv1alpha1.NBServicePolicyList
	if err := r.List(ctx, &list, client.InNamespace(policy.Namespace)); err != nil {
		return "", err
	}
	for i := range list.Items {
		other := &list.Items[i]
		if other.Name == policy.Name || !other.CreationTimestamp.Before(&policy.CreationTimestamp) {
			continue
		}
		for _, t := range policy.Spec.TargetRefs {
			if string(t.Kind) == "HTTPRoute" && policyTargetsRoute(other, string(t.Name)) {
				return other.Name, nil
			}
		}
	}
	return "", nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *NBServicePolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&nbv1alpha1.NBServicePolicy{}, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Watches(&gwv1.HTTPRoute{}, handler.EnqueueRequestsFromMapFunc(r.policiesForRoute)).
		Complete(r)
}

// policiesForRoute enqueues policies targeting a changed HTTPRoute so their
// TargetNotFound status is re-evaluated when the route appears or disappears.
func (r *NBServicePolicyReconciler) policiesForRoute(ctx context.Context, obj client.Object) []reconcile.Request {
	var list nbv1alpha1.NBServicePolicyList
	if err := r.List(ctx, &list, client.InNamespace(obj.GetNamespace())); err != nil {
		return nil
	}
	var reqs []reconcile.Request
	for i := range list.Items {
		if policyTargetsRoute(&list.Items[i], obj.GetName()) {
			reqs = append(reqs, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&list.Items[i])})
		}
	}
	return reqs
}
