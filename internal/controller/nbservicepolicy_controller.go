// SPDX-License-Identifier: BSD-3-Clause

package controller

import (
	"context"

	"github.com/fluxcd/pkg/runtime/conditions"
	"github.com/fluxcd/pkg/runtime/patch"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	nbv1alpha1 "github.com/netbirdio/kubernetes-operator/api/v1alpha1"
)

// NBServicePolicyReconciler manages NBServicePolicy status. The policy's effect
// is applied by the HTTPRoute reconciler (which watches these objects); this
// controller only records acceptance — advancing observedGeneration and setting
// the Ready condition — so kstatus (and therefore Flux) can observe readiness
// instead of hanging at InProgress.
type NBServicePolicyReconciler struct {
	client.Client
}

// +kubebuilder:rbac:groups=netbird.io,resources=nbservicepolicies,verbs=get;list;watch
// +kubebuilder:rbac:groups=netbird.io,resources=nbservicepolicies/status,verbs=get;update;patch

func (r *NBServicePolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	policy := &nbv1alpha1.NBServicePolicy{}
	if err := r.Get(ctx, req.NamespacedName, policy); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if !policy.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, nil
	}

	sp := patch.NewSerialPatcher(policy, r.Client)
	conditions.MarkTrue(policy, nbv1alpha1.ReadyCondition, nbv1alpha1.ReconciledReason, "")
	if err := sp.Patch(ctx, policy, patch.WithStatusObservedGeneration{}); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *NBServicePolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&nbv1alpha1.NBServicePolicy{}).
		Complete(r)
}
