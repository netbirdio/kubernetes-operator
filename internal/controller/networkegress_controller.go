// SPDX-License-Identifier: BSD-3-Clause

package controller

import (
	"context"
	"fmt"

	"github.com/fluxcd/pkg/runtime/conditions"
	"github.com/fluxcd/pkg/runtime/patch"
	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	corev1ac "k8s.io/client-go/applyconfigurations/core/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	netbird "github.com/netbirdio/netbird/shared/management/client/rest"

	nbv1alpha1 "github.com/netbirdio/kubernetes-operator/api/v1alpha1"
	"github.com/netbirdio/kubernetes-operator/internal/k8sutil"
)

// NetworkEgressReconciler reconciles a NetworkEgress object
type NetworkEgressReconciler struct {
	client.Client

	Netbird *netbird.Client
}

// +kubebuilder:rbac:groups=netbird.io,resources=networkegresses,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=netbird.io,resources=networkegresses/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=netbird.io,resources=networkegresses/finalizers,verbs=update

func (r *NetworkEgressReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	netEgress := &nbv1alpha1.NetworkEgress{}
	err := r.Get(ctx, req.NamespacedName, netEgress)
	if err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	sp := patch.NewSerialPatcher(netEgress, r.Client)

	if !netEgress.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, nil
	}

	ownerRef, err := k8sutil.ControllerReference(netEgress, r.Scheme())
	if err != nil {
		return ctrl.Result{}, err
	}

	netRouter := &nbv1alpha1.NetworkRouter{
		ObjectMeta: metav1.ObjectMeta{
			Name:      netEgress.Spec.NetworkRouterRef.Name,
			Namespace: netEgress.Spec.NetworkRouterRef.Namespace,
		},
	}
	err = r.Get(ctx, client.ObjectKeyFromObject(netRouter), netRouter)
	if err != nil {
		if kerrors.IsNotFound(err) {
			conditions.MarkFalse(netEgress, nbv1alpha1.ReadyCondition, nbv1alpha1.DependencyReason, "Referenced NetworkRouter cannot be found.")
			err = sp.Patch(ctx, netEgress)
			if err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	// Create service for egress resource to do port remapping.
	ports := []*corev1ac.ServicePortApplyConfiguration{}
	for _, port := range netEgress.Spec.Ports {
		ports = append(ports, corev1ac.ServicePort().WithName(port.Name).WithPort(port.Port))
	}
	routerSvcAC := corev1ac.Service(netEgress.Name, netEgress.Namespace).
		WithLabels(map[string]string{EgressRouterNameLabel: netRouter.Name, EgressRouterNamespaceLabel: netRouter.Namespace}).
		WithOwnerReferences(ownerRef).
		WithSpec(
			corev1ac.ServiceSpec().
				WithPorts(ports...),
		)
	err = r.Client.Apply(ctx, routerSvcAC, client.ForceOwnership)
	if err != nil {
		return ctrl.Result{}, err
	}

	conditions.MarkTrue(netEgress, nbv1alpha1.ReadyCondition, nbv1alpha1.ReconciledReason, "")
	err = sp.Patch(ctx, netEgress, patch.WithStatusObservedGeneration{})
	if err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *NetworkEgressReconciler) SetupWithManager(mgr ctrl.Manager) error {
	err := mgr.GetFieldIndexer().IndexField(context.Background(), &nbv1alpha1.NetworkEgress{}, ".spec.networkRouterRef", func(obj client.Object) []string {
		netEgress := obj.(*nbv1alpha1.NetworkEgress)
		ref := netEgress.Spec.NetworkRouterRef
		if ref.Name == "" {
			return nil
		}
		if ref.Namespace == "" {
			ref.Namespace = netEgress.Namespace
		}
		return []string{fmt.Sprintf("%s/%s", ref.Name, ref.Namespace)}
	})
	if err != nil {
		return err
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&nbv1alpha1.NetworkEgress{}).
		Owns(&corev1.Service{}).
		Watches(
			&nbv1alpha1.NetworkRouter{},
			handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, obj client.Object) []reconcile.Request {
				netEgressList := &nbv1alpha1.NetworkEgressList{}
				err := r.List(ctx, netEgressList, client.MatchingFields{".spec.networkRouterRef": fmt.Sprintf("%s/%s", obj.GetName(), obj.GetNamespace())})
				if err != nil {
					return nil
				}

				requests := make([]reconcile.Request, len(netEgressList.Items))
				for i, item := range netEgressList.Items {
					requests[i] = reconcile.Request{
						NamespacedName: types.NamespacedName{
							Name:      item.Name,
							Namespace: item.Namespace,
						},
					}
				}
				return requests
			}),
			builder.WithPredicates(predicate.ResourceVersionChangedPredicate{}),
		).
		Complete(r)
}
