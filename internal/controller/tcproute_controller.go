package controller

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"

	"github.com/fluxcd/pkg/runtime/patch"
	nbv1alpha1 "github.com/netbirdio/kubernetes-operator/api/v1alpha1"
	"github.com/netbirdio/kubernetes-operator/internal/gatewayutil"
	"github.com/netbirdio/kubernetes-operator/internal/ssautil"
	nbv1alpha1ac "github.com/netbirdio/kubernetes-operator/pkg/applyconfigurations/api/v1alpha1"
)

type TCPRouteReconciler struct {
	client.Client
}

// nolint:gocyclo
func (r *TCPRouteReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := ctrl.Log.WithName("TCPRoute").WithValues("namespace", req.Namespace, "name", req.Name)

	tr := &gatewayv1alpha2.TCPRoute{}
	err := r.Get(ctx, req.NamespacedName, tr)
	if err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	sp := patch.NewSerialPatcher(tr, r.Client)

	if !tr.DeletionTimestamp.IsZero() {
		return r.reconcileDelete(ctx, sp, tr)
	}

	for _, parent := range tr.Spec.ParentRefs {
		gw, err := gatewayutil.GetParentGateway(ctx, r.Client, parent, tr.Namespace, GatewayControllerName)
		if err != nil {
			return ctrl.Result{}, err
		}
		if gw == nil {
			continue
		}
		if !meta.IsStatusConditionTrue(gw.Status.Conditions, string(gatewayv1.GatewayConditionProgrammed)) {
			logger.Info("gateway is not ready", "name", gw.ObjectMeta.Name)
			continue
		}
		netRouter, err := gatewayutil.GetGatewayNetworkRouter(ctx, r.Client, gw)
		if err != nil {
			return ctrl.Result{}, err
		}

		controllerutil.AddFinalizer(tr, nbv1alpha1.NetbirdFinalizer)
		err = sp.Patch(ctx, tr)
		if err != nil {
			return ctrl.Result{}, err
		}

		// Create network resources.
		svcIdx := map[string]corev1.Service{}
		for _, rule := range tr.Spec.Rules {
			for _, ref := range rule.BackendRefs {
				key := client.ObjectKey{Namespace: tr.Namespace, Name: string(ref.Name)}
				var svc corev1.Service
				err := r.Client.Get(ctx, key, &svc)
				if err != nil {
					return ctrl.Result{}, err
				}
				svcIdx[svc.Name] = svc
			}
		}

		for _, svc := range svcIdx {
			controllerRef, err := ssautil.ControllerReference(&svc, r.Scheme())
			if err != nil {
				return ctrl.Result{}, err
			}
			controllerRef = controllerRef.WithBlockOwnerDeletion(false)
			ownerRef, err := ssautil.OwnerReference(tr, r.Scheme())
			if err != nil {
				return ctrl.Result{}, err
			}
			netResourceAC := nbv1alpha1ac.NetworkResource(svc.Name, svc.Namespace).
				WithOwnerReferences(controllerRef, ownerRef).
				WithSpec(
					nbv1alpha1ac.NetworkResourceSpec().
						WithNetworkRouterRef(nbv1alpha1ac.CrossNamespaceReference().WithName(netRouter.Name).WithNamespace(netRouter.Namespace)).
						WithServiceRef(corev1.LocalObjectReference{Name: svc.Name}),
				)
			err = r.Client.Apply(ctx, netResourceAC)
			if err != nil {
				return ctrl.Result{}, err
			}
		}
	}
	return ctrl.Result{}, nil
}

func (r *TCPRouteReconciler) reconcileDelete(ctx context.Context, sp *patch.SerialPatcher, tr *gatewayv1alpha2.TCPRoute) (ctrl.Result, error) {
	for _, parent := range tr.Spec.ParentRefs {
		gw, err := gatewayutil.GetParentGateway(ctx, r.Client, parent, tr.Namespace, GatewayControllerName)
		if err != nil {
			return ctrl.Result{}, err
		}
		if gw == nil {
			continue
		}

		// Remove the resource from the resource.
		svcIdx := map[string]corev1.Service{}
		for _, rule := range tr.Spec.Rules {
			for _, ref := range rule.BackendRefs {
				key := client.ObjectKey{Namespace: tr.Namespace, Name: string(ref.Name)}
				var svc corev1.Service
				err := r.Client.Get(ctx, key, &svc)
				if kerrors.IsNotFound(err) {
					continue
				}
				if err != nil {
					return ctrl.Result{}, err
				}
				svcIdx[svc.Name] = svc
			}
		}
		for _, svc := range svcIdx {
			netResource := &nbv1alpha1.NetworkResource{
				ObjectMeta: metav1.ObjectMeta{
					Name:      svc.Name,
					Namespace: svc.Namespace,
				},
			}
			err = r.Client.Get(ctx, client.ObjectKeyFromObject(netResource), netResource)
			if err != nil {
				return ctrl.Result{}, err
			}
			err = controllerutil.RemoveOwnerReference(tr, netResource, r.Scheme())
			if err != nil {
				return ctrl.Result{}, err
			}

			if len(netResource.OwnerReferences) > 1 {
				err = r.Client.Update(ctx, netResource)
				if err != nil {
					return ctrl.Result{}, err
				}
			} else {
				// TODO: Precondition that nothing has changed.
				err := r.Client.Delete(ctx, netResource)
				if err != nil {
					return ctrl.Result{}, err
				}
			}
		}
	}

	controllerutil.RemoveFinalizer(tr, nbv1alpha1.NetbirdFinalizer)
	err := sp.Patch(ctx, tr)
	if err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *TCPRouteReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&gatewayv1alpha2.TCPRoute{}).
		Complete(r)
}
