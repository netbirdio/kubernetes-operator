package controller

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"

	netbirdiov1 "github.com/netbirdio/kubernetes-operator/api/v1"
	"github.com/netbirdio/kubernetes-operator/internal/gatewayutil"
)

const (
	TCPRouteFinalizer = "gateway.netbird.io/tcproute"
)

type TCPRouteReconciler struct {
	client.Client

	ClusterDNS string
}

// nolint:gocyclo
func (r *TCPRouteReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := ctrl.Log.WithName("TCPRoute").WithValues("namespace", req.Namespace, "name", req.Name)

	tr := gatewayv1alpha2.TCPRoute{}
	err := r.Get(ctx, req.NamespacedName, &tr)
	if err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if !tr.DeletionTimestamp.IsZero() {
		return r.reconcileDelete(ctx, tr)
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
		nbrp, err := gatewayutil.GetGatewayRoutingPeer(ctx, r.Client, *gw)
		if err != nil {
			return ctrl.Result{}, err
		}

		if controllerutil.AddFinalizer(&tr, TCPRouteFinalizer) {
			err = r.Client.Update(ctx, &tr)
			if err != nil {
				return ctrl.Result{}, err
			}
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
			nbResource := netbirdiov1.NBResource{
				ObjectMeta: metav1.ObjectMeta{
					Name:      svc.Name,
					Namespace: svc.Namespace,
				},
			}
			_, err := controllerutil.CreateOrUpdate(ctx, r.Client, &nbResource, func() error {
				err = controllerutil.SetControllerReference(&svc, &nbResource, r.Scheme(), controllerutil.WithBlockOwnerDeletion(false))
				if err != nil {
					return err
				}
				err = controllerutil.SetOwnerReference(&tr, &nbResource, r.Scheme())
				if err != nil {
					return err
				}
				nbResource.Spec = netbirdiov1.NBResourceSpec{
					Name:      svc.Name,
					NetworkID: *nbrp.Status.NetworkID,
					Address:   fmt.Sprintf("%s.%s.%s", svc.Name, svc.Namespace, r.ClusterDNS),
					Groups:    []string{},
				}
				return nil
			})
			if err != nil {
				return ctrl.Result{}, err
			}
		}
	}
	return ctrl.Result{}, nil
}

func (r *TCPRouteReconciler) reconcileDelete(ctx context.Context, tr gatewayv1alpha2.TCPRoute) (ctrl.Result, error) {
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
			var nbResource netbirdiov1.NBResource
			err = r.Client.Get(ctx, client.ObjectKeyFromObject(&svc), &nbResource)
			if err != nil {
				return ctrl.Result{}, err
			}
			err = controllerutil.RemoveOwnerReference(&tr, &nbResource, r.Scheme())
			if err != nil {
				return ctrl.Result{}, err
			}

			if len(nbResource.OwnerReferences) > 1 {
				err = r.Client.Update(ctx, &nbResource)
				if err != nil {
					return ctrl.Result{}, err
				}
			} else {
				// TODO: Precondition that nothing has changed.
				err := r.Client.Delete(ctx, &nbResource)
				if err != nil {
					return ctrl.Result{}, err
				}
			}
		}
	}

	if controllerutil.RemoveFinalizer(&tr, TCPRouteFinalizer) {
		err := r.Client.Update(ctx, &tr)
		if err != nil {
			return ctrl.Result{}, err
		}
	}
	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *TCPRouteReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&gatewayv1alpha2.TCPRoute{}).
		Complete(r)
}
