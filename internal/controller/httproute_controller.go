package controller

import (
	"context"
	"fmt"
	"time"

	netbird "github.com/netbirdio/netbird/shared/management/client/rest"
	"github.com/netbirdio/netbird/shared/management/http/api"
	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	netbirdiov1 "github.com/netbirdio/kubernetes-operator/api/v1"
	netbirdiov1alpha1 "github.com/netbirdio/kubernetes-operator/api/v1alpha1"
	"github.com/netbirdio/kubernetes-operator/internal/gatewayutil"
	"github.com/netbirdio/kubernetes-operator/internal/util"
)

const (
	HTTPRouteFinalizer = "gateway.netbird.io/httproute"
)

type HTTPRouteReconciler struct {
	client.Client

	Netbird    *netbird.Client
	ClusterDNS string
}

// nolint:gocyclo
func (r *HTTPRouteReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := ctrl.Log.WithName("HTTPRoute").WithValues("namespace", req.Namespace, "name", req.Name)

	hr := gatewayv1.HTTPRoute{}
	err := r.Get(ctx, req.NamespacedName, &hr)
	if err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if !hr.DeletionTimestamp.IsZero() {
		return r.reconcileDelete(ctx, hr)
	}

	// Get resource policies targeting rout.
	rpList := &netbirdiov1alpha1.ResourcePolicyList{}
	err = r.Client.List(ctx, rpList)
	if err != nil {
		return ctrl.Result{}, err
	}
	groups := []string{}
	for _, rp := range rpList.Items {
		for _, ref := range rp.Spec.TargetRefs {
			if ref.Group == "gateway.networking.k8s.io" && ref.Kind == "HTTPRoute" && string(ref.Name) == hr.Name {
				groups = append(groups, rp.Spec.Groups...)
			}
		}
	}

	for _, parent := range hr.Spec.ParentRefs {
		gw, err := gatewayutil.GetParentGateway(ctx, r.Client, parent, hr.Namespace, GatewayControllerName)
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

		if controllerutil.AddFinalizer(&hr, HTTPRouteFinalizer) {
			err = r.Client.Update(ctx, &hr)
			if err != nil {
				return ctrl.Result{}, err
			}
		}

		// Create network resources.
		svcIdx := map[string]corev1.Service{}
		for _, rule := range hr.Spec.Rules {
			for _, ref := range rule.BackendRefs {
				key := client.ObjectKey{Namespace: hr.Namespace, Name: string(ref.Name)}
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
				err = controllerutil.SetOwnerReference(&hr, &nbResource, r.Scheme())
				if err != nil {
					return err
				}
				nbResource.Spec = netbirdiov1.NBResourceSpec{
					Name:      svc.Name,
					NetworkID: *nbrp.Status.NetworkID,
					Address:   fmt.Sprintf("%s.%s.%s", svc.Name, svc.Namespace, r.ClusterDNS),
					Groups:    groups,
				}
				return nil
			})
			if err != nil {
				return ctrl.Result{}, err
			}
		}

		targets := []api.ServiceTarget{}
		for _, svc := range svcIdx {
			var nbResource netbirdiov1.NBResource
			err := r.Client.Get(ctx, client.ObjectKeyFromObject(&svc), &nbResource)
			if err != nil {
				return ctrl.Result{}, err
			}
			ready := func() bool {
				for _, cond := range nbResource.Status.Conditions {
					if cond.Type == netbirdiov1.NBSetupKeyReady && cond.Status == corev1.ConditionTrue {
						return true
					}
				}
				return false
			}()
			if !ready {
				return ctrl.Result{RequeueAfter: 1 * time.Second}, nil
			}

			target := api.ServiceTarget{
				Enabled:    true,
				Path:       nil,
				TargetId:   *nbResource.Status.NetworkResourceID,
				Protocol:   "http",
				TargetType: "domain",
			}
			targets = append(targets, target)
		}

		// Create proxy service.
		proxyServices, err := r.Netbird.ReverseProxyServices.List(ctx)
		if err != nil {
			return ctrl.Result{}, err
		}
		for _, hostname := range hr.Spec.Hostnames {
			proxyReq := api.PostApiReverseProxiesServicesJSONRequestBody{
				Auth:             api.ServiceAuthConfig{},
				Domain:           string(hostname),
				Enabled:          true,
				Name:             string(hostname),
				PassHostHeader:   util.Ptr(false),
				RewriteRedirects: util.Ptr(false),
				Targets:          targets,
			}

			err := func() error {
				for _, proxyService := range proxyServices {
					if proxyService.Domain != string(hostname) {
						continue
					}
					_, err := r.Netbird.ReverseProxyServices.Update(ctx, proxyService.Id, proxyReq)
					if err != nil {
						return err
					}
				}
				_, err := r.Netbird.ReverseProxyServices.Create(ctx, proxyReq)
				if err != nil {
					return err
				}
				return nil
			}()
			if err != nil {
				return ctrl.Result{}, err
			}
		}
	}

	return ctrl.Result{}, nil
}

func (r *HTTPRouteReconciler) reconcileDelete(ctx context.Context, hr gatewayv1.HTTPRoute) (ctrl.Result, error) {
	// Index all proxy services.
	proxyServices, err := r.Netbird.ReverseProxyServices.List(ctx)
	if err != nil {
		return ctrl.Result{}, err
	}
	proxyIdx := map[string]string{}
	for _, proxyService := range proxyServices {
		proxyIdx[proxyService.Domain] = proxyService.Id
	}

	for _, parent := range hr.Spec.ParentRefs {
		gw, err := gatewayutil.GetParentGateway(ctx, r.Client, parent, hr.Namespace, GatewayControllerName)
		if err != nil {
			return ctrl.Result{}, err
		}
		if gw == nil {
			continue
		}

		// Remove the resource from the resource.
		svcIdx := map[string]corev1.Service{}
		for _, rule := range hr.Spec.Rules {
			for _, ref := range rule.BackendRefs {
				key := client.ObjectKey{Namespace: hr.Namespace, Name: string(ref.Name)}
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
			err = controllerutil.RemoveOwnerReference(&hr, &nbResource, r.Scheme())
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

		// Remove the target from the proxy service.
		for _, hostname := range hr.Spec.Hostnames {
			id, ok := proxyIdx[string(hostname)]
			if !ok {
				continue
			}
			err = r.Netbird.ReverseProxyServices.Delete(ctx, id)
			if err != nil && !netbird.IsNotFound(err) {
				return ctrl.Result{}, err
			}
		}
	}

	if controllerutil.RemoveFinalizer(&hr, HTTPRouteFinalizer) {
		err := r.Client.Update(ctx, &hr)
		if err != nil {
			return ctrl.Result{}, err
		}
	}
	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *HTTPRouteReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&gatewayv1.HTTPRoute{}).
		Watches(&netbirdiov1alpha1.ResourcePolicy{}, handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, obj client.Object) []reconcile.Request {
			rp, ok := obj.(*netbirdiov1alpha1.ResourcePolicy)
			if !ok {
				return nil
			}
			reqs := []reconcile.Request{}
			for _, ref := range rp.Spec.TargetRefs {
				nn := client.ObjectKey{
					Namespace: rp.Namespace,
					Name:      string(ref.Name),
				}
				reqs = append(reqs, reconcile.Request{NamespacedName: nn})
			}
			return reqs
		})).
		Complete(r)
}
