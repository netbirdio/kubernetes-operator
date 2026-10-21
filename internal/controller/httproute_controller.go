// SPDX-License-Identifier: BSD-3-Clause

package controller

import (
	"context"
	"slices"
	"time"

	"github.com/fluxcd/pkg/runtime/conditions"
	"github.com/fluxcd/pkg/runtime/patch"
	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gwv1 "sigs.k8s.io/gateway-api/apis/v1"

	netbird "github.com/netbirdio/netbird/shared/management/client/rest"
	"github.com/netbirdio/netbird/shared/management/http/api"

	nbv1alpha1 "github.com/netbirdio/kubernetes-operator/api/v1alpha1"
	"github.com/netbirdio/kubernetes-operator/internal/gatewayutil"
	"github.com/netbirdio/kubernetes-operator/internal/k8sutil"
	nbv1alpha1ac "github.com/netbirdio/kubernetes-operator/pkg/applyconfigurations/api/v1alpha1"
)

const (
	HTTPRouteFinalizer = "gateway.netbird.io/httproute"
)

// httpRouteBackend is a Service port an HTTPRoute sends requests to. The proxy
// targets the Service's network resource on that port.
type httpRouteBackend struct {
	service string
	port    int
}

// backendRefPort returns the Service port a backendRef names. Gateway API
// requires one for a Service, so 0, which leaves the port to NetBird, only
// stands for a reference to some other kind.
func backendRefPort(port *gwv1.PortNumber) int {
	if port == nil {
		return 0
	}
	return int(*port)
}

type HTTPRouteReconciler struct {
	client.Client

	Netbird *netbird.Client
}

// nolint:gocyclo
func (r *HTTPRouteReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := ctrl.Log.WithName("HTTPRoute").WithValues("namespace", req.Namespace, "name", req.Name)

	hr := &gwv1.HTTPRoute{}
	err := r.Get(ctx, req.NamespacedName, hr)
	if err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	sp := patch.NewSerialPatcher(hr, r.Client)

	if !hr.DeletionTimestamp.IsZero() {
		return r.reconcileDelete(ctx, sp, hr)
	}

	for _, parent := range hr.Spec.ParentRefs {
		gw, err := gatewayutil.GetParentGateway(ctx, r.Client, parent, hr.Namespace, GatewayControllerName)
		if err != nil {
			return ctrl.Result{}, err
		}
		if gw == nil {
			continue
		}
		if !meta.IsStatusConditionTrue(gw.Status.Conditions, string(gwv1.GatewayConditionProgrammed)) {
			logger.Info("gateway is not ready", "name", gw.ObjectMeta.Name)
			continue
		}
		netRouter, err := gatewayutil.GetGatewayNetworkRouter(ctx, r.Client, gw)
		if err != nil {
			return ctrl.Result{}, err
		}

		controllerutil.AddFinalizer(hr, k8sutil.Finalizer("httproute"))
		err = sp.Patch(ctx, hr)
		if err != nil {
			return ctrl.Result{}, err
		}

		// Create network resources.
		svcIdx := map[string]corev1.Service{}
		var backends []httpRouteBackend
		for _, rule := range hr.Spec.Rules {
			for _, ref := range rule.BackendRefs {
				key := client.ObjectKey{Namespace: hr.Namespace, Name: string(ref.Name)}
				var svc corev1.Service
				err := r.Client.Get(ctx, key, &svc)
				if err != nil {
					return ctrl.Result{}, err
				}
				svcIdx[svc.Name] = svc
				backend := httpRouteBackend{service: svc.Name, port: backendRefPort(ref.Port)}
				if !slices.Contains(backends, backend) {
					backends = append(backends, backend)
				}
			}
		}

		for _, svc := range svcIdx {
			controllerRef, err := k8sutil.ControllerReference(&svc, r.Scheme())
			if err != nil {
				return ctrl.Result{}, err
			}
			controllerRef = controllerRef.WithBlockOwnerDeletion(false)
			ownerRef, err := k8sutil.OwnerReference(hr, r.Scheme())
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
			err = r.Client.Apply(ctx, netResourceAC, client.ForceOwnership)
			if err != nil {
				return ctrl.Result{}, err
			}
		}

		targets := []api.ServiceTarget{}
		for _, backend := range backends {
			netResource := &nbv1alpha1.NetworkResource{
				ObjectMeta: metav1.ObjectMeta{
					Name:      backend.service,
					Namespace: hr.Namespace,
				},
			}
			err := r.Client.Get(ctx, client.ObjectKeyFromObject(netResource), netResource)
			if err != nil {
				return ctrl.Result{}, err
			}
			if !conditions.Has(netResource, nbv1alpha1.ReadyCondition) {
				return ctrl.Result{RequeueAfter: 1 * time.Second}, nil
			}

			target := api.ServiceTarget{
				Enabled:    true,
				Path:       nil,
				TargetId:   netResource.Status.ResourceID,
				Port:       backend.port,
				Protocol:   api.ServiceTargetProtocolHttp,
				TargetType: api.ServiceTargetTargetTypeHost,
			}
			targets = append(targets, target)
		}

		// Create proxy service.
		proxyServices, err := r.Netbird.ReverseProxyServices.List(ctx)
		if err != nil {
			return ctrl.Result{}, err
		}
		proxyIdx := proxyServicesByDomain(proxyServices)
		for _, hostname := range hr.Spec.Hostnames {
			proxyReq := api.ServiceRequest{
				Domain:           string(hostname),
				Enabled:          true,
				Name:             string(hostname),
				Mode:             new(api.ServiceRequestModeHttp),
				PassHostHeader:   new(false),
				RewriteRedirects: new(false),
				Targets:          &targets,
			}
			err := r.applyProxyService(ctx, proxyReq, proxyIdx[string(hostname)])
			if err != nil {
				return ctrl.Result{}, err
			}
		}
	}

	return ctrl.Result{}, nil
}

func (r *HTTPRouteReconciler) reconcileDelete(ctx context.Context, sp *patch.SerialPatcher, hr *gwv1.HTTPRoute) (ctrl.Result, error) {
	// Index all proxy services.
	proxyServices, err := r.Netbird.ReverseProxyServices.List(ctx)
	if err != nil {
		return ctrl.Result{}, err
	}
	proxyIdx := proxyServicesByDomain(proxyServices)

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
			err = controllerutil.RemoveOwnerReference(hr, netResource, r.Scheme())
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

		// Remove the target from the proxy service.
		for _, hostname := range hr.Spec.Hostnames {
			for _, id := range proxyIdx[string(hostname)] {
				err = r.Netbird.ReverseProxyServices.Delete(ctx, id)
				if err != nil && !netbird.IsNotFound(err) {
					return ctrl.Result{}, err
				}
			}
		}
	}

	controllerutil.RemoveFinalizer(hr, k8sutil.Finalizer("httproute"))
	err = sp.Patch(ctx, hr)
	if err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

// applyProxyService makes the request the one proxy service for its domain. It
// updates the first of the existing services and deletes the rest, which older
// versions of this controller left behind by creating a service on every
// reconcile.
func (r *HTTPRouteReconciler) applyProxyService(ctx context.Context, req api.ServiceRequest, existing []string) error {
	if len(existing) == 0 {
		_, err := r.Netbird.ReverseProxyServices.Create(ctx, req)
		return err
	}
	if _, err := r.Netbird.ReverseProxyServices.Update(ctx, existing[0], req); err != nil {
		return err
	}
	for _, id := range existing[1:] {
		err := r.Netbird.ReverseProxyServices.Delete(ctx, id)
		if err != nil && !netbird.IsNotFound(err) {
			return err
		}
	}
	return nil
}

// proxyServicesByDomain indexes proxy service IDs by the domain they serve.
func proxyServicesByDomain(services []api.Service) map[string][]string {
	idx := map[string][]string{}
	for _, svc := range services {
		idx[svc.Domain] = append(idx[svc.Domain], svc.Id)
	}
	return idx
}

// SetupWithManager sets up the controller with the Manager. A route is skipped
// while its Gateway is not programmed, so a change to a Gateway reconciles the
// routes that reference it.
func (r *HTTPRouteReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&gwv1.HTTPRoute{}).
		Watches(&gwv1.Gateway{}, handler.EnqueueRequestsFromMapFunc(r.routesForGateway)).
		Complete(r)
}

// routesForGateway returns a request for every HTTPRoute that references the
// Gateway.
func (r *HTTPRouteReconciler) routesForGateway(ctx context.Context, obj client.Object) []reconcile.Request {
	gw, ok := obj.(*gwv1.Gateway)
	if !ok {
		return nil
	}
	routes := &gwv1.HTTPRouteList{}
	if err := r.List(ctx, routes); err != nil {
		ctrl.Log.WithName("HTTPRoute").Error(err, "list routes for gateway", "namespace", gw.Namespace, "name", gw.Name)
		return nil
	}
	var reqs []reconcile.Request
	for i := range routes.Items {
		route := &routes.Items[i]
		if gatewayutil.ReferencesGateway(route.Spec.ParentRefs, route.Namespace, gw) {
			reqs = append(reqs, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(route)})
		}
	}
	return reqs
}
