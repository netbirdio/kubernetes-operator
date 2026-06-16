// SPDX-License-Identifier: BSD-3-Clause

package controller

import (
	"context"
	"time"

	"github.com/fluxcd/pkg/runtime/conditions"
	"github.com/fluxcd/pkg/runtime/patch"
	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
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
		portIdx := map[string]int32{}
		for _, rule := range hr.Spec.Rules {
			for _, ref := range rule.BackendRefs {
				key := client.ObjectKey{Namespace: hr.Namespace, Name: string(ref.Name)}
				var svc corev1.Service
				err := r.Client.Get(ctx, key, &svc)
				if err != nil {
					return ctrl.Result{}, err
				}
				svcIdx[svc.Name] = svc
				if ref.Port != nil {
					portIdx[svc.Name] = *ref.Port
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
		for _, svc := range svcIdx {
			netResource := &nbv1alpha1.NetworkResource{
				ObjectMeta: metav1.ObjectMeta{
					Name:      svc.Name,
					Namespace: svc.Namespace,
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
				Port:       backendPortFor(svc, portIdx[svc.Name]),
				TargetId:   netResource.Status.ResourceID,
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
		// Per-service config (private, access groups, CrowdSec, IP/geo
		// restrictions, header behaviour) is supplied by NBServicePolicy
		// objects attached to this route via GEP-713 policy attachment.
		// Without folding these in, only the fields below are ever sent and
		// anything configured out-of-band is reset on the next reconcile.
		policies, err := r.servicePoliciesFor(ctx, hr)
		if err != nil {
			return ctrl.Result{}, err
		}

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
			applyServicePolicies(policies, &proxyReq)

			err := func() error {
				// Upsert by domain: update the existing service if one already
				// serves this hostname, otherwise create it. Falling through to
				// Create after an Update would re-submit the same domain and the
				// API rejects it with "domain already taken".
				for _, proxyService := range proxyServices {
					if proxyService.Domain != string(hostname) {
						continue
					}
					_, err := r.Netbird.ReverseProxyServices.Update(ctx, proxyService.Id, proxyReq)
					return err
				}
				_, err := r.Netbird.ReverseProxyServices.Create(ctx, proxyReq)
				return err
			}()
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

	controllerutil.RemoveFinalizer(hr, k8sutil.Finalizer("httproute"))
	err = sp.Patch(ctx, hr)
	if err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

// backendPortFor resolves the port a proxy target should connect to: the
// HTTPRoute backendRef port (port, or 0 if it was unset), falling back to the
// Service's first declared port.
func backendPortFor(svc corev1.Service, port int32) int {
	if port != 0 {
		return int(port)
	}
	if len(svc.Spec.Ports) > 0 {
		return int(svc.Spec.Ports[0].Port)
	}
	return 0
}

// +kubebuilder:rbac:groups=netbird.io,resources=nbservicepolicies,verbs=get;list;watch

// SetupWithManager sets up the controller with the Manager.
func (r *HTTPRouteReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&gwv1.HTTPRoute{}).
		Watches(&nbv1alpha1.NBServicePolicy{},
			handler.EnqueueRequestsFromMapFunc(routesForServicePolicy),
			// Only spec changes (and create/delete) should re-reconcile the
			// route; ignore the status-only writes from the policy controller.
			builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Complete(r)
}
