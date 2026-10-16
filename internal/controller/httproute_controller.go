// SPDX-License-Identifier: BSD-3-Clause

package controller

import (
	"context"
	"sort"
	"strings"
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
	gwv1 "sigs.k8s.io/gateway-api/apis/v1"

	netbird "github.com/netbirdio/netbird/shared/management/client/rest"
	"github.com/netbirdio/netbird/shared/management/http/api"

	nbv1alpha1 "github.com/netbirdio/kubernetes-operator/api/v1alpha1"
	"github.com/netbirdio/kubernetes-operator/internal/gatewayutil"
	"github.com/netbirdio/kubernetes-operator/internal/k8sutil"
	"github.com/netbirdio/kubernetes-operator/internal/netbirdutil"
	nbv1alpha1ac "github.com/netbirdio/kubernetes-operator/pkg/applyconfigurations/api/v1alpha1"
)

const (
	HTTPRouteFinalizer = "gateway.netbird.io/httproute"

	// proxyServiceOwner is embedded in operator-managed reverse proxy
	// service names so they can be told apart from services with a similar
	// shape created outside the operator (e.g. in the NetBird UI).
	proxyServiceOwner = "netbird-operator"
)

// proxyServiceName returns the name used for operator-managed reverse proxy
// services: the hostname, the proxyServiceOwner marker, and the UID of the
// HTTPRoute that manages it, separated by colons. Embedding the route UID lets
// each route own its own service even when several routes share a hostname,
// and keeps operator services distinct from ones created outside the operator
// (e.g. in the NetBird UI). The marker and UID are always kept; when the full
// name would exceed the server's 255 character limit the hostname is
// shortened to leave room for them.
func proxyServiceName(hostname, routeUID string) string {
	const maxNameLen = 255
	marker := ":" + proxyServiceOwner + ":" + routeUID
	if maxHost := maxNameLen - len(marker); len(hostname) > maxHost {
		hostname = hostname[:maxHost]
	}
	return hostname + marker
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
		gw, gwc, err := gatewayutil.GetParentGateway(ctx, r.Client, parent, hr.Namespace, GatewayControllerName)
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
				TargetId:   netResource.Status.ResourceID,
				Protocol:   api.ServiceTargetProtocolHttp,
				TargetType: api.ServiceTargetTargetTypeHost,
			}
			targets = append(targets, target)
		}

		// Private gateways register a mesh-only reverse proxy service instead
		// of a public one. The groups that may reach it come from the backend
		// services' netbird.io/groups annotation; when none is set, access
		// defaults to denied.
		private := gwc.Name == GatewayClassNamePrivate
		var accessGroupIDs []string
		if private {
			accessGroupIDs, err = r.privateAccessGroupIDs(ctx, svcIdx, hr.Namespace)
			if err != nil {
				return ctrl.Result{}, err
			}
		}

		// Create proxy service.
		proxyServices, err := r.Netbird.ReverseProxyServices.List(ctx)
		if err != nil {
			return ctrl.Result{}, err
		}
		for _, hostname := range hr.Spec.Hostnames {
			proxyReq := api.ServiceRequest{
				Domain:           string(hostname),
				Enabled:          true,
				Name:             proxyServiceName(string(hostname), string(hr.UID)),
				Mode:             new(api.ServiceRequestModeHttp),
				Private:          &private,
				PassHostHeader:   new(false),
				RewriteRedirects: new(false),
				Targets:          &targets,
			}
			if private {
				proxyReq.AccessGroups = &accessGroupIDs
			}

			// Only touch the service this route owns; other services on the
			// same domain belong to other routes or to the user.
			updated := false
			for _, proxyService := range proxyServices {
				if proxyService.Domain != proxyReq.Domain || proxyService.Name != proxyReq.Name {
					continue
				}
				if _, err := r.Netbird.ReverseProxyServices.Update(ctx, proxyService.Id, proxyReq); err != nil {
					return ctrl.Result{}, err
				}
				updated = true
				break
			}
			if !updated {
				if _, err := r.Netbird.ReverseProxyServices.Create(ctx, proxyReq); err != nil {
					return ctrl.Result{}, err
				}
			}
		}
	}

	return ctrl.Result{}, nil
}

// privateAccessGroupIDs resolves the NetBird groups that may reach a private
// route over the tunnel. The groups are the union of the backend services'
// netbird.io/groups annotations; when no group is specified the result is
// empty, which denies access by default.
func (r *HTTPRouteReconciler) privateAccessGroupIDs(ctx context.Context, services map[string]corev1.Service, namespace string) ([]string, error) {
	names := map[string]struct{}{}
	for _, svc := range services {
		for g := range strings.SplitSeq(svc.Annotations[serviceGroupsAnnotation], ",") {
			if g = strings.TrimSpace(g); g != "" {
				names[g] = struct{}{}
			}
		}
	}
	if len(names) == 0 {
		return []string{}, nil
	}

	sorted := make([]string, 0, len(names))
	for name := range names {
		sorted = append(sorted, name)
	}
	sort.Strings(sorted)

	refs := make([]nbv1alpha1.GroupReference, 0, len(sorted))
	for _, name := range sorted {
		n := name
		refs = append(refs, nbv1alpha1.GroupReference{Name: &n})
	}
	return netbirdutil.GetGroupIDs(ctx, r.Client, r.Netbird, refs, namespace)
}

func (r *HTTPRouteReconciler) reconcileDelete(ctx context.Context, sp *patch.SerialPatcher, hr *gwv1.HTTPRoute) (ctrl.Result, error) {
	var proxyIdx map[string]string

	for _, parent := range hr.Spec.ParentRefs {
		gw, _, err := gatewayutil.GetParentGateway(ctx, r.Client, parent, hr.Namespace, GatewayControllerName)
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

		if proxyIdx == nil {
			proxyServices, err := r.Netbird.ReverseProxyServices.List(ctx)
			if err != nil {
				return ctrl.Result{}, err
			}
			proxyIdx = make(map[string]string, len(proxyServices))
			for _, proxyService := range proxyServices {
				proxyIdx[proxyService.Name] = proxyService.Id
			}
		}

		// Remove the proxy service owned by this route; services with the
		// same domain owned by other routes are left in place.
		for _, hostname := range hr.Spec.Hostnames {
			id, ok := proxyIdx[proxyServiceName(string(hostname), string(hr.UID))]
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
	err := sp.Patch(ctx, hr)
	if err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *HTTPRouteReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&gwv1.HTTPRoute{}).
		Complete(r)
}
