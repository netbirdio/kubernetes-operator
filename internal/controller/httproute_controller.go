package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/netbirdio/kubernetes-operator/internal/util"
	netbird "github.com/netbirdio/netbird/shared/management/client/rest"
	"github.com/netbirdio/netbird/shared/management/http/api"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

const (
	HTTPRouteFinalizer      = "gateway.netbird.io/httproute"
	ResourceIDAnnotationKey = "gateway.netbird.io/resource-ids"
	ProxyIDAnnotationKey    = "gateway.netbird.io/proxy-ids"
)

type HTTPRouteReconciler struct {
	client.Client

	Scheme     *runtime.Scheme
	NBClient   *netbird.Client
	ClusterDNS string
}

func (r *HTTPRouteReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := ctrl.Log.WithName("HTTPRoute").WithValues("namespace", req.Namespace, "name", req.Name)

	hr := gatewayv1.HTTPRoute{}
	err := r.Get(ctx, req.NamespacedName, &hr)
	if err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if !hr.DeletionTimestamp.IsZero() {
		err := r.reconcileDelete(ctx, hr)
		if err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	for _, parent := range hr.Spec.ParentRefs {
		// Check if controller is responsible for route.
		parentNamespace := hr.Namespace
		if parent.Namespace != nil {
			parentNamespace = string(*parent.Namespace)
		}
		gw := &gatewayv1.Gateway{}
		err = r.Client.Get(ctx, types.NamespacedName{Namespace: parentNamespace, Name: string(parent.Name)}, gw)
		if err != nil {
			return ctrl.Result{}, err
		}
		gwc := &gatewayv1.GatewayClass{}
		err := r.Get(ctx, client.ObjectKey{Name: string(gw.Spec.GatewayClassName)}, gwc)
		if err != nil {
			return ctrl.Result{}, err
		}
		if gwc.Spec.ControllerName != GatewayControllerName {
			continue
		}

		if !meta.IsStatusConditionTrue(gw.Status.Conditions, string(gatewayv1.GatewayConditionProgrammed)) {
			logger.Info("gateway is not ready", "name", gw.ObjectMeta.Name)
			return ctrl.Result{Requeue: true}, nil
		}

		if controllerutil.AddFinalizer(&hr, HTTPRouteFinalizer) {
			err = r.Client.Update(ctx, &hr)
			if err != nil {
				return ctrl.Result{}, err
			}
		}

		networkID := gw.Annotations[NetworkIDAnnotationKey]

		// Create network resources.
		oldResourceIDs := map[string]string{}
		if s, ok := hr.Annotations[ResourceIDAnnotationKey]; ok {
			err := json.Unmarshal([]byte(s), &oldResourceIDs)
			if err != nil {
				return ctrl.Result{}, err
			}
		}
		resourceIDs := map[string]string{}
		targets := []api.ServiceTarget{}
		for _, rule := range hr.Spec.Rules {
			for _, ref := range rule.BackendRefs {
				refNamespace := hr.Namespace
				// if ref.Namespace != nil {
				// 	refNamespace = string(*ref.Namespace)
				// }

				key := strings.Join([]string{string(ref.Name), refNamespace}, "/")
				networkResourceReq := api.NetworkResourceRequest{
					Name:    fmt.Sprintf("%s/%s/%s/%s", gw.Name, hr.Name, ref.Name, refNamespace),
					Enabled: true,
					Address: fmt.Sprintf("%s.%s.%s", ref.Name, refNamespace, r.ClusterDNS),
					Groups:  []string{gw.Annotations[GroupIDAnnotationKey]},
				}

				id, err := func() (string, error) {
					if id, ok := oldResourceIDs[key]; ok {
						_, err := r.NBClient.Networks.Resources(networkID).Get(ctx, id)
						if err != nil && !netbird.IsNotFound(err) {
							return "", err
						}
						if err == nil {
							_, err = r.NBClient.Networks.Resources(networkID).Update(ctx, id, networkResourceReq)
							if err != nil {
								return "", err
							}
							delete(oldResourceIDs, key)
							return id, nil
						}
					}
					resource, err := r.NBClient.Networks.Resources(networkID).Create(ctx, networkResourceReq)
					if err != nil {
						return "", err
					}
					return resource.Id, nil
				}()
				if err != nil {
					return ctrl.Result{}, err
				}
				resourceIDs[key] = id
				target := api.ServiceTarget{
					Enabled:    true,
					Path:       nil,
					TargetId:   id,
					TargetType: "domain",
				}
				targets = append(targets, target)
			}
		}

		// Create proxy service.
		oldProxyIDs := map[string]string{}
		if s, ok := hr.Annotations[ProxyIDAnnotationKey]; ok {
			err := json.Unmarshal([]byte(s), &oldProxyIDs)
			if err != nil {
				return ctrl.Result{}, err
			}
		}
		proxyIDs := map[string]string{}
		for _, hostname := range hr.Spec.Hostnames {
			proxyCreate := api.PostApiReverseProxiesServicesJSONRequestBody{
				Auth:             api.ServiceAuthConfig{},
				Domain:           string(hostname),
				Enabled:          true,
				Name:             string(hostname),
				PassHostHeader:   util.Ptr(false),
				RewriteRedirects: util.Ptr(false),
				Targets:          targets,
			}

			id, err := func() (string, error) {
				if id, ok := oldProxyIDs[string(hostname)]; ok {
					_, err := r.NBClient.ReverseProxyServices.Get(ctx, id)
					if err != nil && !netbird.IsNotFound(err) {
						return "", err
					}
					if err == nil {
						_, err := r.NBClient.ReverseProxyServices.Update(ctx, id, proxyCreate)
						if err != nil {
							return "", nil
						}
						delete(oldProxyIDs, string(hostname))
						return id, nil
					}
				}
				proxy, err := r.NBClient.ReverseProxyServices.Create(ctx, proxyCreate)
				if err != nil {
					return "", err
				}
				return proxy.Id, nil
			}()
			if err != nil {
				return ctrl.Result{}, err
			}
			proxyIDs[string(hostname)] = id
		}

		for _, id := range oldResourceIDs {
			err = r.NBClient.Networks.Resources(networkID).Delete(ctx, id)
			if err != nil && !netbird.IsNotFound(err) {
				return ctrl.Result{}, err
			}
		}
		for _, id := range oldProxyIDs {
			err = r.NBClient.ReverseProxyServices.Delete(ctx, id)
			if err != nil && !netbird.IsNotFound(err) {
				return ctrl.Result{}, err
			}
		}

		b, err := json.Marshal(resourceIDs)
		if err != nil {
			return ctrl.Result{}, err
		}
		hr.Annotations[ResourceIDAnnotationKey] = string(b)
		b, err = json.Marshal(proxyIDs)
		if err != nil {
			return ctrl.Result{}, err
		}
		hr.Annotations[ProxyIDAnnotationKey] = string(b)
		err = r.Client.Update(ctx, &hr)
		if err != nil {
			return ctrl.Result{}, err
		}
	}

	return ctrl.Result{}, nil
}

func (r *HTTPRouteReconciler) reconcileDelete(ctx context.Context, hr gatewayv1.HTTPRoute) error {
	for _, parent := range hr.Spec.ParentRefs {
		parentNamespace := hr.Namespace
		if parent.Namespace != nil {
			parentNamespace = string(*parent.Namespace)
		}
		gw := &gatewayv1.Gateway{}
		err := r.Client.Get(ctx, types.NamespacedName{Namespace: parentNamespace, Name: string(parent.Name)}, gw)
		if err != nil {
			return err
		}

		networkID := gw.Annotations[NetworkIDAnnotationKey]

		proxyIDs := map[string]string{}
		if s, ok := hr.Annotations[ProxyIDAnnotationKey]; ok {
			err := json.Unmarshal([]byte(s), &proxyIDs)
			if err != nil {
				return err
			}
		}
		for _, id := range proxyIDs {
			err = r.NBClient.ReverseProxyServices.Delete(ctx, id)
			if err != nil && !netbird.IsNotFound(err) {
				return err
			}
		}

		resourceIDs := map[string]string{}
		if s, ok := hr.Annotations[ResourceIDAnnotationKey]; ok {
			err := json.Unmarshal([]byte(s), &resourceIDs)
			if err != nil {
				return err
			}
		}
		for _, id := range resourceIDs {
			err = r.NBClient.Networks.Resources(networkID).Delete(ctx, id)
			if err != nil && !netbird.IsNotFound(err) {
				return err
			}
		}

		if controllerutil.RemoveFinalizer(&hr, HTTPRouteFinalizer) {
			err := r.Client.Update(ctx, &hr)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *HTTPRouteReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&gatewayv1.HTTPRoute{}).
		Complete(r)
}
