/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"
	"fmt"
	"time"

	"github.com/fluxcd/pkg/runtime/conditions"
	"github.com/fluxcd/pkg/runtime/patch"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	nbv1alpha1 "github.com/netbirdio/kubernetes-operator/api/v1alpha1"
	"github.com/netbirdio/kubernetes-operator/internal/gatewayutil"
	"github.com/netbirdio/kubernetes-operator/internal/k8sutil"
)

type GatewayReconciler struct {
	client.Client
}

func (r *GatewayReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	gw := &gatewayv1.Gateway{}
	err := r.Get(ctx, req.NamespacedName, gw)
	if err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	sp := patch.NewSerialPatcher(gw, r.Client)

	// Check if referenced class belongs to this controller.
	gwc := &gatewayv1.GatewayClass{}
	nn := types.NamespacedName{
		Name: string(gw.Spec.GatewayClassName),
	}
	err = r.Get(ctx, nn, gwc)
	if err != nil {
		return ctrl.Result{}, err
	}
	if string(gwc.Spec.ControllerName) != GatewayControllerName {
		return ctrl.Result{}, nil
	}
	if !meta.IsStatusConditionTrue(gwc.Status.Conditions, string(gatewayv1.GatewayClassConditionStatusAccepted)) {
		return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
	}

	// Handle resource deletion.
	if !gw.DeletionTimestamp.IsZero() {
		return r.reconcileDelete(ctx, sp, gw)
	}

	// Verify Gateway configuration.
	routingPeerName, err := gatewayutil.GetNetworkRouterName(gw.Spec.Listeners)
	if err != nil {
		cond := metav1.Condition{
			Type:    string(gatewayv1.GatewayConditionAccepted),
			Status:  metav1.ConditionFalse,
			Reason:  string(gatewayv1.GatewayReasonInvalidParameters),
			Message: err.Error(),
		}
		meta.SetStatusCondition(&gw.Status.Conditions, cond)
		err = sp.Patch(ctx, gw)
		if err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}
	cond := metav1.Condition{
		Type:   string(gatewayv1.GatewayConditionAccepted),
		Status: metav1.ConditionTrue,
		Reason: string(gatewayv1.GatewayReasonAccepted),
	}
	meta.SetStatusCondition(&gw.Status.Conditions, cond)
	controllerutil.AddFinalizer(gw, k8sutil.Finalizer("gateway"))
	err = sp.Patch(ctx, gw)
	if err != nil {
		return ctrl.Result{}, err
	}

	// Ensure routing peer is ready.
	netRouter, err := gatewayutil.GetGatewayNetworkRouter(ctx, r.Client, gw)
	if err != nil {
		return ctrl.Result{}, err
	}
	if !conditions.Has(netRouter, nbv1alpha1.ReadyCondition) {
		// TODO (phillebaba): Should watch routing peer instead of retrying when not found.
		cond := metav1.Condition{
			Type:    string(gatewayv1.GatewayConditionProgrammed),
			Status:  metav1.ConditionFalse,
			Reason:  string(gatewayv1.GatewayReasonProgrammed),
			Message: fmt.Sprintf("NBRoutingPeer %s is not ready", routingPeerName),
		}
		meta.SetStatusCondition(&gw.Status.Conditions, cond)
		err = sp.Patch(ctx, gw)
		if err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
	}

	// Signal Gateway is programmed.
	cond = metav1.Condition{
		Type:   string(gatewayv1.GatewayConditionProgrammed),
		Status: metav1.ConditionTrue,
		Reason: string(gatewayv1.GatewayReasonProgrammed),
	}
	meta.SetStatusCondition(&gw.Status.Conditions, cond)
	err = sp.Patch(ctx, gw)
	if err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

func (r *GatewayReconciler) reconcileDelete(ctx context.Context, sp *patch.SerialPatcher, gw *gatewayv1.Gateway) (ctrl.Result, error) {
	var httpRouteList gatewayv1.HTTPRouteList
	err := r.Client.List(ctx, &httpRouteList)
	if err != nil {
		return ctrl.Result{}, err
	}
	gvk := gw.GroupVersionKind()
	for _, route := range httpRouteList.Items {
		for _, ref := range route.Spec.ParentRefs {
			group := gvk.Group
			if ref.Group != nil {
				group = string(*ref.Group)
			}
			kind := gvk.Kind
			if ref.Kind != nil {
				kind = string(*ref.Kind)
			}
			namespace := route.Namespace
			if ref.Namespace != nil {
				namespace = string(*ref.Namespace)
			}
			if group == gvk.Group && kind == gvk.Kind && namespace == gw.Namespace && string(ref.Name) == gw.Name {
				return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
			}
		}
	}

	controllerutil.RemoveFinalizer(gw, k8sutil.Finalizer("gateway"))
	err = sp.Patch(ctx, gw)
	if err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

func (r *GatewayReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&gatewayv1.Gateway{}).
		Complete(r)
}
