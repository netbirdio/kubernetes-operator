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
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	netbird "github.com/netbirdio/netbird/shared/management/client/rest"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	netbirdiov1 "github.com/netbirdio/kubernetes-operator/api/v1"
)

const (
	GatewayFinalizer = "gateway.netbird.io/gateway"
)

type GatewayReconciler struct {
	client.Client
}

func (r *GatewayReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	gw := gatewayv1.Gateway{}
	err := r.Get(ctx, req.NamespacedName, &gw)
	if err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

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
		return r.reconcileDelete(ctx, gw)
	}

	// Verify Gateway configuration.
	routingPeerName, err := getRoutingPeerName(gw.Spec.Listeners)
	if err != nil {
		cond := metav1.Condition{
			Type:    string(gatewayv1.GatewayConditionAccepted),
			Status:  metav1.ConditionFalse,
			Reason:  string(gatewayv1.GatewayReasonInvalidParameters),
			Message: err.Error(),
		}
		if meta.SetStatusCondition(&gw.Status.Conditions, cond) {
			err = r.Status().Update(ctx, &gw)
			if err != nil {
				return ctrl.Result{}, err
			}
		}
		return ctrl.Result{}, nil
	}

	cond := metav1.Condition{
		Type:   string(gatewayv1.GatewayConditionAccepted),
		Status: metav1.ConditionTrue,
		Reason: string(gatewayv1.GatewayReasonAccepted),
	}
	if meta.SetStatusCondition(&gw.Status.Conditions, cond) {
		err = r.Status().Update(ctx, &gw)
		if err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}
	if controllerutil.AddFinalizer(&gw, GatewayFinalizer) {
		err = r.Client.Update(ctx, &gw)
		if err != nil {
			return ctrl.Result{}, err
		}
	}

	// Ensure routing peer is ready.
	nbrp := &netbirdiov1.NBRoutingPeer{}
	err = r.Get(ctx, types.NamespacedName{Namespace: req.Namespace, Name: routingPeerName}, nbrp)
	if err != nil {
		return ctrl.Result{}, err
	}
	idx := slices.IndexFunc(nbrp.Status.Conditions, func(cond netbirdiov1.NBCondition) bool {
		return cond.Type == netbirdiov1.NBSetupKeyReady
	})
	if idx == -1 || nbrp.Status.Conditions[idx].Status != corev1.ConditionStatus(metav1.ConditionTrue) {
		cond := metav1.Condition{
			Type:    string(gatewayv1.GatewayConditionProgrammed),
			Status:  metav1.ConditionFalse,
			Reason:  string(gatewayv1.GatewayReasonProgrammed),
			Message: fmt.Sprintf("NBRoutingPeer %s is not ready", routingPeerName),
		}
		if meta.SetStatusCondition(&gw.Status.Conditions, cond) {
			err = r.Status().Update(ctx, &gw)
			if err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{}, nil
		}
		return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
	}

	// Signal Gateway is programmed.
	cond = metav1.Condition{
		Type:   string(gatewayv1.GatewayConditionProgrammed),
		Status: metav1.ConditionTrue,
		Reason: string(gatewayv1.GatewayReasonProgrammed),
	}
	if meta.SetStatusCondition(&gw.Status.Conditions, cond) {
		err = r.Status().Update(ctx, &gw)
		if err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	return ctrl.Result{}, nil
}

func (r *GatewayReconciler) reconcileDelete(ctx context.Context, gw gatewayv1.Gateway) (ctrl.Result, error) {
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

	if controllerutil.RemoveFinalizer(&gw, GatewayFinalizer) {
		err := r.Client.Update(ctx, &gw)
		if err != nil && !netbird.IsNotFound(err) {
			return ctrl.Result{}, err
		}
	}
	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *GatewayReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&gatewayv1.Gateway{}).
		Complete(r)
}

func getRoutingPeerName(listeners []gatewayv1.Listener) (string, error) {
	if len(listeners) > 1 {
		return "", errors.New("netbird Gateway only supports a single listener")
	}
	group, kind, ok := strings.Cut(string(listeners[0].Protocol), "/")
	if !ok {
		return "", fmt.Errorf("invalid protocol %s, expected gateway.netbird.io/NBRoutingPeer", listeners[0].Protocol)
	}
	if group != "gateway.netbird.io" || kind != "NBRoutingPeer" {
		return "", fmt.Errorf("invalid group %s and kind %s, expected gateway.netbird.io/NBRoutingPeer", group, kind)
	}
	return string(listeners[0].Name), nil
}
