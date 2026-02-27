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

	"github.com/netbirdio/kubernetes-operator/internal/util"
	netbird "github.com/netbirdio/netbird/shared/management/client/rest"
	"github.com/netbirdio/netbird/shared/management/http/api"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

const (
	GatewayFinalizer        = "gateway.netbird.io/gateway"
	NetworkIDAnnotationKey  = "gateway.netbird.io/network-id"
	GroupIDAnnotationKey    = "gateway.netbird.io/group-id"
	SetupKeyIDAnnotationKey = "gateway.netbird.io/setup-key-id"
	RouterIDAnnotationKey   = "gateway.netbird.io/router-id"
)

type GatewayReconciler struct {
	client.Client

	Scheme        *runtime.Scheme
	NBClient      *netbird.Client
	ManagementURL string
	ClusterName   string
	ClientImage   string
}

func (r *GatewayReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := ctrl.Log.WithName("Gateway").WithValues("namespace", req.Namespace, "name", req.Name)

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
		logger.Info("waiting as class is not ready", "name", gwc.Name)
		return ctrl.Result{Requeue: true}, nil
	}

	// Handle resource deletion.
	if !gw.DeletionTimestamp.IsZero() {
		err := r.reconcileDelete(ctx, gw)
		if err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	// TODO: Validate parameters.
	//

	acceptedCond := metav1.Condition{
		Type:   string(gatewayv1.GatewayConditionAccepted),
		Status: metav1.ConditionTrue,
		Reason: string(gatewayv1.GatewayReasonAccepted),
	}
	if meta.SetStatusCondition(&gw.Status.Conditions, acceptedCond) {
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

	gw, err = r.handleGroup(ctx, gw)
	if err != nil {
		return ctrl.Result{}, err
	}
	err = r.Client.Update(ctx, &gw)
	if err != nil {
		return ctrl.Result{}, err
	}

	gw, err = r.handleNetwork(ctx, gw)
	if err != nil {
		return ctrl.Result{}, err
	}
	err = r.Client.Update(ctx, &gw)
	if err != nil {
		return ctrl.Result{}, err
	}

	gw, err = r.handleSetupKey(ctx, gw)
	if err != nil {
		return ctrl.Result{}, err
	}
	err = r.Client.Update(ctx, &gw)
	if err != nil {
		return ctrl.Result{}, err
	}

	gw, err = r.handleRouter(ctx, gw)
	if err != nil {
		return ctrl.Result{}, err
	}
	err = r.Client.Update(ctx, &gw)
	if err != nil {
		return ctrl.Result{}, err
	}

	err = r.handleDeployment(ctx, gw)
	if err != nil {
		return ctrl.Result{}, err
	}

	programmedCond := metav1.Condition{
		Type:   string(gatewayv1.GatewayConditionProgrammed),
		Status: metav1.ConditionTrue,
		Reason: string(gatewayv1.GatewayReasonProgrammed),
	}
	if meta.SetStatusCondition(&gw.Status.Conditions, programmedCond) {
		err = r.Status().Update(ctx, &gw)
		if err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *GatewayReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&gatewayv1.Gateway{}).
		Owns(&corev1.Secret{}).
		Owns(&appsv1.Deployment{}).
		Complete(r)
}

func (r *GatewayReconciler) reconcileDelete(ctx context.Context, gw gatewayv1.Gateway) error {
	groupID := gw.Annotations[GroupIDAnnotationKey]
	networkID := gw.Annotations[NetworkIDAnnotationKey]
	setupKeyID := gw.Annotations[SetupKeyIDAnnotationKey]
	routerID := gw.Annotations[RouterIDAnnotationKey]

	// TODO: Ignore does not exist errors.

	if networkID != "" && routerID != "" {
		err := r.NBClient.Networks.Routers(networkID).Delete(ctx, routerID)
		if err != nil && !netbird.IsNotFound(err) {
			return err
		}
	}
	if setupKeyID != "" {
		err := r.NBClient.SetupKeys.Delete(ctx, setupKeyID)
		if err != nil && !netbird.IsNotFound(err) {
			return err
		}
	}
	if networkID != "" {
		err := r.NBClient.Networks.Delete(ctx, networkID)
		if err != nil && !netbird.IsNotFound(err) {
			return err
		}
	}
	if groupID != "" {
		err := r.NBClient.Groups.Delete(ctx, groupID)
		if err != nil && !netbird.IsNotFound(err) {
			return err
		}
	}

	if controllerutil.RemoveFinalizer(&gw, GatewayFinalizer) {
		err := r.Client.Update(ctx, &gw)
		if err != nil && !netbird.IsNotFound(err) {
			return err
		}
	}

	return nil
}

func (r *GatewayReconciler) handleNetwork(ctx context.Context, gw gatewayv1.Gateway) (gatewayv1.Gateway, error) {
	networkReq := api.NetworkRequest{
		Name: gw.ObjectMeta.Name,
	}
	id, err := func() (string, error) {
		if id, ok := gw.ObjectMeta.Annotations[NetworkIDAnnotationKey]; ok {
			_, err := r.NBClient.Networks.Get(ctx, id)
			if err != nil && !netbird.IsNotFound(err) {
				return "", err
			}
			if err == nil {
				_, err = r.NBClient.Networks.Update(ctx, id, networkReq)
				if err != nil {
					return "", err
				}
				return id, nil
			}
		}
		network, err := r.NBClient.Networks.Create(ctx, networkReq)
		if err != nil {
			return "", err
		}
		return network.Id, nil
	}()
	if err != nil {
		return gatewayv1.Gateway{}, err
	}
	gw.ObjectMeta.Annotations[NetworkIDAnnotationKey] = id
	return gw, nil
}

func (r *GatewayReconciler) handleGroup(ctx context.Context, gw gatewayv1.Gateway) (gatewayv1.Gateway, error) {
	groupReq := api.GroupRequest{
		Name: gw.Name,
	}
	id, err := func() (string, error) {
		if id, ok := gw.ObjectMeta.Annotations[GroupIDAnnotationKey]; ok {
			_, err := r.NBClient.Groups.Get(ctx, id)
			if err != nil && !netbird.IsNotFound(err) {
				return "", err
			}
			if err == nil {
				_, err = r.NBClient.Groups.Update(ctx, id, groupReq)
				if err != nil {
					return "", err
				}
			}
		}
		group, err := r.NBClient.Groups.Create(ctx, groupReq)
		if err != nil {
			return "", nil
		}
		return group.Id, nil
	}()
	if err != nil {
		return gatewayv1.Gateway{}, err
	}
	gw.ObjectMeta.Annotations[GroupIDAnnotationKey] = id
	return gw, nil
}

func (r *GatewayReconciler) handleSetupKey(ctx context.Context, gw gatewayv1.Gateway) (gatewayv1.Gateway, error) {
	setupKeyID := gw.ObjectMeta.Annotations[SetupKeyIDAnnotationKey]
	if setupKeyID != "" {
		_, err := r.NBClient.SetupKeys.Get(ctx, setupKeyID)
		// TODO: Create setup key if it no longer exists.
		if err != nil {
			return gatewayv1.Gateway{}, err
		}
		return gw, nil
	}

	setupKeyReq := api.CreateSetupKeyRequest{
		Name:       gw.ObjectMeta.Name,
		Ephemeral:  util.Ptr(true),
		Type:       "reusable",
		AutoGroups: []string{gw.Annotations[GroupIDAnnotationKey]},
	}
	setupKey, err := r.NBClient.SetupKeys.Create(ctx, setupKeyReq)
	if err != nil {
		return gatewayv1.Gateway{}, err
	}
	gw.ObjectMeta.Annotations[SetupKeyIDAnnotationKey] = setupKey.Id

	setupKeySecret := corev1.Secret{
		ObjectMeta: v1.ObjectMeta{
			Name:      fmt.Sprintf("%s-setup-key", gw.ObjectMeta.Name),
			Namespace: gw.ObjectMeta.Name,
		},
		StringData: map[string]string{
			"setupKey": setupKey.Key,
		},
	}
	err = controllerutil.SetControllerReference(&gw, &setupKeySecret, r.Scheme)
	if err != nil {
		return gatewayv1.Gateway{}, err
	}
	err = r.Client.Create(ctx, &setupKeySecret)
	if err != nil {
		return gatewayv1.Gateway{}, err
	}

	return gw, nil
}

func (r *GatewayReconciler) handleRouter(ctx context.Context, gw gatewayv1.Gateway) (gatewayv1.Gateway, error) {
	routerID := gw.ObjectMeta.Annotations[RouterIDAnnotationKey]
	if routerID != "" {
		_, err := r.NBClient.Networks.Routers(gw.Annotations[NetworkIDAnnotationKey]).Get(ctx, routerID)
		// TODO: Create router if it no longer exists.
		if err != nil {
			return gatewayv1.Gateway{}, err
		}
		return gw, nil
	}

	routerReq := api.NetworkRouterRequest{
		Enabled:    true,
		Masquerade: true,
		Metric:     9999,
		PeerGroups: &[]string{gw.Annotations[GroupIDAnnotationKey]},
	}
	router, err := r.NBClient.Networks.Routers(gw.Annotations[NetworkIDAnnotationKey]).Create(ctx, routerReq)
	if err != nil {
		return gatewayv1.Gateway{}, err
	}
	gw.ObjectMeta.Annotations[RouterIDAnnotationKey] = router.Id
	return gw, nil
}

func (r *GatewayReconciler) handleDeployment(ctx context.Context, gw gatewayv1.Gateway) error {
	annotations := map[string]string{}
	labels := map[string]string{}
	if gw.Spec.Infrastructure != nil {
		for k, v := range gw.Spec.Infrastructure.Annotations {
			annotations[string(k)] = string(v)
		}
		for k, v := range gw.Spec.Infrastructure.Labels {
			labels[string(k)] = string(v)
		}
	}
	podLabels := labels
	podLabels["app.kubernetes.io/name"] = "netbird-router"

	dep := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-routing-peer", gw.Name),
			Namespace: gw.Namespace,
		},
	}
	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, dep, func() error {
		dep.ObjectMeta.Labels = labels
		dep.ObjectMeta.Annotations = annotations
		dep.Spec = appsv1.DeploymentSpec{
			Replicas: util.Ptr[int32](3),
			Selector: &v1.LabelSelector{
				MatchLabels: map[string]string{
					"app.kubernetes.io/name": "netbird-router",
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: v1.ObjectMeta{
					Labels: podLabels,
				},
				Spec: corev1.PodSpec{
					// NodeSelector: nbrp.Spec.NodeSelector,
					// Tolerations:  nbrp.Spec.Tolerations,
					Containers: []corev1.Container{
						{
							Name:  "netbird",
							Image: r.ClientImage,
							Env: []corev1.EnvVar{
								{
									Name: "NB_SETUP_KEY",
									ValueFrom: &corev1.EnvVarSource{
										SecretKeyRef: &corev1.SecretKeySelector{
											LocalObjectReference: corev1.LocalObjectReference{
												Name: fmt.Sprintf("%s-setup-key", gw.ObjectMeta.Name),
											},
											Key: "setupKey",
										},
									},
								},
								{
									Name:  "NB_MANAGEMENT_URL",
									Value: r.ManagementURL,
								},
							},
							SecurityContext: &corev1.SecurityContext{
								Capabilities: &corev1.Capabilities{
									Add: []corev1.Capability{
										"NET_ADMIN",
									},
								},
							},
							// Resources:    nbrp.Spec.Resources,
							// VolumeMounts: nbrp.Spec.VolumeMounts,
						},
					},
					// Volumes: nbrp.Spec.Volumes,
				},
			},
		}

		return controllerutil.SetControllerReference(&gw, dep, r.Scheme)
	})
	if err != nil {
		return err
	}

	return nil
}
