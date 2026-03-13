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

	"github.com/google/uuid"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	netbirdiov1 "github.com/netbirdio/kubernetes-operator/api/v1"
)

// NBSetupKeyReconciler reconciles a NBSetupKey object
type NBSetupKeyReconciler struct {
	client.Client

	ReferencedSecrets map[string]types.NamespacedName
}

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
func (r *NBSetupKeyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := ctrl.Log.WithName("NBSetupKey").WithValues("namespace", req.Namespace, "name", req.Name)
	logger.Info("Reconciling NBSetupKey")

	nbSetupKey := netbirdiov1.NBSetupKey{}
	err := r.Get(ctx, req.NamespacedName, &nbSetupKey)
	if err != nil {
		logger.Error(fmt.Errorf("internalError"), "error getting NBSetupKey", "err", err)
		return ctrl.Result{}, nil
	}

	if nbSetupKey.Spec.SecretKeyRef.Name == "" || nbSetupKey.Spec.SecretKeyRef.Key == "" {
		if meta.SetStatusCondition(&nbSetupKey.Status.Conditions, metav1.Condition{Type: netbirdiov1.ReadyCondition, Status: metav1.ConditionFalse, Reason: netbirdiov1.InvalidSpecReason, Message: "secret key ref needs to contain both name and key"}) {
			err := r.Client.Status().Update(ctx, &nbSetupKey)
			if err != nil {
				return ctrl.Result{}, err
			}
		}
		return ctrl.Result{}, nil
	}

	// Handle updated secret name
	for k, v := range r.ReferencedSecrets {
		if v == req.NamespacedName {
			delete(r.ReferencedSecrets, k)
			break
		}
	}
	r.ReferencedSecrets[fmt.Sprintf("%s/%s", nbSetupKey.Namespace, nbSetupKey.Spec.SecretKeyRef.Name)] = req.NamespacedName

	secret := corev1.Secret{}
	err = r.Get(ctx, types.NamespacedName{Namespace: nbSetupKey.Namespace, Name: nbSetupKey.Spec.SecretKeyRef.Name}, &secret)
	if err != nil {
		if !errors.IsNotFound(err) {
			return ctrl.Result{}, err
		}
		if meta.SetStatusCondition(&nbSetupKey.Status.Conditions, metav1.Condition{Type: netbirdiov1.ReadyCondition, Status: metav1.ConditionFalse, Reason: netbirdiov1.InvalidSpecReason, Message: "secret reference not found"}) {
			err := r.Client.Status().Update(ctx, &nbSetupKey)
			if err != nil {
				return ctrl.Result{}, err
			}
		}
		return ctrl.Result{}, nil
	}

	uuidBytes, ok := secret.Data[nbSetupKey.Spec.SecretKeyRef.Key]
	if !ok {
		if meta.SetStatusCondition(&nbSetupKey.Status.Conditions, metav1.Condition{Type: netbirdiov1.ReadyCondition, Status: metav1.ConditionFalse, Reason: netbirdiov1.InvalidSpecReason, Message: "key in secret not found"}) {
			err := r.Client.Status().Update(ctx, &nbSetupKey)
			if err != nil {
				return ctrl.Result{}, err
			}
		}
		return ctrl.Result{}, nil
	}

	_, err = uuid.Parse(string(uuidBytes))
	if err != nil {
		if meta.SetStatusCondition(&nbSetupKey.Status.Conditions, metav1.Condition{Type: netbirdiov1.ReadyCondition, Status: metav1.ConditionFalse, Reason: netbirdiov1.InvalidSpecReason, Message: "key is not a valid UUID"}) {
			err := r.Client.Status().Update(ctx, &nbSetupKey)
			if err != nil {
				return ctrl.Result{}, err
			}
		}
		return ctrl.Result{}, nil
	}

	if meta.SetStatusCondition(&nbSetupKey.Status.Conditions, metav1.Condition{Type: netbirdiov1.ReadyCondition, Status: metav1.ConditionTrue}) {
		err := r.Client.Status().Update(ctx, &nbSetupKey)
		if err != nil {
			return ctrl.Result{}, err
		}
	}
	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *NBSetupKeyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	r.ReferencedSecrets = make(map[string]types.NamespacedName)

	return ctrl.NewControllerManagedBy(mgr).
		For(&netbirdiov1.NBSetupKey{}).
		Named("nbsetupkey").
		Watches(
			&corev1.Secret{},
			handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, obj client.Object) []reconcile.Request {
				if v, ok := r.ReferencedSecrets[fmt.Sprintf("%s/%s", obj.GetNamespace(), obj.GetName())]; ok {
					return []reconcile.Request{
						{
							NamespacedName: v,
						},
					}
				}

				return nil
			}),
		). // Trigger reconciliation when a referenced secret changes
		Complete(r)
}
