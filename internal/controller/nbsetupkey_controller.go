// SPDX-License-Identifier: BSD-3-Clause

package controller

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	nbv1 "github.com/netbirdio/kubernetes-operator/api/v1"
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

	nbSetupKey := nbv1.NBSetupKey{}
	err := r.Get(ctx, req.NamespacedName, &nbSetupKey)
	if err != nil {
		logger.Error(fmt.Errorf("internalError"), "error getting NBSetupKey", "err", err)
		return ctrl.Result{}, nil
	}

	if nbSetupKey.Spec.SecretKeyRef.Name == "" || nbSetupKey.Spec.SecretKeyRef.Key == "" {
		logger.Error(fmt.Errorf("invalid NBSetupKey"), "secretKeyRef must contain both secret name and secret key")
		return ctrl.Result{}, r.setStatus(ctx, &nbSetupKey, nbv1.NBSetupKeyStatus{
			Conditions: []nbv1.NBCondition{
				{
					Type:          nbv1.NBSetupKeyReady,
					Status:        corev1.ConditionFalse,
					LastProbeTime: metav1.Now(),
					Reason:        "InvalidConfig",
					Message:       "secretKeyRef must contain both secret name and secret key.",
				},
			},
		})
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
			logger.Error(fmt.Errorf("internalError"), "error getting secret", "err", err)
			return ctrl.Result{}, err
		}
		logger.Error(fmt.Errorf("invalid NBSetupKey"), "secret referenced not found", "err", err)
		return ctrl.Result{}, r.setStatus(ctx, &nbSetupKey, nbv1.NBSetupKeyStatus{Conditions: []nbv1.NBCondition{{
			Type:          nbv1.NBSetupKeyReady,
			Status:        corev1.ConditionFalse,
			LastProbeTime: metav1.Now(),
			Reason:        "SecretNotExists",
			Message:       "Referenced secret does not exist",
		}}})
	}

	uuidBytes, ok := secret.Data[nbSetupKey.Spec.SecretKeyRef.Key]
	if !ok {
		logger.Error(fmt.Errorf("invalid NBSetupKey"), "secret key referenced not found")
		return ctrl.Result{}, r.setStatus(ctx, &nbSetupKey, nbv1.NBSetupKeyStatus{Conditions: []nbv1.NBCondition{{
			Type:          nbv1.NBSetupKeyReady,
			Status:        corev1.ConditionFalse,
			LastProbeTime: metav1.Now(),
			Reason:        "SecretKeyNotExists",
			Message:       "Referenced secret key does not exist",
		}}})
	}

	_, err = uuid.Parse(string(uuidBytes))
	if err != nil {
		logger.Error(fmt.Errorf("invalid NBSetupKey"), "setupKey is not a valid UUID", "err", err)
		return ctrl.Result{}, r.setStatus(ctx, &nbSetupKey, nbv1.NBSetupKeyStatus{Conditions: []nbv1.NBCondition{{
			Type:          nbv1.NBSetupKeyReady,
			Status:        corev1.ConditionFalse,
			LastProbeTime: metav1.Now(),
			Reason:        "InvalidSetupKey",
			Message:       "Referenced secret is not a valid SetupKey",
		}}})
	}
	return ctrl.Result{}, r.setStatus(ctx, &nbSetupKey, nbv1.NBSetupKeyStatus{Conditions: []nbv1.NBCondition{{
		Type:          nbv1.NBSetupKeyReady,
		Status:        corev1.ConditionTrue,
		LastProbeTime: metav1.Now(),
	}}})
}

func (r *NBSetupKeyReconciler) setStatus(ctx context.Context, nbsetupkey *nbv1.NBSetupKey, status nbv1.NBSetupKeyStatus) error {
	nbsetupkey.Status = status
	err := r.Status().Update(ctx, nbsetupkey)
	return err
}

// SetupWithManager sets up the controller with the Manager.
func (r *NBSetupKeyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	r.ReferencedSecrets = make(map[string]types.NamespacedName)

	return ctrl.NewControllerManagedBy(mgr).
		For(&nbv1.NBSetupKey{}).
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
