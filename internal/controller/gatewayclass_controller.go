package controller

import (
	"context"
	"time"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

const (
	GatewayClassFinalizer = "gateway.netbird.io/gatewayclass"
	GatewayControllerName = "gateway.netbird.io/controller"
)

type GatewayClassReconciler struct {
	client.Client
}

func (r *GatewayClassReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	gwc := gatewayv1.GatewayClass{}
	err := r.Client.Get(ctx, req.NamespacedName, &gwc)
	if err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Controller name does not match.
	if gwc.Spec.ControllerName != GatewayControllerName {
		return ctrl.Result{}, nil
	}

	// Gateway class is being deleted.
	if !gwc.GetDeletionTimestamp().IsZero() {
		return r.reconcileDelete(ctx, gwc)
	}

	// Validate configuration.
	if gwc.Spec.ParametersRef != nil {
		cond := metav1.Condition{
			Type:    string(gatewayv1.GatewayClassConditionStatusAccepted),
			Status:  metav1.ConditionFalse,
			Reason:  string(gatewayv1.GatewayClassReasonInvalidParameters),
			Message: "Parameters references is not supported.",
		}
		if meta.SetStatusCondition(&gwc.Status.Conditions, cond) {
			err = r.Client.Status().Update(ctx, &gwc)
			if err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{}, nil
		}
	}

	// Add finalizer to validate deletion.
	if controllerutil.AddFinalizer(&gwc, GatewayClassFinalizer) {
		err = r.Client.Update(ctx, &gwc)
		if err != nil {
			return ctrl.Result{}, err
		}
	}

	// Set condition to accepted.
	cond := metav1.Condition{
		Type:    string(gatewayv1.GatewayClassConditionStatusAccepted),
		Status:  metav1.ConditionTrue,
		Reason:  string(gatewayv1.GatewayClassReasonAccepted),
		Message: "Reconciled by Netbird Operator.",
	}
	meta.SetStatusCondition(&gwc.Status.Conditions, cond)
	err = r.Client.Status().Update(ctx, &gwc)
	if err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

func (r *GatewayClassReconciler) reconcileDelete(ctx context.Context, gwc gatewayv1.GatewayClass) (ctrl.Result, error) {
	var gatewayList gatewayv1.GatewayList
	err := r.Client.List(ctx, &gatewayList)
	if err != nil {
		return ctrl.Result{}, err
	}
	for _, gw := range gatewayList.Items {
		if string(gw.Spec.GatewayClassName) == gwc.ObjectMeta.Name {
			return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
		}
	}
	if controllerutil.RemoveFinalizer(&gwc, GatewayClassFinalizer) {
		err = r.Client.Update(ctx, &gwc)
		if err != nil {
			return ctrl.Result{}, err
		}
	}
	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *GatewayClassReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&gatewayv1.GatewayClass{}).
		Complete(r)
}
