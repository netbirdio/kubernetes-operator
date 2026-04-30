package controller

import (
	"context"
	"time"

	"github.com/fluxcd/pkg/runtime/patch"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	gwv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/netbirdio/kubernetes-operator/internal/k8sutil"
)

const (
	GatewayControllerName = "gateway.netbird.io/controller"
)

type GatewayClassReconciler struct {
	client.Client
}

func (r *GatewayClassReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	gwc := &gwv1.GatewayClass{}
	err := r.Client.Get(ctx, req.NamespacedName, gwc)
	if err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	sp := patch.NewSerialPatcher(gwc, r.Client)

	// Controller name does not match.
	if gwc.Spec.ControllerName != GatewayControllerName {
		return ctrl.Result{}, nil
	}

	// Gateway class is being deleted.
	if !gwc.GetDeletionTimestamp().IsZero() {
		return r.reconcileDelete(ctx, sp, gwc)
	}

	// Validate configuration.
	message := func() string {
		if gwc.Name != "netbird-public" && gwc.Name != "netbird-private" {
			return "GatewayClass name must be netbird-public or netbird-private."
		}
		if gwc.Spec.ParametersRef != nil {
			return "Parameters references is not supported."
		}
		return ""
	}()
	if message != "" {
		cond := metav1.Condition{
			Type:    string(gwv1.GatewayClassConditionStatusAccepted),
			Status:  metav1.ConditionFalse,
			Reason:  string(gwv1.GatewayClassReasonInvalidParameters),
			Message: message,
		}
		meta.SetStatusCondition(&gwc.Status.Conditions, cond)
		err := sp.Patch(ctx, gwc)
		if err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	// Set condition to accepted.
	controllerutil.AddFinalizer(gwc, k8sutil.Finalizer("gatewayclass"))
	cond := metav1.Condition{
		Type:    string(gwv1.GatewayClassConditionStatusAccepted),
		Status:  metav1.ConditionTrue,
		Reason:  string(gwv1.GatewayClassReasonAccepted),
		Message: "Reconciled by Netbird Operator.",
	}
	meta.SetStatusCondition(&gwc.Status.Conditions, cond)
	err = sp.Patch(ctx, gwc)
	if err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

func (r *GatewayClassReconciler) reconcileDelete(ctx context.Context, sp *patch.SerialPatcher, gwc *gwv1.GatewayClass) (ctrl.Result, error) {
	var gatewayList gwv1.GatewayList
	err := r.Client.List(ctx, &gatewayList)
	if err != nil {
		return ctrl.Result{}, err
	}
	for _, gw := range gatewayList.Items {
		if string(gw.Spec.GatewayClassName) == gwc.ObjectMeta.Name {
			return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
		}
	}

	controllerutil.RemoveFinalizer(gwc, k8sutil.Finalizer("gatewayclass"))
	err = sp.Patch(ctx, gwc)
	if err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *GatewayClassReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&gwv1.GatewayClass{}).
		Complete(r)
}
