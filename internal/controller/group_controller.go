package controller

import (
	"context"

	netbird "github.com/netbirdio/netbird/shared/management/client/rest"
	"github.com/netbirdio/netbird/shared/management/http/api"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	nbv1alpha1 "github.com/netbirdio/kubernetes-operator/api/v1alpha1"
	nbv1alpha1ac "github.com/netbirdio/kubernetes-operator/pkg/applyconfigurations/api/v1alpha1"
)

const (
	GroupFinalizer = "netbird.io/group"
)

// GroupReconciler reconciles a Group object
type GroupReconciler struct {
	client.Client

	Netbird *netbird.Client
}

// +kubebuilder:rbac:groups=netbird.io,resources=groups,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=netbird.io,resources=groups/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=netbird.io,resources=groups/finalizers,verbs=update
func (r *GroupReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	group := nbv1alpha1.Group{}
	err := r.Get(ctx, req.NamespacedName, &group)
	if err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if !group.DeletionTimestamp.IsZero() {
		return r.reconcileDelete(ctx, group)
	}

	groupAC := nbv1alpha1ac.Group(req.Name, req.Namespace).WithFinalizers(SetupKeyFinalizer)
	err = r.Client.Apply(ctx, groupAC)
	if err != nil {
		return ctrl.Result{}, err
	}

	groupID, err := func() (string, error) {
		if group.Status.GroupID != nil {
			groupReq := api.GroupRequest{
				Name: group.Spec.Name,
			}
			resp, err := r.Netbird.Groups.Update(ctx, *group.Status.GroupID, groupReq)
			if err != nil && !netbird.IsNotFound(err) {
				return "", err
			}
			if err == nil {
				return resp.Id, nil
			}
		}

		groupReq := api.GroupRequest{
			Name: group.Spec.Name,
		}
		resp, err := r.Netbird.Groups.Create(ctx, groupReq)
		if err != nil {
			return "", err
		}
		return resp.Id, nil
	}()
	if err != nil {
		return ctrl.Result{}, err
	}

	groupAC = nbv1alpha1ac.Group(req.Name, req.Namespace).WithStatus(nbv1alpha1ac.GroupStatus().WithGroupID(groupID))
	err = r.Client.Status().Apply(ctx, groupAC)
	if err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

func (r *GroupReconciler) reconcileDelete(ctx context.Context, group nbv1alpha1.Group) (ctrl.Result, error) {
	if group.Status.GroupID != nil {
		err := r.Netbird.Groups.Delete(ctx, *group.Status.GroupID)
		if err != nil && !netbird.IsNotFound(err) {
			return ctrl.Result{}, err
		}
	}

	groupAC := nbv1alpha1ac.Group(group.Name, group.Namespace).WithFinalizers()
	err := r.Client.Apply(ctx, groupAC)
	if err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *GroupReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&nbv1alpha1.Group{}).
		Complete(r)
}
