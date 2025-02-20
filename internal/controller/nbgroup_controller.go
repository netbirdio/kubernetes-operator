package controller

import (
	"context"
	"fmt"
	"strings"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	netbirdiov1 "github.com/netbirdio/kubernetes-operator/api/v1"
	"github.com/netbirdio/kubernetes-operator/internal/util"
	netbird "github.com/netbirdio/netbird/management/client/rest"
	"github.com/netbirdio/netbird/management/server/http/api"
)

// NBGroupReconciler reconciles a NBGroup object
type NBGroupReconciler struct {
	client.Client
	Scheme        *runtime.Scheme
	APIKey        string
	ManagementURL string
	netbird       *netbird.Client
}

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
func (r *NBGroupReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	_ = log.FromContext(ctx)

	nbGroup := netbirdiov1.NBGroup{}
	err := r.Client.Get(ctx, req.NamespacedName, &nbGroup)
	if err != nil {
		if !errors.IsNotFound(err) {
			ctrl.Log.Error(fmt.Errorf("internalError"), "error getting NBGroup", "err", err, "namespace", req.Namespace, "name", req.Name)
		}
		return ctrl.Result{}, nil
	}

	if nbGroup.DeletionTimestamp != nil {
		if len(nbGroup.Finalizers) == 0 {
			return ctrl.Result{}, nil
		}
		return r.handleDelete(ctx, req, nbGroup)
	}

	groups, err := r.netbird.Groups.List(ctx)
	var group *api.Group
	for _, g := range groups {
		if g.Name == nbGroup.Spec.Name {
			group = &g
		}
	}
	if nbGroup.Status.GroupID == nil && group == nil {
		ctrl.Log.Info("NBGroup: Creating group on NetBird", "name", nbGroup.Spec.Name)
		group, err := r.netbird.Groups.Create(ctx, api.GroupRequest{
			Name: nbGroup.Spec.Name,
		})
		ctrl.Log.Info("NBGroup: Created group on NetBird", "name", nbGroup.Spec.Name, "id", group.Id)

		if err != nil {
			ctrl.Log.Error(fmt.Errorf("netbirdAPIError"), "error creating group", "err", err, "namespace", req.Namespace, "name", req.Name)
			return ctrl.Result{}, err
		}

		nbGroup.Status.GroupID = &group.Id
		err = r.Client.Status().Update(ctx, &nbGroup)
		if err != nil {
			ctrl.Log.Error(fmt.Errorf("internalError"), "error updating NBGroup status", "err", err, "namespace", req.Namespace, "name", req.Name)
			return ctrl.Result{}, err
		}
	} else if nbGroup.Status.GroupID == nil && group != nil {
		ctrl.Log.Info("NBGroup: Found group with same name on NetBird", "name", nbGroup.Spec.Name, "id", group.Id)
		nbGroup.Status.GroupID = &group.Id
		err = r.Client.Status().Update(ctx, &nbGroup)
		if err != nil {
			ctrl.Log.Error(fmt.Errorf("internalError"), "error updating NBGroup status", "err", err, "namespace", req.Namespace, "name", req.Name)
			return ctrl.Result{}, err
		}
	} else if group == nil {
		ctrl.Log.Info("NBGroup: Group was deleted", "name", nbGroup.Spec.Name, "id", *nbGroup.Status.GroupID)
		nbGroup.Status.GroupID = nil
		err = r.Client.Status().Update(ctx, &nbGroup)
		if err != nil {
			ctrl.Log.Error(fmt.Errorf("internalError"), "error updating NBGroup status", "err", err, "namespace", req.Namespace, "name", req.Name)
			return ctrl.Result{}, err
		}
		return ctrl.Result{Requeue: true}, nil
	}

	if nbGroup.Status.GroupID != nil && group != nil && *nbGroup.Status.GroupID != group.Id {
		// There are two possibilities here, either someone deleted and created the group in NetBird, thus the changed ID
		// Or there's a conflict with something else, either way, we just need to take the new ID here
		nbGroup.Status.GroupID = &group.Id
		err = r.Client.Status().Update(ctx, &nbGroup)
		if err != nil {
			ctrl.Log.Error(fmt.Errorf("internalError"), "error updating NBGroup status", "err", err, "namespace", req.Namespace, "name", req.Name)
			return ctrl.Result{}, err
		}
	}

	return ctrl.Result{}, nil
}

func (r *NBGroupReconciler) handleDelete(ctx context.Context, req ctrl.Request, nbGroup netbirdiov1.NBGroup) (ctrl.Result, error) {
	if nbGroup.Status.GroupID == nil {
		nbGroup.Finalizers = util.Without(nbGroup.Finalizers, "netbird.io/group-cleanup")
		err := r.Client.Update(ctx, &nbGroup)
		if err != nil {
			ctrl.Log.Error(fmt.Errorf("internalError"), "error updating NBGroup", "err", err, "namespace", req.Namespace, "name", req.Name)
			return ctrl.Result{}, err
		}

		return ctrl.Result{}, nil
	}

	err := r.netbird.Groups.Delete(ctx, *nbGroup.Status.GroupID)
	if err != nil && !strings.Contains(err.Error(), "not found") {
		ctrl.Log.Error(fmt.Errorf("netbirdAPIError"), "error deleting group", "err", err, "namespace", req.Namespace, "name", req.Name)
		return ctrl.Result{}, err
	}

	nbGroup.Finalizers = util.Without(nbGroup.Finalizers, "netbird.io/group-cleanup")
	err = r.Client.Update(ctx, &nbGroup)
	if err != nil {
		ctrl.Log.Error(fmt.Errorf("internalError"), "error updating NBGroup", "err", err, "namespace", req.Namespace, "name", req.Name)
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *NBGroupReconciler) SetupWithManager(mgr ctrl.Manager) error {
	r.netbird = netbird.New(r.ManagementURL, r.APIKey)

	return ctrl.NewControllerManagedBy(mgr).
		For(&netbirdiov1.NBGroup{}).
		Named("nbgroup").
		Complete(r)
}
