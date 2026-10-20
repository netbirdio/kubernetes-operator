// SPDX-License-Identifier: BSD-3-Clause

package controller

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/fluxcd/pkg/runtime/conditions"
	"github.com/fluxcd/pkg/runtime/patch"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	netbird "github.com/netbirdio/netbird/shared/management/client/rest"
	"github.com/netbirdio/netbird/shared/management/http/api"

	nbv1alpha1 "github.com/netbirdio/kubernetes-operator/api/v1alpha1"
	"github.com/netbirdio/kubernetes-operator/internal/k8sutil"
)

type GroupReconciler struct {
	client.Client

	Netbird *netbird.Client
}

// +kubebuilder:rbac:groups=netbird.io,resources=groups,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=netbird.io,resources=groups/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=netbird.io,resources=groups/finalizers,verbs=update

func (r *GroupReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	group := &nbv1alpha1.Group{}
	err := r.Get(ctx, req.NamespacedName, group)
	if err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	sp := patch.NewSerialPatcher(group, r.Client)

	if !group.DeletionTimestamp.IsZero() {
		return r.reconcileDelete(ctx, sp, group)
	}

	controllerutil.AddFinalizer(group, k8sutil.Finalizer("group"))
	err = sp.Patch(ctx, group)
	if err != nil {
		return ctrl.Result{}, err
	}

	groupID, err := func() (string, error) {
		if group.Status.GroupID != "" {
			groupResp, err := r.Netbird.Groups.Get(ctx, group.Status.GroupID)
			if err != nil && !netbird.IsNotFound(err) {
				return "", err
			}
			if err == nil {
				peers := []string{}
				for _, peer := range groupResp.Peers {
					peers = append(peers, peer.Id)
				}
				groupReq := api.GroupRequest{
					Name:      group.Spec.Name,
					Peers:     &peers,
					Resources: &groupResp.Resources,
				}
				resp, err := r.Netbird.Groups.Update(ctx, group.Status.GroupID, groupReq)
				if err != nil && !netbird.IsNotFound(err) {
					return "", err
				}
				if err == nil {
					return resp.Id, nil
				}
			}
		}
		// NetBird refuses a second group with the same name, so a group that already
		// exists under this name (created by hand, or by this resource before its status
		// was lost, as after restoring NetBird's database into a new cluster) is adopted
		// rather than recreated, unless another Group already owns it.
		groups, err := r.Netbird.Groups.List(ctx)
		if err != nil {
			return "", err
		}
		for _, g := range groups {
			if g.Name != group.Spec.Name {
				continue
			}
			owner, err := r.ownerOf(ctx, group, g.Id)
			if err != nil {
				return "", err
			}
			if owner != nil {
				return "", &groupOwnedError{owner: client.ObjectKeyFromObject(owner)}
			}
			return g.Id, nil
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
	var owned *groupOwnedError
	if errors.As(err, &owned) {
		conditions.MarkFalse(group, nbv1alpha1.ReadyCondition, nbv1alpha1.ConflictReason, "%s", owned.Error())
		err = sp.Patch(ctx, group, patch.WithStatusObservedGeneration{})
		if err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: 15 * time.Minute}, nil
	}
	if err != nil {
		return ctrl.Result{}, err
	}
	group.Status.GroupID = groupID

	conditions.MarkTrue(group, nbv1alpha1.ReadyCondition, nbv1alpha1.ReconciledReason, "")
	err = sp.Patch(ctx, group, patch.WithStatusObservedGeneration{})
	if err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{RequeueAfter: 15 * time.Minute}, nil
}

func (r *GroupReconciler) reconcileDelete(ctx context.Context, sp *patch.SerialPatcher, group *nbv1alpha1.Group) (ctrl.Result, error) {
	if group.Status.GroupID != "" {
		err := r.Netbird.Groups.Delete(ctx, group.Status.GroupID)
		if err != nil && !netbird.IsNotFound(err) {
			return ctrl.Result{}, err
		}
	}

	controllerutil.RemoveFinalizer(group, k8sutil.Finalizer("group"))
	err := sp.Patch(ctx, group)
	if err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

// groupOwnedError reports a NetBird group that another Group resource already owns.
type groupOwnedError struct {
	owner client.ObjectKey
}

func (e *groupOwnedError) Error() string {
	return fmt.Sprintf("A Netbird group with this name already belongs to Group %s.", e.owner)
}

// ownerOf returns the Group resource, other than group, whose status holds the Netbird
// group id, or nil if there is none.
func (r *GroupReconciler) ownerOf(ctx context.Context, group *nbv1alpha1.Group, id string) (*nbv1alpha1.Group, error) {
	groups := &nbv1alpha1.GroupList{}
	err := r.List(ctx, groups)
	if err != nil {
		return nil, err
	}
	for i := range groups.Items {
		other := &groups.Items[i]
		if other.UID != group.UID && other.Status.GroupID == id {
			return other, nil
		}
	}
	return nil, nil
}

func (r *GroupReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&nbv1alpha1.Group{}).
		Complete(r)
}
