package controller

import (
	"context"
	"fmt"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/go-logr/logr"
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

const (
	// defaultRequeueAfter default requeue duration
	// due to controller-runtime limitations, sync periods may reach up to 10 hours if no changes are detected
	// in watched resources.
	// This may cause issues when NetBird-side resources are out-of-sync and need to be reconciled, this is a temporary
	// fix to this issue by syncing with NetBird more frequently.
	defaultRequeueAfter = 15 * time.Minute
)

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
func (r *NBGroupReconciler) Reconcile(ctx context.Context, req ctrl.Request) (res ctrl.Result, err error) {
	logger := ctrl.Log.WithName("NBGroup").WithValues("namespace", req.Namespace, "name", req.Name)
	logger.Info("Reconciling NBGroup")

	nbGroup := netbirdiov1.NBGroup{}
	err = r.Client.Get(ctx, req.NamespacedName, &nbGroup)
	if err != nil {
		if !errors.IsNotFound(err) {
			logger.Error(errKubernetesAPI, "error getting NBGroup", "err", err)
		}
		return ctrl.Result{RequeueAfter: defaultRequeueAfter}, nil
	}

	originalGroup := nbGroup.DeepCopy()
	defer func() {
		if !originalGroup.Status.Equal(nbGroup.Status) {
			updateErr := r.Client.Status().Update(ctx, &nbGroup)
			if updateErr != nil {
				err = updateErr
			}
		}
		if !res.Requeue && res.RequeueAfter == 0 {
			res.RequeueAfter = defaultRequeueAfter
		}
	}()

	if nbGroup.DeletionTimestamp != nil {
		if len(nbGroup.Finalizers) == 0 {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, r.handleDelete(ctx, nbGroup, logger)
	}

	return r.syncNetBirdGroup(ctx, &nbGroup, logger)
}

// syncNetBirdGroup reconciliation logic for non-deleted objects.
func (r *NBGroupReconciler) syncNetBirdGroup(ctx context.Context, nbGroup *netbirdiov1.NBGroup, logger logr.Logger) (ctrl.Result, error) {
	// Get all NetBird groups to ensure no group duplication
	groups, err := r.netbird.Groups.List(ctx)
	if err != nil {
		logger.Error(errNetBirdAPI, "error listing groups", "err", err)
		return ctrl.Result{}, err
	}
	var group *api.Group
	for _, g := range groups {
		if g.Name == nbGroup.Spec.Name {
			group = &g
		}
	}

	// Create group if not exists, and update status.groupId
	if nbGroup.Status.GroupID == nil && group == nil {
		logger.Info("NBGroup: Creating group on NetBird", "name", nbGroup.Spec.Name)
		group, err := r.netbird.Groups.Create(ctx, api.GroupRequest{
			Name: nbGroup.Spec.Name,
		})
		if err != nil {
			nbGroup.Status.Conditions = netbirdiov1.NBConditionFalse("APIError", fmt.Sprintf("NetBird API Error: %v", err))
			logger.Error(errNetBirdAPI, "error creating group", "err", err)
			return ctrl.Result{}, err
		}

		logger.Info("NBGroup: Created group on NetBird", "name", nbGroup.Spec.Name, "id", group.Id)
		nbGroup.Status.GroupID = &group.Id
		nbGroup.Status.Conditions = netbirdiov1.NBConditionTrue()
	} else if nbGroup.Status.GroupID == nil && group != nil {
		logger.Info("NBGroup: Found group with same name on NetBird", "name", nbGroup.Spec.Name, "id", group.Id)
		nbGroup.Status.GroupID = &group.Id
		nbGroup.Status.Conditions = netbirdiov1.NBConditionTrue()
	} else if group == nil {
		logger.Info("NBGroup: Group was deleted", "name", nbGroup.Spec.Name, "id", *nbGroup.Status.GroupID)
		nbGroup.Status.GroupID = nil
		nbGroup.Status.Conditions = netbirdiov1.NBConditionFalse("GroupGone", "Group was deleted from NetBird API")
		return ctrl.Result{Requeue: true}, nil
	} else {
		nbGroup.Status.Conditions = netbirdiov1.NBConditionTrue()
	}

	if nbGroup.Status.GroupID != nil && group != nil && *nbGroup.Status.GroupID != group.Id {
		// There are two possibilities here, either someone deleted and created the group in NetBird, thus the changed ID
		// Or there's a conflict with something else, either way, we just need to take the new ID here
		nbGroup.Status.GroupID = &group.Id
		nbGroup.Status.Conditions = netbirdiov1.NBConditionTrue()
	}
	return ctrl.Result{}, nil
}

func (r *NBGroupReconciler) handleDelete(ctx context.Context, nbGroup netbirdiov1.NBGroup, logger logr.Logger) error {
	// Group doesn't exist on NetBird, no need for cleanup
	if nbGroup.Status.GroupID == nil {
		nbGroup.Finalizers = util.Without(nbGroup.Finalizers, "netbird.io/group-cleanup")
		err := r.Client.Update(ctx, &nbGroup)
		if err != nil {
			logger.Error(errKubernetesAPI, "error updating NBGroup", "err", err)
			return err
		}

		return nil
	}

	err := r.netbird.Groups.Delete(ctx, *nbGroup.Status.GroupID)
	if err != nil && !strings.Contains(err.Error(), "not found") && !strings.Contains(err.Error(), "linked") {
		logger.Error(errNetBirdAPI, "error deleting group", "err", err)
		return err
	}

	if err != nil && strings.Contains(err.Error(), "linked") {
		logger.Info("group still linked to resources on netbird", "err", err)
		// Check if group is defined elsewhere in the cluster
		var groups netbirdiov1.NBGroupList
		listErr := r.Client.List(ctx, &groups)
		if listErr != nil {
			logger.Error(errKubernetesAPI, "error listing NBGroups", "err", listErr)
			return listErr
		}
		for _, v := range groups.Items {
			if v.UID == nbGroup.UID {
				continue
			}
			if v.Status.GroupID != nil && nbGroup.Status.GroupID != nil && *v.Status.GroupID == *nbGroup.Status.GroupID {
				// Same group, multiple resources
				logger.Info("group exists in another namespace", "namespace", v.Namespace, "name", v.Name)
				nbGroup.Finalizers = util.Without(nbGroup.Finalizers, "netbird.io/group-cleanup")
				err = r.Client.Update(ctx, &nbGroup)
				if err != nil {
					logger.Error(errKubernetesAPI, "error updating NBGroup", "err", err)
					return err
				}
				return nil
			}
		}

		// No other NBGroup with same name on the cluster
		// This could be a group created by user elsewhere or some resources belonging to the group are still deleting.
		return err
	}

	nbGroup.Finalizers = util.Without(nbGroup.Finalizers, "netbird.io/group-cleanup")
	err = r.Client.Update(ctx, &nbGroup)
	if err != nil {
		logger.Error(errKubernetesAPI, "error updating NBGroup", "err", err)
		return err
	}

	return nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *NBGroupReconciler) SetupWithManager(mgr ctrl.Manager) error {
	r.netbird = netbird.New(r.ManagementURL, r.APIKey)

	return ctrl.NewControllerManagedBy(mgr).
		For(&netbirdiov1.NBGroup{}).
		Named("nbgroup").
		Complete(r)
}
