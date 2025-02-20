package controller

import (
	"context"
	"fmt"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"

	netbirdiov1 "github.com/netbirdio/kubernetes-operator/api/v1"
	"github.com/netbirdio/kubernetes-operator/internal/util"
	netbird "github.com/netbirdio/netbird/management/client/rest"
	"github.com/netbirdio/netbird/management/server/http/api"
)

// NBResourceReconciler reconciles a NBResource object
type NBResourceReconciler struct {
	client.Client
	Scheme        *runtime.Scheme
	APIKey        string
	ManagementURL string
	netbird       *netbird.Client
}

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
func (r *NBResourceReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	_ = log.FromContext(ctx)

	nbResource := netbirdiov1.NBResource{}
	err := r.Client.Get(ctx, req.NamespacedName, &nbResource)
	if err != nil {
		if !errors.IsNotFound(err) {
			ctrl.Log.Error(fmt.Errorf("internalError"), "error getting NBResource", "err", err, "namespace", req.Namespace, "name", req.Name)
		}
		return ctrl.Result{}, nil
	}

	if nbResource.DeletionTimestamp != nil {
		if len(nbResource.Finalizers) == 0 {
			return ctrl.Result{}, nil
		}
		return r.handleDelete(ctx, req, nbResource)
	}

	groupIDs, res, err := r.handleGroups(ctx, req, nbResource)
	if res != nil {
		return *res, err
	}

	resource, err := r.handleNetBirdResource(ctx, req, nbResource, groupIDs)
	if err != nil {
		return ctrl.Result{}, err
	}

	// resource is only nil if requeue is expected
	if resource == nil {
		return ctrl.Result{Requeue: true}, nil
	}

	err = r.handleGroupUpdate(ctx, req, nbResource, groupIDs, resource)

	return ctrl.Result{}, err
}

func (r *NBResourceReconciler) handleGroupUpdate(ctx context.Context, req ctrl.Request, nbResource netbirdiov1.NBResource, groupIDs []string, resource *api.NetworkResource) error {
	// Handle possible updated group IDs
	groupIDMap := make(map[string]interface{})
	for _, g := range groupIDs {
		groupIDMap[g] = nil
	}

	diffFound := len(groupIDs) != len(resource.Groups)
	for _, g := range resource.Groups {
		if _, ok := groupIDMap[g.Id]; !ok {
			diffFound = true
		}
	}

	if diffFound {
		_, err := r.netbird.Networks.Resources(nbResource.Spec.NetworkID).Update(ctx, resource.Id, api.NetworkResourceRequest{
			Name:        nbResource.Spec.Name,
			Description: util.Ptr("Created by kubernetes-operator"),
			Address:     nbResource.Spec.Address,
			Enabled:     true,
			Groups:      groupIDs,
		})

		if err != nil {
			ctrl.Log.Error(fmt.Errorf("netbirdAPIError"), "error updating resource", "err", err, "namespace", req.Namespace, "name", req.Name)
			return err
		}
	}

	return nil
}

func (r *NBResourceReconciler) handleNetBirdResource(ctx context.Context, req ctrl.Request, nbResource netbirdiov1.NBResource, groupIDs []string) (*api.NetworkResource, error) {
	resources, err := r.netbird.Networks.Resources(nbResource.Spec.NetworkID).List(ctx)
	var resource *api.NetworkResource
	for _, n := range resources {
		if n.Name == nbResource.Spec.Name {
			resource = &n
		}
	}
	if nbResource.Status.NetworkResourceID == nil && resource == nil {
		resource, err = r.netbird.Networks.Resources(nbResource.Spec.NetworkID).Create(ctx, api.NetworkResourceRequest{
			Address:     nbResource.Spec.Address,
			Enabled:     true,
			Groups:      groupIDs,
			Description: util.Ptr("Created by kubernetes-operator"),
			Name:        nbResource.Spec.Name,
		})

		if err != nil {
			ctrl.Log.Error(fmt.Errorf("netbirdAPIError"), "error creating resource", "err", err, "namespace", req.Namespace, "name", req.Name)
			return nil, err
		}

		nbResource.Status.NetworkResourceID = &resource.Id
		err = r.Client.Status().Update(ctx, &nbResource)
		if err != nil {
			ctrl.Log.Error(fmt.Errorf("internalError"), "error updating NBResource status", "err", err, "namespace", req.Namespace, "name", req.Name)
			return nil, err
		}
	} else if nbResource.Status.NetworkResourceID == nil && resource != nil {
		nbResource.Status.NetworkResourceID = &resource.Id
		err = r.Client.Status().Update(ctx, &nbResource)
		if err != nil {
			ctrl.Log.Error(fmt.Errorf("internalError"), "error updating NBResource status", "err", err, "namespace", req.Namespace, "name", req.Name)
			return nil, err
		}
	} else if resource == nil {
		// Status remembers networkResourceID but resource resource with same name doesn't exist
		// There are two possibilties here, either NBResource.Spec.Name is updated
		// Or Resource was deleted elsewhere
		networkUpdated := false
		for _, n := range resources {
			if n.Id == *nbResource.Status.NetworkResourceID {
				// First possibility, update resource name in NetBird
				resource, err = r.netbird.Networks.Resources(nbResource.Spec.NetworkID).Update(ctx, n.Id, api.NetworkResourceRequest{
					Name:        nbResource.Spec.Name,
					Description: util.Ptr("Created by kubernetes-operator"),
					Address:     nbResource.Spec.Address,
					Enabled:     true,
					Groups:      groupIDs,
				})

				if err != nil {
					ctrl.Log.Error(fmt.Errorf("netbirdAPIError"), "error updating resource", "err", err, "namespace", req.Namespace, "name", req.Name)
					return nil, err
				}

				networkUpdated = true
				break
			}
		}

		if !networkUpdated {
			// Second possibility, remove networkID from status and re-enqueue
			nbResource.Status.NetworkResourceID = nil
			err = r.Client.Status().Update(ctx, &nbResource)
			if err != nil {
				ctrl.Log.Error(fmt.Errorf("internalError"), "error updating NBResource status", "err", err, "namespace", req.Namespace, "name", req.Name)
				return nil, err
			}
		}
	} else if *nbResource.Status.NetworkResourceID != resource.Id {
		// There are two possibilities here, either someone deleted and created the resource in NetBird, thus the changed ID
		// Or there's a conflict with something else, either way, we just need to take the new ID here
		nbResource.Status.NetworkResourceID = &resource.Id
		err = r.Client.Status().Update(ctx, &nbResource)
		if err != nil {
			ctrl.Log.Error(fmt.Errorf("internalError"), "error updating NBResource status", "err", err, "namespace", req.Namespace, "name", req.Name)
			return nil, err
		}
	}

	return resource, nil
}

func (r *NBResourceReconciler) handleGroups(ctx context.Context, req ctrl.Request, nbResource netbirdiov1.NBResource) ([]string, *ctrl.Result, error) {
	var groupIDs []string

	for _, groupName := range nbResource.Spec.Groups {
		nbGroup := netbirdiov1.NBGroup{}
		groupNameRFC := strings.ToLower(groupName)
		groupNameRFC = strings.ReplaceAll(groupNameRFC, " ", "-")
		err := r.Client.Get(ctx, types.NamespacedName{Namespace: req.Namespace, Name: groupNameRFC}, &nbGroup)
		if err != nil && !errors.IsNotFound(err) {
			ctrl.Log.Error(fmt.Errorf("internalError"), "error getting NBGroup", "err", err, "namespace", req.Namespace, "name", req.Name)
			return nil, &ctrl.Result{}, err
		} else if errors.IsNotFound(err) {
			nbGroup = netbirdiov1.NBGroup{
				ObjectMeta: v1.ObjectMeta{
					Name:      groupNameRFC,
					Namespace: nbResource.Namespace,
					OwnerReferences: []v1.OwnerReference{
						{
							APIVersion:         nbResource.APIVersion,
							Kind:               nbResource.Kind,
							Name:               nbResource.Name,
							UID:                nbResource.UID,
							BlockOwnerDeletion: util.Ptr(true),
						},
					},
					Finalizers: []string{"netbird.io/group-cleanup", "netbird.io/resource-cleanup"},
				},
				Spec: netbirdiov1.NBGroupSpec{
					Name: groupName,
				},
			}

			err = r.Client.Create(ctx, &nbGroup)
			if err != nil {
				ctrl.Log.Error(fmt.Errorf("internalError"), "error creating NBGroup", "err", err, "namespace", req.Namespace, "name", req.Name)
				return nil, &ctrl.Result{}, err
			}

			continue
		} else {
			ownerExists := false
			for _, o := range nbGroup.OwnerReferences {
				if o.UID == nbResource.UID {
					ownerExists = true
				}
			}

			if !ownerExists {
				nbGroup.OwnerReferences = append(nbGroup.OwnerReferences, v1.OwnerReference{
					APIVersion:         nbResource.APIVersion,
					Kind:               nbResource.Kind,
					Name:               nbResource.Name,
					UID:                nbResource.UID,
					BlockOwnerDeletion: util.Ptr(true),
				})

				err = r.Client.Update(ctx, &nbGroup)
				if err != nil {
					ctrl.Log.Error(fmt.Errorf("internalError"), "error updating NBGroup", "err", err, "namespace", req.Namespace, "name", req.Name)
					return nil, &ctrl.Result{}, err
				}
			}
		}

		if nbGroup.Status.GroupID != nil {
			groupIDs = append(groupIDs, *nbGroup.Status.GroupID)
		}
	}

	if len(groupIDs) != len(nbResource.Spec.Groups) {
		return nil, &ctrl.Result{RequeueAfter: 5 * time.Second}, nil
	}

	return groupIDs, nil, nil
}

func (r *NBResourceReconciler) handleDelete(ctx context.Context, req ctrl.Request, nbResource netbirdiov1.NBResource) (ctrl.Result, error) {
	if nbResource.Status.NetworkResourceID != nil {
		err := r.netbird.Networks.Resources(nbResource.Spec.NetworkID).Delete(ctx, *nbResource.Status.NetworkResourceID)
		if err != nil && !strings.Contains(err.Error(), "not found") {
			ctrl.Log.Error(fmt.Errorf("netbirdAPIError"), "error deleting resource", "err", err, "namespace", req.Namespace, "name", req.Name)
			return ctrl.Result{}, err
		}

		nbResource.Status.NetworkResourceID = nil
		err = r.Client.Status().Update(ctx, &nbResource)
		if err != nil {
			ctrl.Log.Error(fmt.Errorf("internalError"), "error updating NBResource status", "err", err, "namespace", req.Namespace, "name", req.Name)
			return ctrl.Result{}, err
		}
	}

	nbGroupList := netbirdiov1.NBGroupList{}
	err := r.Client.List(ctx, &nbGroupList, &client.ListOptions{Namespace: req.Namespace})
	if err != nil {
		ctrl.Log.Error(fmt.Errorf("internalError"), "error listing NBGroup", "err", err, "namespace", req.Namespace, "name", req.Name)
		return ctrl.Result{}, err
	}

	for _, g := range nbGroupList.Items {
		if len(g.OwnerReferences) > 0 && g.OwnerReferences[0].UID == nbResource.UID {
			g.Finalizers = util.Without(g.Finalizers, "netbird.io/resource-cleanup")
			err = r.Client.Update(ctx, &g)
			if err != nil && !errors.IsNotFound(err) {
				ctrl.Log.Error(fmt.Errorf("internalError"), "error updating NBGroup", "err", err, "namespace", req.Namespace, "name", req.Name)
				return ctrl.Result{}, err
			}
		}
	}

	nbResource.Finalizers = nil
	err = r.Client.Update(ctx, &nbResource)
	if err != nil {
		ctrl.Log.Error(fmt.Errorf("internalError"), "error updating NBGroup", "err", err, "namespace", req.Namespace, "name", req.Name)
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *NBResourceReconciler) SetupWithManager(mgr ctrl.Manager) error {
	r.netbird = netbird.New(r.ManagementURL, r.APIKey)

	return ctrl.NewControllerManagedBy(mgr).
		For(&netbirdiov1.NBResource{}).
		Named("nbresource").
		Watches(&netbirdiov1.NBGroup{}, handler.EnqueueRequestForOwner(r.Scheme, mgr.GetRESTMapper(), &netbirdiov1.NBResource{})).
		Complete(r)
}
