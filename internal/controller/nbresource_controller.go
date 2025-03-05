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

	"github.com/go-logr/logr"
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
func (r *NBResourceReconciler) Reconcile(ctx context.Context, req ctrl.Request) (res ctrl.Result, err error) {
	logger := ctrl.Log.WithName("NBResource").WithValues("namespace", req.Namespace, "name", req.Name)
	logger.Info("Reconciling NBResource")

	nbResource := &netbirdiov1.NBResource{}
	err = r.Client.Get(ctx, req.NamespacedName, nbResource)
	if err != nil {
		if !errors.IsNotFound(err) {
			logger.Error(errKubernetesAPI, "error getting NBResource", "err", err)
		}
		return ctrl.Result{RequeueAfter: defaultRequeueAfter}, nil
	}

	originalResource := nbResource.DeepCopy()

	defer func() {
		if !originalResource.Status.Equal(nbResource.Status) {
			updateErr := r.Client.Status().Update(ctx, nbResource)
			if updateErr != nil {
				err = updateErr
			}
		}
		if !res.Requeue && res.RequeueAfter == 0 {
			res.RequeueAfter = defaultRequeueAfter
		}
	}()

	if nbResource.DeletionTimestamp != nil {
		if len(nbResource.Finalizers) == 0 {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, r.handleDelete(ctx, req, nbResource, logger)
	}

	groupIDs, result, err := r.handleGroups(ctx, req, nbResource, logger)
	if result != nil {
		nbResource.Status.Conditions = netbirdiov1.NBConditionFalse("internalError", fmt.Sprintf("Error occurred handling groups: %v", err))
		return *result, err
	}

	resource, err := r.handleNetBirdResource(ctx, nbResource, groupIDs, logger)
	if err != nil {
		nbResource.Status.Conditions = netbirdiov1.NBConditionFalse("internalError", fmt.Sprintf("Error occurred handling NetBird Network Resource: %v", err))
		return ctrl.Result{}, err
	}

	// resource is only nil if requeue is expected
	if resource == nil {
		return ctrl.Result{Requeue: true}, nil
	}

	err = r.handleGroupUpdate(ctx, nbResource, groupIDs, resource, logger)
	if err != nil {
		nbResource.Status.Conditions = netbirdiov1.NBConditionFalse("internalError", fmt.Sprintf("Error occurred handling groups: %v", err))
		return ctrl.Result{}, err
	}

	err = r.handlePolicy(ctx, req, nbResource, groupIDs, logger)
	if err != nil {
		nbResource.Status.Conditions = netbirdiov1.NBConditionFalse("internalError", fmt.Sprintf("Error occurred handling policy changes: %v", err))
	}

	nbResource.Status.Conditions = netbirdiov1.NBConditionTrue()

	return ctrl.Result{}, nil
}

// handlePolicy update NBPolicy if defined to add self reference to policy status
func (r *NBResourceReconciler) handlePolicy(ctx context.Context, req ctrl.Request, nbResource *netbirdiov1.NBResource, groupIDs []string, logger logr.Logger) error {
	if nbResource.Status.PolicyName == nil && nbResource.Spec.PolicyName == "" {
		return nil
	}

	updatePolicyStatus := false

	var nbPolicy netbirdiov1.NBPolicy
	if nbResource.Spec.PolicyName == "" && nbResource.Status.PolicyName != nil {
		// Remove self reference from policy status
		nbResource.Status.PolicyName = nil
		err := r.Client.Get(ctx, types.NamespacedName{Name: *nbResource.Status.PolicyName}, &nbPolicy)
		if err != nil {
			logger.Error(errKubernetesAPI, "error getting NBPolicy", "err", err, "policyName", nbResource.Spec.PolicyName)
			return err
		}
		if util.Contains(nbPolicy.Status.ManagedServiceList, req.NamespacedName.String()) {
			nbPolicy.Status.ManagedServiceList = util.Without(nbPolicy.Status.ManagedServiceList, req.NamespacedName.String())
			nbPolicy.Status.LastUpdatedAt = &v1.Time{Time: time.Now()}
			updatePolicyStatus = true
		}
	} else {
		// Update policy settings if any difference is found
		// TODO: Handle updated policy name by removing reference from old policy name in status.policyName
		err := r.Client.Get(ctx, types.NamespacedName{Name: nbResource.Spec.PolicyName}, &nbPolicy)
		if err != nil {
			logger.Error(errKubernetesAPI, "error getting NBPolicy", "err", err, "policyName", nbResource.Spec.PolicyName)
			return err
		}

		if nbResource.Status.PolicyName == nil || *nbResource.Status.PolicyName != nbPolicy.Name {
			nbResource.Status.PolicyName = &nbPolicy.Name
		}

		if !util.Contains(nbPolicy.Status.ManagedServiceList, req.NamespacedName.String()) {
			nbPolicy.Status.ManagedServiceList = append(nbPolicy.Status.ManagedServiceList, req.NamespacedName.String())
			nbPolicy.Status.LastUpdatedAt = &v1.Time{Time: time.Now()}
			updatePolicyStatus = true
		}

		if !util.Equivalent(nbResource.Spec.TCPPorts, nbResource.Status.TCPPorts) {
			nbResource.Status.TCPPorts = nbResource.Spec.TCPPorts
			nbPolicy.Status.LastUpdatedAt = &v1.Time{Time: time.Now()}
			updatePolicyStatus = true
		}

		if !util.Equivalent(nbResource.Spec.UDPPorts, nbResource.Status.UDPPorts) {
			nbResource.Status.UDPPorts = nbResource.Spec.UDPPorts
			nbPolicy.Status.LastUpdatedAt = &v1.Time{Time: time.Now()}
			updatePolicyStatus = true
		}

		if !util.Equivalent(nbResource.Status.Groups, groupIDs) {
			nbResource.Status.Groups = groupIDs
			nbPolicy.Status.LastUpdatedAt = &v1.Time{Time: time.Now()}
			updatePolicyStatus = true
		}
	}

	if updatePolicyStatus {
		err := r.Client.Status().Update(ctx, &nbPolicy)
		if err != nil {
			logger.Error(errKubernetesAPI, "error updating NBPolicy", "err", err, "policyName", nbResource.Spec.PolicyName)
			return err
		}
	}

	return nil
}

// handleGroupUpdate update network resource groups
func (r *NBResourceReconciler) handleGroupUpdate(ctx context.Context, nbResource *netbirdiov1.NBResource, groupIDs []string, resource *api.NetworkResource, logger logr.Logger) error {
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
			Description: &networkDescription,
			Address:     nbResource.Spec.Address,
			Enabled:     true,
			Groups:      groupIDs,
		})

		if err != nil {
			logger.Error(errNetBirdAPI, "error updating resource", "err", err)
			return err
		}
	}

	return nil
}

// handleNetBirdResource sync NetBird Network Resource
func (r *NBResourceReconciler) handleNetBirdResource(ctx context.Context, nbResource *netbirdiov1.NBResource, groupIDs []string, logger logr.Logger) (*api.NetworkResource, error) {
	var resource *api.NetworkResource
	var err error
	if nbResource.Status.NetworkResourceID != nil {
		resource, err = r.netbird.Networks.Resources(nbResource.Spec.NetworkID).Get(ctx, *nbResource.Status.NetworkResourceID)
		if err != nil && !strings.Contains(err.Error(), "not found") {
			logger.Error(errNetBirdAPI, "error getting network resource", "err", err)
			return nil, err
		}
	}

	// Create/Update upstream network resource
	if nbResource.Status.NetworkResourceID == nil && resource == nil {
		resource, err := r.netbird.Networks.Resources(nbResource.Spec.NetworkID).Create(ctx, api.NetworkResourceRequest{
			Address:     nbResource.Spec.Address,
			Enabled:     true,
			Groups:      groupIDs,
			Description: &networkDescription,
			Name:        nbResource.Spec.Name,
		})

		if err != nil {
			logger.Error(errNetBirdAPI, "error creating resource", "err", err)
			return nil, err
		}

		nbResource.Status.NetworkResourceID = &resource.Id
	} else if nbResource.Status.NetworkResourceID == nil && resource != nil {
		nbResource.Status.NetworkResourceID = &resource.Id
	} else if resource == nil {
		// Status remembers networkResourceID but resource was deleted elsewhere
		// remove networkID from status and re-enqueue
		nbResource.Status.NetworkResourceID = nil
	} else {
		resourceGroups := make([]string, 0, len(resource.Groups))
		for _, v := range resource.Groups {
			resourceGroups = append(resourceGroups, v.Id)
		}
		if resource.Address != nbResource.Spec.Address ||
			!resource.Enabled ||
			!util.Equivalent(resourceGroups, groupIDs) ||
			*resource.Description != networkDescription ||
			resource.Name != nbResource.Spec.Name {
			_, err = r.netbird.Networks.Resources(nbResource.Spec.NetworkID).Update(ctx, *nbResource.Status.NetworkResourceID, api.NetworkResourceRequest{
				Address:     nbResource.Spec.Address,
				Enabled:     true,
				Groups:      groupIDs,
				Description: &networkDescription,
				Name:        nbResource.Spec.Name,
			})
			if err != nil {
				return resource, err
			}
		}
	}

	return resource, nil
}

// handleGroups create NBGroup objects for each group specified in NBResource
func (r *NBResourceReconciler) handleGroups(ctx context.Context, req ctrl.Request, nbResource *netbirdiov1.NBResource, logger logr.Logger) ([]string, *ctrl.Result, error) {
	var groupIDs []string

	for _, groupName := range nbResource.Spec.Groups {
		nbGroup := netbirdiov1.NBGroup{}
		groupNameRFC := strings.ToLower(groupName)
		groupNameRFC = strings.ReplaceAll(groupNameRFC, " ", "-")
		err := r.Client.Get(ctx, types.NamespacedName{Namespace: req.Namespace, Name: groupNameRFC}, &nbGroup)
		if err != nil && !errors.IsNotFound(err) {
			logger.Error(errKubernetesAPI, "error getting NBGroup", "err", err)
			return nil, &ctrl.Result{}, err
		} else if errors.IsNotFound(err) {
			// Create NBGroup
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
				logger.Error(errKubernetesAPI, "error creating NBGroup", "err", err)
				return nil, &ctrl.Result{}, err
			}

			continue
		} else {
			// Add NBResource as owner to NBGroup if not already done
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
					logger.Error(errKubernetesAPI, "error updating NBGroup", "err", err)
					return nil, &ctrl.Result{}, err
				}
			}
		}

		if nbGroup.Status.GroupID != nil {
			groupIDs = append(groupIDs, *nbGroup.Status.GroupID)
		}
	}

	// if not all groups are ready, requeue
	if len(groupIDs) != len(nbResource.Spec.Groups) {
		return nil, &ctrl.Result{RequeueAfter: 5 * time.Second}, nil
	}

	return groupIDs, nil, nil
}

func (r *NBResourceReconciler) handleDelete(ctx context.Context, req ctrl.Request, nbResource *netbirdiov1.NBResource, logger logr.Logger) error {
	if nbResource.Status.PolicyName != nil {
		var nbPolicy netbirdiov1.NBPolicy
		err := r.Client.Get(ctx, types.NamespacedName{Name: *nbResource.Status.PolicyName}, &nbPolicy)
		if err != nil && !errors.IsNotFound(err) {
			logger.Error(errKubernetesAPI, "error getting NBPolicy", "err", err, "policyName", nbResource.Spec.PolicyName)
			return err
		}

		if !errors.IsNotFound(err) && util.Contains(nbPolicy.Status.ManagedServiceList, req.NamespacedName.String()) {
			nbPolicy.Status.ManagedServiceList = util.Without(nbPolicy.Status.ManagedServiceList, req.NamespacedName.String())
			nbPolicy.Status.LastUpdatedAt = &v1.Time{Time: time.Now()}
			err = r.Client.Status().Update(ctx, &nbPolicy)
			if err != nil {
				return err
			}
		}
	}

	if nbResource.Status.NetworkResourceID != nil {
		err := r.netbird.Networks.Resources(nbResource.Spec.NetworkID).Delete(ctx, *nbResource.Status.NetworkResourceID)
		if err != nil && !strings.Contains(err.Error(), "not found") {
			logger.Error(errNetBirdAPI, "error deleting resource", "err", err)
			return err
		}

		nbResource.Status.NetworkResourceID = nil
	}

	nbGroupList := netbirdiov1.NBGroupList{}
	err := r.Client.List(ctx, &nbGroupList, &client.ListOptions{Namespace: req.Namespace})
	if err != nil {
		logger.Error(errKubernetesAPI, "error listing NBGroup", "err", err)
		return err
	}

	for _, g := range nbGroupList.Items {
		// TODO: Handle multiple owners
		if len(g.OwnerReferences) > 0 && g.OwnerReferences[0].UID == nbResource.UID {
			g.Finalizers = util.Without(g.Finalizers, "netbird.io/resource-cleanup")
			err = r.Client.Update(ctx, &g)
			if err != nil && !errors.IsNotFound(err) {
				logger.Error(errKubernetesAPI, "error updating NBGroup", "err", err)
				return err
			}
		}
	}

	nbResource.Finalizers = nil
	err = r.Client.Update(ctx, nbResource)
	if err != nil {
		logger.Error(errKubernetesAPI, "error updating NBGroup", "err", err)
		return err
	}

	return nil
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
