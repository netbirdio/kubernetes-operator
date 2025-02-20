package controller

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	netbirdiov1 "github.com/netbirdio/kubernetes-operator/api/v1"
	"github.com/netbirdio/kubernetes-operator/internal/util"
	netbird "github.com/netbirdio/netbird/management/client/rest"
	"github.com/netbirdio/netbird/management/server/http/api"
)

// NBPolicyReconciler reconciles a NBPolicy object
type NBPolicyReconciler struct {
	client.Client
	Scheme        *runtime.Scheme
	ClusterName   string
	APIKey        string
	ManagementURL string
	netbird       *netbird.Client
}

var (
	errUnknownProtocol = fmt.Errorf("Unknown protocol")
	errKubernetesAPI   = fmt.Errorf("kubernetes API error")
	errNetBirdAPI      = fmt.Errorf("netbird API error")
)

func (r *NBPolicyReconciler) getResources(ctx context.Context, nbPolicy *netbirdiov1.NBPolicy) ([]netbirdiov1.NBResource, error) {
	var resourceList []netbirdiov1.NBResource
	var updatedManagedServiceList []string
	for _, rss := range nbPolicy.Status.ManagedServiceList {
		var resource netbirdiov1.NBResource
		namespacedName := types.NamespacedName{Namespace: strings.Split(rss, "/")[0], Name: strings.Split(rss, "/")[1]}
		err := r.Client.Get(ctx, namespacedName, &resource)
		if err != nil && !errors.IsNotFound(err) {
			ctrl.Log.Error(errKubernetesAPI, "Error getting NBResource", "namespace", namespacedName.Namespace, "name", namespacedName.Name)
			nbPolicy.Status.Conditions = netbirdiov1.NBConditionFalse("internalError", fmt.Sprintf("Error getting NBResource: %v", err))
			return nil, err
		}
		if err == nil && resource.DeletionTimestamp == nil {
			updatedManagedServiceList = append(updatedManagedServiceList, rss)
			resourceList = append(resourceList, resource)
		}
	}

	nbPolicy.Status.ManagedServiceList = updatedManagedServiceList

	return resourceList, nil
}

func (r *NBPolicyReconciler) mapResources(ctx context.Context, req ctrl.Request, nbPolicy *netbirdiov1.NBPolicy, resources []netbirdiov1.NBResource) (map[string][]int32, []string, error) {
	portMapping := map[string]map[int32]interface{}{
		"tcp": make(map[int32]interface{}),
		"udp": make(map[int32]interface{}),
	}
	groups, err := r.groupNamesToIDs(ctx, req, nbPolicy.Spec.DestinationGroups)
	if err != nil {
		return nil, nil, err
	}

	for _, resource := range resources {
		if resource.Status.PolicyName != nil && *resource.Status.PolicyName == nbPolicy.Name {
			// Groups
			groups = append(groups, resource.Status.Groups...)

			for _, p := range resource.Spec.TCPPorts {
				portMapping["tcp"][p] = nil
			}
			for _, p := range resource.Spec.UDPPorts {
				portMapping["udp"][p] = nil
			}
		}
	}

	ports := make(map[string][]int32)
	for k, vs := range portMapping {
		for v := range vs {
			ports[k] = append(ports[k], v)
		}
	}

	return ports, groups, nil
}

func (r *NBPolicyReconciler) createPolicy(ctx context.Context, req ctrl.Request, nbPolicy *netbirdiov1.NBPolicy, protocol string, sourceGroupIDs, destinationGroupIDs, ports []string) (*string, error) {
	policyName := fmt.Sprintf("%s %s", nbPolicy.Spec.Name, strings.ToUpper(protocol))
	ctrl.Log.Info("Creating NetBird Policy", "name", policyName, "description", nbPolicy.Spec.Description, "protocol", protocol, "sources", sourceGroupIDs, "destinations", destinationGroupIDs, "ports", ports, "bidirectional", nbPolicy.Spec.Bidirectional)
	policy, err := r.netbird.Policies.Create(ctx, api.PostApiPoliciesJSONRequestBody{
		Enabled:     true,
		Name:        policyName,
		Description: &nbPolicy.Spec.Description,
		Rules: []api.PolicyRuleUpdate{
			{
				Enabled:       true,
				Name:          policyName,
				Description:   &nbPolicy.Spec.Description,
				Action:        api.PolicyRuleUpdateActionAccept,
				Protocol:      api.PolicyRuleUpdateProtocol(protocol),
				Bidirectional: nbPolicy.Spec.Bidirectional,
				Sources:       &sourceGroupIDs,
				Destinations:  &destinationGroupIDs,
				Ports:         &ports,
			},
		},
	})

	if err != nil {
		ctrl.Log.Error(errNetBirdAPI, "Error creating Policy", "namespace", req.Namespace, "name", req.Name, "err", err)
		nbPolicy.Status.Conditions = netbirdiov1.NBConditionFalse("APIError", fmt.Sprintf("Error creating policy: %v", err))
		return nil, err
	}

	return policy.Id, nil
}

func (r *NBPolicyReconciler) updatePolicy(ctx context.Context, req ctrl.Request, policyID *string, nbPolicy *netbirdiov1.NBPolicy, protocol string, sourceGroupIDs, destinationGroupIDs, ports []string) (*string, bool, error) {
	policyName := fmt.Sprintf("%s %s", nbPolicy.Spec.Name, strings.ToUpper(protocol))
	ctrl.Log.Info("Updating NetBird Policy", "name", policyName, "description", nbPolicy.Spec.Description, "protocol", protocol, "sources", sourceGroupIDs, "destinations", destinationGroupIDs, "ports", ports, "bidirectional", nbPolicy.Spec.Bidirectional)
	policy, err := r.netbird.Policies.Update(ctx, *policyID, api.PutApiPoliciesPolicyIdJSONRequestBody{
		Enabled:     true,
		Name:        policyName,
		Description: &nbPolicy.Spec.Description,
		Rules: []api.PolicyRuleUpdate{
			{
				Enabled:       true,
				Name:          policyName,
				Description:   &nbPolicy.Spec.Description,
				Action:        api.PolicyRuleUpdateActionAccept,
				Protocol:      api.PolicyRuleUpdateProtocol(protocol),
				Bidirectional: nbPolicy.Spec.Bidirectional,
				Sources:       &sourceGroupIDs,
				Destinations:  &destinationGroupIDs,
				Ports:         &ports,
			},
		},
	})

	if err != nil && !strings.Contains(err.Error(), "not found") {
		ctrl.Log.Error(errNetBirdAPI, "Error updating Policy", "namespace", req.Namespace, "name", req.Name, "err", err)
		nbPolicy.Status.Conditions = netbirdiov1.NBConditionFalse("APIError", fmt.Sprintf("Error updating policy: %v", err))
		return policyID, false, err
	}

	requeue := false

	if err != nil && strings.Contains(err.Error(), "not found") {
		ctrl.Log.Info("Policy deleted from NetBird API, recreating", "namespace", req.Namespace, "name", req.Name, "protocol", protocol)
		policyID = nil
		requeue = true
		nbPolicy.Status.Conditions = netbirdiov1.NBConditionFalse("Gone", "Policy deleted from NetBird API")
	}

	if err == nil && (policyID == nil || *policy.Id != *policyID) {
		policyID = policy.Id
	}
	return policyID, requeue, nil
}

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
func (r *NBPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (res ctrl.Result, err error) {
	_ = log.FromContext(ctx)

	ctrl.Log.Info("NBPolicy: Reconciling", "namespace", req.Namespace, "name", req.Name)

	var nbPolicy netbirdiov1.NBPolicy
	err = r.Client.Get(ctx, req.NamespacedName, &nbPolicy)
	if err != nil {
		if errors.IsNotFound(err) {
			err = nil
		}
		if err != nil {
			ctrl.Log.Error(errKubernetesAPI, "error getting NBPolicy", "err", err, "namespace", req.Namespace, "name", req.Name)
		}
		return ctrl.Result{RequeueAfter: defaultRequeueAfter}, err
	}

	originalPolicy := nbPolicy.DeepCopy()

	defer func() {
		if !originalPolicy.Status.Equal(nbPolicy.Status) {
			updateErr := r.Client.Status().Update(ctx, &nbPolicy)
			if updateErr != nil {
				err = updateErr
			}
		}
		if !res.Requeue && res.RequeueAfter == 0 {
			res.RequeueAfter = defaultRequeueAfter
		}
	}()

	if nbPolicy.DeletionTimestamp != nil {
		if len(nbPolicy.Finalizers) == 0 {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, r.handleDelete(ctx, req, nbPolicy)
	}

	resourceList, err := r.getResources(ctx, &nbPolicy)
	if err != nil {
		return ctrl.Result{}, err
	}

	portMapping, destGroups, err := r.mapResources(ctx, req, &nbPolicy, resourceList)
	if err != nil {
		return ctrl.Result{}, err
	}

	sourceGroupIDs, err := r.groupNamesToIDs(ctx, req, nbPolicy.Spec.SourceGroups)
	if err != nil {
		nbPolicy.Status.Conditions = netbirdiov1.NBConditionFalse("APIError", fmt.Sprintf("Error getting group IDs: %v", err))
		return ctrl.Result{}, err
	}

	requeue, err := r.handlePolicies(ctx, req, &nbPolicy, sourceGroupIDs, destGroups, portMapping)

	if requeue || err != nil {
		return ctrl.Result{Requeue: requeue}, err
	}

	nbPolicy.Status.Conditions = netbirdiov1.NBConditionTrue()

	return ctrl.Result{}, nil
}

func (r *NBPolicyReconciler) handlePolicies(ctx context.Context, req ctrl.Request, nbPolicy *netbirdiov1.NBPolicy, sourceGroups, destGroups []string, portMapping map[string][]int32) (bool, error) {
	requeue := false

	for protocol, ports := range portMapping {
		var policyID *string
		switch protocol {
		case "tcp":
			policyID = nbPolicy.Status.TCPPolicyID
		case "udp":
			policyID = nbPolicy.Status.UDPPolicyID
		default:
			ctrl.Log.Error(errKubernetesAPI, "Unknown protocol", "namespace", req.Namespace, "name", req.Name, "protocol", protocol)
			nbPolicy.Status.Conditions = netbirdiov1.NBConditionFalse("ConfigError", fmt.Sprintf("Unknown protocol: %s", protocol))
			return requeue, errUnknownProtocol
		}

		if len(nbPolicy.Spec.Protocols) > 0 && !util.Contains(nbPolicy.Spec.Protocols, protocol) {
			if policyID != nil {
				ctrl.Log.Info("Deleting protocol policy as NBPolicy has restricted protocols", "protocol", protocol)
				err := r.netbird.Policies.Delete(ctx, *policyID)
				if err != nil && !strings.Contains(err.Error(), "not found") {
					nbPolicy.Status.Conditions = netbirdiov1.NBConditionFalse("APIError", fmt.Sprintf("Error deleting policy: %v", err))
					return requeue, err
				}
				policyID = nil

			} else {
				ctrl.Log.Info("Ignoring protocol as NBPolicy has restricted protocols", "protocol", protocol)
			}
		} else if len(ports) == 0 && policyID == nil {
			ctrl.Log.Info("0 ports found for protocol in policy", "namespace", req.Namespace, "name", req.Name, "protocol", protocol)
			continue
		} else if len(destGroups) == 0 && policyID == nil {
			ctrl.Log.Info("no destinations found for protocol in policy", "namespace", req.Namespace, "name", req.Name, "protocol", protocol)
			continue
		} else if len(sourceGroups) == 0 && policyID == nil {
			ctrl.Log.Info("no sources found for protocol in policy", "namespace", req.Namespace, "name", req.Name, "protocol", protocol)
			continue
		} else if len(ports) == 0 || len(destGroups) == 0 || len(sourceGroups) == 0 {
			// Delete policy
			ctrl.Log.Info("Deleting policy", "namespace", req.Namespace, "name", req.Name, "protocol", protocol)
			err := r.netbird.Policies.Delete(ctx, *policyID)
			if err != nil && !strings.Contains(err.Error(), "not found") {
				nbPolicy.Status.Conditions = netbirdiov1.NBConditionFalse("APIError", fmt.Sprintf("Error deleting policy: %v", err))
				return requeue, err
			}
			policyID = nil
		} else {
			var stringPorts []string
			for _, v := range ports {
				stringPorts = append(stringPorts, strconv.FormatInt(int64(v), 10))
			}
			for _, v := range nbPolicy.Spec.Ports {
				stringPorts = append(stringPorts, strconv.FormatInt(int64(v), 10))
			}

			var err error
			if policyID == nil {
				policyID, err = r.createPolicy(ctx, req, nbPolicy, protocol, sourceGroups, destGroups, stringPorts)
			} else {
				policyID, requeue, err = r.updatePolicy(ctx, req, policyID, nbPolicy, protocol, sourceGroups, destGroups, stringPorts)
			}
			if err != nil {
				return requeue, err
			}
		}

		switch protocol {
		case "tcp":
			nbPolicy.Status.TCPPolicyID = policyID
		case "udp":
			nbPolicy.Status.UDPPolicyID = policyID
		default:
			ctrl.Log.Error(errKubernetesAPI, "Unknown protocol", "namespace", req.Namespace, "name", req.Name, "protocol", protocol)
			nbPolicy.Status.Conditions = netbirdiov1.NBConditionFalse("ConfigError", fmt.Sprintf("Unknown protocol: %s", protocol))
			return requeue, errUnknownProtocol
		}
	}

	return requeue, nil
}

func (r *NBPolicyReconciler) handleDelete(ctx context.Context, req ctrl.Request, nbPolicy netbirdiov1.NBPolicy) error {
	if nbPolicy.Status.TCPPolicyID != nil {
		err := r.netbird.Policies.Delete(ctx, *nbPolicy.Status.TCPPolicyID)
		if err != nil {
			return err
		}
		nbPolicy.Status.TCPPolicyID = nil
	}
	if nbPolicy.Status.UDPPolicyID != nil {
		err := r.netbird.Policies.Delete(ctx, *nbPolicy.Status.UDPPolicyID)
		if err != nil {
			return err
		}
		nbPolicy.Status.UDPPolicyID = nil
	}
	if util.Contains(nbPolicy.Finalizers, "netbird.io/cleanup") {
		nbPolicy.Finalizers = util.Without(nbPolicy.Finalizers, "netbird.io/cleanup")
		err := r.Client.Update(ctx, &nbPolicy)
		if err != nil {
			ctrl.Log.Error(errKubernetesAPI, "Error updating NBPolicy", "namespace", req.Namespace, "name", req.Name, "err", err)
			return err
		}
	}
	return nil
}

func (r *NBPolicyReconciler) groupNamesToIDs(ctx context.Context, req ctrl.Request, groupNames []string) ([]string, error) {
	groups, err := r.netbird.Groups.List(ctx)
	if err != nil {
		ctrl.Log.Error(errNetBirdAPI, "Error listing Groups", "namespace", req.Namespace, "name", req.Name, "err", err)
		return nil, err
	}

	groupNameIDMapping := make(map[string]string)
	for _, g := range groups {
		groupNameIDMapping[g.Name] = g.Id
	}

	ret := make([]string, 0, len(groupNames))
	for _, g := range groupNames {
		ret = append(ret, groupNameIDMapping[g])
	}

	return ret, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *NBPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	r.netbird = netbird.New(r.ManagementURL, r.APIKey)

	return ctrl.NewControllerManagedBy(mgr).
		For(&netbirdiov1.NBPolicy{}).
		Named("nbpolicy").
		Complete(r)
}
