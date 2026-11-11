// SPDX-License-Identifier: BSD-3-Clause

package controller

import (
	"cmp"
	"context"
	"slices"
	"strconv"
	"time"

	"github.com/fluxcd/pkg/runtime/conditions"
	"github.com/fluxcd/pkg/runtime/patch"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	netbird "github.com/netbirdio/netbird/shared/management/client/rest"
	"github.com/netbirdio/netbird/shared/management/http/api"

	nbv1alpha1 "github.com/netbirdio/kubernetes-operator/api/v1alpha1"
	"github.com/netbirdio/kubernetes-operator/internal/k8sutil"
	"github.com/netbirdio/kubernetes-operator/internal/netbirdutil"
)

// PolicyReconciler reconciles a Policy object into a Netbird policy with a single rule.
type PolicyReconciler struct {
	client.Client

	Netbird *netbird.Client
}

// +kubebuilder:rbac:groups=netbird.io,resources=policies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=netbird.io,resources=policies/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=netbird.io,resources=policies/finalizers,verbs=update

// Reconcile creates or updates the Netbird policy for a Policy, and deletes it when the
// Policy is deleted.
func (r *PolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	policy := &nbv1alpha1.Policy{}
	err := r.Get(ctx, req.NamespacedName, policy)
	if err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	sp := patch.NewSerialPatcher(policy, r.Client)

	if !policy.DeletionTimestamp.IsZero() {
		return r.reconcileDelete(ctx, sp, policy)
	}

	sourceIDs, err := netbirdutil.GetGroupIDs(ctx, r.Client, r.Netbird, policy.Spec.SourceGroups, policy.Namespace)
	if err != nil {
		return ctrl.Result{}, err
	}
	destinationIDs, err := netbirdutil.GetGroupIDs(ctx, r.Client, r.Netbird, policy.Spec.DestinationGroups, policy.Namespace)
	if err != nil {
		return ctrl.Result{}, err
	}

	controllerutil.AddFinalizer(policy, k8sutil.Finalizer("policy"))
	err = sp.Patch(ctx, policy)
	if err != nil {
		return ctrl.Result{}, err
	}

	policyReq := policyRequest(policy, sourceIDs, destinationIDs)
	policyID, err := func() (string, error) {
		if policy.Status.PolicyID != "" {
			policyResp, err := r.Netbird.Policies.Get(ctx, policy.Status.PolicyID)
			if err != nil && !netbird.IsNotFound(err) {
				return "", err
			}
			if err == nil {
				// Every update makes Netbird recompute and push the network map to all
				// peers, so a policy that already matches is left alone.
				if policyMatches(policyResp, policyReq) {
					return policy.Status.PolicyID, nil
				}
				resp, err := r.Netbird.Policies.Update(ctx, policy.Status.PolicyID, api.PolicyCreate(policyReq))
				if err != nil && !netbird.IsNotFound(err) {
					return "", err
				}
				if err == nil {
					return *resp.Id, nil
				}
			}
		}
		resp, err := r.Netbird.Policies.Create(ctx, policyReq)
		if err != nil {
			return "", err
		}
		return *resp.Id, nil
	}()
	if err != nil {
		return ctrl.Result{}, err
	}
	policy.Status.PolicyID = policyID

	conditions.MarkTrue(policy, nbv1alpha1.ReadyCondition, nbv1alpha1.ReconciledReason, "")
	err = sp.Patch(ctx, policy, patch.WithStatusObservedGeneration{})
	if err != nil {
		return ctrl.Result{}, err
	}
	// Requeue to revert changes made to the policy outside the cluster.
	return ctrl.Result{RequeueAfter: 15 * time.Minute}, nil
}

// reconcileDelete deletes the Netbird policy and removes the finalizer.
func (r *PolicyReconciler) reconcileDelete(ctx context.Context, sp *patch.SerialPatcher, policy *nbv1alpha1.Policy) (ctrl.Result, error) {
	if policy.Status.PolicyID != "" {
		err := r.Netbird.Policies.Delete(ctx, policy.Status.PolicyID)
		if err != nil && !netbird.IsNotFound(err) {
			return ctrl.Result{}, err
		}
	}

	controllerutil.RemoveFinalizer(policy, k8sutil.Finalizer("policy"))
	err := sp.Patch(ctx, policy)
	if err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

// policyRequest builds the Netbird policy for the spec, with its single rule named
// after the policy.
func policyRequest(policy *nbv1alpha1.Policy, sourceIDs, destinationIDs []string) api.PolicyUpdate {
	enabled := policy.Spec.Enabled == nil || *policy.Spec.Enabled
	action := cmp.Or(policy.Spec.Action, string(api.PolicyRuleUpdateActionAccept))
	protocol := cmp.Or(policy.Spec.Protocol, string(api.PolicyRuleUpdateProtocolAll))

	rule := api.PolicyRuleUpdate{
		Name:          policy.Spec.Name,
		Enabled:       enabled,
		Action:        api.PolicyRuleUpdateAction(action),
		Bidirectional: policy.Spec.Bidirectional,
		Protocol:      api.PolicyRuleUpdateProtocol(protocol),
		Sources:       &sourceIDs,
		Destinations:  &destinationIDs,
	}
	if len(policy.Spec.Ports) > 0 {
		ports := make([]string, 0, len(policy.Spec.Ports))
		for _, port := range policy.Spec.Ports {
			ports = append(ports, strconv.Itoa(int(port)))
		}
		rule.Ports = &ports
	}
	if len(policy.Spec.PortRanges) > 0 {
		portRanges := make([]api.RulePortRange, 0, len(policy.Spec.PortRanges))
		for _, portRange := range policy.Spec.PortRanges {
			portRanges = append(portRanges, api.RulePortRange{Start: int(portRange.Start), End: int(portRange.End)})
		}
		rule.PortRanges = &portRanges
	}

	req := api.PolicyUpdate{
		Name:    policy.Spec.Name,
		Enabled: enabled,
		Rules:   []api.PolicyRuleUpdate{rule},
	}
	if policy.Spec.Description != "" {
		req.Description = new(policy.Spec.Description)
	}
	return req
}

// policyMatches reports whether the Netbird policy already is what the request asks for.
// Group order and the way ports are written (a port or a range of one) do not count.
func policyMatches(policy *api.Policy, req api.PolicyUpdate) bool {
	if policy.Name != req.Name || policy.Enabled != req.Enabled || deref(policy.Description) != deref(req.Description) {
		return false
	}
	if len(policy.Rules) != 1 || len(req.Rules) != 1 {
		return false
	}
	got, want := policy.Rules[0], req.Rules[0]
	return got.Name == want.Name &&
		got.Enabled == want.Enabled &&
		string(got.Action) == string(want.Action) &&
		got.Bidirectional == want.Bidirectional &&
		string(got.Protocol) == string(want.Protocol) &&
		slices.Equal(groupIDs(got.Sources), sortedIDs(want.Sources)) &&
		slices.Equal(groupIDs(got.Destinations), sortedIDs(want.Destinations)) &&
		slices.Equal(portRanges(got.Ports, got.PortRanges), portRanges(want.Ports, want.PortRanges))
}

// deref returns the string s points to, or "" if s is nil.
func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// groupIDs returns the sorted IDs of the groups.
func groupIDs(groups *[]api.GroupMinimum) []string {
	ids := []string{}
	if groups != nil {
		for _, g := range *groups {
			ids = append(ids, g.Id)
		}
	}
	slices.Sort(ids)
	return ids
}

// sortedIDs returns a sorted copy of the IDs.
func sortedIDs(ids *[]string) []string {
	sorted := []string{}
	if ids != nil {
		sorted = append(sorted, *ids...)
	}
	slices.Sort(sorted)
	return sorted
}

// portRanges merges ports and port ranges into a sorted list of ranges, a port being a
// range of one.
func portRanges(ports *[]string, ranges *[]api.RulePortRange) []api.RulePortRange {
	merged := []api.RulePortRange{}
	if ports != nil {
		for _, p := range *ports {
			port, err := strconv.Atoi(p)
			if err != nil {
				continue
			}
			merged = append(merged, api.RulePortRange{Start: port, End: port})
		}
	}
	if ranges != nil {
		merged = append(merged, *ranges...)
	}
	slices.SortFunc(merged, func(a, b api.RulePortRange) int {
		return cmp.Or(cmp.Compare(a.Start, b.Start), cmp.Compare(a.End, b.End))
	})
	return slices.Compact(merged)
}

// SetupWithManager sets up the controller with the Manager.
func (r *PolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// Status updates do not change the generation, so they never trigger a new pass.
	return ctrl.NewControllerManagedBy(mgr).
		For(&nbv1alpha1.Policy{}, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Complete(r)
}
