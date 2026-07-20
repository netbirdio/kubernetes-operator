// SPDX-License-Identifier: BSD-3-Clause

package controller

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"strings"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	corev1ac "k8s.io/client-go/applyconfigurations/core/v1"
	discoveryv1ac "k8s.io/client-go/applyconfigurations/discovery/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/netbirdio/kube-egress-forwarder/pkg/forwarder"

	nbv1alpha1 "github.com/netbirdio/kubernetes-operator/api/v1alpha1"
	"github.com/netbirdio/kubernetes-operator/internal/k8sutil"
)

const (
	ForwarderRouterNameLabel   = "netbird.io/forwarder-router-name"
	EgressRouterNameLabel      = "netbird.io/egress-router-name"
	EgressRouterNamespaceLabel = "netbird.io/egress-router-namespace"
)

// ForwarderServiceReconciler reconciles a EndpointSlice object
type ForwarderServiceReconciler struct {
	client.Client
}

func (r *ForwarderServiceReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	svc := &corev1.Service{}
	err := r.Get(ctx, req.NamespacedName, svc)
	if err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if !svc.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, nil
	}

	ownerRef, err := k8sutil.ControllerReference(svc, r.Scheme())
	if err != nil {
		return ctrl.Result{}, err
	}

	routerName, ok := svc.Labels[ForwarderRouterNameLabel]
	if !ok {
		return ctrl.Result{}, errors.New("missing forwarder router label")
	}

	// Load port manager state.
	ruleConfigmap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      req.Name,
			Namespace: req.Namespace,
		},
	}
	err = r.Client.Get(ctx, client.ObjectKeyFromObject(ruleConfigmap), ruleConfigmap)
	if err != nil && !kerrors.IsNotFound(err) {
		return ctrl.Result{}, err
	}
	ruleMgr, err := forwarder.NewRuleManager(ruleConfigmap.Data)
	if err != nil {
		return ctrl.Result{}, err
	}

	// Get endpoint slices for forwarder service.
	endpointSliceList := &discoveryv1.EndpointSliceList{}
	err = r.Client.List(ctx, endpointSliceList, &client.MatchingLabels{discoveryv1.LabelServiceName: svc.Name})
	if err != nil {
		return ctrl.Result{}, err
	}

	// Get services for egress resources.
	egressSvcList := &corev1.ServiceList{}
	err = r.Client.List(ctx, egressSvcList, &client.MatchingLabels{EgressRouterNameLabel: routerName, EgressRouterNamespaceLabel: req.Namespace})
	if err != nil {
		return ctrl.Result{}, err
	}

	// Copy router endpoint slices to egress services.
	desired := map[types.NamespacedName]struct{}{}

	for _, egressSvc := range egressSvcList.Items {
		netEgress := &nbv1alpha1.NetworkEgress{
			ObjectMeta: metav1.ObjectMeta{
				Name:      egressSvc.OwnerReferences[0].Name,
				Namespace: egressSvc.Namespace,
			},
		}
		err = r.Get(ctx, client.ObjectKeyFromObject(netEgress), netEgress)
		if err != nil {
			return ctrl.Result{}, err
		}

		targetPorts := []int32{}
		for _, port := range egressSvc.Spec.Ports {
			dest, err := func() (string, error) {
				switch {
				case netEgress.Spec.Target.IP != nil:
					addr, err := netip.ParseAddr(netEgress.Spec.Target.IP.Address)
					if err != nil {
						return "", err
					}
					return netip.AddrPortFrom(addr, uint16(port.Port)).String(), nil
				case netEgress.Spec.Target.FQDN != nil:
					return fmt.Sprintf("%s:%d", netEgress.Spec.Target.FQDN.Hostname, port.Port), nil
				}
				return "", errors.New("egress target not found")
			}()
			if err != nil {
				return ctrl.Result{}, err
			}
			rule := ruleMgr.Allocate(port.Protocol, dest)
			targetPorts = append(targetPorts, rule.Port)
		}
		portACs := toPortApplyConfigurations(egressSvc.Spec.Ports, targetPorts)

		egressSvcOwnerRef, err := k8sutil.ControllerReference(&egressSvc, r.Scheme())
		if err != nil {
			return ctrl.Result{}, err
		}
		for _, endpointSlice := range endpointSliceList.Items {
			nameSuffx := strings.TrimPrefix(endpointSlice.Name, endpointSlice.GenerateName)

			labels := make(map[string]string, len(egressSvc.Labels)+2)
			maps.Copy(labels, egressSvc.Labels)
			labels[discoveryv1.LabelServiceName] = egressSvc.Name
			labels[discoveryv1.LabelManagedBy] = "netbird-operator.netbird.io"

			name := fmt.Sprintf("%s-%s", egressSvc.Name, nameSuffx)
			desired[types.NamespacedName{Namespace: egressSvc.Namespace, Name: name}] = struct{}{}
			endpointACs := toEndpointApplyConfigurations(endpointSlice.Endpoints)
			endpointSliceAC := discoveryv1ac.EndpointSlice(name, egressSvc.Namespace).
				WithLabels(labels).
				WithOwnerReferences(egressSvcOwnerRef).
				WithAddressType(endpointSlice.AddressType).
				WithEndpoints(endpointACs...).
				WithPorts(portACs...)
			err = r.Client.Apply(ctx, endpointSliceAC, client.ForceOwnership)
			if err != nil {
				return ctrl.Result{}, err
			}
		}
	}

	// Write the port config to the port conversion.
	data, err := ruleMgr.Data()
	if err != nil {
		return ctrl.Result{}, err
	}
	cmAC := corev1ac.ConfigMap(req.Name, req.Namespace).
		WithOwnerReferences(ownerRef).
		WithData(data)
	err = r.Client.Apply(ctx, cmAC, client.ForceOwnership)
	if err != nil {
		return ctrl.Result{}, err
	}

	// Cleanup old endpoint slices.
	err = r.Client.List(ctx, endpointSliceList, &client.MatchingLabels{EgressRouterNameLabel: routerName, EgressRouterNamespaceLabel: req.Namespace})
	if err != nil {
		return ctrl.Result{}, err
	}
	for _, item := range endpointSliceList.Items {
		if _, ok := desired[client.ObjectKeyFromObject(&item)]; ok {
			continue
		}
		if err := r.Client.Delete(ctx, &item); err != nil && !kerrors.IsNotFound(err) {
			return ctrl.Result{}, err
		}
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *ForwarderServiceReconciler) SetupWithManager(mgr ctrl.Manager) error {
	forwarderSvcSelector := metav1.LabelSelector{
		MatchExpressions: []metav1.LabelSelectorRequirement{
			{
				Key:      ForwarderRouterNameLabel,
				Operator: metav1.LabelSelectorOpExists,
			},
		},
	}
	forwarderSvcPred, err := predicate.LabelSelectorPredicate(forwarderSvcSelector)
	if err != nil {
		return err
	}

	egressSvcSelector := metav1.LabelSelector{
		MatchExpressions: []metav1.LabelSelectorRequirement{
			{
				Key:      EgressRouterNameLabel,
				Operator: metav1.LabelSelectorOpExists,
			},
			{
				Key:      EgressRouterNamespaceLabel,
				Operator: metav1.LabelSelectorOpExists,
			},
		},
	}
	egressSvcPred, err := predicate.LabelSelectorPredicate(egressSvcSelector)
	if err != nil {
		return err
	}

	return ctrl.NewControllerManagedBy(mgr).
		Named("forwarderservice").
		For(&corev1.Service{}, builder.WithPredicates(forwarderSvcPred)).
		Owns(&discoveryv1.EndpointSlice{}, builder.WithPredicates(forwarderSvcPred)).
		Owns(&corev1.ConfigMap{}).
		Watches(&nbv1alpha1.NetworkEgress{}, handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, obj client.Object) []reconcile.Request {
			imp, ok := obj.(*nbv1alpha1.NetworkEgress)
			if !ok {
				return nil
			}
			return []reconcile.Request{
				{
					NamespacedName: types.NamespacedName{
						Name:      fmt.Sprintf("networkrouter-%s-forwarder", imp.Spec.NetworkRouterRef.Name),
						Namespace: imp.Spec.NetworkRouterRef.Namespace,
					},
				},
			}
		})).
		Watches(&corev1.Service{}, handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, obj client.Object) []reconcile.Request {
			return []reconcile.Request{
				{
					NamespacedName: types.NamespacedName{
						Name:      fmt.Sprintf("networkrouter-%s-forwarder", obj.GetLabels()[EgressRouterNameLabel]),
						Namespace: obj.GetLabels()[EgressRouterNamespaceLabel],
					},
				},
			}
		}), builder.WithPredicates(egressSvcPred)).
		Watches(&discoveryv1.EndpointSlice{}, handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, obj client.Object) []reconcile.Request {
			return []reconcile.Request{
				{
					NamespacedName: types.NamespacedName{
						Name:      fmt.Sprintf("networkrouter-%s-forwarder", obj.GetLabels()[EgressRouterNameLabel]),
						Namespace: obj.GetLabels()[EgressRouterNamespaceLabel],
					},
				},
			}
		}), builder.WithPredicates(egressSvcPred)).
		Complete(r)
}

func toEndpointApplyConfigurations(endpoints []discoveryv1.Endpoint) []*discoveryv1ac.EndpointApplyConfiguration {
	endpointACs := make([]*discoveryv1ac.EndpointApplyConfiguration, 0, len(endpoints))
	for _, endpoint := range endpoints {
		conditionAC := discoveryv1ac.EndpointConditions()
		if endpoint.Conditions.Ready != nil {
			conditionAC.WithReady(*endpoint.Conditions.Ready)
		}
		if endpoint.Conditions.Serving != nil {
			conditionAC.WithServing(*endpoint.Conditions.Serving)
		}
		if endpoint.Conditions.Terminating != nil {
			conditionAC.WithTerminating(*endpoint.Conditions.Terminating)
		}

		endpointAC := discoveryv1ac.Endpoint().
			WithAddresses(endpoint.Addresses...).
			WithConditions(conditionAC)

		if endpoint.NodeName != nil {
			endpointAC = endpointAC.WithNodeName(*endpoint.NodeName)
		}
		if endpoint.Zone != nil {
			endpointAC = endpointAC.WithZone(*endpoint.Zone)
		}
		if endpoint.Hints != nil {
			hintAC := discoveryv1ac.EndpointHints()
			for _, hint := range endpoint.Hints.ForNodes {
				hintAC = hintAC.WithForNodes(discoveryv1ac.ForNode().WithName(hint.Name))
			}
			for _, hint := range endpoint.Hints.ForZones {
				hintAC = hintAC.WithForZones(discoveryv1ac.ForZone().WithName(hint.Name))
			}
			endpointAC = endpointAC.WithHints(hintAC)
		}
		if endpoint.TargetRef != nil {
			endpointAC = endpointAC.WithTargetRef(corev1ac.ObjectReference().
				WithResourceVersion(endpoint.TargetRef.ResourceVersion).
				WithFieldPath(endpoint.TargetRef.FieldPath).
				WithUID(endpoint.TargetRef.UID).
				WithAPIVersion(endpoint.TargetRef.APIVersion).
				WithKind(endpoint.TargetRef.Kind).
				WithName(endpoint.TargetRef.Name).
				WithNamespace(endpoint.TargetRef.Namespace),
			)
		}

		endpointACs = append(endpointACs, endpointAC)
	}
	return endpointACs
}

func toPortApplyConfigurations(ports []corev1.ServicePort, targetPorts []int32) []*discoveryv1ac.EndpointPortApplyConfiguration {
	portACs := make([]*discoveryv1ac.EndpointPortApplyConfiguration, 0, len(ports))
	for i, port := range ports {
		portAC := discoveryv1ac.EndpointPort().WithName(port.Name).WithPort(targetPorts[i]).WithProtocol(port.Protocol)
		if port.AppProtocol != nil {
			portAC = portAC.WithAppProtocol(*port.AppProtocol)
		}
		portACs = append(portACs, portAC)
	}
	return portACs
}
