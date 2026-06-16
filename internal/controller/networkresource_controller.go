// SPDX-License-Identifier: BSD-3-Clause

package controller

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/fluxcd/pkg/runtime/conditions"
	"github.com/fluxcd/pkg/runtime/patch"
	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	netbird "github.com/netbirdio/netbird/shared/management/client/rest"
	"github.com/netbirdio/netbird/shared/management/http/api"

	nbv1alpha1 "github.com/netbirdio/kubernetes-operator/api/v1alpha1"
	"github.com/netbirdio/kubernetes-operator/internal/k8sutil"
	"github.com/netbirdio/kubernetes-operator/internal/netbirdutil"
)

type NetworkResourceReconciler struct {
	client.Client

	Netbird *netbird.Client
}

// +kubebuilder:rbac:groups=netbird.io,resources=networkresources,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=netbird.io,resources=networkresources/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=netbird.io,resources=networkresources/finalizers,verbs=update

// nolint:gocyclo
func (r *NetworkResourceReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	netResource := &nbv1alpha1.NetworkResource{}
	err := r.Get(ctx, req.NamespacedName, netResource)
	if err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	sp := patch.NewSerialPatcher(netResource, r.Client)

	if !netResource.DeletionTimestamp.IsZero() {
		return r.reconcileDelete(ctx, sp, netResource)
	}

	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      netResource.Spec.ServiceRef.Name,
			Namespace: netResource.Namespace,
		},
	}
	err = r.Get(ctx, client.ObjectKeyFromObject(svc), svc)
	if err != nil {
		if kerrors.IsNotFound(err) {
			conditions.MarkFalse(netResource, nbv1alpha1.ReadyCondition, nbv1alpha1.DependencyReason, "Referenced Service cannot be found.")
			err = sp.Patch(ctx, netResource)
			if err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}
	if svc.Spec.Type != corev1.ServiceTypeClusterIP {
		conditions.MarkFalse(netResource, nbv1alpha1.ReadyCondition, nbv1alpha1.DependencyReason, "Referenced Service is not of type ClusterIP.")
		err = sp.Patch(ctx, netResource)
		if err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}
	if svc.Spec.ClusterIP == "" || svc.Spec.ClusterIP == corev1.ClusterIPNone {
		conditions.MarkFalse(netResource, nbv1alpha1.ReadyCondition, nbv1alpha1.DependencyReason, "Referenced Service does not have a ClusterIP set.")
		err = sp.Patch(ctx, netResource)
		if err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	netRouter := &nbv1alpha1.NetworkRouter{
		ObjectMeta: metav1.ObjectMeta{
			Name:      netResource.Spec.NetworkRouterRef.Name,
			Namespace: netResource.Spec.NetworkRouterRef.Namespace,
		},
	}
	err = r.Get(ctx, client.ObjectKeyFromObject(netRouter), netRouter)
	if err != nil {
		if kerrors.IsNotFound(err) {
			conditions.MarkFalse(netResource, nbv1alpha1.ReadyCondition, nbv1alpha1.DependencyReason, "Referenced NetworkRouter cannot be found.")
			err = sp.Patch(ctx, netResource)
			if err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}
	if netRouter.Status.NetworkID == "" || netRouter.Status.RoutingPeerID == "" {
		conditions.MarkFalse(netResource, nbv1alpha1.ReadyCondition, nbv1alpha1.DependencyReason, "Referenced NetworkRouter is not ready.")
		err = sp.Patch(ctx, netResource)
		if err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	groupIDs, err := netbirdutil.GetGroupIDs(ctx, r.Client, r.Netbird, netResource.Spec.Groups, netResource.Namespace)
	if err != nil {
		return ctrl.Result{}, err
	}

	controllerutil.AddFinalizer(netResource, k8sutil.Finalizer("networkresource"))

	resourceID, err := func() (string, error) {
		netReq := api.NetworkResourceRequest{
			Name:        string(netResource.UID),
			Description: new(svc.Name + "/" + svc.Namespace),
			Address:     svc.Spec.ClusterIP,
			Enabled:     true,
			Groups:      groupIDs,
		}
		if netResource.Status.ResourceID != "" {
			netResp, err := r.Netbird.Networks.Resources(netRouter.Status.NetworkID).Update(ctx, netResource.Status.ResourceID, netReq)
			if err != nil && !netbird.IsNotFound(err) {
				return "", err
			}
			if err == nil {
				return netResp.Id, nil
			}
		}
		netResp, err := r.Netbird.Networks.Resources(netRouter.Status.NetworkID).Create(ctx, netReq)
		if err != nil {
			return "", err
		}
		return netResp.Id, nil
	}()
	if err != nil {
		return ctrl.Result{}, err
	}
	netResource.Status.NetworkID = netRouter.Status.NetworkID
	netResource.Status.ResourceID = resourceID
	err = sp.Patch(ctx, netResource)
	if err != nil {
		return ctrl.Result{}, err
	}

	// Create DNS records for the resource: an A per IPv4 ClusterIP and an AAAA
	// per IPv6 ClusterIP. The record name is built from the zone's Domain (the
	// FQDN), not its Name identifier, so records sit within the zone.
	zone, err := netbirdutil.GetDNSZoneByName(ctx, r.Netbird, netRouter.Spec.DNSZoneRef.Name)
	if err != nil {
		return ctrl.Result{}, err
	}
	fqdn := strings.Join([]string{svc.Name, svc.Namespace, zone.Domain}, ".")
	if err := r.reconcileDNSRecords(ctx, sp, netResource, zone, fqdn, clusterIPsOf(svc)); err != nil {
		return ctrl.Result{}, err
	}

	conditions.MarkTrue(netResource, nbv1alpha1.ReadyCondition, nbv1alpha1.ReconciledReason, "")
	err = sp.Patch(ctx, netResource, patch.WithStatusObservedGeneration{})
	if err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

// clusterIPsOf returns the Service's dualstack ClusterIPs, falling back to the
// single ClusterIP for older API objects.
func clusterIPsOf(svc *corev1.Service) []string {
	if len(svc.Spec.ClusterIPs) > 0 {
		return svc.Spec.ClusterIPs
	}
	return []string{svc.Spec.ClusterIP}
}

// recordMatchKey builds a comparison key for a DNS record that is stable across
// the multiple textual forms of an IP. An IPv6 address has several
// representations (e.g. "2001:db8::1" vs "2001:0db8:0:0:0:0:0:1"); if NetBird
// stores a record in a different canonical form than the Service's ClusterIP
// string, a raw-string compare would miss the match and the record would be
// deleted and recreated (hitting "identical record already exists"). Comparing
// the canonicalized IP avoids that.
func recordMatchKey(recordType, content string) string {
	if ip := net.ParseIP(content); ip != nil {
		content = ip.String()
	}
	return recordType + "|" + content
}

// reconcileDNSRecords ensures the zone holds one A record per IPv4 and one AAAA
// per IPv6 ClusterIP at fqdn. It reconciles against the zone's *live* records
// (via ListRecords), adopting any that already exist by name+type+content, so a
// status that has drifted from NetBird can't cause a duplicate create
// ("identical record already exists") or a spurious delete. Only stale records
// at this exact fqdn are removed; records under other names are untouched.
func (r *NetworkResourceReconciler) reconcileDNSRecords(ctx context.Context, sp *patch.SerialPatcher, netResource *nbv1alpha1.NetworkResource, zone api.Zone, fqdn string, clusterIPs []string) error {
	type desiredRecord struct {
		rType   api.DNSRecordType
		content string
	}
	var desired []desiredRecord
	for _, ip := range clusterIPs {
		parsed := net.ParseIP(ip)
		if parsed == nil {
			continue
		}
		if parsed.To4() != nil {
			desired = append(desired, desiredRecord{api.DNSRecordTypeA, ip})
		} else {
			desired = append(desired, desiredRecord{api.DNSRecordTypeAAAA, ip})
		}
	}

	// On a zone change, drop records tracked in the old zone first.
	if netResource.Status.DNSZoneID != "" && netResource.Status.DNSZoneID != zone.Id {
		for _, rec := range netResource.Status.DNSRecords {
			if err := r.Netbird.DNSZones.DeleteRecord(ctx, netResource.Status.DNSZoneID, rec.ID); err != nil && !netbird.IsNotFound(err) {
				return err
			}
		}
		if netResource.Status.DNSRecordID != "" {
			if err := r.Netbird.DNSZones.DeleteRecord(ctx, netResource.Status.DNSZoneID, netResource.Status.DNSRecordID); err != nil && !netbird.IsNotFound(err) {
				return err
			}
		}
		netResource.Status.DNSRecords = nil
		netResource.Status.DNSRecordID = ""
		netResource.Status.DNSZoneID = ""
	}

	// Clean up the legacy single A record (its name used the zone identifier,
	// not the domain) now that records are managed as a set under fqdn.
	if netResource.Status.DNSRecordID != "" {
		if err := r.Netbird.DNSZones.DeleteRecord(ctx, zone.Id, netResource.Status.DNSRecordID); err != nil && !netbird.IsNotFound(err) {
			return err
		}
		netResource.Status.DNSRecordID = ""
	}

	// Index the zone's live records that belong to this resource (name == fqdn),
	// so we can adopt existing ones rather than creating duplicates.
	zoneRecords, err := r.Netbird.DNSZones.ListRecords(ctx, zone.Id)
	if err != nil {
		return err
	}
	existing := map[string]api.DNSRecord{}
	var ours []api.DNSRecord
	for _, rec := range zoneRecords {
		if rec.Name != fqdn {
			continue
		}
		ours = append(ours, rec)
		existing[recordMatchKey(string(rec.Type), rec.Content)] = rec
	}

	kept := make([]nbv1alpha1.DNSRecordStatus, 0, len(desired))
	desiredKeys := map[string]bool{}
	for _, d := range desired {
		key := recordMatchKey(string(d.rType), d.content)
		desiredKeys[key] = true
		if cur, ok := existing[key]; ok {
			kept = append(kept, nbv1alpha1.DNSRecordStatus{Type: string(d.rType), Content: d.content, ID: cur.Id})
			continue
		}
		resp, err := r.Netbird.DNSZones.CreateRecord(ctx, zone.Id, api.DNSRecordRequest{
			Content: d.content,
			Name:    fqdn,
			Ttl:     int(5 * time.Minute / time.Second),
			Type:    d.rType,
		})
		if err != nil {
			return err
		}
		kept = append(kept, nbv1alpha1.DNSRecordStatus{Type: string(d.rType), Content: d.content, ID: resp.Id})
	}

	// Delete stale records at this fqdn (e.g. a previous ClusterIP).
	for _, rec := range ours {
		if !desiredKeys[recordMatchKey(string(rec.Type), rec.Content)] {
			if err := r.Netbird.DNSZones.DeleteRecord(ctx, zone.Id, rec.Id); err != nil && !netbird.IsNotFound(err) {
				return err
			}
		}
	}

	netResource.Status.DNSZoneID = zone.Id
	netResource.Status.DNSRecords = kept
	return sp.Patch(ctx, netResource)
}

func (r *NetworkResourceReconciler) reconcileDelete(ctx context.Context, sp *patch.SerialPatcher, netResource *nbv1alpha1.NetworkResource) (ctrl.Result, error) {
	if netResource.Status.NetworkID != "" && netResource.Status.ResourceID != "" {
		err := r.Netbird.Networks.Resources(netResource.Status.NetworkID).Delete(ctx, netResource.Status.ResourceID)
		if err != nil && !netbird.IsNotFound(err) {
			return ctrl.Result{}, err
		}
	}
	if netResource.Status.DNSZoneID != "" {
		for _, rec := range netResource.Status.DNSRecords {
			if err := r.Netbird.DNSZones.DeleteRecord(ctx, netResource.Status.DNSZoneID, rec.ID); err != nil && !netbird.IsNotFound(err) {
				return ctrl.Result{}, err
			}
		}
		if netResource.Status.DNSRecordID != "" {
			if err := r.Netbird.DNSZones.DeleteRecord(ctx, netResource.Status.DNSZoneID, netResource.Status.DNSRecordID); err != nil && !netbird.IsNotFound(err) {
				return ctrl.Result{}, err
			}
		}
	}

	controllerutil.RemoveFinalizer(netResource, k8sutil.Finalizer("networkresource"))
	err := sp.Patch(ctx, netResource)
	if err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

func (r *NetworkResourceReconciler) SetupWithManager(mgr ctrl.Manager) error {
	err := mgr.GetFieldIndexer().IndexField(context.Background(), &nbv1alpha1.NetworkResource{}, ".spec.networkRouterRef", func(obj client.Object) []string {
		netResource := obj.(*nbv1alpha1.NetworkResource)
		ref := netResource.Spec.NetworkRouterRef
		if ref.Name == "" {
			return nil
		}
		if ref.Namespace == "" {
			ref.Namespace = netResource.Namespace
		}
		return []string{fmt.Sprintf("%s/%s", ref.Name, ref.Namespace)}
	})
	if err != nil {
		return err
	}
	err = mgr.GetFieldIndexer().IndexField(context.Background(), &nbv1alpha1.NetworkResource{}, ".spec.serviceRef", func(obj client.Object) []string {
		netResource := obj.(*nbv1alpha1.NetworkResource)
		ref := netResource.Spec.ServiceRef
		if ref.Name == "" {
			return nil
		}
		return []string{netResource.Spec.ServiceRef.Name}
	})
	if err != nil {
		return err
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&nbv1alpha1.NetworkResource{}).
		Watches(
			&nbv1alpha1.NetworkRouter{},
			handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, obj client.Object) []reconcile.Request {
				netResourceList := &nbv1alpha1.NetworkResourceList{}
				err := r.List(ctx, netResourceList, client.MatchingFields{".spec.networkRouterRef": fmt.Sprintf("%s/%s", obj.GetName(), obj.GetNamespace())})
				if err != nil {
					return nil
				}

				requests := make([]reconcile.Request, len(netResourceList.Items))
				for i, item := range netResourceList.Items {
					requests[i] = reconcile.Request{
						NamespacedName: types.NamespacedName{
							Name:      item.Name,
							Namespace: item.Namespace,
						},
					}
				}
				return requests
			}),
			builder.WithPredicates(predicate.ResourceVersionChangedPredicate{}),
		).
		Watches(
			&corev1.Service{},
			handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, obj client.Object) []reconcile.Request {
				netResourceList := &nbv1alpha1.NetworkResourceList{}
				err := r.List(ctx, netResourceList, client.InNamespace(obj.GetNamespace()), client.MatchingFields{".spec.serviceRef": obj.GetName()})
				if err != nil {
					return nil
				}

				requests := make([]reconcile.Request, len(netResourceList.Items))
				for i, item := range netResourceList.Items {
					requests[i] = reconcile.Request{
						NamespacedName: types.NamespacedName{
							Name:      item.Name,
							Namespace: item.Namespace,
						},
					}
				}
				return requests
			}),
			builder.WithPredicates(predicate.ResourceVersionChangedPredicate{}),
		).
		Complete(r)
}
