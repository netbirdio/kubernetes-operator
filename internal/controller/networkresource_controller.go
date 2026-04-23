package controller

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/fluxcd/pkg/runtime/conditions"
	"github.com/fluxcd/pkg/runtime/patch"
	netbird "github.com/netbirdio/netbird/shared/management/client/rest"
	"github.com/netbirdio/netbird/shared/management/http/api"
	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

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
			Description: ptr.To(svc.Name + "/" + svc.Namespace),
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

	// Create DNS records for resource.
	zone, err := netbirdutil.GetDNSZoneByName(ctx, r.Netbird, netRouter.Spec.DNSZoneRef.Name)
	if err != nil {
		return ctrl.Result{}, err
	}

	// If zone has changed we need to delete the old records.
	if netResource.Status.DNSZoneID != "" && netResource.Status.DNSZoneID != zone.Id {
		err = r.Netbird.DNSZones.DeleteRecord(ctx, netResource.Status.DNSZoneID, netResource.Status.DNSRecordID)
		if err != nil && !netbird.IsNotFound(err) {
			return ctrl.Result{}, err
		}
		netResource.Status.DNSZoneID = ""
		netResource.Status.DNSRecordID = ""
	}

	recordID, err := func() (string, error) {
		dnsReq := api.DNSRecordRequest{
			Content: svc.Spec.ClusterIP,
			Name:    strings.Join([]string{svc.Name, svc.Namespace, zone.Name}, "."),
			Ttl:     int(5 * time.Minute / time.Second),
			Type:    api.DNSRecordTypeA,
		}
		if netResource.Status.DNSZoneID != "" && netResource.Status.DNSRecordID != "" {
			recordResp, err := r.Netbird.DNSZones.UpdateRecord(ctx, netResource.Status.DNSZoneID, netResource.Status.DNSRecordID, dnsReq)
			if err != nil && !netbird.IsNotFound(err) {
				return "", err
			}
			if err == nil {
				return recordResp.Id, nil
			}
		}
		recordResp, err := r.Netbird.DNSZones.CreateRecord(ctx, zone.Id, dnsReq)
		if err != nil {
			return "", err
		}
		return recordResp.Id, nil
	}()
	if err != nil {
		return ctrl.Result{}, err
	}
	netResource.Status.DNSZoneID = zone.Id
	netResource.Status.DNSRecordID = recordID

	conditions.MarkTrue(netResource, nbv1alpha1.ReadyCondition, nbv1alpha1.ReconciledReason, "")
	err = sp.Patch(ctx, netResource, patch.WithStatusObservedGeneration{})
	if err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

func (r *NetworkResourceReconciler) reconcileDelete(ctx context.Context, sp *patch.SerialPatcher, netResource *nbv1alpha1.NetworkResource) (ctrl.Result, error) {
	if netResource.Status.NetworkID != "" && netResource.Status.ResourceID != "" {
		err := r.Netbird.Networks.Resources(netResource.Status.NetworkID).Delete(ctx, netResource.Status.ResourceID)
		if err != nil && !netbird.IsNotFound(err) {
			return ctrl.Result{}, err
		}
	}
	if netResource.Status.DNSZoneID != "" && netResource.Status.DNSRecordID != "" {
		err := r.Netbird.DNSZones.DeleteRecord(ctx, netResource.Status.DNSZoneID, netResource.Status.DNSRecordID)
		if err != nil && !netbird.IsNotFound(err) {
			return ctrl.Result{}, err
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
