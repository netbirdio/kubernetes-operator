package controller

import (
	"context"
	"fmt"
	"strings"
	"time"

	netbirdiov1 "github.com/netbirdio/kubernetes-operator/api/v1"
	"github.com/netbirdio/kubernetes-operator/internal/util"
	netbird "github.com/netbirdio/netbird/management/client/rest"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// ServiceReconciler reconciles a Service object
type ServiceReconciler struct {
	client.Client
	Scheme              *runtime.Scheme
	ClusterName         string
	ClusterDNS          string
	APIKey              string
	ManagementURL       string
	NamespacedNetworks  bool
	ControllerNamespace string
	netbird             *netbird.Client
}

const (
	serviceExposeAnnotation   = "netbird.io/expose"
	serviceGroupsAnnotation   = "netbird.io/groups"
	serviceResourceAnnotation = "netbird.io/resource-name"
)

var (
	networkDescription = "Created by kubernetes-operator"
)

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
func (r *ServiceReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	_ = log.FromContext(ctx)

	svc := corev1.Service{}
	err := r.Get(ctx, req.NamespacedName, &svc)
	if err != nil {
		if !errors.IsNotFound(err) {
			ctrl.Log.Error(fmt.Errorf("internalError"), "error getting Service", "err", err, "namespace", req.Namespace, "name", req.Name)
		}
		return ctrl.Result{}, nil
	}

	_, shouldExpose := svc.Annotations[serviceExposeAnnotation]

	// If Service is being deleted, un-expose
	shouldExpose = shouldExpose && svc.DeletionTimestamp == nil

	if shouldExpose {
		return r.exposeService(ctx, req, svc)
	}

	return r.hideService(ctx, req, svc)
}

func (r *ServiceReconciler) hideService(ctx context.Context, req ctrl.Request, svc corev1.Service) (ctrl.Result, error) {
	var nbResource netbirdiov1.NBResource
	err := r.Client.Get(ctx, req.NamespacedName, &nbResource)
	if err != nil && !errors.IsNotFound(err) {
		ctrl.Log.Error(fmt.Errorf("internalError"), "error getting NBResource", "err", err, "namespace", req.Namespace, "name", req.Name)
		return ctrl.Result{}, err
	}

	if !errors.IsNotFound(err) {
		err = r.Client.Delete(ctx, &nbResource)
		if err != nil {
			ctrl.Log.Error(fmt.Errorf("internalError"), "error deleting NBResource", "err", err, "namespace", req.Namespace, "name", req.Name)
			return ctrl.Result{}, err
		}
	}

	if util.Contains(svc.Finalizers, "netbird.io/cleanup") {
		svc.Finalizers = util.Without(svc.Finalizers, "netbird.io/cleanup")
		err := r.Client.Update(ctx, &svc)
		if err != nil {
			ctrl.Log.Error(fmt.Errorf("internalError"), "error updating Service", "err", err, "namespace", req.Namespace, "name", req.Name)
			return ctrl.Result{}, err
		}
	}

	return ctrl.Result{}, nil
}

func (r *ServiceReconciler) exposeService(ctx context.Context, req ctrl.Request, svc corev1.Service) (ctrl.Result, error) {
	networkName := r.ClusterName
	routerNamespace := r.ControllerNamespace
	if r.NamespacedNetworks {
		networkName += "-" + req.Namespace
		routerNamespace = req.Namespace
	}

	if !util.Contains(svc.Finalizers, "netbird.io/cleanup") {
		svc.Finalizers = append(svc.Finalizers, "netbird.io/cleanup")
		err := r.Client.Update(ctx, &svc)
		if err != nil {
			ctrl.Log.Error(fmt.Errorf("internalError"), "error updating Service", "err", err, "namespace", req.Namespace, "name", req.Name)
			return ctrl.Result{}, err
		}
	}

	var routingPeer netbirdiov1.NBRoutingPeer
	// Check if NBRoutingPeer exists
	err := r.Client.Get(ctx, types.NamespacedName{Namespace: routerNamespace, Name: "router"}, &routingPeer)
	if err != nil && !errors.IsNotFound(err) {
		ctrl.Log.Error(fmt.Errorf("internalError"), "error getting NBRoutingPeer", "err", err, "namespace", req.Namespace, "name", req.Name)
		return ctrl.Result{}, err
	}

	// Create NBRoutingPeer with default values if not exists
	if errors.IsNotFound(err) {
		routingPeer = netbirdiov1.NBRoutingPeer{
			ObjectMeta: v1.ObjectMeta{
				Name:       "router",
				Namespace:  routerNamespace,
				Finalizers: []string{"netbird.io/cleanup"},
			},
			Spec: netbirdiov1.NBRoutingPeerSpec{},
		}

		err = r.Client.Create(ctx, &routingPeer)
		if err != nil {
			ctrl.Log.Error(fmt.Errorf("internalError"), "error creating NBRoutingPeer", "err", err, "namespace", req.Namespace, "name", req.Name)
			return ctrl.Result{}, err
		}

		ctrl.Log.Info("Network not available")
		// Requeue to make sure network is created
		return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
	}

	if routingPeer.Status.NetworkID == nil {
		ctrl.Log.Info("Network not available")
		return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
	}

	resourceName := fmt.Sprintf("%s-%s", req.Namespace, req.Name)
	if v, ok := svc.Annotations[serviceResourceAnnotation]; ok {
		resourceName = v
	}

	groups := []string{fmt.Sprintf("%s-%s-%s", r.ClusterName, req.Namespace, req.Name)}
	if v, ok := svc.Annotations[serviceGroupsAnnotation]; ok {
		groups = nil
		for _, g := range strings.Split(v, ",") {
			groups = append(groups, strings.TrimSpace(g))
		}
	}

	var nbResource netbirdiov1.NBResource
	err = r.Client.Get(ctx, req.NamespacedName, &nbResource)
	if err != nil && !errors.IsNotFound(err) {
		ctrl.Log.Error(fmt.Errorf("internalError"), "error getting NBResource", "err", err, "namespace", req.Namespace, "name", req.Name)
		return ctrl.Result{}, err
	}

	if errors.IsNotFound(err) {
		nbResource = netbirdiov1.NBResource{
			ObjectMeta: v1.ObjectMeta{
				Name:       req.Name,
				Namespace:  req.Namespace,
				Finalizers: []string{"netbird.io/cleanup"},
			},
			Spec: netbirdiov1.NBResourceSpec{
				Name:      resourceName,
				NetworkID: *routingPeer.Status.NetworkID,
				Address:   fmt.Sprintf("%s.%s.%s", svc.Name, svc.Namespace, r.ClusterDNS),
				Groups:    groups,
			},
		}

		err = r.Client.Create(ctx, &nbResource)
		if err != nil {
			ctrl.Log.Error(fmt.Errorf("internalError"), "error creating NBResource", "err", err, "namespace", req.Namespace, "name", req.Name)
			return ctrl.Result{}, err
		}
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *ServiceReconciler) SetupWithManager(mgr ctrl.Manager) error {
	r.netbird = netbird.New(r.ManagementURL, r.APIKey)

	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Service{}).
		Named("service"). // TODO: Watch NBRoutingPeer changes to possibly reconcile
		Complete(r)
}
