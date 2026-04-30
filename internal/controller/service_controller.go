package controller

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	nbv1 "github.com/netbirdio/kubernetes-operator/api/v1"
	"github.com/netbirdio/kubernetes-operator/internal/util"
)

// ServiceReconciler reconciles a Service object
type ServiceReconciler struct {
	client.Client

	ClusterName         string
	ClusterDNS          string
	NamespacedNetworks  bool
	ControllerNamespace string
	DefaultLabels       map[string]string
}

const (
	// ServiceExposeAnnotation Service annotation for exposing
	ServiceExposeAnnotation             = "netbird.io/expose"
	serviceGroupsAnnotation             = "netbird.io/groups"
	serviceResourceAnnotation           = "netbird.io/resource-name"
	servicePolicyAnnotation             = "netbird.io/policy"
	servicePortsAnnotation              = "netbird.io/policy-ports"
	serviceProtocolAnnotation           = "netbird.io/policy-protocol"
	servicePolicySourceGroupsAnnotation = "netbird.io/policy-source-groups"
	servicePolicyNameAnnotation         = "netbird.io/policy-name"
)

var (
	networkDescription = "Created by kubernetes-operator"
)

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
func (r *ServiceReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := ctrl.Log.WithName("Service").WithValues("namespace", req.Namespace, "name", req.Name)
	logger.Info("Reconciling Service")

	svc := corev1.Service{}
	err := r.Get(ctx, req.NamespacedName, &svc)
	if err != nil {
		if !errors.IsNotFound(err) {
			logger.Error(errKubernetesAPI, "error getting Service", "err", err)
		}
		return ctrl.Result{}, nil
	}

	// Special case for kubernetes API Service
	// Handled by Helm chart
	if svc.Namespace == "default" && svc.Name == "kubernetes" {
		return ctrl.Result{}, nil
	}

	_, shouldExpose := svc.Annotations[ServiceExposeAnnotation]

	// If Service is being deleted, un-expose
	shouldExpose = shouldExpose && svc.DeletionTimestamp == nil

	if shouldExpose {
		return r.exposeService(ctx, req, svc, logger)
	}

	return r.hideService(ctx, req, svc, logger)
}

// hideService deletes NBResource for Service
func (r *ServiceReconciler) hideService(ctx context.Context, req ctrl.Request, svc corev1.Service, logger logr.Logger) (ctrl.Result, error) {
	var nbResource nbv1.NBResource
	err := r.Client.Get(ctx, req.NamespacedName, &nbResource)
	if err != nil && !errors.IsNotFound(err) {
		logger.Error(errKubernetesAPI, "error getting NBResource", "err", err)
		return ctrl.Result{}, err
	}

	if !errors.IsNotFound(err) {
		err = r.Client.Delete(ctx, &nbResource)
		if err != nil {
			logger.Error(errKubernetesAPI, "error deleting NBResource", "err", err)
			return ctrl.Result{}, err
		}
	}

	if slices.Contains(svc.Finalizers, "netbird.io/cleanup") {
		svc.Finalizers = util.Without(svc.Finalizers, "netbird.io/cleanup")
		err := r.Client.Update(ctx, &svc)
		if err != nil {
			logger.Error(errKubernetesAPI, "error updating Service", "err", err)
			return ctrl.Result{}, err
		}
	}

	return ctrl.Result{}, nil
}

// exposeService creates/updates NBResource for Service
func (r *ServiceReconciler) exposeService(ctx context.Context, req ctrl.Request, svc corev1.Service, logger logr.Logger) (ctrl.Result, error) {
	routerNamespace := r.ControllerNamespace
	if r.NamespacedNetworks {
		routerNamespace = req.Namespace
	}

	if !slices.Contains(svc.Finalizers, "netbird.io/cleanup") {
		svc.Finalizers = append(svc.Finalizers, "netbird.io/cleanup")
		err := r.Client.Update(ctx, &svc)
		if err != nil {
			logger.Error(errKubernetesAPI, "error updating Service", "err", err)
			return ctrl.Result{}, err
		}
	}

	var routingPeer nbv1.NBRoutingPeer
	// Check if NBRoutingPeer exists
	err := r.Client.Get(ctx, types.NamespacedName{Namespace: routerNamespace, Name: "router"}, &routingPeer)
	if err != nil && !errors.IsNotFound(err) {
		logger.Error(errKubernetesAPI, "error getting NBRoutingPeer", "err", err)
		return ctrl.Result{}, err
	}

	// Create NBRoutingPeer with default values if not exists
	if errors.IsNotFound(err) {
		routingPeer = nbv1.NBRoutingPeer{
			ObjectMeta: metav1.ObjectMeta{
				Name:       "router",
				Namespace:  routerNamespace,
				Finalizers: []string{"netbird.io/cleanup"},
				Labels:     r.DefaultLabels,
			},
			Spec: nbv1.NBRoutingPeerSpec{},
		}

		err = r.Client.Create(ctx, &routingPeer)
		if err != nil {
			logger.Error(errKubernetesAPI, "error creating NBRoutingPeer", "err", err)
			return ctrl.Result{}, err
		}

		logger.Info("Network not available")
		// Requeue to make sure network is created
		return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
	}

	if routingPeer.Status.NetworkID == nil {
		logger.Info("Network not available")
		return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
	}

	var nbResource nbv1.NBResource
	err = r.Client.Get(ctx, req.NamespacedName, &nbResource)
	if err != nil && !errors.IsNotFound(err) {
		logger.Error(errKubernetesAPI, "error getting NBResource", "err", err)
		return ctrl.Result{}, err
	}

	originalNBResource := nbResource.DeepCopy()
	nbrsErr := r.reconcileNBResource(&nbResource, req, svc, routingPeer, logger)
	if nbrsErr != nil {
		return ctrl.Result{}, nbrsErr
	}

	if errors.IsNotFound(err) {
		err = r.Client.Create(ctx, &nbResource)
		if err != nil {
			logger.Error(errKubernetesAPI, "error creating NBResource", "err", err)
			return ctrl.Result{}, err
		}
	} else if !originalNBResource.Spec.Equal(nbResource.Spec) {
		err = r.Client.Update(ctx, &nbResource)
		if err != nil {
			logger.Error(errKubernetesAPI, "error updating NBResource", "err", err)
			return ctrl.Result{}, err
		}
	}

	return ctrl.Result{}, nil
}

// reconcileNBResource ensures NBResource settings are in-line with Service definition and annotations
func (r *ServiceReconciler) reconcileNBResource(nbResource *nbv1.NBResource, req ctrl.Request, svc corev1.Service, routingPeer nbv1.NBRoutingPeer, logger logr.Logger) error {
	groups := []string{fmt.Sprintf("%s-%s-%s", r.ClusterName, req.Namespace, req.Name)}
	if v, ok := svc.Annotations[serviceGroupsAnnotation]; ok {
		//nolint:prealloc
		groups = nil
		for g := range strings.SplitSeq(v, ",") {
			groups = append(groups, strings.TrimSpace(g))
		}
	}

	resourceName := fmt.Sprintf("%s-%s", req.Namespace, req.Name)
	if v, ok := svc.Annotations[serviceResourceAnnotation]; ok {
		resourceName = v
	}

	nbResource.ObjectMeta.Name = req.Name
	nbResource.ObjectMeta.Namespace = req.Namespace
	nbResource.ObjectMeta.Labels = r.DefaultLabels
	nbResource.Finalizers = []string{"netbird.io/cleanup"}
	nbResource.Spec.Name = resourceName
	nbResource.Spec.NetworkID = *routingPeer.Status.NetworkID
	nbResource.Spec.Address = fmt.Sprintf("%s.%s.%s", svc.Name, svc.Namespace, r.ClusterDNS)
	nbResource.Spec.Groups = groups

	if _, ok := svc.Annotations[servicePolicyAnnotation]; ok {
		err := r.applyPolicy(nbResource, svc, logger)
		if err != nil {
			return err
		}
	} else if nbResource.Spec.PolicyName != "" {
		nbResource.Spec.PolicyName = ""
		nbResource.Spec.TCPPorts = nil
		nbResource.Spec.UDPPorts = nil
	}

	return nil
}

func (r *ServiceReconciler) applyPolicy(nbResource *nbv1.NBResource, svc corev1.Service, logger logr.Logger) error {
	nbResource.Spec.PolicyName = svc.Annotations[servicePolicyAnnotation]
	var filterProtocols []string
	if v, ok := svc.Annotations[serviceProtocolAnnotation]; ok {
		filterProtocols = []string{v}
	}
	var filterPorts []int32
	if v, ok := svc.Annotations[servicePortsAnnotation]; ok {
		for v := range strings.SplitSeq(v, ",") {
			port, err := strconv.ParseInt(v, 10, 64)
			if err != nil {
				return err
			}

			filterPorts = append(filterPorts, int32(port))
		}
	}

	if v, ok := svc.Annotations[servicePolicySourceGroupsAnnotation]; ok {
		nbResource.Spec.PolicySourceGroups = util.SplitTrim(v, ",")
	} else {
		nbResource.Spec.PolicySourceGroups = nil
	}

	policyFriendlyNameList := util.SplitTrim(svc.Annotations[servicePolicyNameAnnotation], ",")
	nbResource.Spec.PolicyFriendlyName = make(map[string]string)
	for _, v := range policyFriendlyNameList {
		friendlyNameMap := util.SplitTrim(v, ":")
		if len(friendlyNameMap) != 2 {
			logger.Info("Invalid number of : found in annotation", "annotation", servicePolicyNameAnnotation, "value", v)
			continue
		}
		nbResource.Spec.PolicyFriendlyName[friendlyNameMap[0]] = friendlyNameMap[1]
	}

	for _, p := range svc.Spec.Ports {
		switch p.Protocol {
		case corev1.ProtocolTCP:
			if (len(filterPorts) > 0 && !slices.Contains(filterPorts, p.Port)) || (len(filterProtocols) > 0 && !slices.Contains(filterProtocols, "tcp")) {
				if slices.Contains(nbResource.Spec.TCPPorts, p.Port) {
					nbResource.Spec.TCPPorts = util.Without(nbResource.Spec.TCPPorts, p.Port)
				}
				continue
			}
			if !slices.Contains(nbResource.Spec.TCPPorts, p.Port) {
				nbResource.Spec.TCPPorts = append(nbResource.Spec.TCPPorts, p.Port)
			}
		case corev1.ProtocolUDP:
			if (len(filterPorts) > 0 && !slices.Contains(filterPorts, p.Port)) || (len(filterProtocols) > 0 && !slices.Contains(filterProtocols, "udp")) {
				if slices.Contains(nbResource.Spec.UDPPorts, p.Port) {
					nbResource.Spec.UDPPorts = util.Without(nbResource.Spec.UDPPorts, p.Port)
				}
				continue
			}
			if !slices.Contains(nbResource.Spec.UDPPorts, p.Port) {
				nbResource.Spec.UDPPorts = append(nbResource.Spec.UDPPorts, p.Port)
			}
		default:
			logger.Info("Unsupported protocol %v", p.Protocol)
			continue
		}
	}

	return nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *ServiceReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Service{}).
		Named("service").
		Complete(r)
}
