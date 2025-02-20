package controller

import (
	"context"
	"fmt"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"

	netbirdiov1 "github.com/netbirdio/kubernetes-operator/api/v1"
	"github.com/netbirdio/kubernetes-operator/internal/util"
	netbird "github.com/netbirdio/netbird/management/client/rest"
	"github.com/netbirdio/netbird/management/server/http/api"
)

// NBRoutingPeerReconciler reconciles a NBRoutingPeer object
type NBRoutingPeerReconciler struct {
	client.Client
	Scheme             *runtime.Scheme
	ClientImage        string
	ClusterName        string
	APIKey             string
	ManagementURL      string
	NamespacedNetworks bool
	netbird            *netbird.Client
}

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
func (r *NBRoutingPeerReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	_ = log.FromContext(ctx)

	nbrp := netbirdiov1.NBRoutingPeer{}
	err := r.Get(ctx, req.NamespacedName, &nbrp)
	if err != nil {
		if !errors.IsNotFound(err) {
			ctrl.Log.Error(fmt.Errorf("internalError"), "error getting NBRoutingPeer", "err", err, "namespace", req.Namespace, "name", req.Name)
		}
		return ctrl.Result{}, nil
	}

	if nbrp.DeletionTimestamp != nil {
		if len(nbrp.Finalizers) == 0 {
			return ctrl.Result{}, nil
		}
		return r.handleDelete(ctx, req, nbrp)
	}

	ctrl.Log.Info("NBRoutingPeer: Checking network", "namespace", req.Namespace, "name", req.Name)
	err = r.handleNetwork(ctx, req, nbrp)
	if err != nil {
		return ctrl.Result{}, err
	}

	ctrl.Log.Info("NBRoutingPeer: Checking groups", "namespace", req.Namespace, "name", req.Name)
	nbGroup, res, err := r.handleGroup(ctx, req, nbrp)
	if nbGroup == nil {
		return *res, err
	}

	ctrl.Log.Info("NBRoutingPeer: Checking setup keys", "namespace", req.Namespace, "name", req.Name)
	res, err = r.handleSetupKey(ctx, req, nbrp, *nbGroup)
	if res != nil {
		return *res, err
	}

	ctrl.Log.Info("NBRoutingPeer: Checking network router", "namespace", req.Namespace, "name", req.Name)
	err = r.handleRouter(ctx, req, nbrp, *nbGroup)
	if err != nil {
		return ctrl.Result{}, err
	}

	ctrl.Log.Info("NBRoutingPeer: Checking deployment", "namespace", req.Namespace, "name", req.Name)
	return ctrl.Result{}, r.handleDeployment(ctx, req, nbrp)
}

func (r *NBRoutingPeerReconciler) handleDeployment(ctx context.Context, req ctrl.Request, nbrp netbirdiov1.NBRoutingPeer) error {
	routingPeerDeployment := appsv1.Deployment{}
	err := r.Client.Get(ctx, req.NamespacedName, &routingPeerDeployment)
	if err != nil && !errors.IsNotFound(err) {
		ctrl.Log.Error(fmt.Errorf("internalError"), "error getting Deployment", "err", err, "namespace", req.Namespace, "name", req.Name)
		return err
	}

	if errors.IsNotFound(err) {
		var replicas int32 = 3
		if nbrp.Spec.Replicas != nil {
			replicas = *nbrp.Spec.Replicas
		}
		routingPeerDeployment = appsv1.Deployment{
			ObjectMeta: v1.ObjectMeta{
				Name:      nbrp.Name,
				Namespace: nbrp.Namespace,
				OwnerReferences: []v1.OwnerReference{
					{
						APIVersion:         nbrp.APIVersion,
						Kind:               nbrp.Kind,
						Name:               nbrp.Name,
						UID:                nbrp.UID,
						BlockOwnerDeletion: util.Ptr(true),
					},
				},
				Labels:      nbrp.Spec.Labels,
				Annotations: nbrp.Spec.Annotations,
			},
			Spec: appsv1.DeploymentSpec{
				Replicas: &replicas,
				Selector: &v1.LabelSelector{
					MatchLabels: map[string]string{
						"app.kubernetes.io/name": "netbird-router",
					},
				},
				Template: corev1.PodTemplateSpec{
					ObjectMeta: v1.ObjectMeta{
						Labels: map[string]string{
							"app.kubernetes.io/name": "netbird-router",
						},
					},
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{
							{
								Name:  "netbird",
								Image: r.ClientImage,
								Env: []corev1.EnvVar{
									{
										Name: "NB_SETUP_KEY",
										ValueFrom: &corev1.EnvVarSource{
											SecretKeyRef: &corev1.SecretKeySelector{
												LocalObjectReference: corev1.LocalObjectReference{
													Name: nbrp.Name,
												},
												Key: "setupKey",
											},
										},
									},
									{
										Name:  "NB_MANAGEMENT_URL",
										Value: r.ManagementURL,
									},
								},
								SecurityContext: &corev1.SecurityContext{
									Capabilities: &corev1.Capabilities{
										Add: []corev1.Capability{
											"NET_ADMIN",
										},
									},
								},
							},
						},
					},
				},
			},
		}

		err = r.Client.Create(ctx, &routingPeerDeployment)
		if err != nil {
			ctrl.Log.Error(fmt.Errorf("internalError"), "error creating Deployment", "err", err, "namespace", req.Namespace, "name", req.Name)
			return err
		}
	} else {
		updatedDeployment := routingPeerDeployment.DeepCopy()
		updatedDeployment.ObjectMeta.Name = nbrp.Name
		updatedDeployment.ObjectMeta.Namespace = nbrp.Namespace
		updatedDeployment.ObjectMeta.OwnerReferences = []v1.OwnerReference{
			{
				APIVersion:         nbrp.APIVersion,
				Kind:               nbrp.Kind,
				Name:               nbrp.Name,
				UID:                nbrp.UID,
				BlockOwnerDeletion: util.Ptr(true),
			},
		}
		updatedDeployment.ObjectMeta.Labels = nbrp.Spec.Labels
		for k, v := range nbrp.Spec.Annotations {
			updatedDeployment.ObjectMeta.Annotations[k] = nbrp.Spec.Annotations[v]
		}
		var replicas int32 = 3
		if nbrp.Spec.Replicas != nil {
			replicas = *nbrp.Spec.Replicas
		}
		updatedDeployment.Spec.Replicas = &replicas
		updatedDeployment.Spec.Selector = &v1.LabelSelector{
			MatchLabels: map[string]string{
				"app.kubernetes.io/name": "netbird-router",
			},
		}
		updatedDeployment.Spec.Template.ObjectMeta.Labels = map[string]string{
			"app.kubernetes.io/name": "netbird-router",
		}
		if len(updatedDeployment.Spec.Template.Spec.Containers) != 1 {
			updatedDeployment.Spec.Template.Spec.Containers = []corev1.Container{}
		}
		updatedDeployment.Spec.Template.Spec.Containers[0].Name = "netbird"
		updatedDeployment.Spec.Template.Spec.Containers[0].Image = r.ClientImage
		updatedDeployment.Spec.Template.Spec.Containers[0].Env = []corev1.EnvVar{
			{
				Name: "NB_SETUP_KEY",
				ValueFrom: &corev1.EnvVarSource{
					SecretKeyRef: &corev1.SecretKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: nbrp.Name,
						},
						Key: "setupKey",
					},
				},
			},
			{
				Name:  "NB_MANAGEMENT_URL",
				Value: r.ManagementURL,
			},
		}
		updatedDeployment.Spec.Template.Spec.Containers[0].SecurityContext = &corev1.SecurityContext{
			Capabilities: &corev1.Capabilities{
				Add: []corev1.Capability{
					"NET_ADMIN",
				},
			},
		}

		patch := client.StrategicMergeFrom(&routingPeerDeployment)
		bs, _ := patch.Data(updatedDeployment)
		// Minimum patch size is 2 for "{}"
		if len(bs) <= 2 {
			return nil
		}
		err = r.Client.Patch(ctx, updatedDeployment, patch)
		if err != nil {
			ctrl.Log.Error(fmt.Errorf("internalError"), "error updating Deployment", "err", err, "namespace", req.Namespace, "name", req.Name)
			return err
		}
	}

	return nil
}

func (r *NBRoutingPeerReconciler) handleRouter(ctx context.Context, req ctrl.Request, nbrp netbirdiov1.NBRoutingPeer, nbGroup netbirdiov1.NBGroup) error {
	// Refresh nbrp
	err := r.Client.Get(ctx, req.NamespacedName, &nbrp)
	if err != nil {
		return err
	}

	// Check NetworkRouter exists
	routers, err := r.netbird.Networks.Routers(*nbrp.Status.NetworkID).List(ctx)

	if err != nil {
		ctrl.Log.Error(fmt.Errorf("netbirdAPIError"), "error listing network routers", "err", err, "namespace", req.Namespace, "name", req.Name)
		return err
	}

	if nbrp.Status.RouterID == nil || len(routers) == 0 {
		if len(routers) > 0 {
			nbrp.Status.RouterID = &routers[0].Id
		} else {
			router, err := r.netbird.Networks.Routers(*nbrp.Status.NetworkID).Create(ctx, api.NetworkRouterRequest{
				Enabled:    true,
				Masquerade: true,
				Metric:     9999,
				PeerGroups: &[]string{*nbGroup.Status.GroupID},
			})

			if err != nil {
				ctrl.Log.Error(fmt.Errorf("netbirdAPIError"), "error creating network router", "err", err, "namespace", req.Namespace, "name", req.Name)
				return err
			}

			nbrp.Status.RouterID = &router.Id
		}

		err = r.Client.Status().Update(ctx, &nbrp)
		if err != nil {
			ctrl.Log.Error(fmt.Errorf("internalError"), "error updating NBRoutingPeer status", "err", err, "namespace", req.Namespace, "name", req.Name)
			return err
		}
	} else {
		if !routers[0].Enabled || !routers[0].Masquerade || routers[0].Metric != 9999 || len(*routers[0].PeerGroups) != 1 || (*routers[0].PeerGroups)[0] != *nbGroup.Status.GroupID {
			r.netbird.Networks.Routers(*nbrp.Status.NetworkID).Update(ctx, routers[0].Id, api.NetworkRouterRequest{
				Enabled:    true,
				Masquerade: true,
				Metric:     9999,
				PeerGroups: &[]string{*nbGroup.Status.GroupID},
			})
		}
	}

	return nil
}

func (r *NBRoutingPeerReconciler) handleSetupKey(ctx context.Context, req ctrl.Request, nbrp netbirdiov1.NBRoutingPeer, nbGroup netbirdiov1.NBGroup) (*ctrl.Result, error) {
	networkName := r.ClusterName
	if r.NamespacedNetworks {
		networkName += "-" + req.Namespace
	}

	// Check if setup key exists
	if nbrp.Status.SetupKeyID == nil {
		// Create new setup key with group Status.GroupID
		setupKey, err := r.netbird.SetupKeys.Create(ctx, api.CreateSetupKeyRequest{
			AutoGroups: []string{*nbGroup.Status.GroupID},
			Ephemeral:  util.Ptr(true),
			Name:       networkName,
			Type:       "reusable",
		})

		if err != nil {
			ctrl.Log.Error(fmt.Errorf("netbirdAPIError"), "error creating setup key", "err", err, "namespace", req.Namespace, "name", req.Name)
			return &ctrl.Result{}, err
		}

		nbrp.Status.SetupKeyID = &setupKey.Id
		err = r.Client.Status().Update(ctx, &nbrp)
		if err != nil {
			ctrl.Log.Error(fmt.Errorf("internalError"), "error updating NBRoutingPeer status", "err", err, "namespace", req.Namespace, "name", req.Name)
			return &ctrl.Result{}, err
		}

		skSecret := corev1.Secret{
			ObjectMeta: v1.ObjectMeta{
				Name:      nbrp.Name,
				Namespace: nbrp.Namespace,
				OwnerReferences: []v1.OwnerReference{
					{
						APIVersion:         nbrp.APIVersion,
						Kind:               nbrp.Kind,
						Name:               nbrp.Name,
						UID:                nbrp.UID,
						BlockOwnerDeletion: util.Ptr(true),
					},
				},
			},
			StringData: map[string]string{
				"setupKey": setupKey.Key,
			},
		}
		err = r.Client.Create(ctx, &skSecret)
		if errors.IsAlreadyExists(err) {
			err = r.Client.Update(ctx, &skSecret)
		}

		if err != nil {
			ctrl.Log.Error(fmt.Errorf("internalError"), "error creating Secret", "err", err, "namespace", req.Namespace, "name", req.Name)
			return &ctrl.Result{}, err
		}
	} else {
		// Check SetupKey is not revoked
		setupKey, err := r.netbird.SetupKeys.Get(ctx, *nbrp.Status.SetupKeyID)
		if err != nil && !strings.Contains(err.Error(), "not found") {
			ctrl.Log.Error(fmt.Errorf("netbirdAPIError"), "error getting setup key", "err", err, "namespace", req.Namespace, "name", req.Name)
			return &ctrl.Result{}, err
		}

		if (err != nil && strings.Contains(err.Error(), "not found")) || setupKey.Revoked {
			nbrp.Status.SetupKeyID = nil
			err = r.Client.Status().Update(ctx, &nbrp)
			if err != nil {
				ctrl.Log.Error(fmt.Errorf("internalError"), "error updating NBRoutingPeer status", "err", err, "namespace", req.Namespace, "name", req.Name)
				return &ctrl.Result{}, err
			}

			return &ctrl.Result{Requeue: true}, nil
		}

		// Check if valid setup key exists
		skSecret := corev1.Secret{}
		err = r.Client.Get(ctx, req.NamespacedName, &skSecret)
		if err != nil && !errors.IsNotFound(err) {
			ctrl.Log.Error(fmt.Errorf("internalError"), "error getting Secret", "err", err, "namespace", req.Namespace, "name", req.Name)
			return &ctrl.Result{}, err
		}

		if _, ok := skSecret.Data["setupKey"]; errors.IsNotFound(err) || !ok {
			// Someone deleted setup key secret
			// Revoke SK from NetBird and re-generate
			err = r.netbird.SetupKeys.Delete(ctx, *nbrp.Status.SetupKeyID)

			if err != nil {
				ctrl.Log.Error(fmt.Errorf("netbirdAPIError"), "error deleting setup key", "err", err, "namespace", req.Namespace, "name", req.Name)
				return &ctrl.Result{}, err
			}

			nbrp.Status.SetupKeyID = nil
			err = r.Client.Status().Update(ctx, &nbrp)
			if err != nil {
				ctrl.Log.Error(fmt.Errorf("internalError"), "error updating NBRoutingPeer status", "err", err, "namespace", req.Namespace, "name", req.Name)
				return &ctrl.Result{}, err
			}

			// Requeue to avoid repeating code
			return &ctrl.Result{Requeue: true}, nil
		}
	}

	return nil, nil
}

func (r *NBRoutingPeerReconciler) handleGroup(ctx context.Context, req ctrl.Request, nbrp netbirdiov1.NBRoutingPeer) (*netbirdiov1.NBGroup, *ctrl.Result, error) {
	networkName := r.ClusterName
	if r.NamespacedNetworks {
		networkName += "-" + req.Namespace
	}

	// Check if NetBird Group exists
	nbGroup := netbirdiov1.NBGroup{}
	err := r.Client.Get(ctx, req.NamespacedName, &nbGroup)
	if err != nil && !errors.IsNotFound(err) {
		ctrl.Log.Error(fmt.Errorf("internalError"), "error getting NBGroup", "err", err, "namespace", req.Namespace, "name", req.Name)
		return nil, &ctrl.Result{}, err
	}

	if errors.IsNotFound(err) {
		nbGroup = netbirdiov1.NBGroup{
			ObjectMeta: v1.ObjectMeta{
				Name:      nbrp.Name,
				Namespace: nbrp.Namespace,
				OwnerReferences: []v1.OwnerReference{
					{
						APIVersion:         nbrp.APIVersion,
						Kind:               nbrp.Kind,
						Name:               nbrp.Name,
						UID:                nbrp.UID,
						BlockOwnerDeletion: util.Ptr(true),
					},
				},
				Finalizers: []string{"netbird.io/group-cleanup", "netbird.io/routing-peer-cleanup"},
			},
			Spec: netbirdiov1.NBGroupSpec{
				Name: networkName,
			},
		}

		err = r.Client.Create(ctx, &nbGroup)

		if err != nil {
			ctrl.Log.Error(fmt.Errorf("internalError"), "error creating NBGroup", "err", err, "namespace", req.Namespace, "name", req.Name)
			return nil, &ctrl.Result{}, err
		}

		// Requeue after 5 seconds to ensure group creation is successful by NBGroup controller.
		return nil, &ctrl.Result{RequeueAfter: 5 * time.Second}, nil
	}

	if nbGroup.Status.GroupID == nil {
		// Group is not yet created successfully, requeue
		return nil, &ctrl.Result{RequeueAfter: 10 * time.Second}, nil
	}

	return &nbGroup, nil, nil
}

func (r *NBRoutingPeerReconciler) handleNetwork(ctx context.Context, req ctrl.Request, nbrp netbirdiov1.NBRoutingPeer) error {
	networkName := r.ClusterName
	if r.NamespacedNetworks {
		networkName += "-" + req.Namespace
	}

	if nbrp.Status.NetworkID == nil {
		// Check if network exists
		networks, err := r.netbird.Networks.List(ctx)
		if err != nil {
			ctrl.Log.Error(fmt.Errorf("netbirdAPIError"), "error listing networks", "err", err, "namespace", req.Namespace, "name", req.Name)
			return err
		}
		var network *api.Network
		for _, n := range networks {
			if n.Name == networkName {
				ctrl.Log.Info("network already exists", "network-id", n.Id)
				network = &n
			}
		}

		if network != nil {
			nbrp.Status.NetworkID = &network.Id
		} else {
			ctrl.Log.Info("creating network", "name", networkName)
			network, err := r.netbird.Networks.Create(ctx, api.NetworkRequest{
				Name:        networkName,
				Description: &networkDescription,
			})
			if err != nil {
				ctrl.Log.Error(fmt.Errorf("netbirdAPIError"), "error creating network", "err", err, "namespace", req.Namespace, "name", req.Name)
				return err
			}

			nbrp.Status.NetworkID = &network.Id
		}

		err = r.Client.Status().Update(ctx, &nbrp)
		if err != nil {
			ctrl.Log.Error(fmt.Errorf("internalError"), "error updating NBRoutingPeer", "err", err, "namespace", req.Namespace, "name", req.Name)
			return err
		}
	}
	return nil
}

func (r *NBRoutingPeerReconciler) handleDelete(ctx context.Context, req ctrl.Request, nbrp netbirdiov1.NBRoutingPeer) (ctrl.Result, error) {
	nbDeployment := appsv1.Deployment{}
	err := r.Client.Get(ctx, req.NamespacedName, &nbDeployment)
	if err != nil && !errors.IsNotFound(err) {
		ctrl.Log.Error(fmt.Errorf("internalError"), "error getting Deployment", "err", err, "namespace", req.Namespace, "name", req.Name)
		return ctrl.Result{}, err
	}
	if err == nil {
		err = r.Client.Delete(ctx, &nbDeployment)
		if err != nil {
			ctrl.Log.Error(fmt.Errorf("internalError"), "error deleting Deployment", "err", err, "namespace", req.Namespace, "name", req.Name)
			return ctrl.Result{}, err
		}
	}

	if nbrp.Status.SetupKeyID != nil {
		ctrl.Log.Info("Deleting setup key", "id", *nbrp.Status.SetupKeyID)
		err = r.netbird.SetupKeys.Delete(ctx, *nbrp.Status.SetupKeyID)
		if err != nil && !strings.Contains(err.Error(), "not found") {
			ctrl.Log.Error(fmt.Errorf("netbirdAPIError"), "error deleting setupKey", "err", err, "namespace", req.Namespace, "name", req.Name)
			return ctrl.Result{}, err
		}

		setupKeyID := *nbrp.Status.SetupKeyID
		nbrp.Status.SetupKeyID = nil
		err = r.Client.Status().Update(ctx, &nbrp)
		if err != nil {
			ctrl.Log.Error(fmt.Errorf("internalError"), "error updating NBRoutingPeer status", "err", err, "namespace", req.Namespace, "name", req.Name)
			return ctrl.Result{}, err
		}

		ctrl.Log.Info("Setup key deleted", "id", setupKeyID)
	}

	if nbrp.Status.RouterID != nil {
		err = r.netbird.Networks.Routers(*nbrp.Status.NetworkID).Delete(ctx, *nbrp.Status.RouterID)
		if err != nil && !strings.Contains(err.Error(), "not found") {
			ctrl.Log.Error(fmt.Errorf("netbirdAPIError"), "error deleting Network Router", "err", err, "namespace", req.Namespace, "name", req.Name)
			return ctrl.Result{}, err
		}

		nbrp.Status.RouterID = nil
		err = r.Client.Status().Update(ctx, &nbrp)
		if err != nil {
			ctrl.Log.Error(fmt.Errorf("internalError"), "error updating NBRoutingPeer status", "err", err, "namespace", req.Namespace, "name", req.Name)
			return ctrl.Result{}, err
		}
	}

	nbGroup := netbirdiov1.NBGroup{}
	err = r.Client.Get(ctx, req.NamespacedName, &nbGroup)
	if err != nil && !errors.IsNotFound(err) {
		ctrl.Log.Error(fmt.Errorf("internalError"), "error getting NBGroup", "err", err, "namespace", req.Namespace, "name", req.Name)
		return ctrl.Result{}, err
	}

	if nbGroup.Status.GroupID != nil {
		peers, err := r.netbird.Peers.List(ctx)
		if err != nil {
			ctrl.Log.Error(fmt.Errorf("netbirdAPIError"), "error listing peers", "err", err, "namespace", req.Namespace, "name", req.Name)
			return ctrl.Result{}, err
		}

		for _, p := range peers {
			for _, g := range p.Groups {
				if g.Id == *nbGroup.Status.GroupID {
					ctrl.Log.Info("Deleting peer", "id", p.Id)
					err = r.netbird.Peers.Delete(ctx, p.Id)
					if err != nil {
						ctrl.Log.Error(fmt.Errorf("netbirdAPIError"), "error deleting peer", "err", err, "namespace", req.Namespace, "name", req.Name)
						return ctrl.Result{}, err
					}
					break
				}
			}
		}
	}

	if nbrp.Status.NetworkID != nil {
		namespaceList := corev1.NamespaceList{}
		err = r.Client.List(ctx, &namespaceList)
		if err != nil {
			ctrl.Log.Error(fmt.Errorf("internalError"), "error listing namespaces", "err", err, "namespace", req.Namespace, "name", req.Name)
			return ctrl.Result{}, err
		}

		for _, ns := range namespaceList.Items {
			nbResourceList := netbirdiov1.NBResourceList{}
			err = r.Client.List(ctx, &nbResourceList, &client.ListOptions{
				Namespace: ns.Name,
			})
			if err != nil {
				ctrl.Log.Error(fmt.Errorf("internalError"), "error listing NBResource", "err", err, "namespace", req.Namespace, "name", req.Name)
				return ctrl.Result{}, err
			}

			for _, nbrs := range nbResourceList.Items {
				if nbrs.Spec.NetworkID == *nbrp.Status.NetworkID {
					ctrl.Log.Info("Deleting NBResource", "namespace", nbrs.Namespace, "name", nbrs.Name)
					err = r.Client.Delete(ctx, &nbrs)
				}
			}
		}

		for _, ns := range namespaceList.Items {
			nbResourceList := netbirdiov1.NBResourceList{}
			err = r.Client.List(ctx, &nbResourceList, &client.ListOptions{
				Namespace: ns.Name,
			})
			if err != nil {
				ctrl.Log.Error(fmt.Errorf("internalError"), "error listing NBResource", "err", err, "namespace", req.Namespace, "name", req.Name)
				return ctrl.Result{}, err
			}

			for _, nbrs := range nbResourceList.Items {
				if nbrs.Spec.NetworkID == *nbrp.Status.NetworkID {
					// Wait for all resources to be deleted
					ctrl.Log.Info("Waiting for NBResource deletion", "namespace", nbrs.Namespace, "name", nbrs.Name)
					return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
				}
			}
		}

		ctrl.Log.Info("Deleting NetBird Network", "id", *nbrp.Status.NetworkID)
		err = r.netbird.Networks.Delete(ctx, *nbrp.Status.NetworkID)
		if err != nil && !strings.Contains(err.Error(), "not found") {
			ctrl.Log.Error(fmt.Errorf("netbirdAPIError"), "error deleting Network", "err", err, "namespace", req.Namespace, "name", req.Name)
			return ctrl.Result{}, err
		}

		nbrp.Status.NetworkID = nil
	}

	if nbGroup.Spec.Name != "" && util.Contains(nbGroup.Finalizers, "netbird.io/routing-peer-cleanup") {
		nbGroup.Finalizers = util.Without(nbGroup.Finalizers, "netbird.io/routing-peer-cleanup")
		ctrl.Log.Info("Removing netbird.io/routing-peer-cleanup finalizer NBGroup", "namespace", nbGroup.Namespace, "name", nbGroup.Name)
		err = r.Client.Update(ctx, &nbGroup)
		if err != nil {
			ctrl.Log.Error(fmt.Errorf("internalError"), "error deleting NBGroup", "err", err, "namespace", req.Namespace, "name", req.Name)
			return ctrl.Result{}, err
		}
	}

	if len(nbrp.Finalizers) > 0 {
		ctrl.Log.Info("Removing finalizers", "namespace", nbrp.Namespace, "name", nbrp.Name)
		nbrp.Finalizers = nil
		err = r.Client.Update(ctx, &nbrp)
		if err != nil {
			ctrl.Log.Error(fmt.Errorf("internalError"), "error updating NBRoutingPeer finalizers", "err", err, "namespace", req.Namespace, "name", req.Name)
			return ctrl.Result{}, err
		}
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *NBRoutingPeerReconciler) SetupWithManager(mgr ctrl.Manager) error {
	r.netbird = netbird.New(r.ManagementURL, r.APIKey)

	return ctrl.NewControllerManagedBy(mgr).
		For(&netbirdiov1.NBRoutingPeer{}).
		Named("nbroutingpeer").
		Watches(&appsv1.Deployment{}, handler.EnqueueRequestForOwner(r.Scheme, mgr.GetRESTMapper(), &netbirdiov1.NBRoutingPeer{})).
		Watches(&corev1.Secret{}, handler.EnqueueRequestForOwner(r.Scheme, mgr.GetRESTMapper(), &netbirdiov1.NBRoutingPeer{})).
		Watches(&netbirdiov1.NBGroup{}, handler.EnqueueRequestForOwner(r.Scheme, mgr.GetRESTMapper(), &netbirdiov1.NBRoutingPeer{})).
		Complete(r)
}
