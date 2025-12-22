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

	"github.com/go-logr/logr"
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
	DefaultLabels      map[string]string
	netbird            *netbird.Client
}

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
func (r *NBRoutingPeerReconciler) Reconcile(ctx context.Context, req ctrl.Request) (res ctrl.Result, err error) {
	logger := ctrl.Log.WithName("NBRoutingPeer").WithValues("namespace", req.Namespace, "name", req.Name)
	logger.Info("Reconciling NBRoutingPeer")

	nbrp := &netbirdiov1.NBRoutingPeer{}
	err = r.Get(ctx, req.NamespacedName, nbrp)
	if err != nil {
		if !errors.IsNotFound(err) {
			logger.Error(errKubernetesAPI, "error getting NBRoutingPeer", "err", err)
		}
		return ctrl.Result{RequeueAfter: defaultRequeueAfter}, nil
	}

	originalNBRP := nbrp.DeepCopy()
	defer func() {
		if originalNBRP.DeletionTimestamp != nil && len(nbrp.Finalizers) == 0 {
			return
		}
		if !originalNBRP.Status.Equal(nbrp.Status) {
			err = r.Client.Status().Update(ctx, nbrp)
			if err != nil {
				logger.Error(errKubernetesAPI, "error updating NBRoutingPeer Status", "err", err)
			}
		}
		if err != nil {
			// double check result is nil, otherwise error is not printed
			// and exponential backoff doesn't work properly
			res = ctrl.Result{}
			return
		}
		if !res.Requeue && res.RequeueAfter == 0 {
			res.RequeueAfter = defaultRequeueAfter
		}
	}()

	if nbrp.DeletionTimestamp != nil {
		if len(nbrp.Finalizers) == 0 {
			return ctrl.Result{}, nil
		}
		return r.handleDelete(ctx, req, nbrp, logger)
	}

	logger.Info("NBRoutingPeer: Checking network")
	err = r.handleNetwork(ctx, req, nbrp, logger)
	if err != nil {
		return ctrl.Result{}, err
	}

	logger.Info("NBRoutingPeer: Checking groups")
	nbGroup, result, err := r.handleGroup(ctx, req, nbrp, logger)
	if nbGroup == nil {
		return *result, err
	}

	logger.Info("NBRoutingPeer: Checking setup keys")
	result, err = r.handleSetupKey(ctx, req, nbrp, *nbGroup, logger)
	if result != nil {
		return *result, err
	}

	logger.Info("NBRoutingPeer: Checking network router")
	err = r.handleRouter(ctx, nbrp, *nbGroup, logger)
	if err != nil {
		return ctrl.Result{}, err
	}

	logger.Info("NBRoutingPeer: Checking deployment")
	err = r.handleDeployment(ctx, req, nbrp, logger)
	if err != nil {
		return ctrl.Result{}, err
	}

	nbrp.Status.Conditions = netbirdiov1.NBConditionTrue()
	return ctrl.Result{}, nil
}

// handleDeployment reconcile routing peer Deployment
func (r *NBRoutingPeerReconciler) handleDeployment(ctx context.Context, req ctrl.Request, nbrp *netbirdiov1.NBRoutingPeer, logger logr.Logger) error {
	routingPeerDeployment := appsv1.Deployment{}
	err := r.Client.Get(ctx, req.NamespacedName, &routingPeerDeployment)
	if err != nil && !errors.IsNotFound(err) {
		logger.Error(errKubernetesAPI, "error getting Deployment", "err", err)
		nbrp.Status.Conditions = netbirdiov1.NBConditionFalse("internalError", fmt.Sprintf("error getting Deployment: %v", err))
		return err
	}

	labels := r.DefaultLabels
	for k, v := range nbrp.Spec.Labels {
		labels[k] = v
	}
	podLabels := labels
	podLabels["app.kubernetes.io/name"] = "netbird-router"

	// Create deployment
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
						APIVersion:         netbirdiov1.GroupVersion.Identifier(),
						Kind:               "NBRoutingPeer",
						Name:               nbrp.Name,
						UID:                nbrp.UID,
						BlockOwnerDeletion: util.Ptr(true),
					},
				},
				Labels:      labels,
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
						Labels: podLabels,
					},
					Spec: corev1.PodSpec{
						NodeSelector: nbrp.Spec.NodeSelector,
						Tolerations:  nbrp.Spec.Tolerations,
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
								Resources:    nbrp.Spec.Resources,
								VolumeMounts: nbrp.Spec.VolumeMounts,
							},
						},
						Volumes: nbrp.Spec.Volumes,
					},
				},
			},
		}

		err = r.Client.Create(ctx, &routingPeerDeployment)
		if err != nil {
			logger.Error(errKubernetesAPI, "error creating Deployment", "err", err)
			nbrp.Status.Conditions = netbirdiov1.NBConditionFalse("internalError", fmt.Sprintf("error creating Deployment: %v", err))
			return err
		}
	} else if err == nil {
		updatedDeployment := routingPeerDeployment.DeepCopy()
		updatedDeployment.ObjectMeta.Name = nbrp.Name
		updatedDeployment.ObjectMeta.Namespace = nbrp.Namespace
		updatedDeployment.ObjectMeta.OwnerReferences = []v1.OwnerReference{
			{
				APIVersion:         netbirdiov1.GroupVersion.Identifier(),
				Kind:               "NBRoutingPeer",
				Name:               nbrp.Name,
				UID:                nbrp.UID,
				BlockOwnerDeletion: util.Ptr(true),
			},
		}
		updatedDeployment.ObjectMeta.Labels = labels
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
		updatedDeployment.Spec.Template.Spec.Tolerations = nbrp.Spec.Tolerations
		updatedDeployment.Spec.Template.Spec.NodeSelector = nbrp.Spec.NodeSelector
		updatedDeployment.Spec.Template.ObjectMeta.Labels = podLabels
		updatedDeployment.Spec.Template.Spec.Volumes = nbrp.Spec.Volumes
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
		updatedDeployment.Spec.Template.Spec.Containers[0].Resources = nbrp.Spec.Resources
		updatedDeployment.Spec.Template.Spec.Containers[0].VolumeMounts = nbrp.Spec.VolumeMounts

		patch := client.StrategicMergeFrom(&routingPeerDeployment)
		bs, _ := patch.Data(updatedDeployment)
		// To ensure no useless patching is done to the deployment being watched
		// Minimum patch size is 2 for "{}"
		if len(bs) <= 2 {
			return nil
		}
		err = r.Client.Patch(ctx, updatedDeployment, patch)
		if err != nil {
			logger.Error(errKubernetesAPI, "error updating Deployment", "err", err)
			nbrp.Status.Conditions = netbirdiov1.NBConditionFalse("internalError", fmt.Sprintf("error updating Deployment: %v", err))
			return err
		}
	}

	return err
}

// handleRouter reconcile network routing peer in NetBird management API
func (r *NBRoutingPeerReconciler) handleRouter(ctx context.Context, nbrp *netbirdiov1.NBRoutingPeer, nbGroup netbirdiov1.NBGroup, logger logr.Logger) error {
	// Check NetworkRouter exists
	routers, err := r.netbird.Networks.Routers(*nbrp.Status.NetworkID).List(ctx)

	if err != nil {
		logger.Error(errNetBirdAPI, "error listing network routers", "err", err)
		nbrp.Status.Conditions = netbirdiov1.NBConditionFalse("APIError", fmt.Sprintf("error listing network routers: %v", err))
		return err
	}

	if nbrp.Status.RouterID == nil || len(routers) == 0 {
		if len(routers) > 0 {
			// Router exists but isn't saved to status
			nbrp.Status.RouterID = &routers[0].Id
		} else {
			// Create network router
			router, err := r.netbird.Networks.Routers(*nbrp.Status.NetworkID).Create(ctx, api.NetworkRouterRequest{
				Enabled:    true,
				Masquerade: true,
				Metric:     9999,
				PeerGroups: &[]string{*nbGroup.Status.GroupID},
			})

			if err != nil {
				logger.Error(errNetBirdAPI, "error creating network router", "err", err)
				nbrp.Status.Conditions = netbirdiov1.NBConditionFalse("APIError", fmt.Sprintf("error creating network router: %v", err))
				return err
			}

			nbrp.Status.RouterID = &router.Id
		}
	} else {
		// Ensure network router settings are correct
		if !routers[0].Enabled || !routers[0].Masquerade || routers[0].Metric != 9999 || len(*routers[0].PeerGroups) != 1 || (*routers[0].PeerGroups)[0] != *nbGroup.Status.GroupID {
			_, err = r.netbird.Networks.Routers(*nbrp.Status.NetworkID).Update(ctx, routers[0].Id, api.NetworkRouterRequest{
				Enabled:    true,
				Masquerade: true,
				Metric:     9999,
				PeerGroups: &[]string{*nbGroup.Status.GroupID},
			})

			if err != nil {
				logger.Error(errNetBirdAPI, "error updating network router", "err", err)
				nbrp.Status.Conditions = netbirdiov1.NBConditionFalse("APIError", fmt.Sprintf("error updating network router: %v", err))
				return err
			}
		}
	}

	return nil
}

// handleSetupKey reconcile setup key and regenerate if invalid
func (r *NBRoutingPeerReconciler) handleSetupKey(ctx context.Context, req ctrl.Request, nbrp *netbirdiov1.NBRoutingPeer, nbGroup netbirdiov1.NBGroup, logger logr.Logger) (*ctrl.Result, error) {
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
			logger.Error(errNetBirdAPI, "error creating setup key", "err", err)
			nbrp.Status.Conditions = netbirdiov1.NBConditionFalse("APIError", fmt.Sprintf("error creating setup key: %v", err))
			return &ctrl.Result{}, err
		}

		nbrp.Status.SetupKeyID = &setupKey.Id

		skSecret := corev1.Secret{
			ObjectMeta: v1.ObjectMeta{
				Name:      nbrp.Name,
				Namespace: nbrp.Namespace,
				OwnerReferences: []v1.OwnerReference{
					{
						APIVersion:         netbirdiov1.GroupVersion.Identifier(),
						Kind:               "NBRoutingPeer",
						Name:               nbrp.Name,
						UID:                nbrp.UID,
						BlockOwnerDeletion: util.Ptr(true),
					},
				},
				Labels: r.DefaultLabels,
			},
			StringData: map[string]string{
				"setupKey": setupKey.Key,
			},
		}
		err = r.Client.Create(ctx, &skSecret)
		if errors.IsAlreadyExists(err) {
			err = r.Client.Get(ctx, req.NamespacedName, &skSecret)
			if err != nil {
				logger.Error(errNetBirdAPI, "error getting secret", "err", err)
				return &ctrl.Result{}, err
			}
			skSecret.Data = map[string][]byte{
				"setupKey": []byte(setupKey.Key),
			}
			err = r.Client.Update(ctx, &skSecret)
		}

		if err != nil {
			logger.Error(errKubernetesAPI, "error creating Secret", "err", err)
			nbrp.Status.Conditions = netbirdiov1.NBConditionFalse("internalError", fmt.Sprintf("error creating secret: %v", err))
			return &ctrl.Result{}, err
		}
	} else {
		// Check SetupKey is not revoked
		setupKey, err := r.netbird.SetupKeys.Get(ctx, *nbrp.Status.SetupKeyID)
		if err != nil && !strings.Contains(err.Error(), "not found") {
			logger.Error(errNetBirdAPI, "error getting setup key", "err", err)
			nbrp.Status.Conditions = netbirdiov1.NBConditionFalse("APIError", fmt.Sprintf("error getting setup key: %v", err))
			return &ctrl.Result{}, err
		}

		if (err != nil && strings.Contains(err.Error(), "not found")) || setupKey == nil || setupKey.Revoked {
			if setupKey != nil && setupKey.Revoked {
				err = r.netbird.SetupKeys.Delete(ctx, *nbrp.Status.SetupKeyID)

				if err != nil {
					logger.Error(errNetBirdAPI, "error deleting setup key", "err", err)
					nbrp.Status.Conditions = netbirdiov1.NBConditionFalse("APIError", fmt.Sprintf("error deleting setup key: %v", err))
					return &ctrl.Result{}, err
				}
			}

			nbrp.Status.SetupKeyID = nil
			// Requeue to avoid repeating code
			return &ctrl.Result{Requeue: true}, nil
		}

		// Check if secret is valid
		skSecret := corev1.Secret{}
		err = r.Client.Get(ctx, req.NamespacedName, &skSecret)
		if err != nil && !errors.IsNotFound(err) {
			logger.Error(errKubernetesAPI, "error getting Secret", "err", err)
			nbrp.Status.Conditions = netbirdiov1.NBConditionFalse("internalError", fmt.Sprintf("error getting secret: %v", err))
			return &ctrl.Result{}, err
		}

		if _, ok := skSecret.Data["setupKey"]; errors.IsNotFound(err) || !ok {
			// Someone deleted setup key secret
			// Revoke SK from NetBird and re-generate
			err = r.netbird.SetupKeys.Delete(ctx, *nbrp.Status.SetupKeyID)

			if err != nil {
				logger.Error(errNetBirdAPI, "error deleting setup key", "err", err)
				nbrp.Status.Conditions = netbirdiov1.NBConditionFalse("APIError", fmt.Sprintf("error deleting setup key: %v", err))
				return &ctrl.Result{}, err
			}

			nbrp.Status.SetupKeyID = nil

			nbrp.Status.Conditions = netbirdiov1.NBConditionFalse("Gone", "generated secret was deleted")
			// Requeue to avoid repeating code
			return &ctrl.Result{Requeue: true}, nil
		}
	}

	return nil, nil
}

// handleGroup creates/updates NBGroup for routing peer
func (r *NBRoutingPeerReconciler) handleGroup(ctx context.Context, req ctrl.Request, nbrp *netbirdiov1.NBRoutingPeer, logger logr.Logger) (*netbirdiov1.NBGroup, *ctrl.Result, error) {
	networkName := r.ClusterName
	if r.NamespacedNetworks {
		networkName += "-" + req.Namespace
	}

	// Check if NetBird Group exists
	nbGroup := netbirdiov1.NBGroup{}
	err := r.Client.Get(ctx, req.NamespacedName, &nbGroup)
	if err != nil && !errors.IsNotFound(err) {
		logger.Error(errKubernetesAPI, "error getting NBGroup", "err", err)
		nbrp.Status.Conditions = netbirdiov1.NBConditionFalse("internalError", fmt.Sprintf("error getting NBGroup: %v", err))
		return nil, &ctrl.Result{}, err
	}

	if errors.IsNotFound(err) {
		nbGroup = netbirdiov1.NBGroup{
			ObjectMeta: v1.ObjectMeta{
				Name:      nbrp.Name,
				Namespace: nbrp.Namespace,
				OwnerReferences: []v1.OwnerReference{
					{
						APIVersion:         netbirdiov1.GroupVersion.Identifier(),
						Kind:               "NBRoutingPeer",
						Name:               nbrp.Name,
						UID:                nbrp.UID,
						BlockOwnerDeletion: util.Ptr(true),
					},
				},
				Finalizers: []string{"netbird.io/group-cleanup", "netbird.io/routing-peer-cleanup"},
				Labels:     r.DefaultLabels,
			},
			Spec: netbirdiov1.NBGroupSpec{
				Name: networkName,
			},
		}

		err = r.Client.Create(ctx, &nbGroup)

		if err != nil {
			logger.Error(errKubernetesAPI, "error creating NBGroup", "err", err)
			nbrp.Status.Conditions = netbirdiov1.NBConditionFalse("internalError", fmt.Sprintf("error creating NBGroup: %v", err))
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

// handleNetwork Create/Update NetBird Network
func (r *NBRoutingPeerReconciler) handleNetwork(ctx context.Context, req ctrl.Request, nbrp *netbirdiov1.NBRoutingPeer, logger logr.Logger) error {
	networkName := r.ClusterName
	if r.NamespacedNetworks {
		networkName += "-" + req.Namespace
	}

	if nbrp.Status.NetworkID == nil {
		// Check if network exists
		networks, err := r.netbird.Networks.List(ctx)
		if err != nil {
			logger.Error(errNetBirdAPI, "error listing networks", "err", err)
			nbrp.Status.Conditions = netbirdiov1.NBConditionFalse("APIError", fmt.Sprintf("error listing networks: %v", err))
			return err
		}
		var network *api.Network
		for _, n := range networks {
			if n.Name == networkName {
				logger.Info("network already exists", "network-id", n.Id)
				network = &n
			}
		}

		if network != nil {
			nbrp.Status.NetworkID = &network.Id
		} else {
			logger.Info("creating network", "name", networkName)
			network, err := r.netbird.Networks.Create(ctx, api.NetworkRequest{
				Name:        networkName,
				Description: &networkDescription,
			})
			if err != nil {
				logger.Error(errNetBirdAPI, "error creating network", "err", err)
				nbrp.Status.Conditions = netbirdiov1.NBConditionFalse("APIError", fmt.Sprintf("error creating network: %v", err))
				return err
			}

			nbrp.Status.NetworkID = &network.Id
		}
	}
	return nil
}

func (r *NBRoutingPeerReconciler) handleDelete(ctx context.Context, req ctrl.Request, nbrp *netbirdiov1.NBRoutingPeer, logger logr.Logger) (ctrl.Result, error) {
	nbDeployment := appsv1.Deployment{}
	err := r.Client.Get(ctx, req.NamespacedName, &nbDeployment)
	if err != nil && !errors.IsNotFound(err) {
		logger.Error(errKubernetesAPI, "error getting Deployment", "err", err)
		return ctrl.Result{}, err
	}
	if err == nil {
		err = r.Client.Delete(ctx, &nbDeployment)
		if err != nil {
			logger.Error(errKubernetesAPI, "error deleting Deployment", "err", err)
			return ctrl.Result{}, err
		}
	}

	if nbrp.Status.SetupKeyID != nil {
		logger.Info("Deleting setup key", "id", *nbrp.Status.SetupKeyID)
		err = r.netbird.SetupKeys.Delete(ctx, *nbrp.Status.SetupKeyID)
		if err != nil && !strings.Contains(err.Error(), "not found") {
			logger.Error(errNetBirdAPI, "error deleting setupKey", "err", err)
			return ctrl.Result{}, err
		}

		setupKeyID := *nbrp.Status.SetupKeyID
		nbrp.Status.SetupKeyID = nil
		logger.Info("Setup key deleted", "id", setupKeyID)
	}

	nbGroup := netbirdiov1.NBGroup{}
	err = r.Client.Get(ctx, req.NamespacedName, &nbGroup)
	if err != nil && !errors.IsNotFound(err) {
		logger.Error(errKubernetesAPI, "error getting NBGroup", "err", err)
		return ctrl.Result{}, err
	}

	if nbrp.Status.NetworkID != nil {
		nbResourceList := netbirdiov1.NBResourceList{}
		err = r.Client.List(ctx, &nbResourceList)
		if err != nil {
			logger.Error(errKubernetesAPI, "error listing NBResource", "err", err)
			return ctrl.Result{}, err
		}

		for _, nbrs := range nbResourceList.Items {
			if nbrs.Spec.NetworkID == *nbrp.Status.NetworkID {
				logger.Info("Deleting NBResource", "namespace", nbrs.Namespace, "name", nbrs.Name)
				err = r.Client.Delete(ctx, &nbrs)
				if err != nil {
					logger.Error(errKubernetesAPI, "error deleting NBResource", "err", err)
					return ctrl.Result{}, err
				}
			}
		}

		if len(nbResourceList.Items) == 0 {
			logger.Info("Deleting NetBird Network", "id", *nbrp.Status.NetworkID)
			err = r.netbird.Networks.Delete(ctx, *nbrp.Status.NetworkID)
			if err != nil && !strings.Contains(err.Error(), "not found") {
				logger.Error(errNetBirdAPI, "error deleting Network", "err", err)
				return ctrl.Result{}, err
			}

			nbrp.Status.NetworkID = nil
			nbrp.Status.RouterID = nil
		}
	}

	if nbGroup.Spec.Name != "" && util.Contains(nbGroup.Finalizers, "netbird.io/routing-peer-cleanup") {
		nbGroup.Finalizers = util.Without(nbGroup.Finalizers, "netbird.io/routing-peer-cleanup")
		logger.Info("Removing netbird.io/routing-peer-cleanup finalizer NBGroup", "namespace", nbGroup.Namespace, "name", nbGroup.Name)
		err = r.Client.Update(ctx, &nbGroup)
		if err != nil {
			logger.Error(errKubernetesAPI, "error deleting NBGroup", "err", err)
			return ctrl.Result{}, err
		}
	}

	if nbrp.Status.NetworkID != nil {
		return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
	}

	if len(nbrp.Finalizers) > 0 {
		logger.Info("Removing finalizers", "namespace", nbrp.Namespace, "name", nbrp.Name)
		nbrp.Finalizers = nil
		err = r.Client.Update(ctx, nbrp)
		if err != nil {
			logger.Error(errKubernetesAPI, "error updating NBRoutingPeer finalizers", "err", err)
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
