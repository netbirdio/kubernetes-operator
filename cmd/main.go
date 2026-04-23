/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	// Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
	// to ensure that exec-entrypoint and run can make use of them.
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	netbird "github.com/netbirdio/netbird/shared/management/client/rest"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/certwatcher"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"

	netbirdiov1 "github.com/netbirdio/kubernetes-operator/api/v1"
	netbirdiov1alpha1 "github.com/netbirdio/kubernetes-operator/api/v1alpha1"
	"github.com/netbirdio/kubernetes-operator/internal/controller"
	webhooknetbirdiov1 "github.com/netbirdio/kubernetes-operator/internal/webhook/v1"
	// +kubebuilder:scaffold:imports
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))

	utilruntime.Must(netbirdiov1.AddToScheme(scheme))
	utilruntime.Must(corev1.AddToScheme(scheme))
	utilruntime.Must(gatewayv1.Install(scheme))
	utilruntime.Must(gatewayv1alpha2.Install(scheme))
	utilruntime.Must(netbirdiov1alpha1.AddToScheme(scheme))
	// +kubebuilder:scaffold:scheme
}

// nolint:gocyclo
func main() {
	// NB Specific flags
	var (
		runtimeNamespace             string
		managementURL                string
		clientImage                  string
		clusterName                  string
		namespacedNetworks           bool
		clusterDNS                   string
		netbirdAPIKey                string
		allowAutomaticPolicyCreation bool
		defaultLabels                string
		gatewayAPIEnabled            bool
	)
	flag.StringVar(&runtimeNamespace, "runtime-namespace", "", "Namespace the controller is running in")
	flag.StringVar(&managementURL, "netbird-management-url", "https://api.netbird.io", "Management service URL")
	flag.StringVar(&clientImage, "netbird-client-image", "netbirdio/netbird:latest", "Image for netbird client container")
	flag.StringVar(
		&clusterName,
		"cluster-name",
		"kubernetes",
		"User-friendly name for kubernetes cluster for NetBird resource creation",
	)
	flag.BoolVar(
		&namespacedNetworks,
		"namespaced-networks",
		false,
		"Create NetBird Network per namespace, set to true if a NetworkPolicy exists that would require this",
	)
	flag.StringVar(&clusterDNS, "cluster-dns", "svc.cluster.local", "Cluster DNS name")
	flag.StringVar(&netbirdAPIKey, "netbird-api-key", "", "API key for NetBird API operations")
	flag.BoolVar(
		&allowAutomaticPolicyCreation,
		"allow-automatic-policy-creation",
		false,
		"Allow creating NBPolicy resources from annotations on Services",
	)
	flag.StringVar(
		&defaultLabels,
		"default-labels",
		"",
		"Default labels used for all resources, in format key=value,key=value",
	)
	flag.BoolVar(&gatewayAPIEnabled, "gateway-api-enabled", false, "When true Gateway API resources will be reconciled.")

	// Controller generic flags
	var (
		metricsAddr          string
		webhookCertPath      string
		webhookCertName      string
		webhookCertKey       string
		enableLeaderElection bool
		probeAddr            string
		enableWebhooks       bool
	)

	flag.StringVar(&metricsAddr, "metrics-bind-address", "0", "The address the metrics endpoint binds to. "+
		"Use :8443 for HTTPS or :8080 for HTTP, or leave as 0 to disable the metrics service.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	flag.StringVar(&webhookCertPath, "webhook-cert-path", "", "The directory that contains the webhook certificate.")
	flag.StringVar(&webhookCertName, "webhook-cert-name", "tls.crt", "The name of the webhook certificate file.")
	flag.StringVar(&webhookCertKey, "webhook-cert-key", "tls.key", "The name of the webhook key file.")
	flag.BoolVar(&enableWebhooks, "enable-webhooks", true, "If set, enable Mutating and Validating webhooks.")
	opts := zap.Options{
		Development: true,
	}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	runtimeNamespace, err := getRuntimeNamespace(runtimeNamespace)
	if err != nil {
		setupLog.Error(err, "unable to get runtime namespace")
		os.Exit(1)
	}

	defaultLabelsMap := make(map[string]string)
	if defaultLabels != "" {
		for s := range strings.SplitSeq(defaultLabels, ",") {
			kv := strings.Split(s, "=")
			if len(kv) != 2 {
				panic(fmt.Errorf("invalid label format: %s", s))
			}
			defaultLabelsMap[kv[0]] = kv[1]
		}
	}

	// Setup webhook server.
	type TLSOption = func(*tls.Config)
	certWatcher, tlsOpt, err := func() (*certwatcher.CertWatcher, TLSOption, error) {
		if webhookCertPath == "" {
			return nil, nil, nil
		}

		certWatcher, err := certwatcher.New(
			filepath.Join(webhookCertPath, webhookCertName),
			filepath.Join(webhookCertPath, webhookCertKey),
		)
		if err != nil {
			return nil, nil, err
		}

		tlsOpt := func(config *tls.Config) {
			config.GetCertificate = certWatcher.GetCertificate
		}

		return certWatcher, tlsOpt, nil
	}()
	if err != nil {
		setupLog.Error(err, "Failed to initialize webhook certificate watcher")
		os.Exit(1)
	}
	webhookServer := webhook.NewServer(webhook.Options{TLSOpts: []TLSOption{tlsOpt}})

	// Setup controller manager.
	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme: scheme,
		Metrics: metricsserver.Options{
			BindAddress: metricsAddr,
		},
		Client: client.Options{
			FieldOwner: "netbird-operator",
		},
		WebhookServer:           webhookServer,
		HealthProbeBindAddress:  probeAddr,
		LeaderElectionNamespace: runtimeNamespace,
		LeaderElection:          enableLeaderElection,
		LeaderElectionID:        "operator.netbird.io",
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	nbSetupKeyController := &controller.NBSetupKeyReconciler{
		Client: mgr.GetClient(),
	}
	if err = nbSetupKeyController.SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "NBSetupKey")
		os.Exit(1)
	}

	if enableWebhooks {
		if err = webhooknetbirdiov1.SetupPodWebhookWithManager(mgr, managementURL, clientImage); err != nil {
			setupLog.Error(err, "unable to create webhook", "webhook", "Pod")
			os.Exit(1)
		}
	}

	if len(netbirdAPIKey) > 0 {
		nbClient := netbird.NewWithOptions(
			netbird.WithManagementURL(managementURL),
			netbird.WithBearerToken(netbirdAPIKey),
			netbird.WithUserAgent("netbird-operator"),
		)

		if err = (&controller.NBRoutingPeerReconciler{
			Client:             mgr.GetClient(),
			Netbird:            nbClient,
			ClientImage:        clientImage,
			ClusterName:        clusterName,
			ManagementURL:      managementURL,
			NamespacedNetworks: namespacedNetworks,
			DefaultLabels:      defaultLabelsMap,
		}).SetupWithManager(mgr); err != nil {
			setupLog.Error(err, "unable to create controller", "controller", "NBRoutingPeer")
			os.Exit(1)
		}

		if err = (&controller.ServiceReconciler{
			Client:              mgr.GetClient(),
			ClusterName:         clusterName,
			ClusterDNS:          clusterDNS,
			NamespacedNetworks:  namespacedNetworks,
			ControllerNamespace: runtimeNamespace,
			DefaultLabels:       defaultLabelsMap,
		}).SetupWithManager(mgr); err != nil {
			setupLog.Error(err, "unable to create controller", "controller", "Service")
			os.Exit(1)
		}

		if err = (&controller.NBResourceReconciler{
			Client:                       mgr.GetClient(),
			Netbird:                      nbClient,
			AllowAutomaticPolicyCreation: allowAutomaticPolicyCreation,
			ClusterName:                  clusterName,
			DefaultLabels:                defaultLabelsMap,
		}).SetupWithManager(mgr); err != nil {
			setupLog.Error(err, "unable to create controller", "controller", "NBResource")
			os.Exit(1)
		}

		if err = (&controller.NBGroupReconciler{
			Client:  mgr.GetClient(),
			Netbird: nbClient,
		}).SetupWithManager(mgr); err != nil {
			setupLog.Error(err, "unable to create controller", "controller", "NBGroup")
			os.Exit(1)
		}

		if err = (&controller.NBPolicyReconciler{
			Client:  mgr.GetClient(),
			Netbird: nbClient,
		}).SetupWithManager(mgr); err != nil {
			setupLog.Error(err, "unable to create controller", "controller", "NBPolicy")
			os.Exit(1)
		}

		if enableWebhooks {
			if err = webhooknetbirdiov1.SetupNBGroupWebhookWithManager(mgr); err != nil {
				setupLog.Error(err, "unable to create webhook", "webhook", "NBGroup")
				os.Exit(1)
			}
		}

		if err := (&controller.SetupKeyReconciler{
			Client:  mgr.GetClient(),
			Netbird: nbClient,
		}).SetupWithManager(mgr); err != nil {
			setupLog.Error(err, "Failed to create controller", "controller", "SetupKey")
			os.Exit(1)
		}
		if err := (&controller.GroupReconciler{
			Client:  mgr.GetClient(),
			Netbird: nbClient,
		}).SetupWithManager(mgr); err != nil {
			setupLog.Error(err, "Failed to create controller", "controller", "Group")
			os.Exit(1)
		}
		if err := (&controller.NetworkRouterReconciler{
			Client:        mgr.GetClient(),
			Netbird:       nbClient,
			ClientImage:   clientImage,
			ManagementURL: managementURL,
		}).SetupWithManager(mgr); err != nil {
			setupLog.Error(err, "Failed to create controller", "controller", "NetworkRouter")
			os.Exit(1)
		}
		if err := (&controller.NetworkResourceReconciler{
			Client:  mgr.GetClient(),
			Netbird: nbClient,
		}).SetupWithManager(mgr); err != nil {
			setupLog.Error(err, "Failed to create controller", "controller", "NetworkResource")
			os.Exit(1)
		}

		if gatewayAPIEnabled {
			if err = (&controller.GatewayClassReconciler{
				Client: mgr.GetClient(),
			}).SetupWithManager(mgr); err != nil {
				setupLog.Error(err, "unable to create controller", "controller", "GatewayClass")
				os.Exit(1)
			}
			if err = (&controller.GatewayReconciler{
				Client: mgr.GetClient(),
			}).SetupWithManager(mgr); err != nil {
				setupLog.Error(err, "unable to create controller", "controller", "Gateway")
				os.Exit(1)
			}
			if err = (&controller.HTTPRouteReconciler{
				Client:  mgr.GetClient(),
				Netbird: nbClient,
			}).SetupWithManager(mgr); err != nil {
				setupLog.Error(err, "unable to create controller", "controller", "HTTPRoute")
				os.Exit(1)
			}
			if err = (&controller.TCPRouteReconciler{
				Client: mgr.GetClient(),
			}).SetupWithManager(mgr); err != nil {
				setupLog.Error(err, "unable to create controller", "controller", "TCPRoute")
				os.Exit(1)
			}
		}
	} else {
		setupLog.Info("netbird API key not provided, ingress capabilities disabled")
	}
	// +kubebuilder:scaffold:builder

	if certWatcher != nil {
		setupLog.Info("Adding webhook certificate watcher to manager")
		if err := mgr.Add(certWatcher); err != nil {
			setupLog.Error(err, "unable to add webhook certificate watcher to manager")
			os.Exit(1)
		}
	}

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	readyChecker := healthz.Ping
	if certWatcher != nil {
		readyChecker = mgr.GetWebhookServer().StartedChecker()
	}
	if err := mgr.AddReadyzCheck("readyz", readyChecker); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	setupLog.Info("starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}

func getRuntimeNamespace(runtimeNamespace string) (string, error) {
	if runtimeNamespace != "" {
		return runtimeNamespace, nil
	}
	inClusterNamespacePath := "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
	b, err := os.ReadFile(inClusterNamespacePath)
	if errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("not running in-cluster, runtime namespace needs to be set")
	}
	if err != nil {
		return "", fmt.Errorf("error reading namespace file: %w", err)
	}
	return string(b), nil
}
