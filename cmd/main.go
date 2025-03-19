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
	"flag"
	"fmt"
	"os"
	"path/filepath"

	// Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
	// to ensure that exec-entrypoint and run can make use of them.
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/certwatcher"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/webhook"

	corev1 "k8s.io/api/core/v1"

	netbirdiov1 "github.com/netbirdio/kubernetes-operator/api/v1"
	"github.com/netbirdio/kubernetes-operator/internal/controller"
	webhookk8siov1 "github.com/netbirdio/kubernetes-operator/internal/webhook/v1"
	webhooknetbirdiov1 "github.com/netbirdio/kubernetes-operator/internal/webhook/v1"
	// +kubebuilder:scaffold:imports
)

const (
	inClusterNamespacePath = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))

	utilruntime.Must(netbirdiov1.AddToScheme(scheme))
	utilruntime.Must(corev1.AddToScheme(scheme))
	// +kubebuilder:scaffold:scheme
}

// nolint:gocyclo
func main() {
	// NB Specific flags
	var (
		managementURL      string
		clientImage        string
		clusterName        string
		namespacedNetworks bool
		clusterDNS         string
		netbirdAPIKey      string
	)
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

	// Controller generic flags
	var (
		metricsAddr          string
		webhookCertPath      string
		webhookCertName      string
		webhookCertKey       string
		enableLeaderElection bool
		probeAddr            string
		enableHTTP2          bool
		enableWebhooks       bool
		tlsOpts              []func(*tls.Config)
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
	flag.BoolVar(&enableHTTP2, "enable-http2", false,
		"If set, HTTP/2 will be enabled for the metrics and webhook servers")
	flag.BoolVar(&enableWebhooks, "enable-webhooks", true, "If set, enable Mutating and Validating webhooks.")
	opts := zap.Options{
		Development: true,
	}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	disableHTTP2 := func(c *tls.Config) {
		setupLog.Info("disabling http/2")
		c.NextProtos = []string{"http/1.1"}
	}

	if !enableHTTP2 {
		tlsOpts = append(tlsOpts, disableHTTP2)
	}

	// Create watcher for webhooks certificates
	var webhookCertWatcher *certwatcher.CertWatcher

	// Initial webhook TLS options
	webhookTLSOpts := tlsOpts

	if len(webhookCertPath) > 0 {
		setupLog.Info("Initializing webhook certificate watcher using provided certificates",
			"webhook-cert-path", webhookCertPath, "webhook-cert-name", webhookCertName, "webhook-cert-key", webhookCertKey)

		var err error
		webhookCertWatcher, err = certwatcher.New(
			filepath.Join(webhookCertPath, webhookCertName),
			filepath.Join(webhookCertPath, webhookCertKey),
		)
		if err != nil {
			setupLog.Error(err, "Failed to initialize webhook certificate watcher")
			os.Exit(1)
		}

		webhookTLSOpts = append(webhookTLSOpts, func(config *tls.Config) {
			config.GetCertificate = webhookCertWatcher.GetCertificate
		})
	}

	webhookServer := webhook.NewServer(webhook.Options{
		TLSOpts: webhookTLSOpts,
	})

	metricsServerOptions := metricsserver.Options{
		BindAddress: metricsAddr,
		TLSOpts:     tlsOpts,
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsServerOptions,
		WebhookServer:          webhookServer,
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       "operator.netbird.io",
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	nbSetupKeyController := &controller.NBSetupKeyReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}
	if err = nbSetupKeyController.SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "NBSetupKey")
		os.Exit(1)
	}

	if enableWebhooks {
		if err = webhookk8siov1.SetupPodWebhookWithManager(mgr, managementURL, clientImage); err != nil {
			setupLog.Error(err, "unable to create webhook", "webhook", "Pod")
			os.Exit(1)
		}

		if err = webhooknetbirdiov1.SetupNBSetupKeyWebhookWithManager(mgr); err != nil {
			setupLog.Error(err, "unable to create webhook", "webhook", "NBSetupKey")
			os.Exit(1)
		}
	}
	if len(netbirdAPIKey) > 0 {
		if err = (&controller.NBRoutingPeerReconciler{
			Client:             mgr.GetClient(),
			Scheme:             mgr.GetScheme(),
			ClientImage:        clientImage,
			ClusterName:        clusterName,
			APIKey:             netbirdAPIKey,
			ManagementURL:      managementURL,
			NamespacedNetworks: namespacedNetworks,
		}).SetupWithManager(mgr); err != nil {
			setupLog.Error(err, "unable to create controller", "controller", "NBRoutingPeer")
			os.Exit(1)
		}

		controllerNamespace, err := getInClusterNamespace()
		if err != nil {
			setupLog.Error(err, "unable to get main namespace", "controller", "Service")
			os.Exit(1)
		}

		if err = (&controller.ServiceReconciler{
			Client:              mgr.GetClient(),
			Scheme:              mgr.GetScheme(),
			ClusterName:         clusterName,
			ClusterDNS:          clusterDNS,
			NamespacedNetworks:  namespacedNetworks,
			ControllerNamespace: controllerNamespace,
		}).SetupWithManager(mgr); err != nil {
			setupLog.Error(err, "unable to create controller", "controller", "Service")
			os.Exit(1)
		}

		if err = (&controller.NBResourceReconciler{
			Client:        mgr.GetClient(),
			Scheme:        mgr.GetScheme(),
			APIKey:        netbirdAPIKey,
			ManagementURL: managementURL,
		}).SetupWithManager(mgr); err != nil {
			setupLog.Error(err, "unable to create controller", "controller", "NBResource")
			os.Exit(1)
		}

		if err = (&controller.NBGroupReconciler{
			Client:        mgr.GetClient(),
			Scheme:        mgr.GetScheme(),
			APIKey:        netbirdAPIKey,
			ManagementURL: managementURL,
		}).SetupWithManager(mgr); err != nil {
			setupLog.Error(err, "unable to create controller", "controller", "NBGroup")
			os.Exit(1)
		}

		if err = (&controller.NBPolicyReconciler{
			Client:        mgr.GetClient(),
			Scheme:        mgr.GetScheme(),
			APIKey:        netbirdAPIKey,
			ManagementURL: managementURL,
		}).SetupWithManager(mgr); err != nil {
			setupLog.Error(err, "unable to create controller", "controller", "NBPolicy")
			os.Exit(1)
		}

		if enableWebhooks {
			if err = webhooknetbirdiov1.SetupNBResourceWebhookWithManager(mgr); err != nil {
				setupLog.Error(err, "unable to create webhook", "webhook", "NBResource")
				os.Exit(1)
			}

			if err = webhooknetbirdiov1.SetupNBRoutingPeerWebhookWithManager(mgr); err != nil {
				setupLog.Error(err, "unable to create webhook", "webhook", "NBRoutingPeer")
				os.Exit(1)
			}

			if err = webhooknetbirdiov1.SetupNBGroupWebhookWithManager(mgr); err != nil {
				setupLog.Error(err, "unable to create webhook", "webhook", "NBGroup")
				os.Exit(1)
			}
		}
	} else {
		setupLog.Info("netbird API key not provided, ingress capabilities disabled")
	}
	// +kubebuilder:scaffold:builder

	if webhookCertWatcher != nil {
		setupLog.Info("Adding webhook certificate watcher to manager")
		if err := mgr.Add(webhookCertWatcher); err != nil {
			setupLog.Error(err, "unable to add webhook certificate watcher to manager")
			os.Exit(1)
		}
	}

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	setupLog.Info("starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}

func getInClusterNamespace() (string, error) {
	// Check whether the namespace file exists.
	// If not, we are not running in cluster so can't guess the namespace.
	if _, err := os.Stat(inClusterNamespacePath); os.IsNotExist(err) {
		return "", fmt.Errorf("not running in-cluster, please specify LeaderElectionNamespace")
	} else if err != nil {
		return "", fmt.Errorf("error checking namespace file: %w", err)
	}

	// Load the namespace file and return its content
	namespace, err := os.ReadFile(inClusterNamespacePath)
	if err != nil {
		return "", fmt.Errorf("error reading namespace file: %w", err)
	}
	return string(namespace), nil
}
