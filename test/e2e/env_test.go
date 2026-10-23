// SPDX-License-Identifier: BSD-3-Clause

//go:build e2e

package e2e

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kruntime "k8s.io/apimachinery/pkg/runtime"
	kruntimeutil "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gwv1 "sigs.k8s.io/gateway-api/apis/v1"
	gwv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"
	"sigs.k8s.io/kind/pkg/cluster"

	nbv1 "github.com/netbirdio/kubernetes-operator/api/v1"
	nbv1alpha1 "github.com/netbirdio/kubernetes-operator/api/v1alpha1"
	"github.com/netbirdio/netbird/e2e/harness"
	netbird "github.com/netbirdio/netbird/shared/management/client/rest"
)

const (
	// managementURL is how everything in the cluster reaches management: the
	// harness's exposed address. It resolves only on the deployment's Docker
	// network, which is why the Kind nodes are created on that network.
	managementURL = "http://netbird.local:8080"

	netbirdNamespace = "netbird"
	apiKeySecretName = "netbird-mgmt-api-key"
	kindClusterName  = "netbird-operator-e2e"

	// The node image has to match the Kind version in go.mod, which is why these
	// images carry it in their tag.
	defaultKindNodeImage = "ghcr.io/spegel-org/test-images/kind-node:v0.32.0-v1.37.0"

	// Kind reads the network to create nodes on from this variable, and only
	// from this variable.
	kindNetworkEnv = "KIND_EXPERIMENTAL_DOCKER_NETWORK"

	envOperatorImage = "IMG_REF"
	envKindNodeImage = "NB_E2E_KIND_NODE_IMAGE"
	envSkipUpgrade   = "NB_E2E_SKIP_UPGRADE"
	envKeep          = "NB_E2E_KEEP"
	envArtifactsDir  = "NB_E2E_ARTIFACTS_DIR"

	// Building the server and client images from source dominates a cold run.
	bootstrapTimeout = 40 * time.Minute
)

// testEnv is the deployment and cluster TestMain brought up. Tests reach it
// through requireEnv.
var testEnv *environment

// environment is a running NetBird deployment and a Kind cluster attached to its
// network, with the operator under test installed.
type environment struct {
	srv *harness.Combined
	// nb is the management API as the account owner.
	nb *netbird.Client
	// clientImage is the NetBird client the operator deploys for routing peers
	// and sidecars, built from the pinned NetBird revision.
	clientImage string

	kind       *cluster.Provider
	kubeconfig string
	k8s        client.Client
	clientset  kubernetes.Interface

	workDir string

	// The network fixtures, and the peer outside the cluster that checks access
	// through them, start on first use, so a run that does not route traffic
	// does not pay for them.
	networkOnce sync.Once
	network     *networkFixtures
	networkErr  error

	// The reverse proxy starts on first use too.
	proxyOnce sync.Once
	proxy     *harness.Proxy
	proxyErr  error

	// upgrade holds what the published operator created before the upgrade;
	// nil when the run skipped the upgrade.
	upgrade *upgradeFixtures
}

// bootstrap brings the environment up. On error it returns whatever it got as
// far as, so the caller can still collect logs and tear it down.
func bootstrap(ctx context.Context) (*environment, error) {
	operatorImage := os.Getenv(envOperatorImage)
	if operatorImage == "" {
		return nil, fmt.Errorf("%s must name the operator image under test; make test-e2e builds it and sets it", envOperatorImage)
	}
	workDir, err := os.MkdirTemp("", "netbird-operator-e2e-*")
	if err != nil {
		return nil, fmt.Errorf("create work dir: %w", err)
	}
	env := &environment{workDir: workDir}

	log.Print("e2e: starting the NetBird deployment")
	env.srv, err = harness.StartCombined(ctx)
	if err != nil {
		return env, fmt.Errorf("start the NetBird deployment: %w", err)
	}
	pat, err := env.srv.Bootstrap(ctx)
	if err != nil {
		return env, fmt.Errorf("activate the account through /api/setup: %w", err)
	}
	env.nb = netbird.New(env.srv.BaseURL, pat)

	log.Print("e2e: building the NetBird client image")
	env.clientImage, err = harness.ClientImage(ctx)
	if err != nil {
		return env, fmt.Errorf("build the NetBird client image: %w", err)
	}

	log.Print("e2e: creating the Kind cluster")
	if err := env.createCluster(); err != nil {
		return env, err
	}
	if err := env.loadImages(ctx, operatorImage, env.clientImage); err != nil {
		return env, err
	}
	if err := env.checkManagementReachable(ctx); err != nil {
		return env, err
	}
	if err := env.installGatewayAPI(ctx); err != nil {
		return env, err
	}

	log.Print("e2e: installing the operator")
	if err := env.installOperator(ctx, operatorImage, pat); err != nil {
		return env, err
	}
	return env, nil
}

// createCluster creates the Kind cluster on the deployment's Docker network.
func (e *environment) createCluster() error {
	nodeImage := os.Getenv(envKindNodeImage)
	if nodeImage == "" {
		nodeImage = defaultKindNodeImage
	}
	e.kubeconfig = filepath.Join(e.workDir, "kubeconfig")
	e.kind = cluster.NewProvider()

	// A cluster left behind by an interrupted run holds the name, and its nodes
	// are attached to a network that no longer exists.
	if err := e.kind.Delete(kindClusterName, e.kubeconfig); err != nil {
		return fmt.Errorf("delete a leftover Kind cluster: %w", err)
	}

	prev, hadPrev := os.LookupEnv(kindNetworkEnv)
	if err := os.Setenv(kindNetworkEnv, e.srv.NetworkName()); err != nil {
		return err
	}
	err := e.kind.Create(kindClusterName,
		cluster.CreateWithNodeImage(nodeImage),
		cluster.CreateWithKubeconfigPath(e.kubeconfig),
		cluster.CreateWithWaitForReady(3*time.Minute),
		cluster.CreateWithDisplayUsage(false),
		cluster.CreateWithDisplaySalutation(false),
	)
	if hadPrev {
		_ = os.Setenv(kindNetworkEnv, prev)
	} else {
		_ = os.Unsetenv(kindNetworkEnv)
	}
	if err != nil {
		return fmt.Errorf("create Kind cluster from %s: %w", nodeImage, err)
	}

	cfg, err := clientcmd.BuildConfigFromFlags("", e.kubeconfig)
	if err != nil {
		return fmt.Errorf("load kubeconfig: %w", err)
	}
	e.k8s, err = client.New(cfg, client.Options{Scheme: newScheme()})
	if err != nil {
		return fmt.Errorf("create Kubernetes client: %w", err)
	}
	e.clientset, err = kubernetes.NewForConfig(cfg)
	if err != nil {
		return fmt.Errorf("create Kubernetes clientset: %w", err)
	}
	return nil
}

// checkManagementReachable runs a pod that fetches the management API from
// inside the cluster. Every agent the operator deploys depends on this path, and
// without the check its absence shows up much later as peers that never
// connect, with nothing pointing at DNS or the network.
func (e *environment) checkManagementReachable(ctx context.Context) error {
	script := fmt.Sprintf("wget -q -O /dev/null -T 5 %s/api/instance", managementURL)
	if err := e.runCheck(ctx, metav1.NamespaceDefault, "management-reachable", script); err != nil {
		return fmt.Errorf("pods in the cluster cannot reach management at %s: %w", managementURL, err)
	}
	return nil
}

// runCheck runs a shell command in a pod, from the client image, until it
// succeeds or about two minutes pass, and returns the pod's log if it never
// does. It is how a test checks what a workload inside the cluster can reach.
func (e *environment) runCheck(ctx context.Context, namespace, name, script string) error {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: corev1.PodSpec{
			RestartPolicy: corev1.RestartPolicyNever,
			Containers: []corev1.Container{
				{
					Name:    "check",
					Image:   e.clientImage,
					Command: []string{"sh", "-c", fmt.Sprintf("for i in $(seq 40); do %s && exit 0; sleep 3; done; exit 1", script)},
				},
			},
		},
	}
	// A namespace's default service account appears a moment after the
	// namespace, and admission refuses the pod until it does.
	var createErr error
	err := wait.PollUntilContextTimeout(ctx, 2*time.Second, time.Minute, true, func(ctx context.Context) (bool, error) {
		createErr = e.k8s.Create(ctx, pod)
		return createErr == nil, nil
	})
	if err != nil {
		return fmt.Errorf("create pod %s: %w (%w)", name, err, createErr)
	}
	defer func() {
		_ = e.k8s.Delete(context.Background(), pod)
	}()

	var phase corev1.PodPhase
	err = wait.PollUntilContextTimeout(ctx, 2*time.Second, 4*time.Minute, true, func(ctx context.Context) (bool, error) {
		if err := e.k8s.Get(ctx, client.ObjectKeyFromObject(pod), pod); err != nil {
			return false, err
		}
		phase = pod.Status.Phase
		return phase == corev1.PodSucceeded || phase == corev1.PodFailed, nil
	})
	if err == nil && phase == corev1.PodSucceeded {
		return nil
	}
	return fmt.Errorf("%q never succeeded in pod %s (phase %q, %v); log:\n%s",
		script, name, phase, err, e.podLogTail(context.Background(), namespace, name, "check", 20))
}

// teardown removes the cluster before the deployment: the Kind nodes sit on the
// deployment's network, which cannot be removed while they are attached.
func (e *environment) teardown() {
	if envBool(envKeep) {
		log.Printf("e2e: %s is set, leaving the environment running; kubeconfig: %s, management: %s",
			envKeep, e.kubeconfig, e.srvURL())
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if e.kind != nil {
		if err := e.kind.Delete(kindClusterName, e.kubeconfig); err != nil {
			log.Printf("e2e: delete the Kind cluster: %v", err)
		}
	}
	if e.proxy != nil {
		if err := e.proxy.Terminate(ctx); err != nil {
			log.Printf("e2e: terminate the reverse proxy: %v", err)
		}
	}
	if e.network != nil && e.network.laptop != nil {
		if err := e.network.laptop.Terminate(ctx); err != nil {
			log.Printf("e2e: terminate the %s peer: %v", laptopName, err)
		}
	}
	if e.srv != nil {
		if err := e.srv.Terminate(ctx); err != nil {
			log.Printf("e2e: terminate the NetBird deployment: %v", err)
		}
	}
	if err := os.RemoveAll(e.workDir); err != nil {
		log.Printf("e2e: remove %s: %v", e.workDir, err)
	}
}

// collectArtifacts writes the cluster's and the server's logs for CI to keep,
// when NB_E2E_ARTIFACTS_DIR asks for them. The environment is torn down before
// the run reports, so this is the only chance to read them.
func (e *environment) collectArtifacts() {
	dir := os.Getenv(envArtifactsDir)
	if dir == "" {
		return
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		log.Printf("e2e: create %s: %v", dir, err)
		return
	}
	if e.srv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		if err := os.WriteFile(filepath.Join(dir, "netbird-server.log"), []byte(e.srv.Logs(ctx)), 0o644); err != nil {
			log.Printf("e2e: write the server log: %v", err)
		}
	}
	if e.kind != nil {
		if err := e.kind.CollectLogs(kindClusterName, filepath.Join(dir, "kind")); err != nil {
			log.Printf("e2e: collect the Kind logs: %v", err)
		}
	}
}

func (e *environment) srvURL() string {
	if e.srv == nil {
		return ""
	}
	return e.srv.BaseURL
}

// ensureNamespace creates a namespace if it is not there yet.
func (e *environment) ensureNamespace(ctx context.Context, name string) error {
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}}
	err := e.k8s.Create(ctx, ns)
	if err != nil && !kerrors.IsAlreadyExists(err) {
		return fmt.Errorf("create namespace %s: %w", name, err)
	}
	return nil
}

func newScheme() *kruntime.Scheme {
	scheme := kruntime.NewScheme()
	kruntimeutil.Must(clientgoscheme.AddToScheme(scheme))
	kruntimeutil.Must(nbv1alpha1.AddToScheme(scheme))
	kruntimeutil.Must(nbv1.AddToScheme(scheme))
	kruntimeutil.Must(gwv1.AddToScheme(scheme))
	kruntimeutil.Must(gwv1alpha2.AddToScheme(scheme))
	return scheme
}

// envBool reads a boolean knob. An unparsable value is reported rather than
// silently read as false.
func envBool(name string) bool {
	val := os.Getenv(name)
	if val == "" {
		return false
	}
	b, err := strconv.ParseBool(val)
	if err != nil {
		log.Printf("e2e: ignoring %s=%q: %v", name, val, err)
		return false
	}
	return b
}
