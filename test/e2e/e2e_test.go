package e2e

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/fluxcd/cli-utils/pkg/kstatus/status"
	"github.com/go-openapi/testify/v2/require"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/mount"
	"github.com/moby/moby/api/types/network"
	mobyclient "github.com/moby/moby/client"
	netbird "github.com/netbirdio/netbird/shared/management/client/rest"
	"github.com/netbirdio/netbird/shared/management/http/api"
	"helm.sh/helm/v4/pkg/action"
	"helm.sh/helm/v4/pkg/chart/v2/loader"
	"helm.sh/helm/v4/pkg/downloader"
	"helm.sh/helm/v4/pkg/getter"
	"helm.sh/helm/v4/pkg/kube"
	"helm.sh/helm/v4/pkg/registry"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	kruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	kruntimeutil "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/controller-runtime/pkg/client"
	kindv1alpha1 "sigs.k8s.io/kind/pkg/apis/config/v1alpha4"
	"sigs.k8s.io/kind/pkg/cluster"
	"sigs.k8s.io/kind/pkg/cluster/nodeutils"

	nbv1alpha1 "github.com/netbirdio/kubernetes-operator/api/v1alpha1"
	"github.com/netbirdio/kubernetes-operator/pkg/version"
)

const (
	netbirdNamespace = "netbird"
)

func TestE2E(t *testing.T) {
	imgRef := os.Getenv("IMG_REF")
	require.NotEmpty(t, imgRef)

	mobyClient, err := mobyclient.New(mobyclient.FromEnv)
	require.NoError(t, err)
	t.Cleanup(func() {
		err = mobyClient.Close()
		if err != nil {
			t.Log("could not close moby client", err)
		}
	})

	t.Log("Exporting image", imgRef)
	saveRes, err := mobyClient.ImageSave(t.Context(), []string{imgRef})
	require.NoError(t, err)
	imgPath := filepath.Join(t.TempDir(), "image")
	f, err := os.OpenFile(imgPath, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0o644)
	require.NoError(t, err)
	_, err = io.Copy(f, saveRes)
	require.NoError(t, err)
	err = f.Close()
	require.NoError(t, err)

	_, serverTag, ok := strings.Cut(version.NetbirdClientImage, ":")
	require.TrueT(t, ok)
	serverTag, _, ok = strings.Cut(serverTag, "@")
	require.TrueT(t, ok)
	serverImage := "ghcr.io/netbirdio/netbird-server:" + serverTag

	kubernetesVersions := []string{
		"v0.32.0-v1.36.2",
	}
	for _, kubernetesVersion := range kubernetesVersions {
		t.Run(kubernetesVersion, func(t *testing.T) {
			t.Log("Creating NetBird server", serverImage)
			bridgeNetwork, err := mobyClient.NetworkInspect(t.Context(), "bridge", mobyclient.NetworkInspectOptions{})
			require.NoError(t, err)
			require.Len(t, bridgeNetwork.Network.IPAM.Config, 1)
			listener, err := net.Listen("tcp", "localhost:0")
			require.NoError(t, err)
			_, netbirdPort, err := net.SplitHostPort(listener.Addr().String())
			require.NoError(t, err)
			err = listener.Close()
			require.NoError(t, err)
			managementURL := fmt.Sprintf("http://%s:%s", bridgeNetwork.Network.IPAM.Config[0].Gateway.String(), netbirdPort)

			configPath := filepath.Join(t.TempDir(), "config.yaml")
			netbirdConfig := fmt.Sprintf(`server:
  listenAddress: ":8080"
  exposedAddress: "%s"
  stunPorts:
    - 3478
  logLevel: "info"
  logFile: "console"
  authSecret: "test"
  dataDir: "/var/lib/netbird"
  auth:
    issuer: "https://example.com/oauth2"
    dashboardRedirectURIs:
      - "https://example.com/nb-auth"
    cliRedirectURIs:
      - "http://localhost:53000/"`, managementURL)
			err = os.WriteFile(configPath, []byte(netbirdConfig), 0o644)
			require.NoError(t, err)

			pullResp, err := mobyClient.ImagePull(t.Context(), serverImage, mobyclient.ImagePullOptions{})
			require.NoError(t, err)
			err = pullResp.Wait(t.Context())
			require.NoError(t, err)
			apiContainerPort, err := network.ParsePort("8080/tcp")
			require.NoError(t, err)
			createOpt := mobyclient.ContainerCreateOptions{
				Config: &container.Config{
					Image: serverImage,
					Env: []string{
						"NB_SETUP_PAT_ENABLED=true",
						"NB_DISABLE_GEOLOCATION=true",
					},
					ExposedPorts: map[network.Port]struct{}{
						apiContainerPort: {},
					},
				},
				HostConfig: &container.HostConfig{
					PortBindings: network.PortMap{
						apiContainerPort: []network.PortBinding{
							{
								HostIP:   netip.MustParseAddr("0.0.0.0"),
								HostPort: netbirdPort,
							},
						},
					},
					Mounts: []mount.Mount{
						{
							Type:   mount.TypeBind,
							Source: configPath,
							Target: "/etc/netbird/config.yaml",
						},
						{
							Type:   mount.TypeBind,
							Source: t.TempDir(),
							Target: "/var/lib/netbird",
						},
					},
				},
			}
			createResp, err := mobyClient.ContainerCreate(t.Context(), createOpt)
			require.NoError(t, err)
			t.Cleanup(func() {
				if t.Failed() {
					return
				}
				_, err := mobyClient.ContainerKill(context.Background(), createResp.ID, mobyclient.ContainerKillOptions{})
				if err != nil {
					t.Log("could not kill container", err)
					return
				}
				_, err = mobyClient.ContainerRemove(context.Background(), createResp.ID, mobyclient.ContainerRemoveOptions{})
				if err != nil {
					t.Log("could not remove container", err)
					return
				}
			})
			_, err = mobyClient.ContainerStart(t.Context(), createResp.ID, mobyclient.ContainerStartOptions{})
			require.NoError(t, err)

			t.Log("Configuring NetBird server", managementURL)
			nbClient := netbird.New(managementURL, "")
			require.Eventually(t, func(ctx context.Context) error {
				_, err = nbClient.Instance.GetStatus(ctx)
				if err != nil {
					t.Log("Get status error", err)
					return err
				}
				return nil
			}, 60*time.Second, 1*time.Second)

			setupReq := api.SetupRequest{
				Name:      "admin",
				CreatePat: new(true),
				Email:     "test@example.com",
				Password:  "securepassword123",
			}
			setupResp, err := nbClient.Instance.Setup(t.Context(), setupReq)
			require.NoError(t, err)
			nbClient = netbird.New(managementURL, *setupResp.PersonalAccessToken)

			t.Log("Creating Kind cluster")
			kcPath := filepath.Join(t.TempDir(), "kind.kubeconfig")
			provider := cluster.NewProvider()
			createCfg := &kindv1alpha1.Cluster{
				Nodes: []kindv1alpha1.Node{
					{
						Role: kindv1alpha1.ControlPlaneRole,
					},
				},
			}
			createOpts := []cluster.CreateOption{
				cluster.CreateWithV1Alpha4Config(createCfg),
				cluster.CreateWithNodeImage(fmt.Sprintf("ghcr.io/spegel-org/test-images/kind-node:%s", kubernetesVersion)),
				cluster.CreateWithKubeconfigPath(kcPath),
			}
			kindName := fmt.Sprintf("netbird-operator-e2e-%s", strings.ReplaceAll(kubernetesVersion, ".", "-"))
			err = provider.Create(kindName, createOpts...)
			require.NoError(t, err)
			t.Cleanup(func() {
				if t.Failed() {
					return
				}
				err = provider.Delete(kindName, "")
				require.NoError(t, err)
			})
			kindNodes, err := provider.ListNodes(kindName)
			require.NoError(t, err)

			k8sCfg, err := clientcmd.BuildConfigFromFlags("", kcPath)
			require.NoError(t, err)
			scheme := kruntime.NewScheme()
			kruntimeutil.Must(corev1.AddToScheme(scheme))
			kruntimeutil.Must(appsv1.AddToScheme(scheme))
			kruntimeutil.Must(rbacv1.AddToScheme(scheme))
			kruntimeutil.Must(nbv1alpha1.AddToScheme(scheme))
			k8sClient, err := client.New(k8sCfg, client.Options{Scheme: scheme})
			require.NoError(t, err)

			require.Eventually(t, func(ctx context.Context) error {
				for _, kindNode := range kindNodes {
					node := &corev1.Node{
						ObjectMeta: metav1.ObjectMeta{
							Name: kindNode.String(),
						},
					}
					err := k8sClient.Get(ctx, client.ObjectKeyFromObject(node), node)
					if err != nil {
						return err
					}
					idx := slices.IndexFunc(node.Status.Conditions, func(cond corev1.NodeCondition) bool {
						return cond.Type == corev1.NodeReady
					})
					if idx == -1 {
						return errors.New("ready condition not found")
					}
					if node.Status.Conditions[idx].Status != corev1.ConditionTrue {
						return fmt.Errorf("node %s is not ready", kindNode.String())
					}
				}
				return nil
			}, 60*time.Second, 1*time.Second)

			t.Log("Importing image", imgRef)
			f, err := os.Open(imgPath)
			require.NoError(t, err)
			for _, node := range kindNodes {
				_, err = f.Seek(0, io.SeekStart)
				require.NoError(t, err)
				err = nodeutils.LoadImageArchive(node, f)
				require.NoError(t, err)
			}

			namespace := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: netbirdNamespace,
				},
			}
			err = k8sClient.Create(t.Context(), namespace)
			require.NoError(t, err)
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "netbird-mgmt-api-key",
					Namespace: netbirdNamespace,
				},
				StringData: map[string]string{
					"NB_API_KEY": *setupResp.PersonalAccessToken,
				},
			}
			err = k8sClient.Create(t.Context(), secret)
			require.NoError(t, err)
			installOperator(t, k8sClient, kcPath, false, managementURL)
			installOperator(t, k8sClient, kcPath, true, managementURL)

			t.Run("cluster proxy", testClusterProxy(k8sClient, nbClient))
		})
	}
}

func testClusterProxy(k8sClient client.Client, nbClient *netbird.Client) func(*testing.T) {
	return func(t *testing.T) {
		t.Parallel()

		serviceAccount := &corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "clusterproxy-prod",
				Namespace: "netbird",
			},
		}
		err := k8sClient.Create(t.Context(), serviceAccount)
		require.NoError(t, err)
		clusterRole := &rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{
				Name: "clusterproxy-prod",
			},
			Rules: []rbacv1.PolicyRule{
				{
					APIGroups: []string{""},
					Resources: []string{"users", "groups"},
					Verbs:     []string{"impersonate"},
				},
				{
					APIGroups: []string{"authentication.k8s.io"},
					Resources: []string{"userextras/*", "uids"},
					Verbs:     []string{"impersonate"},
				},
			},
		}
		err = k8sClient.Create(t.Context(), clusterRole)
		require.NoError(t, err)
		clusterRoleBinding := &rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name: "clusterproxy-prod",
			},
			RoleRef: rbacv1.RoleRef{
				APIGroup: "rbac.authorization.k8s.io",
				Kind:     "ClusterRole",
				Name:     clusterRole.Name,
			},
			Subjects: []rbacv1.Subject{
				{
					Kind:      "ServiceAccount",
					Name:      serviceAccount.Name,
					Namespace: serviceAccount.Namespace,
				},
			},
		}
		err = k8sClient.Create(t.Context(), clusterRoleBinding)
		require.NoError(t, err)
		clusterProxy := &nbv1alpha1.ClusterProxy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "prod",
				Namespace: "netbird",
			},
			Spec: nbv1alpha1.ClusterProxySpec{
				ClusterName:        "prod",
				ServiceAccountName: serviceAccount.Name,
				APIServer:          "https://kubernetes.default.svc.cluster.local/",
			},
		}
		err = k8sClient.Create(t.Context(), clusterProxy)
		require.NoError(t, err)
		require.Eventually(t, func(ctx context.Context) error {
			u := &unstructured.Unstructured{}
			u.SetGroupVersionKind(schema.GroupVersionKind{
				Version: "v1",
				Group:   "apps",
				Kind:    "Deployment",
			})
			err = k8sClient.Get(ctx, client.ObjectKey{Namespace: clusterProxy.Namespace, Name: "clusterproxy-" + clusterProxy.Name}, u)
			if err != nil {
				return err
			}
			res, err := status.Compute(u)
			if err != nil {
				return err
			}
			if res.Status != status.CurrentStatus {
				return errors.New("waiting for ready")
			}
			return nil
		}, 60*time.Second, 1*time.Second)

		peers, err := nbClient.Peers.List(t.Context())
		require.NoError(t, err)
		require.Len(t, peers, 3)
		dnsLabel := "prod.netbird-kubeapi-proxy.netbird.selfhosted"
		for _, peer := range peers {
			require.Len(t, peer.ExtraDnsLabels, 1)
			require.Equal(t, dnsLabel, peer.ExtraDnsLabels[0])
		}
	}
}

func installOperator(t *testing.T, k8sClient client.Client, kcPath string, dev bool, managementURL string) {
	t.Helper()

	regClient, err := registry.NewClient()
	require.NoError(t, err)
	actionCfg := &action.Configuration{
		RegistryClient: regClient,
	}
	actionCfg.SetLogger(slog.DiscardHandler)
	clientGetter := &genericclioptions.ConfigFlags{KubeConfig: &kcPath, Namespace: new(netbirdNamespace)}
	err = actionCfg.Init(clientGetter, netbirdNamespace, "secret")
	require.NoError(t, err)

	chartPath, version := func() (string, string) {
		if !dev {
			tags, err := actionCfg.RegistryClient.Tags("ghcr.io/netbirdio/helm-charts/netbird-operator")
			require.NoError(t, err)
			buf := bytes.NewBuffer(nil)
			dl := downloader.ChartDownloader{
				Out:            buf,
				Verify:         downloader.VerifyIfPossible,
				ContentCache:   t.TempDir(),
				Getters:        getter.Getters(getter.WithRegistryClient(actionCfg.RegistryClient)),
				RegistryClient: actionCfg.RegistryClient,
			}
			chartPath, _, err := dl.DownloadTo("oci://ghcr.io/netbirdio/helm-charts/netbird-operator", tags[0], t.TempDir())
			require.NoError(t, err, buf.String())
			return chartPath, tags[0]
		}
		return "../../charts/netbird-operator", "dev"
	}()
	charter, err := loader.Load(chartPath)
	require.NoError(t, err)

	t.Log("Deploying NetBird Operator", version)
	vals := map[string]any{
		"managementURL": managementURL,
		"webhook": map[string]any{
			"enableCertManager": false,
			"failurePolicy":     "Ignore",
		},
	}
	if dev {
		vals["operator"] = map[string]any{
			"image": map[string]any{
				"tag":        "dev",
				"pullPolicy": "Never",
			},
		}
	}

	_, err = action.NewGet(actionCfg).Run("netbird-operator")
	if err != nil {
		install := action.NewInstall(actionCfg)
		install.ReleaseName = "netbird-operator"
		install.Namespace = netbirdNamespace
		install.CreateNamespace = true
		install.WaitStrategy = kube.StatusWatcherStrategy
		install.Timeout = 60 * time.Second
		_, err = install.RunWithContext(t.Context(), charter, vals)
		require.NoError(t, err)
	} else {
		for _, crd := range charter.CRDObjects() {
			docs := yaml.NewYAMLOrJSONDecoder(bytes.NewReader(crd.File.Data), 4096)
			var obj unstructured.Unstructured
			err := docs.Decode(&obj)
			require.NoError(t, err)
			err = k8sClient.Patch(t.Context(), &obj, client.Apply, client.ForceOwnership, client.FieldOwner("helm"))
			require.NoError(t, err)
		}

		upgrade := action.NewUpgrade(actionCfg)
		upgrade.Namespace = netbirdNamespace
		upgrade.WaitStrategy = kube.StatusWatcherStrategy
		upgrade.Timeout = 60 * time.Second
		_, err := upgrade.RunWithContext(t.Context(), "netbird-operator", charter, vals)
		require.NoError(t, err)
	}
}
