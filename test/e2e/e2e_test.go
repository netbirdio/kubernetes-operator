package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-openapi/testify/v2/require"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/mount"
	"github.com/moby/moby/api/types/network"
	"github.com/moby/moby/client"
	"helm.sh/helm/v4/pkg/action"
	"helm.sh/helm/v4/pkg/chart/loader"
	"helm.sh/helm/v4/pkg/kube"
	"helm.sh/helm/v4/pkg/registry"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/utils/ptr"
	kindv1alpha1 "sigs.k8s.io/kind/pkg/apis/config/v1alpha4"
	"sigs.k8s.io/kind/pkg/cluster"
	"sigs.k8s.io/kind/pkg/cluster/nodeutils"

	netbird "github.com/netbirdio/netbird/shared/management/client/rest"

	"github.com/netbirdio/netbird/shared/management/http/api"
)

const (
	netbirdNamespace = "netbird"
)

func TestE2E(t *testing.T) {
	imgRef := os.Getenv("IMG_REF")
	require.NotEmpty(t, imgRef)

	mobyClient, err := client.New(client.FromEnv)
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

	kubernetesVersions := []string{
		"1.36.0",
		// "1.35.3",
		// "1.34.6",
	}
	for _, kubernetesVersion := range kubernetesVersions {
		t.Run(kubernetesVersion, func(t *testing.T) {
			t.Log("Running Netbird server")
			bridgeNetwork, err := mobyClient.NetworkInspect(t.Context(), "bridge", client.NetworkInspectOptions{})
			require.NoError(t, err)
			bridgeIP := bridgeNetwork.Network.IPAM.Config[0].Gateway

			combined.Default()

			configPath, err := filepath.Abs("./testdata/config.yaml")
			require.NoError(t, err)

			apiContainerPort, err := network.ParsePort("8080/tcp")
			require.NoError(t, err)
			createOpt := client.ContainerCreateOptions{
				Config: &container.Config{
					Image: "ghcr.io/netbirdio/netbird-server:pr-6003",
					Env: []string{
						"NB_SETUP_PAT_ENABLED=true",
						"NB_DISABLE_GEOLOCATION=true",
					},
				},
				HostConfig: &container.HostConfig{
					PortBindings: network.PortMap{
						apiContainerPort: []network.PortBinding{
							{
								HostPort: "",
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
			resp, err := mobyClient.ContainerCreate(t.Context(), createOpt)
			require.NoError(t, err)
			t.Cleanup(func() {
				_, err := mobyClient.ContainerKill(context.Background(), resp.ID, client.ContainerKillOptions{})
				if err != nil {
					t.Log("could not kill container", err)
					return
				}
				_, err = mobyClient.ContainerRemove(context.Background(), resp.ID, client.ContainerRemoveOptions{})
				if err != nil {
					t.Log("could not remove container", err)
					return
				}
			})
			_, err = mobyClient.ContainerStart(t.Context(), resp.ID, client.ContainerStartOptions{})
			require.NoError(t, err)
			info, err := mobyClient.ContainerInspect(t.Context(), resp.ID, client.ContainerInspectOptions{})
			require.NoError(t, err)
			require.NotEmpty(t, info.Container.NetworkSettings.Ports[apiContainerPort])
			apiHostIP := info.Container.NetworkSettings.Ports[apiContainerPort][0].HostIP
			apiHostPort, err := strconv.ParseInt(info.Container.NetworkSettings.Ports[apiContainerPort][0].HostPort, 10, 32)
			require.NoError(t, err)

			managementURL := fmt.Sprintf("http://%s:%d", bridgeIP, apiHostPort)
			nbClient := netbird.New(managementURL, "")
			require.Eventually(t, func(ctx context.Context) error {
				_, err := nbClient.Instance.GetStatus(ctx)
				if err != nil {
					return err
				}
				return nil
			}, 15*time.Second, 1*time.Second)

			// TODO: Change to client once PR is merged.
			body := `{"email": "admin@example.com", "password": "securepassword123", "name": "Admin", "create_pat": true}`
			setupReq, err := http.NewRequestWithContext(t.Context(), http.MethodPost, fmt.Sprintf("http://%s:%d/api/setup", apiHostIP.String(), apiHostPort), bytes.NewBufferString(body))
			require.NoError(t, err)
			setupResp, err := http.DefaultClient.Do(setupReq)
			require.NoError(t, err)
			require.Equal(t, http.StatusOK, setupResp.StatusCode)
			b, err := io.ReadAll(setupResp.Body)
			require.NoError(t, err)
			setup := map[string]string{}
			err = json.Unmarshal(b, &setup)
			require.NoError(t, err)
			apiToken := setup["personal_access_token"]

			nbClient = netbird.New(managementURL, apiToken)

			t.Log("Creating Kind cluster")
			kcPath := filepath.Join(t.TempDir(), "kind.kubeconfig")
			provider := cluster.NewProvider()
			createCfg := &kindv1alpha1.Cluster{
				Nodes: []kindv1alpha1.Node{
					{
						Role: kindv1alpha1.ControlPlaneRole,
						ExtraPortMappings: []kindv1alpha1.PortMapping{
							{
								ContainerPort: int32(apiHostPort),
								HostPort:      int32(apiHostPort) + 1,
								Protocol:      "TCP",
							},
						},
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
			k8sClient, err := kubernetes.NewForConfig(k8sCfg)
			require.NoError(t, err)

			require.Eventually(t, func(ctx context.Context) error {
				for _, kindNode := range kindNodes {
					node, err := k8sClient.CoreV1().Nodes().Get(ctx, kindNode.String(), metav1.GetOptions{})
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
			}, 30*time.Second, 1*time.Second)

			t.Log("Importing image", imgRef)
			f, err := os.Open(imgPath)
			require.NoError(t, err)
			for _, node := range kindNodes {
				_, err = f.Seek(0, io.SeekStart)
				require.NoError(t, err)
				err = nodeutils.LoadImageArchive(node, f)
				require.NoError(t, err)
			}

			t.Log("Deploying Netbird operator")
			namespace := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: netbirdNamespace,
				},
			}
			_, err = k8sClient.CoreV1().Namespaces().Create(t.Context(), namespace, metav1.CreateOptions{})
			require.NoError(t, err)

			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "netbird-mgmt-api-key",
					Namespace: netbirdNamespace,
				},
				StringData: map[string]string{
					"NB_API_KEY": apiToken,
				},
			}
			_, err = k8sClient.CoreV1().Secrets(netbirdNamespace).Create(t.Context(), secret, metav1.CreateOptions{})
			require.NoError(t, err)

			regClient, err := registry.NewClient()
			require.NoError(t, err)
			actionCfg := &action.Configuration{
				RegistryClient: regClient,
			}
			actionCfg.SetLogger(slog.DiscardHandler)
			clientGetter := &genericclioptions.ConfigFlags{KubeConfig: &kcPath, Namespace: ptr.To(netbirdNamespace)}
			err = actionCfg.Init(clientGetter, netbirdNamespace, "secret")
			require.NoError(t, err)

			charter, err := loader.Load("../../helm/kubernetes-operator")
			require.NoError(t, err)

			vals := map[string]any{
				"image": map[string]any{
					"tag":        "dev",
					"pullPolicy": "Never",
				},
				"webhook": map[string]any{
					"enableCertManager": false,
					"failurePolicy":     "Ignore",
				},
				"managementURL": managementURL,
			}
			_, err = action.NewGet(actionCfg).Run(netbirdNamespace)
			if err != nil {
				install := action.NewInstall(actionCfg)
				install.ReleaseName = netbirdNamespace
				install.Namespace = netbirdNamespace
				install.CreateNamespace = true
				install.WaitStrategy = kube.StatusWatcherStrategy
				install.Timeout = 60 * time.Second
				_, err = install.RunWithContext(t.Context(), charter, vals)
				require.NoError(t, err)
			} else {
				upgrade := action.NewUpgrade(actionCfg)
				upgrade.Namespace = netbirdNamespace
				upgrade.WaitStrategy = kube.StatusWatcherStrategy
				upgrade.Timeout = 60 * time.Second
				_, err := upgrade.RunWithContext(t.Context(), netbirdNamespace, charter, vals)
				require.NoError(t, err)
			}

			t.Log("Creating network router")
			allGroup, err := nbClient.Groups.GetByName(t.Context(), "All")
			require.NoError(t, err)
			zoneReq := api.ZoneRequest{
				Name:               "prod.company.internal",
				Domain:             "prod.company.internal",
				DistributionGroups: []string{allGroup.Id},
			}
			_, err = nbClient.DNSZones.CreateZone(t.Context(), zoneReq)
			require.NoError(t, err)

			t.Log("Sleeping")
			time.Sleep(5 * time.Minute)
		})
	}
}
