package e2e

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-openapi/testify/v2/require"
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
	kindv1alpha1 "sigs.k8s.io/kind/pkg/apis/config/v1alpha4"
	"sigs.k8s.io/kind/pkg/cluster"
	"sigs.k8s.io/kind/pkg/cluster/nodeutils"
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
	}
	for _, kubernetesVersion := range kubernetesVersions {
		t.Run(kubernetesVersion, func(t *testing.T) {
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
					"NB_API_KEY": "dummy",
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
			clientGetter := &genericclioptions.ConfigFlags{KubeConfig: &kcPath, Namespace: new(netbirdNamespace)}
			err = actionCfg.Init(clientGetter, netbirdNamespace, "secret")
			require.NoError(t, err)

			charter, err := loader.Load("../../charts/netbird-operator")
			require.NoError(t, err)

			vals := map[string]any{
				"operator": map[string]any{
					"image": map[string]any{
						"tag":        "dev",
						"pullPolicy": "Never",
					},
				},
				"webhook": map[string]any{
					"enableCertManager": false,
					"failurePolicy":     "Ignore",
				},
			}
			_, err = action.NewGet(actionCfg).Run(netbirdNamespace)
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
				upgrade := action.NewUpgrade(actionCfg)
				upgrade.Namespace = netbirdNamespace
				upgrade.WaitStrategy = kube.StatusWatcherStrategy
				upgrade.Timeout = 60 * time.Second
				_, err := upgrade.RunWithContext(t.Context(), "netbird-operator", charter, vals)
				require.NoError(t, err)
			}
		})
	}
}
