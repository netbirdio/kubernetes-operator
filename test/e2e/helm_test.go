// SPDX-License-Identifier: BSD-3-Clause

//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"maps"
	"strings"
	"time"

	"github.com/distribution/reference"
	"helm.sh/helm/v4/pkg/action"
	"helm.sh/helm/v4/pkg/chart/v2/loader"
	"helm.sh/helm/v4/pkg/downloader"
	"helm.sh/helm/v4/pkg/getter"
	"helm.sh/helm/v4/pkg/kube"
	"helm.sh/helm/v4/pkg/registry"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	releaseName    = "netbird-operator"
	publishedChart = "oci://ghcr.io/netbirdio/helm-charts/netbird-operator"
	localChart     = "../../charts/netbird-operator"
	helmTimeout    = 3 * time.Minute
)

// installOperator installs the latest published chart and upgrades it to the
// local chart and operator image, so every run also covers the upgrade path
// users take. NB_E2E_SKIP_UPGRADE installs the local chart directly.
func (e *environment) installOperator(ctx context.Context, operatorImage, apiKey string) error {
	if err := e.ensureNamespace(ctx, netbirdNamespace); err != nil {
		return err
	}
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      apiKeySecretName,
			Namespace: netbirdNamespace,
		},
		StringData: map[string]string{
			"NB_API_KEY": apiKey,
		},
	}
	if err := e.k8s.Create(ctx, secret); err != nil {
		return fmt.Errorf("create the API key secret: %w", err)
	}

	cfg, err := e.helmConfig()
	if err != nil {
		return err
	}

	if !envBool(envSkipUpgrade) {
		chartPath, version, err := e.downloadPublishedChart(cfg)
		if err != nil {
			return err
		}
		log.Printf("e2e: installing the published chart %s", version)
		if err := e.helmInstallOrUpgrade(ctx, cfg, chartPath, e.operatorValues()); err != nil {
			return fmt.Errorf("install the published chart %s: %w", version, err)
		}
		log.Printf("e2e: creating objects with the published operator")
		e.upgrade, err = e.createUpgradeFixtures(ctx)
		if err != nil {
			return fmt.Errorf("create objects with the published operator %s: %w", version, err)
		}
	}

	vals, err := e.devValues(operatorImage)
	if err != nil {
		return err
	}
	log.Printf("e2e: installing the local chart with %s", operatorImage)
	if err := e.helmInstallOrUpgrade(ctx, cfg, localChart, vals); err != nil {
		return fmt.Errorf("install the local chart: %w", err)
	}
	return nil
}

// operatorValues are the values every install shares: the deployment's
// management address, the client build the agents run, Gateway API support,
// and self-signed webhook certificates instead of cert-manager.
func (e *environment) operatorValues() map[string]any {
	return map[string]any{
		"managementURL":      managementURL,
		"routingClientImage": e.clientImage,
		"gatewayAPI": map[string]any{
			"enabled": true,
		},
		"webhook": map[string]any{
			"enableCertManager": false,
		},
	}
}

// devValues point the chart at the operator image loaded into the nodes.
func (e *environment) devValues(operatorImage string) (map[string]any, error) {
	named, err := reference.ParseNormalizedNamed(operatorImage)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", operatorImage, err)
	}
	tagged, ok := named.(reference.Tagged)
	if !ok {
		return nil, fmt.Errorf("%s=%s has no tag", envOperatorImage, operatorImage)
	}
	vals := e.operatorValues()
	maps.Copy(vals, map[string]any{
		"operator": map[string]any{
			"image": map[string]any{
				"registry":   reference.Domain(named),
				"repository": reference.Path(named),
				"tag":        tagged.Tag(),
				"pullPolicy": "Never",
			},
		},
	})
	return vals, nil
}

func (e *environment) helmConfig() (*action.Configuration, error) {
	regClient, err := registry.NewClient()
	if err != nil {
		return nil, fmt.Errorf("create Helm registry client: %w", err)
	}
	cfg := &action.Configuration{RegistryClient: regClient}
	cfg.SetLogger(slog.DiscardHandler)
	flags := &genericclioptions.ConfigFlags{KubeConfig: &e.kubeconfig, Namespace: new(netbirdNamespace)}
	if err := cfg.Init(flags, netbirdNamespace, "secret"); err != nil {
		return nil, fmt.Errorf("initialize Helm: %w", err)
	}
	return cfg, nil
}

// downloadPublishedChart fetches the newest published chart and returns its
// path and version.
func (e *environment) downloadPublishedChart(cfg *action.Configuration) (string, string, error) {
	tags, err := cfg.RegistryClient.Tags(strings.TrimPrefix(publishedChart, "oci://"))
	if err != nil {
		return "", "", fmt.Errorf("list published chart versions: %w", err)
	}
	if len(tags) == 0 {
		return "", "", errors.New("no published chart versions found")
	}
	out := bytes.NewBuffer(nil)
	dl := downloader.ChartDownloader{
		Out:            out,
		Verify:         downloader.VerifyIfPossible,
		ContentCache:   e.workDir,
		Getters:        getter.Getters(getter.WithRegistryClient(cfg.RegistryClient)),
		RegistryClient: cfg.RegistryClient,
	}
	path, _, err := dl.DownloadTo(publishedChart, tags[0], e.workDir)
	if err != nil {
		return "", "", fmt.Errorf("download chart %s: %w\n%s", tags[0], err, out.String())
	}
	return path, tags[0], nil
}

// helmInstallOrUpgrade installs the chart, or upgrades the release when it is
// already installed. Helm never upgrades CRDs, so on upgrade they are applied
// first, the way a user following the upgrade notes would.
func (e *environment) helmInstallOrUpgrade(ctx context.Context, cfg *action.Configuration, chartPath string, vals map[string]any) error {
	ch, err := loader.Load(chartPath)
	if err != nil {
		return fmt.Errorf("load chart %s: %w", chartPath, err)
	}

	if _, err := action.NewGet(cfg).Run(releaseName); err != nil {
		install := action.NewInstall(cfg)
		install.ReleaseName = releaseName
		install.Namespace = netbirdNamespace
		install.WaitStrategy = kube.StatusWatcherStrategy
		install.Timeout = helmTimeout
		_, err := install.RunWithContext(ctx, ch, vals)
		return err
	}

	for _, crd := range ch.CRDObjects() {
		if err := e.applyCRD(ctx, crd.Name, crd.File.Data); err != nil {
			return err
		}
	}
	upgrade := action.NewUpgrade(cfg)
	upgrade.Namespace = netbirdNamespace
	upgrade.WaitStrategy = kube.StatusWatcherStrategy
	upgrade.Timeout = helmTimeout
	_, err = upgrade.RunWithContext(ctx, releaseName, ch, vals)
	return err
}

func (e *environment) applyCRD(ctx context.Context, name string, data []byte) error {
	var obj unstructured.Unstructured
	if err := yaml.NewYAMLOrJSONDecoder(bytes.NewReader(data), 4096).Decode(&obj); err != nil {
		return fmt.Errorf("decode CRD %s: %w", name, err)
	}
	if err := e.k8s.Patch(ctx, &obj, client.Apply, client.ForceOwnership, client.FieldOwner("helm")); err != nil {
		return fmt.Errorf("apply CRD %s: %w", name, err)
	}
	return nil
}
