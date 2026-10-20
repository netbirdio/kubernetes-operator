// SPDX-License-Identifier: BSD-3-Clause

//go:build e2e

package e2e

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os/exec"
	"strings"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apimachinery/pkg/util/yaml"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/netbirdio/netbird/e2e/harness"
)

// installGatewayAPI installs the Gateway API CRDs at the version the operator
// is built against. The experimental channel, because TCPRoute is not in the
// standard one.
func (e *environment) installGatewayAPI(ctx context.Context) error {
	out, err := exec.CommandContext(ctx, "go", "list", "-mod=readonly", "-m", "-f", "{{.Version}}", "sigs.k8s.io/gateway-api").Output()
	if err != nil {
		return fmt.Errorf("find the Gateway API version: %w", err)
	}
	version := strings.TrimSpace(string(out))
	url := fmt.Sprintf("https://github.com/kubernetes-sigs/gateway-api/releases/download/%s/experimental-install.yaml", version)
	log.Printf("e2e: installing the Gateway API %s CRDs", version)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("download %s: %w", url, err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download %s: %s", url, resp.Status)
	}

	var crds []string
	decoder := yaml.NewYAMLOrJSONDecoder(resp.Body, 4096)
	for {
		obj := &unstructured.Unstructured{}
		err := decoder.Decode(&obj.Object)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("decode %s: %w", url, err)
		}
		if len(obj.Object) == 0 {
			continue
		}
		if err := e.k8s.Patch(ctx, obj, client.Apply, client.ForceOwnership, client.FieldOwner("e2e")); err != nil {
			return fmt.Errorf("apply %s %s: %w", obj.GetKind(), obj.GetName(), err)
		}
		if obj.GetKind() == "CustomResourceDefinition" {
			crds = append(crds, obj.GetName())
		}
	}

	// The operator starts watching these kinds as soon as it runs, and fails to
	// start while one is not served yet.
	for _, name := range crds {
		if err := e.waitCRDEstablished(ctx, name); err != nil {
			return err
		}
	}
	return nil
}

func (e *environment) waitCRDEstablished(ctx context.Context, name string) error {
	crd := &unstructured.Unstructured{}
	crd.SetGroupVersionKind(schema.GroupVersionKind{Group: "apiextensions.k8s.io", Version: "v1", Kind: "CustomResourceDefinition"})
	return wait.PollUntilContextTimeout(ctx, time.Second, time.Minute, true, func(ctx context.Context) (bool, error) {
		if err := e.k8s.Get(ctx, client.ObjectKey{Name: name}, crd); err != nil {
			return false, err
		}
		conditions, _, _ := unstructured.NestedSlice(crd.Object, "status", "conditions")
		for _, c := range conditions {
			cond, ok := c.(map[string]any)
			if ok && cond["type"] == "Established" && cond["status"] == "True" {
				return true, nil
			}
		}
		return false, nil
	})
}

// requireProxy returns the NetBird reverse proxy, starting it and waiting for
// its cluster to come online on first use.
func (e *environment) requireProxy(t *testing.T) *harness.Proxy {
	t.Helper()
	e.proxyOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
		defer cancel()
		e.proxy, e.proxyErr = e.startProxy(ctx)
	})
	if e.proxyErr != nil {
		t.Fatalf("reverse proxy unavailable: %v", e.proxyErr)
	}
	return e.proxy
}

func (e *environment) startProxy(ctx context.Context) (*harness.Proxy, error) {
	// A token created without an account is global, so the proxy serves the
	// whole cluster.
	token, err := e.srv.CreateProxyTokenCLI(ctx, "e2e-proxy")
	if err != nil {
		return nil, fmt.Errorf("mint a proxy token: %w", err)
	}
	proxy, err := harness.StartProxy(ctx, e.srv, token)
	if err != nil {
		return nil, fmt.Errorf("start the reverse proxy: %w", err)
	}
	err = wait.PollUntilContextTimeout(ctx, 3*time.Second, 3*time.Minute, true, func(ctx context.Context) (bool, error) {
		clusters, err := e.nb.ReverseProxyClusters.List(ctx)
		if err != nil {
			return false, err
		}
		for _, c := range clusters {
			if c.Online {
				return true, nil
			}
		}
		return false, nil
	})
	if err != nil {
		return proxy, fmt.Errorf("wait for the proxy cluster to come online: %w\n%s", err, tail(proxy.Logs(ctx), serverLogLines))
	}
	return proxy, nil
}
