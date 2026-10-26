// SPDX-License-Identifier: BSD-3-Clause

package gatewayutil

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gwv1 "sigs.k8s.io/gateway-api/apis/v1"

	nbv1alpha1 "github.com/netbirdio/kubernetes-operator/api/v1alpha1"
)

func GetParentGateway(ctx context.Context, k8sClient client.Client, parent gwv1.ParentReference, namespace, controllerName string) (*gwv1.Gateway, error) {
	if parent.Namespace != nil {
		namespace = string(*parent.Namespace)
	}
	gw := &gwv1.Gateway{}
	err := k8sClient.Get(ctx, types.NamespacedName{Namespace: namespace, Name: string(parent.Name)}, gw)
	if err != nil {
		return nil, err
	}
	gwc := &gwv1.GatewayClass{}
	err = k8sClient.Get(ctx, client.ObjectKey{Name: string(gw.Spec.GatewayClassName)}, gwc)
	if err != nil {
		return nil, err
	}
	if string(gwc.Spec.ControllerName) != controllerName {
		return nil, nil
	}

	// TODO (phillebaba): Enforce allowed routes in gateway.

	return gw, nil
}

// ReferencesGateway reports whether any of a route's parent references names the
// Gateway. A reference without a namespace points into the route's own.
func ReferencesGateway(parents []gwv1.ParentReference, routeNamespace string, gw *gwv1.Gateway) bool {
	return slices.ContainsFunc(parents, func(parent gwv1.ParentReference) bool {
		if parent.Group != nil && *parent.Group != gwv1.GroupName {
			return false
		}
		if parent.Kind != nil && *parent.Kind != "Gateway" {
			return false
		}
		namespace := routeNamespace
		if parent.Namespace != nil {
			namespace = string(*parent.Namespace)
		}
		return namespace == gw.Namespace && string(parent.Name) == gw.Name
	})
}

func GetGatewayNetworkRouter(ctx context.Context, k8sClient client.Client, gw *gwv1.Gateway) (*nbv1alpha1.NetworkRouter, error) {
	netRouterName, err := GetNetworkRouterName(gw.Spec.Listeners)
	if err != nil {
		return nil, err
	}
	netRouter := &nbv1alpha1.NetworkRouter{}
	err = k8sClient.Get(ctx, types.NamespacedName{Namespace: gw.Namespace, Name: netRouterName}, netRouter)
	if err != nil {
		return nil, err
	}
	return netRouter, nil
}

func GetNetworkRouterName(listeners []gwv1.Listener) (string, error) {
	if len(listeners) > 1 {
		return "", errors.New("netbird Gateway only supports a single listener")
	}
	group, kind, ok := strings.Cut(string(listeners[0].Protocol), "/")
	if !ok {
		return "", fmt.Errorf("invalid protocol %s, expected gateway.netbird.io/NetworkRouter", listeners[0].Protocol)
	}
	if group != "gateway.netbird.io" || kind != "NetworkRouter" {
		return "", fmt.Errorf("invalid group %s and kind %s, expected gateway.netbird.io/NetworkRouter", group, kind)
	}
	return string(listeners[0].Name), nil
}
