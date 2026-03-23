package gatewayutil

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gwv1 "sigs.k8s.io/gateway-api/apis/v1"

	netbirdiov1 "github.com/netbirdio/kubernetes-operator/api/v1"
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

func GetGatewayRoutingPeer(ctx context.Context, k8sClient client.Client, gw gwv1.Gateway) (*netbirdiov1.NBRoutingPeer, error) {
	routingPeerName, err := GetRoutingPeerName(gw.Spec.Listeners)
	if err != nil {
		return nil, err
	}
	nbrp := &netbirdiov1.NBRoutingPeer{}
	err = k8sClient.Get(ctx, types.NamespacedName{Namespace: gw.Namespace, Name: routingPeerName}, nbrp)
	if err != nil {
		return nil, err
	}
	return nbrp, nil
}

func GetRoutingPeerName(listeners []gwv1.Listener) (string, error) {
	if len(listeners) > 1 {
		return "", errors.New("netbird Gateway only supports a single listener")
	}
	group, kind, ok := strings.Cut(string(listeners[0].Protocol), "/")
	if !ok {
		return "", fmt.Errorf("invalid protocol %s, expected gateway.netbird.io/NBRoutingPeer", listeners[0].Protocol)
	}
	if group != "gateway.netbird.io" || kind != "NBRoutingPeer" {
		return "", fmt.Errorf("invalid group %s and kind %s, expected gateway.netbird.io/NBRoutingPeer", group, kind)
	}
	return string(listeners[0].Name), nil
}
