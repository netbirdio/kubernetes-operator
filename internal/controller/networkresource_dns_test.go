// SPDX-License-Identifier: BSD-3-Clause

package controller

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/go-openapi/testify/v2/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	netbird "github.com/netbirdio/netbird/shared/management/client/rest"
	"github.com/netbirdio/netbird/shared/management/http/api"

	nbv1alpha1 "github.com/netbirdio/kubernetes-operator/api/v1alpha1"
	"github.com/netbirdio/kubernetes-operator/internal/k8sutil"
	"github.com/netbirdio/kubernetes-operator/internal/netbirdmock"
)

func TestSelectDNSRecord(t *testing.T) {
	t.Parallel()

	request := api.DNSRecordRequest{
		Name:    "service.namespace.cluster.local",
		Type:    api.DNSRecordTypeA,
		Content: "10.43.0.10",
		Ttl:     300,
	}
	exact := api.DNSRecord{Id: "exact", Name: request.Name, Type: request.Type, Content: request.Content, Ttl: 60}

	tests := map[string]struct {
		records []api.DNSRecord
		wantID  string
		wantErr bool
	}{
		"missing":             {},
		"exact":               {records: []api.DNSRecord{exact}, wantID: exact.Id},
		"other name ignored":  {records: []api.DNSRecord{{Id: "other", Name: "other.cluster.local", Type: request.Type, Content: request.Content}}},
		"different content":   {records: []api.DNSRecord{{Id: "conflict", Name: request.Name, Type: request.Type, Content: "10.43.0.11"}}, wantErr: true},
		"different type":      {records: []api.DNSRecord{{Id: "conflict", Name: request.Name, Type: api.DNSRecordTypeCNAME, Content: request.Content}}, wantErr: true},
		"multiple exact":      {records: []api.DNSRecord{exact, {Id: "duplicate", Name: request.Name, Type: request.Type, Content: request.Content}}, wantErr: true},
		"exact plus conflict": {records: []api.DNSRecord{exact, {Id: "conflict", Name: request.Name, Type: request.Type, Content: "10.43.0.11"}}, wantErr: true},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			record, err := selectDNSRecord(tt.records, request)
			if tt.wantErr {
				require.Error(t, err)
				var conflictErr *dnsRecordConflictError
				require.ErrorAs(t, err, &conflictErr)
				return
			}
			require.NoError(t, err)
			if tt.wantID == "" {
				require.Nil(t, record)
				return
			}
			require.Equal(t, tt.wantID, record.Id)
		})
	}
}

func TestEnsureDNSRecordAdoptsRecordAfterCreateConflict(t *testing.T) {
	t.Parallel()

	request := api.DNSRecordRequest{
		Name:    "service.namespace.cluster.local",
		Type:    api.DNSRecordTypeA,
		Content: "10.43.0.10",
		Ttl:     300,
	}
	var persisted atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/dns/zones/zone-id/records":
			records := []api.DNSRecord{}
			if persisted.Load() {
				records = append(records, api.DNSRecord{Id: "adopted", Name: request.Name, Type: request.Type, Content: request.Content, Ttl: request.Ttl})
			}
			if err := json.NewEncoder(w).Encode(records); err != nil {
				t.Errorf("encode DNS records: %v", err)
			}
		case r.Method == http.MethodPost && r.URL.Path == "/api/dns/zones/zone-id/records":
			persisted.Store(true)
			w.WriteHeader(http.StatusConflict)
			if err := json.NewEncoder(w).Encode(map[string]string{"message": "identical record already exists"}); err != nil {
				t.Errorf("encode conflict response: %v", err)
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	scheme := runtime.NewScheme()
	require.NoError(t, nbv1alpha1.AddToScheme(scheme))
	netResource := &nbv1alpha1.NetworkResource{ObjectMeta: metav1.ObjectMeta{Name: "resource", Namespace: "namespace"}}
	r := &NetworkResourceReconciler{
		Client:  fake.NewClientBuilder().WithScheme(scheme).WithObjects(netResource).Build(),
		Netbird: netbird.New(server.URL, "token"),
	}

	recordID, err := r.ensureDNSRecord(context.Background(), netResource, "zone-id", request)
	require.NoError(t, err)
	require.Equal(t, "adopted", recordID)
}

func TestAdoptDNSRecordRejectsAnotherNetworkResourceOwner(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	nbClient := netbirdmock.Client()
	zone, err := nbClient.DNSZones.CreateZone(ctx, api.ZoneRequest{Name: "cluster.local", Domain: "cluster.local"})
	require.NoError(t, err)
	request := api.DNSRecordRequest{Name: "service.namespace.cluster.local", Type: api.DNSRecordTypeA, Content: "10.43.0.10", Ttl: 300}
	record, err := nbClient.DNSZones.CreateRecord(ctx, zone.Id, request)
	require.NoError(t, err)

	scheme := runtime.NewScheme()
	require.NoError(t, nbv1alpha1.AddToScheme(scheme))
	current := &nbv1alpha1.NetworkResource{ObjectMeta: metav1.ObjectMeta{Name: "current", Namespace: "namespace"}}
	owner := &nbv1alpha1.NetworkResource{
		ObjectMeta: metav1.ObjectMeta{Name: "owner", Namespace: "namespace"},
		Status: nbv1alpha1.NetworkResourceStatus{
			DNSZoneID:   zone.Id,
			DNSRecordID: record.Id,
		},
	}
	r := &NetworkResourceReconciler{
		Client:  fake.NewClientBuilder().WithScheme(scheme).WithObjects(current, owner).Build(),
		Netbird: nbClient,
	}

	_, err = r.adoptDNSRecord(ctx, current, zone.Id, request)
	require.Error(t, err)
	var conflictErr *dnsRecordConflictError
	require.ErrorAs(t, err, &conflictErr)
}

func TestAdoptDNSRecordScopesLookupToZone(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	request := api.DNSRecordRequest{Name: "service.namespace.target.local", Type: api.DNSRecordTypeA, Content: "10.43.0.10", Ttl: 300}
	var otherZoneListed atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/dns/zones/target-zone/records":
			if err := json.NewEncoder(w).Encode([]api.DNSRecord{}); err != nil {
				t.Errorf("encode target-zone records: %v", err)
			}
		case "/api/dns/zones/other-zone/records":
			otherZoneListed.Store(true)
			if err := json.NewEncoder(w).Encode([]api.DNSRecord{{Id: "conflict", Name: request.Name, Type: request.Type, Content: "10.43.0.11"}}); err != nil {
				t.Errorf("encode other-zone records: %v", err)
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	scheme := runtime.NewScheme()
	require.NoError(t, nbv1alpha1.AddToScheme(scheme))
	current := &nbv1alpha1.NetworkResource{ObjectMeta: metav1.ObjectMeta{Name: "current", Namespace: "namespace"}}
	r := &NetworkResourceReconciler{
		Client:  fake.NewClientBuilder().WithScheme(scheme).WithObjects(current).Build(),
		Netbird: netbird.New(server.URL, "token"),
	}

	record, err := r.adoptDNSRecord(ctx, current, "target-zone", request)
	require.NoError(t, err)
	require.Nil(t, record)
	require.False(t, otherZoneListed.Load())
}

type failingPatchClient struct {
	client.Client
	err error
}

func (c *failingPatchClient) Patch(context.Context, client.Object, client.Patch, ...client.PatchOption) error {
	return c.err
}

func TestNetworkResourcePersistsFinalizerBeforeExternalMutation(t *testing.T) {
	t.Parallel()

	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, nbv1alpha1.AddToScheme(scheme))

	nn := client.ObjectKey{Name: "resource", Namespace: "namespace"}
	service := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "service", Namespace: nn.Namespace},
		Spec: corev1.ServiceSpec{
			Type:      corev1.ServiceTypeClusterIP,
			ClusterIP: "10.43.0.10",
		},
	}
	router := &nbv1alpha1.NetworkRouter{
		ObjectMeta: metav1.ObjectMeta{Name: "router", Namespace: nn.Namespace},
		Status: nbv1alpha1.NetworkRouterStatus{
			NetworkID:     "network-id",
			RoutingPeerID: "routing-peer-id",
		},
	}
	netResource := &nbv1alpha1.NetworkResource{
		ObjectMeta: metav1.ObjectMeta{Name: nn.Name, Namespace: nn.Namespace},
		Spec: nbv1alpha1.NetworkResourceSpec{
			ServiceRef:       corev1.LocalObjectReference{Name: service.Name},
			NetworkRouterRef: nbv1alpha1.CrossNamespaceReference{Name: router.Name, Namespace: router.Namespace},
		},
	}
	baseClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(service, router, netResource).Build()
	patchErr := errors.New("persist finalizer")
	r := &NetworkResourceReconciler{Client: &failingPatchClient{Client: baseClient, err: patchErr}}

	_, err := r.Reconcile(context.Background(), reconcile.Request{NamespacedName: nn})
	require.ErrorIs(t, err, patchErr)

	stored := &nbv1alpha1.NetworkResource{}
	require.NoError(t, baseClient.Get(context.Background(), nn, stored))
	require.NotContains(t, stored.Finalizers, k8sutil.Finalizer("networkresource"))
}
