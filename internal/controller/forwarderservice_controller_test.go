// SPDX-License-Identifier: BSD-3-Clause

package controller

import (
	"context"
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	nbv1alpha1 "github.com/netbirdio/kubernetes-operator/api/v1alpha1"
)

var _ = Describe("ForwarderService Controller", func() {
	Context("When reconciling", func() {
		ctx := context.Background()

		const routerName = "fwd-router"
		var namespace string
		var fwdSvcNN client.ObjectKey

		var netEgressRec *NetworkEgressReconciler
		var forwarderRec *ForwarderServiceReconciler

		BeforeEach(func() {
			namespace = fmt.Sprintf("forwarder-service-%d", time.Now().UnixNano())
			fwdSvcNN = client.ObjectKey{
				Name:      fmt.Sprintf("networkrouter-%s-forwarder", routerName),
				Namespace: namespace,
			}
			netEgressRec = &NetworkEgressReconciler{
				Client: k8sClient,
			}
			forwarderRec = &ForwarderServiceReconciler{
				Client: k8sClient,
			}

			ns := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: namespace,
				},
			}
			Expect(k8sClient.Create(ctx, ns)).To(Succeed())

			netRouter := &nbv1alpha1.NetworkRouter{
				ObjectMeta: metav1.ObjectMeta{
					Name:      routerName,
					Namespace: namespace,
				},
				Spec: nbv1alpha1.NetworkRouterSpec{
					DNSZoneRef: nbv1alpha1.DNSZoneReference{
						Name: "foo.bar",
					},
				},
			}
			Expect(k8sClient.Create(ctx, netRouter)).To(Succeed())

			fwdSvc := &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name:      fwdSvcNN.Name,
					Namespace: namespace,
					Labels: map[string]string{
						ForwarderRouterNameLabel: routerName,
					},
				},
				Spec: corev1.ServiceSpec{
					Ports: []corev1.ServicePort{
						{Name: "http", Port: 80},
					},
				},
			}
			Expect(k8sClient.Create(ctx, fwdSvc)).To(Succeed())

			fwdSlice := &discoveryv1.EndpointSlice{
				ObjectMeta: metav1.ObjectMeta{
					Name:         fwdSvcNN.Name + "-abc12",
					GenerateName: fwdSvcNN.Name + "-",
					Namespace:    namespace,
					Labels: map[string]string{
						discoveryv1.LabelServiceName: fwdSvcNN.Name,
					},
				},
				AddressType: discoveryv1.AddressTypeIPv4,
				Endpoints: []discoveryv1.Endpoint{
					{Addresses: []string{"10.0.0.1"}},
				},
			}
			Expect(k8sClient.Create(ctx, fwdSlice)).To(Succeed())

			netEgress := &nbv1alpha1.NetworkEgress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "egress",
					Namespace: namespace,
				},
				Spec: nbv1alpha1.NetworkEgressSpec{
					NetworkRouterRef: nbv1alpha1.CrossNamespaceReference{
						Name:      routerName,
						Namespace: namespace,
					},
					Target: nbv1alpha1.NetworkEgressTarget{
						FQDN: &nbv1alpha1.NetworkEgressFQDNTarget{
							Hostname: "example.com",
						},
					},
					Ports: []nbv1alpha1.NetworkEgressPort{
						{Name: "http", Port: 80},
					},
				},
			}
			Expect(k8sClient.Create(ctx, netEgress)).To(Succeed())
			_, err := netEgressRec.Reconcile(ctx, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(netEgress)})
			Expect(err).NotTo(HaveOccurred())
		})

		AfterEach(func() {
			ns := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: namespace,
				},
			}
			Expect(k8sClient.Delete(ctx, ns)).To(Succeed())
		})

		It("does not modify derived objects when nothing changed", func() {
			_, err := forwarderRec.Reconcile(ctx, reconcile.Request{NamespacedName: fwdSvcNN})
			Expect(err).NotTo(HaveOccurred())

			cm := &corev1.ConfigMap{}
			Expect(k8sClient.Get(ctx, fwdSvcNN, cm)).To(Succeed())
			sliceList := &discoveryv1.EndpointSliceList{}
			Expect(k8sClient.List(ctx, sliceList, client.InNamespace(namespace), client.MatchingLabels{EgressRouterNameLabel: routerName})).To(Succeed())
			Expect(sliceList.Items).NotTo(BeEmpty())
			versions := map[string]string{cm.Name: cm.ResourceVersion}
			for _, item := range sliceList.Items {
				versions[item.Name] = item.ResourceVersion
			}

			time.Sleep(1100 * time.Millisecond)
			_, err = forwarderRec.Reconcile(ctx, reconcile.Request{NamespacedName: fwdSvcNN})
			Expect(err).NotTo(HaveOccurred())

			Expect(k8sClient.Get(ctx, fwdSvcNN, cm)).To(Succeed())
			Expect(cm.ResourceVersion).To(Equal(versions[cm.Name]))
			Expect(k8sClient.List(ctx, sliceList, client.InNamespace(namespace), client.MatchingLabels{EgressRouterNameLabel: routerName})).To(Succeed())
			for _, item := range sliceList.Items {
				Expect(item.ResourceVersion).To(Equal(versions[item.Name]), item.Name)
			}
		})

		It("prunes endpoint slices that are no longer desired", func() {
			stray := &discoveryv1.EndpointSlice{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "stray",
					Namespace: namespace,
					Labels: map[string]string{
						discoveryv1.LabelServiceName: "gone",
						EgressRouterNameLabel:        routerName,
						EgressRouterNamespaceLabel:   namespace,
					},
				},
				AddressType: discoveryv1.AddressTypeIPv4,
				Endpoints: []discoveryv1.Endpoint{
					{Addresses: []string{"10.0.0.2"}},
				},
			}
			Expect(k8sClient.Create(ctx, stray)).To(Succeed())

			_, err := forwarderRec.Reconcile(ctx, reconcile.Request{NamespacedName: fwdSvcNN})
			Expect(err).NotTo(HaveOccurred())

			err = k8sClient.Get(ctx, client.ObjectKeyFromObject(stray), stray)
			Expect(kerrors.IsNotFound(err)).To(BeTrue())
		})

		It("prunes same-named endpoint slices in other namespaces", func() {
			otherNamespace := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{Name: namespace + "-other"},
			}
			Expect(k8sClient.Create(ctx, otherNamespace)).To(Succeed())
			DeferCleanup(func() {
				Expect(k8sClient.Delete(ctx, otherNamespace)).To(Succeed())
			})

			stray := &discoveryv1.EndpointSlice{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "egress-abc12",
					Namespace: otherNamespace.Name,
					Labels: map[string]string{
						discoveryv1.LabelServiceName: "egress",
						EgressRouterNameLabel:        routerName,
						EgressRouterNamespaceLabel:   namespace,
					},
				},
				AddressType: discoveryv1.AddressTypeIPv4,
				Endpoints: []discoveryv1.Endpoint{
					{Addresses: []string{"10.0.0.2"}},
				},
			}
			Expect(k8sClient.Create(ctx, stray)).To(Succeed())

			_, err := forwarderRec.Reconcile(ctx, reconcile.Request{NamespacedName: fwdSvcNN})
			Expect(err).NotTo(HaveOccurred())

			err = k8sClient.Get(ctx, client.ObjectKeyFromObject(stray), stray)
			Expect(kerrors.IsNotFound(err)).To(BeTrue())
		})

		It("preserves system labels on derived endpoint slices", func() {
			egressSvc := &corev1.Service{}
			key := client.ObjectKey{Name: "egress", Namespace: namespace}
			Expect(k8sClient.Get(ctx, key, egressSvc)).To(Succeed())
			egressSvc.Labels[discoveryv1.LabelServiceName] = "wrong"
			egressSvc.Labels[discoveryv1.LabelManagedBy] = "wrong"
			egressSvc.Labels["example.com/custom"] = "value"
			Expect(k8sClient.Update(ctx, egressSvc)).To(Succeed())

			_, err := forwarderRec.Reconcile(ctx, reconcile.Request{NamespacedName: fwdSvcNN})
			Expect(err).NotTo(HaveOccurred())

			slice := &discoveryv1.EndpointSlice{}
			key = client.ObjectKey{Name: "egress-abc12", Namespace: namespace}
			Expect(k8sClient.Get(ctx, key, slice)).To(Succeed())
			Expect(slice.Labels).To(HaveKeyWithValue(discoveryv1.LabelServiceName, "egress"))
			Expect(slice.Labels).To(HaveKeyWithValue(discoveryv1.LabelManagedBy, "netbird-operator.netbird.io"))
			Expect(slice.Labels).To(HaveKeyWithValue("example.com/custom", "value"))
		})
	})
})
