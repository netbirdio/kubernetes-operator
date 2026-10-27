// SPDX-License-Identifier: BSD-3-Clause

package controller

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/rand"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	nbv1alpha1 "github.com/netbirdio/kubernetes-operator/api/v1alpha1"
	"github.com/netbirdio/kubernetes-operator/internal/netbirdmock"
)

var _ = Describe("ClusterProxy Controller", func() {
	Context("When reconciling a resource", func() {
		ctx := context.Background()
		const proxyImage = "registry.example.com/netbird-kubeapi-proxy:custom"

		var rec *ClusterProxyReconciler
		var setupKeyRec *SetupKeyReconciler
		var nn client.ObjectKey

		// reconcile runs the ClusterProxy controller twice around the SetupKey
		// controller: the first pass creates the setup key and waits for its ID,
		// which only the SetupKey controller sets.
		reconcileProxy := func() {
			_, err := rec.Reconcile(ctx, reconcile.Request{NamespacedName: nn})
			Expect(err).NotTo(HaveOccurred())
			setupKey := client.ObjectKey{Namespace: nn.Namespace, Name: "clusterproxy-" + nn.Name}
			_, err = setupKeyRec.Reconcile(ctx, reconcile.Request{NamespacedName: setupKey})
			Expect(err).NotTo(HaveOccurred())
			_, err = rec.Reconcile(ctx, reconcile.Request{NamespacedName: nn})
			Expect(err).NotTo(HaveOccurred())
		}

		proxyDeployment := func() *appsv1.Deployment {
			dep := &appsv1.Deployment{}
			Expect(k8sClient.Get(ctx, client.ObjectKey{Namespace: nn.Namespace, Name: "clusterproxy-" + nn.Name}, dep)).To(Succeed())
			return dep
		}

		BeforeEach(func() {
			// envtest runs no namespace controller, so a deleted namespace never goes
			// away and each spec needs its own.
			nn = client.ObjectKey{Namespace: "cluster-proxy-" + rand.String(5), Name: "proxy"}
			nbClient := netbirdmock.Client()
			rec = &ClusterProxyReconciler{
				Client:        k8sClient,
				ApiKey:        "api-key",
				ManagementURL: "https://netbird.example.com",
				Image:         proxyImage,
			}
			setupKeyRec = &SetupKeyReconciler{Client: k8sClient, Netbird: nbClient}

			Expect(k8sClient.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: nn.Namespace}})).To(Succeed())
			Expect(k8sClient.Create(ctx, &nbv1alpha1.ClusterProxy{
				ObjectMeta: metav1.ObjectMeta{Name: nn.Name, Namespace: nn.Namespace},
				Spec: nbv1alpha1.ClusterProxySpec{
					ClusterName:        "test-cluster",
					APIServer:          "https://kubernetes.default.svc",
					ServiceAccountName: "proxy",
				},
			})).To(Succeed())
		})

		It("deploys the configured kubeapi-proxy image", func() {
			reconcileProxy()

			containers := proxyDeployment().Spec.Template.Spec.Containers
			Expect(containers).To(HaveLen(1))
			Expect(containers[0].Image).To(Equal(proxyImage))
			Expect(containers[0].Args).To(ContainElements(
				"--cluster-name", "test-cluster",
				"--kubernetes-api-server", "https://kubernetes.default.svc",
				"--management-url", "https://netbird.example.com",
			))

			proxy := &nbv1alpha1.ClusterProxy{}
			Expect(k8sClient.Get(ctx, nn, proxy)).To(Succeed())
			Expect(meta.IsStatusConditionTrue(proxy.Status.Conditions, nbv1alpha1.ReadyCondition)).To(BeTrue())
		})

		It("rolls the Deployment to a new image when the operator's image changes", func() {
			reconcileProxy()
			Expect(proxyDeployment().Spec.Template.Spec.Containers[0].Image).To(Equal(proxyImage))

			// An operator restarted with another --kubeapi-proxy-image has to move
			// existing proxies to it, not only new ones.
			const newImage = "mirror.example.com/netbird-kubeapi-proxy:v0.0.5"
			rec.Image = newImage
			_, err := rec.Reconcile(ctx, reconcile.Request{NamespacedName: nn})
			Expect(err).NotTo(HaveOccurred())
			Expect(proxyDeployment().Spec.Template.Spec.Containers[0].Image).To(Equal(newImage))
		})
	})
})
