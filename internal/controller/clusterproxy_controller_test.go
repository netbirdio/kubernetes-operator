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

		It("applies the workload override to the Deployment", func() {
			// The proxy has to schedule on tainted nodes, such as control plane nodes
			// when every worker is down, or AKS node pools that are all tainted.
			toleration := corev1.Toleration{
				Key:      "node-role.kubernetes.io/control-plane",
				Operator: corev1.TolerationOpExists,
				Effect:   corev1.TaintEffectNoSchedule,
			}
			proxy := &nbv1alpha1.ClusterProxy{}
			Expect(k8sClient.Get(ctx, nn, proxy)).To(Succeed())
			proxy.Spec.WorkloadOverride = &nbv1alpha1.WorkloadOverride{
				Labels:      map[string]string{"team": "platform"},
				Annotations: map[string]string{"example.com/owner": "platform"},
				Replicas:    new(int32(1)),
				PodTemplate: &corev1.PodTemplateSpec{
					Spec: corev1.PodSpec{
						NodeSelector: map[string]string{"kubernetes.io/os": "linux"},
						Tolerations:  []corev1.Toleration{toleration},
						// An added env var lands ahead of the operator's own entries in the
						// merged list, which used to leak their valueFrom into it.
						Containers: []corev1.Container{{
							Name: "proxy",
							Env:  []corev1.EnvVar{{Name: "EXAMPLE_ENV", Value: "example"}},
						}},
					},
				},
			}
			Expect(k8sClient.Update(ctx, proxy)).To(Succeed())

			reconcileProxy()

			dep := proxyDeployment()
			Expect(dep.Labels).To(HaveKeyWithValue("team", "platform"), "override labels should be on the Deployment")
			Expect(dep.Labels).To(HaveKeyWithValue("app.kubernetes.io/name", "clusterproxy"), "selector labels must be kept")
			Expect(dep.Annotations).To(HaveKeyWithValue("example.com/owner", "platform"), "override annotations should be on the Deployment")
			Expect(*dep.Spec.Replicas).To(Equal(int32(1)), "override replicas should replace the default")

			podSpec := dep.Spec.Template.Spec
			Expect(podSpec.Tolerations).To(ContainElement(toleration), "override tolerations should be on the pod")
			Expect(podSpec.NodeSelector).To(HaveKeyWithValue("kubernetes.io/os", "linux"), "override node selector should be on the pod")
			Expect(podSpec.TopologySpreadConstraints).To(HaveLen(1), "default spread constraint must be kept")

			Expect(podSpec.Containers).To(HaveLen(1))
			container := podSpec.Containers[0]
			Expect(container.Image).To(Equal(proxyImage), "default image must be kept")
			Expect(container.Env).To(ContainElement(corev1.EnvVar{Name: "EXAMPLE_ENV", Value: "example"}))
			Expect(container.Env).To(ContainElement(And(
				HaveField("Name", "SETUP_KEY"),
				HaveField("Value", BeEmpty()),
				HaveField("ValueFrom.SecretKeyRef.Key", SetupKeySecretKey),
			)), "operator env vars must keep their secret references")
			for _, env := range container.Env {
				if env.ValueFrom != nil {
					Expect(env.Value).To(BeEmpty(), "env var %s must not set both value and valueFrom", env.Name)
				}
			}
		})

		It("keeps the generated containers when the override only sets tolerations", func() {
			// An override without containers is the common case for scheduling. Its
			// containers field marshals to null, which a strategic merge reads as a
			// delete, so it must not reach the merge.
			toleration := corev1.Toleration{
				Key:      "node-role.kubernetes.io/control-plane",
				Operator: corev1.TolerationOpExists,
				Effect:   corev1.TaintEffectNoSchedule,
			}
			proxy := &nbv1alpha1.ClusterProxy{}
			Expect(k8sClient.Get(ctx, nn, proxy)).To(Succeed())
			proxy.Spec.WorkloadOverride = &nbv1alpha1.WorkloadOverride{
				PodTemplate: &corev1.PodTemplateSpec{
					Spec: corev1.PodSpec{Tolerations: []corev1.Toleration{toleration}},
				},
			}
			Expect(k8sClient.Update(ctx, proxy)).To(Succeed())

			reconcileProxy()

			podSpec := proxyDeployment().Spec.Template.Spec
			Expect(podSpec.Tolerations).To(ContainElement(toleration), "override tolerations should be on the pod")
			Expect(podSpec.Containers).To(HaveLen(1), "the generated proxy container must be kept")
			Expect(podSpec.Containers[0].Image).To(Equal(proxyImage), "the generated proxy container must be kept")
			Expect(podSpec.ServiceAccountName).To(Equal("proxy"), "generated pod fields must be kept")
		})

		It("defaults to three replicas without a workload override", func() {
			reconcileProxy()

			dep := proxyDeployment()
			Expect(*dep.Spec.Replicas).To(Equal(int32(3)), "default replica count")
			Expect(dep.Spec.Template.Spec.Tolerations).To(BeEmpty(), "no tolerations without an override")
		})
	})
})
