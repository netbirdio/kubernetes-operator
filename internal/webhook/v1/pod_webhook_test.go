// SPDX-License-Identifier: BSD-3-Clause

package v1

import (
	"context"
	"testing"

	"github.com/go-openapi/testify/v2/require"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kruntime "k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	nbv1 "github.com/netbirdio/kubernetes-operator/api/v1"
	nbv1alpha1 "github.com/netbirdio/kubernetes-operator/api/v1alpha1"
)

func TestPodInjectorSidecarProfile(t *testing.T) {
	t.Parallel()

	for _, mode := range []nbv1alpha1.InjectionMode{nbv1alpha1.InjectionModeContainer, nbv1alpha1.InjectionModeSidecar} {
		t.Run(string(mode), func(t *testing.T) {
			t.Parallel()

			setupKey := &nbv1alpha1.SetupKey{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "test",
				},
				Spec: nbv1alpha1.SetupKeySpec{
					Name:      "test",
					Ephemeral: true,
				},
			}
			sidecarProfile := &nbv1alpha1.SidecarProfile{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "test",
				},
				Spec: nbv1alpha1.SidecarProfileSpec{
					SetupKeyRef: corev1.LocalObjectReference{
						Name: "test",
					},
					InjectionMode: mode,
				},
			}

			scheme := kruntime.NewScheme()
			err := corev1.AddToScheme(scheme)
			require.NoError(t, err)
			err = nbv1alpha1.AddToScheme(scheme)
			require.NoError(t, err)
			k8sClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(sidecarProfile, setupKey).Build()
			injector := PodNetbirdInjector{
				client:        k8sClient,
				managementURL: "https://api.netbird.io",
				clientImage:   "netbirdio/netbird:latest",
			}

			pod := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "test",
				},
				Spec: corev1.PodSpec{
					InitContainers: []corev1.Container{
						{
							Name: "app-init",
						},
					},
					Containers: []corev1.Container{
						{
							Name: "app",
						},
					},
				},
			}
			err = injector.Default(t.Context(), pod)
			require.NoError(t, err)

			require.EqualT(t, "test", pod.Annotations[SidecarProfileAnnotation])
			switch mode {
			case nbv1alpha1.InjectionModeContainer:
				require.Len(t, pod.Spec.InitContainers, 2)
				require.EqualT(t, "resolv-conf", pod.Spec.InitContainers[0].Name)
				require.EqualT(t, "app-init", pod.Spec.InitContainers[1].Name)
				require.Len(t, pod.Spec.Containers, 2)
				require.EqualT(t, "netbird", pod.Spec.Containers[0].Name)
				require.EqualT(t, "app", pod.Spec.Containers[1].Name)
			case nbv1alpha1.InjectionModeSidecar:
				require.Len(t, pod.Spec.InitContainers, 3)
				require.EqualT(t, "resolv-conf", pod.Spec.InitContainers[0].Name)
				require.Nil(t, pod.Spec.InitContainers[0].RestartPolicy)
				require.EqualT(t, "netbird", pod.Spec.InitContainers[1].Name)
				require.EqualT(t, corev1.ContainerRestartPolicyAlways, *pod.Spec.InitContainers[1].RestartPolicy)
				require.EqualT(t, "app-init", pod.Spec.InitContainers[2].Name)
				require.Len(t, pod.Spec.Containers, 1)
				require.EqualT(t, "app", pod.Spec.Containers[0].Name)
			}
		})
	}
}

var _ = Describe("Pod Webhook", func() {
	var (
		obj       *corev1.Pod
		defaulter PodNetbirdInjector
	)

	BeforeEach(func() {
		obj = &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:        "test",
				Namespace:   "test",
				Annotations: make(map[string]string),
			},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Name: "test",
					},
				},
			},
		}
		defaulter = PodNetbirdInjector{
			client:        k8sClient,
			managementURL: "https://api.netbird.io",
			clientImage:   "netbirdio/netbird:latest",
		}
		Expect(defaulter).NotTo(BeNil(), "Expected defaulter to be initialized")
		Expect(obj).NotTo(BeNil(), "Expected obj to be initialized")
	})

	AfterEach(func() {
	})

	Context("When creating Pod without annotation", func() {
		It("Should not modify anything", func() {
			err := defaulter.Default(context.Background(), obj)
			Expect(err).NotTo(HaveOccurred())
			Expect(obj.Spec.Containers).To(HaveLen(1))
		})
	})

	Context("When creating Pod with annotation", func() {
		BeforeEach(func() {
			obj.Annotations[setupKeyAnnotation] = "test"
		})

		When("NBSetupKey doesn't exist", func() {
			It("Should fail", func() {
				Expect(defaulter.Default(context.Background(), obj)).To(HaveOccurred())
				Expect(obj.Spec.Containers).To(HaveLen(1))
			})
		})

		When("NBSetupKey exists", Ordered, func() {
			BeforeAll(func() {
				sk := nbv1.NBSetupKey{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test",
						Namespace: "test",
					},
					Spec: nbv1.NBSetupKeySpec{
						SecretKeyRef: corev1.SecretKeySelector{
							LocalObjectReference: corev1.LocalObjectReference{
								Name: "test",
							},
							Key: "test",
						},
					},
				}

				err := k8sClient.Create(context.Background(), &corev1.Namespace{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test",
					},
				})
				Expect(err).NotTo(HaveOccurred())

				err = k8sClient.Create(context.Background(), &sk)
				Expect(err).NotTo(HaveOccurred())

				sk.Status = nbv1.NBSetupKeyStatus{
					Conditions: []nbv1.NBCondition{
						{
							Type:   nbv1.NBSetupKeyReady,
							Status: corev1.ConditionTrue,
						},
					},
				}

				err = k8sClient.Status().Update(context.Background(), &sk)
				Expect(err).NotTo(HaveOccurred())
			})

			It("Should inject NB container", func() {
				Expect(defaulter.Default(context.Background(), obj)).NotTo(HaveOccurred())
				Expect(obj.Spec.Containers).To(HaveLen(2))
				Expect(obj.Spec.Containers[1].Name).To(Equal("netbird"))
			})

			It("Should inject NB container as native sidecar when init-sidecar annotation is true", func() {
				obj.Annotations[sidecarAnnotation] = "true"
				Expect(defaulter.Default(context.Background(), obj)).NotTo(HaveOccurred())
				Expect(obj.Spec.Containers).To(HaveLen(1), "original containers should be unchanged")
				Expect(obj.Spec.InitContainers).To(HaveLen(1))
				Expect(obj.Spec.InitContainers[0].Name).To(Equal("netbird"))
				Expect(obj.Spec.InitContainers[0].RestartPolicy).NotTo(BeNil())
				Expect(*obj.Spec.InitContainers[0].RestartPolicy).To(Equal(corev1.ContainerRestartPolicyAlways))
			})

			It("Should inject NB as regular container when init-sidecar annotation is false", func() {
				obj.Annotations[sidecarAnnotation] = "false"
				Expect(defaulter.Default(context.Background(), obj)).NotTo(HaveOccurred())
				Expect(obj.Spec.Containers).To(HaveLen(2))
				Expect(obj.Spec.Containers[1].Name).To(Equal("netbird"))
				Expect(obj.Spec.InitContainers).To(BeEmpty())
			})

			It("Should inject NB as regular container when init-sidecar annotation is absent", func() {
				delete(obj.Annotations, sidecarAnnotation)
				Expect(defaulter.Default(context.Background(), obj)).NotTo(HaveOccurred())
				Expect(obj.Spec.Containers).To(HaveLen(2))
				Expect(obj.Spec.Containers[1].Name).To(Equal("netbird"))
				Expect(obj.Spec.InitContainers).To(BeEmpty())
			})

		})
	})
})
