package v1

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"

	netbirdiov1 "github.com/netbirdio/kubernetes-operator/api/v1"
	"github.com/netbirdio/kubernetes-operator/internal/util"
)

var _ = Describe("NBRoutingPeer Webhook", func() {
	var (
		obj       *netbirdiov1.NBRoutingPeer
		oldObj    *netbirdiov1.NBRoutingPeer
		validator NBRoutingPeerCustomValidator
	)

	BeforeEach(func() {
		obj = &netbirdiov1.NBRoutingPeer{}
		oldObj = &netbirdiov1.NBRoutingPeer{}
		validator = NBRoutingPeerCustomValidator{
			client: k8sClient,
		}
	})

	Context("When creating or updating NBRoutingPeer under Validating Webhook", func() {
		It("should allow creation", func() {
			Expect(validator.ValidateCreate(ctx, obj)).Error().NotTo(HaveOccurred())
		})
		It("should allow update", func() {
			Expect(validator.ValidateUpdate(ctx, oldObj, obj)).Error().NotTo(HaveOccurred())
		})
		When("No NBResources Exist", func() {
			It("should allow deletion", func() {
				Expect(validator.ValidateDelete(ctx, obj)).Error().NotTo(HaveOccurred())
			})
		})
		When("Deleteable NBResources Exist", func() {
			BeforeEach(func() {
				nbResource := &netbirdiov1.NBResource{
					ObjectMeta: v1.ObjectMeta{
						Name:      "isexist",
						Namespace: "default",
					},
					Spec: netbirdiov1.NBResourceSpec{
						Name:      "test1",
						NetworkID: "test2",
						Address:   "test3",
						Groups:    []string{"test"},
					},
				}

				Expect(k8sClient.Create(ctx, nbResource)).To(Succeed())

				obj = &netbirdiov1.NBRoutingPeer{
					Status: netbirdiov1.NBRoutingPeerStatus{
						NetworkID: util.Ptr("test2"),
					},
				}
			})

			AfterEach(func() {
				nbResource := &netbirdiov1.NBResource{}
				err := k8sClient.Get(ctx, types.NamespacedName{Namespace: "default", Name: "isexist"}, nbResource)
				if !errors.IsNotFound(err) {
					Expect(err).NotTo(HaveOccurred())
					if len(nbResource.Finalizers) > 0 {
						nbResource.Finalizers = nil
						Expect(k8sClient.Update(ctx, nbResource)).To(Succeed())
					}
					err = k8sClient.Delete(ctx, nbResource)
					if !errors.IsNotFound(err) {
						Expect(err).NotTo(HaveOccurred())
					}
				}
			})
			It("should allow deletion", func() {
				Expect(validator.ValidateDelete(ctx, obj)).Error().NotTo(HaveOccurred())
			})
		})
		When("Exposed Services for Network Exist", func() {
			BeforeEach(func() {
				nbResource := &netbirdiov1.NBResource{
					ObjectMeta: v1.ObjectMeta{
						Name:      "maw",
						Namespace: "default",
					},
					Spec: netbirdiov1.NBResourceSpec{
						Name:      "test1",
						NetworkID: "test2",
						Address:   "test3",
						Groups:    []string{"test"},
					},
				}

				Expect(k8sClient.Create(ctx, nbResource)).To(Succeed())

				svc := &corev1.Service{
					ObjectMeta: v1.ObjectMeta{
						Name:      "maw",
						Namespace: "default",
						Annotations: map[string]string{
							"netbird.io/expose": "true",
						},
					},
					Spec: corev1.ServiceSpec{
						Ports: []corev1.ServicePort{
							{
								Protocol:   corev1.ProtocolTCP,
								Port:       80,
								TargetPort: intstr.FromInt32(80),
							},
						},
					},
				}
				Expect(k8sClient.Create(ctx, svc)).To(Succeed())

				obj = &netbirdiov1.NBRoutingPeer{
					Status: netbirdiov1.NBRoutingPeerStatus{
						NetworkID: util.Ptr("test2"),
					},
				}
			})

			AfterEach(func() {
				nbResource := &netbirdiov1.NBResource{}
				err := k8sClient.Get(ctx, types.NamespacedName{Namespace: "default", Name: "maw"}, nbResource)
				if !errors.IsNotFound(err) {
					Expect(err).NotTo(HaveOccurred())
					if len(nbResource.Finalizers) > 0 {
						nbResource.Finalizers = nil
						Expect(k8sClient.Update(ctx, nbResource)).To(Succeed())
					}
					err = k8sClient.Delete(ctx, nbResource)
					if !errors.IsNotFound(err) {
						Expect(err).NotTo(HaveOccurred())
					}
				}

				svc := &corev1.Service{}
				err = k8sClient.Get(ctx, types.NamespacedName{Namespace: "default", Name: "maw"}, svc)
				if !errors.IsNotFound(err) {
					Expect(err).NotTo(HaveOccurred())
					if len(svc.Finalizers) > 0 {
						svc.Finalizers = nil
						Expect(k8sClient.Update(ctx, svc)).To(Succeed())
					}
					err = k8sClient.Delete(ctx, svc)
					if !errors.IsNotFound(err) {
						Expect(err).NotTo(HaveOccurred())
					}
				}
			})
			It("should deny deletion", func() {
				Expect(validator.ValidateDelete(ctx, obj)).Error().To(HaveOccurred())
			})
		})
		When("Exposed NBResources do not belong to network", func() {
			BeforeEach(func() {
				nbResource := &netbirdiov1.NBResource{
					ObjectMeta: v1.ObjectMeta{
						Name:      "maw",
						Namespace: "default",
					},
					Spec: netbirdiov1.NBResourceSpec{
						Name:      "test1",
						NetworkID: "test5",
						Address:   "test3",
						Groups:    []string{"test"},
					},
				}

				Expect(k8sClient.Create(ctx, nbResource)).To(Succeed())

				svc := &corev1.Service{
					ObjectMeta: v1.ObjectMeta{
						Name:      "maw",
						Namespace: "default",
						Annotations: map[string]string{
							"netbird.io/expose": "true",
						},
					},
					Spec: corev1.ServiceSpec{
						Ports: []corev1.ServicePort{
							{
								Protocol:   corev1.ProtocolTCP,
								Port:       80,
								TargetPort: intstr.FromInt32(80),
							},
						},
					},
				}
				Expect(k8sClient.Create(ctx, svc)).To(Succeed())

				obj = &netbirdiov1.NBRoutingPeer{
					Status: netbirdiov1.NBRoutingPeerStatus{
						NetworkID: util.Ptr("test2"),
					},
				}
			})

			AfterEach(func() {
				nbResource := &netbirdiov1.NBResource{}
				err := k8sClient.Get(ctx, types.NamespacedName{Namespace: "default", Name: "maw"}, nbResource)
				if !errors.IsNotFound(err) {
					Expect(err).NotTo(HaveOccurred())
					if len(nbResource.Finalizers) > 0 {
						nbResource.Finalizers = nil
						Expect(k8sClient.Update(ctx, nbResource)).To(Succeed())
					}
					err = k8sClient.Delete(ctx, nbResource)
					if !errors.IsNotFound(err) {
						Expect(err).NotTo(HaveOccurred())
					}
				}

				svc := &corev1.Service{}
				err = k8sClient.Get(ctx, types.NamespacedName{Namespace: "default", Name: "maw"}, svc)
				if !errors.IsNotFound(err) {
					Expect(err).NotTo(HaveOccurred())
					if len(svc.Finalizers) > 0 {
						svc.Finalizers = nil
						Expect(k8sClient.Update(ctx, svc)).To(Succeed())
					}
					err = k8sClient.Delete(ctx, svc)
					if !errors.IsNotFound(err) {
						Expect(err).NotTo(HaveOccurred())
					}
				}
			})
			It("should allow deletion", func() {
				Expect(validator.ValidateDelete(ctx, obj)).Error().NotTo(HaveOccurred())
			})
		})
	})

})
