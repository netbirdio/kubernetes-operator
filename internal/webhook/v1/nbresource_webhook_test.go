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
)

var _ = Describe("NBResource Webhook", func() {
	var (
		obj       *netbirdiov1.NBResource
		oldObj    *netbirdiov1.NBResource
		validator NBResourceCustomValidator
	)

	BeforeEach(func() {
		obj = &netbirdiov1.NBResource{}
		oldObj = &netbirdiov1.NBResource{}
		validator = NBResourceCustomValidator{
			client: k8sClient,
		}
	})

	Context("When creating or updating NBResource under Validating Webhook", func() {
		It("should allow creation", func() {
			Expect(validator.ValidateCreate(ctx, obj)).Error().NotTo(HaveOccurred())
		})
		It("should allow update", func() {
			Expect(validator.ValidateUpdate(ctx, oldObj, obj)).Error().NotTo(HaveOccurred())
		})
		When("No services are exposed", func() {
			BeforeEach(func() {
				obj.Name = "maw"
				obj.Namespace = "default"
				svc := &corev1.Service{
					ObjectMeta: v1.ObjectMeta{
						Name:      "ne",
						Namespace: "default",
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
			})
			AfterEach(func() {
				svc := &netbirdiov1.NBResource{}
				err := k8sClient.Get(ctx, types.NamespacedName{Namespace: "default", Name: "ne"}, svc)
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

		When("A service is exposed", func() {
			BeforeEach(func() {
				obj.Name = "maw"
				obj.Namespace = "default"
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
			})
			AfterEach(func() {
				svc := &corev1.Service{}
				err := k8sClient.Get(ctx, types.NamespacedName{Namespace: "default", Name: "maw"}, svc)
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
	})
})
