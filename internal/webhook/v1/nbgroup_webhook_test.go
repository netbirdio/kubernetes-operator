package v1

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	netbirdiov1 "github.com/netbirdio/kubernetes-operator/api/v1"
)

var _ = Describe("NBGroup Webhook", func() {
	var (
		obj       *netbirdiov1.NBGroup
		oldObj    *netbirdiov1.NBGroup
		validator NBGroupCustomValidator
	)

	BeforeEach(func() {
		obj = &netbirdiov1.NBGroup{}
		oldObj = &netbirdiov1.NBGroup{}
		validator = NBGroupCustomValidator{
			client: k8sClient,
		}
		Expect(validator).NotTo(BeNil(), "Expected validator to be initialized")
		Expect(oldObj).NotTo(BeNil(), "Expected oldObj to be initialized")
		Expect(obj).NotTo(BeNil(), "Expected obj to be initialized")
	})

	AfterEach(func() {
	})

	Context("When creating or updating NBGroup under Validating Webhook", func() {
		It("should allow creation", func() {
			Expect(validator.ValidateCreate(ctx, obj)).Error().NotTo(HaveOccurred())
		})
		It("should allow update", func() {
			Expect(validator.ValidateUpdate(ctx, oldObj, obj)).Error().NotTo(HaveOccurred())
		})
		When("There are no owners", func() {
			It("should allow deletion", func() {
				obj = &netbirdiov1.NBGroup{
					ObjectMeta: v1.ObjectMeta{
						Name:            "test",
						Namespace:       "default",
						OwnerReferences: nil,
					},
				}
				Expect(validator.ValidateDelete(ctx, obj)).Error().NotTo(HaveOccurred())
			})
		})
		When("There deleted owners", func() {
			It("should allow deletion", func() {
				obj = &netbirdiov1.NBGroup{
					ObjectMeta: v1.ObjectMeta{
						Name:      "test",
						Namespace: "default",
						OwnerReferences: []v1.OwnerReference{
							{
								APIVersion: netbirdiov1.GroupVersion.Identifier(),
								Kind:       "NBResource",
								Name:       "notexist",
								UID:        obj.UID,
							},
						},
					},
				}
				Expect(validator.ValidateDelete(ctx, obj)).Error().NotTo(HaveOccurred())
			})
		})
		When("NBResource owner exists", func() {
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

				obj = &netbirdiov1.NBGroup{
					ObjectMeta: v1.ObjectMeta{
						Name:      "test",
						Namespace: "default",
						OwnerReferences: []v1.OwnerReference{
							{
								APIVersion: netbirdiov1.GroupVersion.Identifier(),
								Kind:       nbResource.Kind,
								Name:       nbResource.Name,
								UID:        nbResource.UID,
							},
						},
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
			It("should deny deletion", func() {
				Expect(validator.ValidateDelete(ctx, obj)).Error().To(HaveOccurred())
			})
		})
		When("NBRoutingPeer owner exists", func() {
			BeforeEach(func() {
				nbrp := &netbirdiov1.NBRoutingPeer{
					ObjectMeta: v1.ObjectMeta{
						Name:      "isexist",
						Namespace: "default",
					},
					Spec: netbirdiov1.NBRoutingPeerSpec{},
				}

				Expect(k8sClient.Create(ctx, nbrp)).To(Succeed())

				obj = &netbirdiov1.NBGroup{
					ObjectMeta: v1.ObjectMeta{
						Name:      "test",
						Namespace: "default",
						OwnerReferences: []v1.OwnerReference{
							{
								APIVersion: netbirdiov1.GroupVersion.Identifier(),
								Kind:       nbrp.Kind,
								Name:       nbrp.Name,
								UID:        nbrp.UID,
							},
						},
					},
				}
			})
			AfterEach(func() {
				nbrp := &netbirdiov1.NBRoutingPeer{}
				err := k8sClient.Get(ctx, types.NamespacedName{Namespace: "default", Name: "isexist"}, nbrp)
				if !errors.IsNotFound(err) {
					Expect(err).NotTo(HaveOccurred())
					if len(nbrp.Finalizers) > 0 {
						nbrp.Finalizers = nil
						Expect(k8sClient.Update(ctx, nbrp)).To(Succeed())
					}
					err = k8sClient.Delete(ctx, nbrp)
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
