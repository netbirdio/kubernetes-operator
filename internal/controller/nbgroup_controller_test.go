package controller

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	netbirdiov1 "github.com/netbirdio/kubernetes-operator/api/v1"
	"github.com/netbirdio/kubernetes-operator/internal/util"
	netbird "github.com/netbirdio/netbird/management/client/rest"
	"github.com/netbirdio/netbird/management/server/http/api"
)

var _ = Describe("NBGroup Controller", func() {
	Context("When reconciling a resource", func() {
		const resourceName = "test-resource"

		ctx := context.Background()

		typeNamespacedName := types.NamespacedName{
			Name:      resourceName,
			Namespace: "default",
		}

		var netbirdClient *netbird.Client
		var mux *http.ServeMux
		var server *httptest.Server
		var nbGroup netbirdiov1.NBGroup

		BeforeEach(func() {
			mux = &http.ServeMux{}
			server = httptest.NewServer(mux)
			netbirdClient = netbird.New(server.URL, "ABC")

			err := k8sClient.Get(ctx, typeNamespacedName, &nbGroup)
			if err == nil {
				deleteErr := k8sClient.Delete(ctx, &nbGroup)
				Expect(deleteErr).NotTo(HaveOccurred())
			}
			if err == nil || errors.IsNotFound(err) {
				nbGroup = netbirdiov1.NBGroup{
					ObjectMeta: v1.ObjectMeta{
						Name:       resourceName,
						Namespace:  typeNamespacedName.Namespace,
						Finalizers: []string{"netbird.io/group-cleanup"},
					},
					Spec: netbirdiov1.NBGroupSpec{
						Name: resourceName,
					},
				}
				err = k8sClient.Create(ctx, &nbGroup)
				Expect(err).NotTo(HaveOccurred())
			}
		})

		AfterEach(func() {
			server.Close()
			resource := &netbirdiov1.NBGroup{}
			err := k8sClient.Get(ctx, typeNamespacedName, resource)
			if errors.IsNotFound(err) {
				return
			}
			Expect(err).NotTo(HaveOccurred())
			if len(resource.Finalizers) > 0 {
				resource.Finalizers = nil
				Expect(k8sClient.Update(ctx, resource)).To(Succeed())
			}

			if resource.DeletionTimestamp == nil {
				By("Cleanup the specific resource instance NBGroup")
				Expect(k8sClient.Delete(ctx, resource)).To(Succeed())
			}
		})

		When("Group doesn't exist", func() {
			It("should create group", func() {
				By("Reconciling the created resource")
				controllerReconciler := &NBGroupReconciler{
					Client:  k8sClient,
					Scheme:  k8sClient.Scheme(),
					netbird: netbirdClient,
				}

				mux.HandleFunc("/api/groups", func(w http.ResponseWriter, r *http.Request) {
					if r.Method == http.MethodGet {
						_, err := w.Write([]byte("[]"))
						Expect(err).NotTo(HaveOccurred())
					} else {
						resp := api.Group{
							Id:   "Test",
							Name: resourceName,
						}
						bs, err := json.Marshal(resp)
						Expect(err).NotTo(HaveOccurred())
						_, err = w.Write(bs)
						Expect(err).NotTo(HaveOccurred())
					}
				})

				_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
					NamespacedName: typeNamespacedName,
				})
				Expect(err).NotTo(HaveOccurred())
				err = k8sClient.Get(ctx, typeNamespacedName, &nbGroup)
				Expect(err).NotTo(HaveOccurred())
				Expect(nbGroup.Status.GroupID).NotTo(BeNil())
				Expect(*nbGroup.Status.GroupID).To(Equal("Test"))
				Expect(nbGroup.Status.Conditions).To(HaveLen(1))
				Expect(nbGroup.Status.Conditions[0].Status).To(BeEquivalentTo(v1.ConditionTrue))
				Expect(nbGroup.Status.Conditions[0].Type).To(Equal(netbirdiov1.NBSetupKeyReady))
			})
		})

		When("Group already exists", func() {
			It("should use existing group", func() {
				By("Reconciling the created resource")
				controllerReconciler := &NBGroupReconciler{
					Client:  k8sClient,
					Scheme:  k8sClient.Scheme(),
					netbird: netbirdClient,
				}

				mux.HandleFunc("/api/groups", func(w http.ResponseWriter, r *http.Request) {
					resp := []api.Group{
						{
							Id:   "Test",
							Name: resourceName,
						},
					}
					bs, err := json.Marshal(resp)
					Expect(err).NotTo(HaveOccurred())
					_, err = w.Write(bs)
					Expect(err).NotTo(HaveOccurred())
				})

				_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
					NamespacedName: typeNamespacedName,
				})
				Expect(err).NotTo(HaveOccurred())
				err = k8sClient.Get(ctx, typeNamespacedName, &nbGroup)
				Expect(err).NotTo(HaveOccurred())
				Expect(nbGroup.Status.GroupID).NotTo(BeNil())
				Expect(*nbGroup.Status.GroupID).To(Equal("Test"))
				Expect(nbGroup.Status.Conditions).To(HaveLen(1))
				Expect(nbGroup.Status.Conditions[0].Status).To(BeEquivalentTo(v1.ConditionTrue))
				Expect(nbGroup.Status.Conditions[0].Type).To(Equal(netbirdiov1.NBSetupKeyReady))
			})
		})

		When("NBGroup is set for deletion", func() {
			deleteGroup := func() {
				GinkgoHelper()
				By("Adding the group ID in status")
				nbGroup.Status.GroupID = util.Ptr("Test")
				err := k8sClient.Status().Update(ctx, &nbGroup)
				Expect(err).NotTo(HaveOccurred())

				By("Deleting the object")
				err = k8sClient.Delete(ctx, &nbGroup)
				Expect(err).NotTo(HaveOccurred())
			}

			When("Group is not linked to any resources", func() {
				It("should delete group", func() {
					deleteGroup()
					By("Reconciling the deleting resource")
					controllerReconciler := &NBGroupReconciler{
						Client:  k8sClient,
						Scheme:  k8sClient.Scheme(),
						netbird: netbirdClient,
					}

					method := ""
					mux.HandleFunc("/api/groups/Test", func(w http.ResponseWriter, r *http.Request) {
						method = r.Method
						_, err := w.Write([]byte("{}"))
						Expect(err).NotTo(HaveOccurred())
					})

					_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
						NamespacedName: typeNamespacedName,
					})
					Expect(err).NotTo(HaveOccurred())
					err = k8sClient.Get(ctx, typeNamespacedName, &nbGroup)
					Expect(errors.IsNotFound(err)).To(BeTrue())
					Expect(method).To(Equal(http.MethodDelete))
				})
			})

			When("Group is linked to other resources", func() {
				It("should return error", func() {
					deleteGroup()
					By("Reconciling the deleting resource")
					controllerReconciler := &NBGroupReconciler{
						Client:  k8sClient,
						Scheme:  k8sClient.Scheme(),
						netbird: netbirdClient,
					}

					method := ""
					mux.HandleFunc("/api/groups/Test", func(w http.ResponseWriter, r *http.Request) {
						method = r.Method
						w.WriteHeader(400)
						_, err := w.Write([]byte(`{"message": "group has been linked to Policy: meow"}`))
						Expect(err).NotTo(HaveOccurred())
					})

					_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
						NamespacedName: typeNamespacedName,
					})
					Expect(err).To(HaveOccurred())
					err = k8sClient.Get(ctx, typeNamespacedName, &nbGroup)
					Expect(errors.IsNotFound(err)).To(BeFalse())
					Expect(method).To(Equal(http.MethodDelete))
				})
			})

			When("Group already exists in another namespace", func() {
				It("Should delete NBGroup after linked failure", func() {
					deleteGroup()
					otherGroup := &netbirdiov1.NBGroup{
						ObjectMeta: v1.ObjectMeta{
							Name:      nbGroup.Name,
							Namespace: "kube-system",
						},
						Spec: netbirdiov1.NBGroupSpec{
							Name: nbGroup.Spec.Name,
						},
					}
					Expect(k8sClient.Create(ctx, otherGroup)).To(Succeed())

					otherGroup.Status.GroupID = nbGroup.Status.GroupID
					Expect(k8sClient.Status().Update(ctx, otherGroup)).To(Succeed())

					By("Reconciling the deleting resource")
					controllerReconciler := &NBGroupReconciler{
						Client:  k8sClient,
						Scheme:  k8sClient.Scheme(),
						netbird: netbirdClient,
					}

					method := ""
					mux.HandleFunc("/api/groups/Test", func(w http.ResponseWriter, r *http.Request) {
						method = r.Method
						w.WriteHeader(400)
						_, err := w.Write([]byte(`{"message": "group has been linked to Policy: meow"}`))
						Expect(err).NotTo(HaveOccurred())
					})

					_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
						NamespacedName: typeNamespacedName,
					})

					Expect(err).NotTo(HaveOccurred())
					err = k8sClient.Get(ctx, typeNamespacedName, &nbGroup)
					Expect(errors.IsNotFound(err)).To(BeTrue())
					Expect(method).To(Equal(http.MethodDelete))
				})
			})
		})

		When("Group already exists with different ID", func() {
			It("should re-use existing group ID", func() {
				controllerReconciler := &NBGroupReconciler{
					Client:  k8sClient,
					Scheme:  k8sClient.Scheme(),
					netbird: netbirdClient,
				}

				mux.HandleFunc("/api/groups", func(w http.ResponseWriter, r *http.Request) {
					resp := []api.Group{
						{
							Id:   "Test",
							Name: resourceName,
						},
					}
					bs, err := json.Marshal(resp)
					Expect(err).NotTo(HaveOccurred())
					_, err = w.Write(bs)
					Expect(err).NotTo(HaveOccurred())
				})

				nbGroup.Status.GroupID = util.Ptr("Toast")
				Expect(k8sClient.Status().Update(ctx, &nbGroup)).To(Succeed())

				_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
					NamespacedName: typeNamespacedName,
				})
				Expect(err).NotTo(HaveOccurred())
				err = k8sClient.Get(ctx, typeNamespacedName, &nbGroup)
				Expect(err).NotTo(HaveOccurred())
				Expect(nbGroup.Status.GroupID).NotTo(BeNil())
				Expect(*nbGroup.Status.GroupID).To(Equal("Test"))
				Expect(nbGroup.Status.Conditions).To(HaveLen(1))
				Expect(nbGroup.Status.Conditions[0].Status).To(BeEquivalentTo(v1.ConditionTrue))
				Expect(nbGroup.Status.Conditions[0].Type).To(Equal(netbirdiov1.NBSetupKeyReady))
			})
		})

		When("Group deleted from NetBird API", func() {
			It("Should requeue and create group on next run", func() {
				controllerReconciler := &NBGroupReconciler{
					Client:  k8sClient,
					Scheme:  k8sClient.Scheme(),
					netbird: netbirdClient,
				}

				mux.HandleFunc("/api/groups", func(w http.ResponseWriter, r *http.Request) {
					if r.Method == http.MethodGet {
						resp := []api.Group{}
						bs, err := json.Marshal(resp)
						Expect(err).NotTo(HaveOccurred())
						_, err = w.Write(bs)
						Expect(err).NotTo(HaveOccurred())
					}
					if r.Method == http.MethodPost {
						resp := api.Group{
							Id:   "Test",
							Name: resourceName,
						}
						bs, err := json.Marshal(resp)
						Expect(err).NotTo(HaveOccurred())
						_, err = w.Write(bs)
						Expect(err).NotTo(HaveOccurred())
					}
				})

				nbGroup.Status.GroupID = util.Ptr("Toast")
				Expect(k8sClient.Status().Update(ctx, &nbGroup)).To(Succeed())

				res, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
					NamespacedName: typeNamespacedName,
				})
				Expect(err).NotTo(HaveOccurred())
				Expect(res.Requeue).To(BeTrue())

				err = k8sClient.Get(ctx, typeNamespacedName, &nbGroup)
				Expect(err).NotTo(HaveOccurred())

				Expect(nbGroup.Status.GroupID).To(BeNil())
				Expect(nbGroup.Status.Conditions).To(HaveLen(1))
				Expect(nbGroup.Status.Conditions[0].Status).To(BeEquivalentTo(v1.ConditionFalse))

				_, err = controllerReconciler.Reconcile(ctx, reconcile.Request{
					NamespacedName: typeNamespacedName,
				})
				Expect(err).NotTo(HaveOccurred())

				err = k8sClient.Get(ctx, typeNamespacedName, &nbGroup)
				Expect(err).NotTo(HaveOccurred())

				Expect(nbGroup.Status.GroupID).NotTo(BeNil())
				Expect(*nbGroup.Status.GroupID).To(Equal("Test"))
				Expect(nbGroup.Status.Conditions).To(HaveLen(1))
				Expect(nbGroup.Status.Conditions[0].Status).To(BeEquivalentTo(v1.ConditionTrue))
			})
		})
	})
})
