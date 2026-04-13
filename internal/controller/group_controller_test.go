package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/http/httptest"

	netbird "github.com/netbirdio/netbird/shared/management/client/rest"
	"github.com/netbirdio/netbird/shared/management/http/api"
	"github.com/netbirdio/netbird/shared/management/http/util"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	nbv1alpha1 "github.com/netbirdio/kubernetes-operator/api/v1alpha1"
)

var _ = Describe("Group Controller", func() {
	Context("When reconciling a resource", func() {
		ctx := context.Background()

		r := rand.New(rand.NewSource(GinkgoRandomSeed()))
		groupStore := map[string]*api.Group{}
		mux := &http.ServeMux{}
		mux.Handle("POST /api/groups", http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
			b, err := io.ReadAll(req.Body)
			Expect(err).NotTo(HaveOccurred())
			groupReq := api.GroupRequest{}
			err = json.Unmarshal(b, &groupReq)
			Expect(err).NotTo(HaveOccurred())

			groupResp := &api.Group{
				Id:   fmt.Sprintf("id-%d", r.Int63()),
				Name: groupReq.Name,
			}
			groupStore[groupResp.Id] = groupResp
			b, err = json.Marshal(groupResp)
			Expect(err).NotTo(HaveOccurred())
			_, err = rw.Write(b)
			Expect(err).NotTo(HaveOccurred())
		}))
		mux.Handle("PUT /api/groups/{id}", http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
			id := req.PathValue("id")
			groupResp, ok := groupStore[id]
			if !ok {
				util.WriteErrorResponse("Not Found", http.StatusNotFound, rw)
				return
			}

			b, err := io.ReadAll(req.Body)
			Expect(err).NotTo(HaveOccurred())
			groupReq := api.GroupRequest{}
			err = json.Unmarshal(b, &groupReq)
			Expect(err).NotTo(HaveOccurred())

			groupResp.Name = groupReq.Name

			b, err = json.Marshal(groupResp)
			Expect(err).NotTo(HaveOccurred())
			_, err = rw.Write(b)
			Expect(err).NotTo(HaveOccurred())
		}))
		mux.Handle("DELETE /api/groups/{id}", http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
			id := req.PathValue("id")
			_, ok := groupStore[id]
			if !ok {
				util.WriteErrorResponse("Not Found", http.StatusNotFound, rw)
				return
			}
			delete(groupStore, id)
		}))
		server := httptest.NewServer(mux)
		nbClient := netbird.New(server.URL, "ABC")

		var controllerReconciler *GroupReconciler
		nn := client.ObjectKey{
			Name:      "test-resource",
			Namespace: "default",
		}

		BeforeEach(func() {
			controllerReconciler = &GroupReconciler{
				Client:  k8sClient,
				Netbird: nbClient,
			}
		})

		AfterEach(func() {
			groupStore = map[string]*api.Group{}

			group := &nbv1alpha1.Group{}
			err := k8sClient.Get(ctx, nn, group)
			if kerrors.IsNotFound(err) {
				return
			}
			Expect(err).ToNot(HaveOccurred())
			Expect(k8sClient.Delete(ctx, group)).To(Succeed())
			_, err = controllerReconciler.Reconcile(ctx, reconcile.Request{NamespacedName: nn})
			Expect(err).ToNot(HaveOccurred())
		})

		It("ensures a Netbird group exists on reconcile", func() {
			group := &nbv1alpha1.Group{
				ObjectMeta: metav1.ObjectMeta{
					Name:      nn.Name,
					Namespace: nn.Namespace,
				},
				Spec: nbv1alpha1.GroupSpec{
					Name: "foobar",
				},
			}
			Expect(k8sClient.Create(ctx, group)).To(Succeed())

			By("creating a group on initial creation")
			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{NamespacedName: nn})
			Expect(err).NotTo(HaveOccurred())
			err = k8sClient.Get(ctx, nn, group)
			Expect(err).NotTo(HaveOccurred())
			Expect(*group.Status.GroupID).NotTo(BeEmpty())

			By("crerating a new group when deleted from API")
			delete(groupStore, *group.Status.GroupID)
			_, err = controllerReconciler.Reconcile(ctx, reconcile.Request{NamespacedName: nn})
			Expect(err).NotTo(HaveOccurred())
			newGroup := &nbv1alpha1.Group{}
			err = k8sClient.Get(ctx, nn, newGroup)
			Expect(err).NotTo(HaveOccurred())
			Expect(*newGroup.Status.GroupID).NotTo(BeEmpty())
			Expect(*newGroup.Status.GroupID).NotTo(Equal(*group.Status.GroupID))
		})
	})
})
