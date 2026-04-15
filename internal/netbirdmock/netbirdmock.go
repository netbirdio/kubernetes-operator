package netbirdmock

import (
	"encoding/json"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"sync"

	netbird "github.com/netbirdio/netbird/shared/management/client/rest"
	"github.com/netbirdio/netbird/shared/management/http/api"
	"github.com/netbirdio/netbird/shared/management/http/util"
)

func Client() *netbird.Client {
	mux := &http.ServeMux{}

	addHandler(mux, "groups", func(id string, input api.GroupRequest, output api.Group) api.Group {
		output.Id = id
		output.Name = input.Name
		return output
	})
	addHandler(mux, "setup-keys", func(id string, input api.SetupKeyRequest, output api.SetupKeyClear) api.SetupKeyClear {
		output.Id = id
		output.AutoGroups = input.AutoGroups
		output.Revoked = input.Revoked
		if output.Key == "" {
			output.Key = fmt.Sprintf("%d", rand.Int64())
		}
		return output
	})

	srv := httptest.NewServer(mux)
	return netbird.New(srv.URL, "ABC")
}

func addHandler[T, U any](mux *http.ServeMux, resource string, convertFn func(string, U, T) T) {
	var itemMx sync.RWMutex
	items := map[string]T{}

	mux.Handle(fmt.Sprintf("GET /api/%s/{id}", resource), http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		itemMx.RLock()
		defer itemMx.RUnlock()

		id := req.PathValue("id")
		respData, ok := items[id]
		if !ok {
			util.WriteErrorResponse("Not Found", http.StatusNotFound, rw)
			return
		}
		b, err := json.Marshal(respData)
		if err != nil {
			util.WriteErrorResponse("Marshal Error", http.StatusInternalServerError, rw)
			return
		}
		_, err = rw.Write(b)
		if err != nil {
			util.WriteErrorResponse("Write Error", http.StatusInternalServerError, rw)
			return
		}
	}))
	mux.Handle(fmt.Sprintf("POST /api/%s", resource), http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		itemMx.Lock()
		defer itemMx.Unlock()

		b, err := io.ReadAll(req.Body)
		if err != nil {
			util.WriteErrorResponse("Read Error", http.StatusBadRequest, rw)
			return
		}
		var reqData U
		err = json.Unmarshal(b, &reqData)
		if err != nil {
			util.WriteErrorResponse("Unmarshal Error", http.StatusBadRequest, rw)
			return
		}
		id := fmt.Sprintf("id-%d", rand.Int64())
		var zero T
		respData := convertFn(id, reqData, zero)
		items[id] = respData
		b, err = json.Marshal(respData)
		if err != nil {
			util.WriteErrorResponse("Marshal Error", http.StatusInternalServerError, rw)
			return
		}
		_, err = rw.Write(b)
		if err != nil {
			util.WriteErrorResponse("Write Error", http.StatusInternalServerError, rw)
			return
		}
	}))
	mux.Handle(fmt.Sprintf("PUT /api/%s/{id}", resource), http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		itemMx.Lock()
		defer itemMx.Unlock()

		id := req.PathValue("id")
		respData, ok := items[id]
		if !ok {
			util.WriteErrorResponse("Not Found", http.StatusNotFound, rw)
			return
		}

		b, err := io.ReadAll(req.Body)
		if err != nil {
			util.WriteErrorResponse("Read Error", http.StatusBadRequest, rw)
			return
		}
		var reqData U
		err = json.Unmarshal(b, &reqData)
		if err != nil {
			util.WriteErrorResponse("Unmarshal Error", http.StatusBadRequest, rw)
			return
		}
		respData = convertFn(id, reqData, respData)
		items[id] = respData
		b, err = json.Marshal(respData)
		if err != nil {
			util.WriteErrorResponse("Marshal Error", http.StatusInternalServerError, rw)
			return
		}
		_, err = rw.Write(b)
		if err != nil {
			util.WriteErrorResponse("Write Error", http.StatusInternalServerError, rw)
			return
		}
	}))
	mux.Handle(fmt.Sprintf("DELETE /api/%s/{id}", resource), http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		itemMx.Lock()
		defer itemMx.Unlock()

		id := req.PathValue("id")
		_, ok := items[id]
		if !ok {
			util.WriteErrorResponse("Not Found", http.StatusNotFound, rw)
			return
		}
		delete(items, id)
	}))
}
