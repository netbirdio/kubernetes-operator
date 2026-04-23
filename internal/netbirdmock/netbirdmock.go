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
	addHandler(mux, "networks", func(id string, input api.NetworkRequest, output api.Network) api.Network {
		output.Id = id
		output.Name = input.Name
		output.Description = input.Description
		return output
	})
	addHandler(mux, "networks/{network}/routers", func(id string, input api.NetworkRouterRequest, output api.NetworkRouter) api.NetworkRouter {
		output.Id = id
		output.Enabled = input.Enabled
		output.Masquerade = input.Masquerade
		output.Metric = input.Metric
		output.PeerGroups = input.PeerGroups
		return output
	})
	addHandler(mux, "networks/{network}/resources", func(id string, input api.NetworkResourceRequest, output api.NetworkResource) api.NetworkResource {
		output.Id = id
		output.Address = input.Address
		output.Description = input.Description
		output.Enabled = input.Enabled
		return output
	})
	addHandler(mux, "dns/zones", func(id string, input api.ZoneRequest, output api.Zone) api.Zone {
		output.Id = id
		output.Name = input.Name
		output.Domain = input.Domain
		output.DistributionGroups = input.DistributionGroups
		output.EnableSearchDomain = input.EnableSearchDomain
		if input.Enabled != nil {
			output.Enabled = *input.Enabled
		}
		return output
	})
	addHandler(mux, "dns/zones/{zone}/records", func(id string, input api.DNSRecordRequest, output api.DNSRecord) api.DNSRecord {
		output.Id = id
		output.Name = input.Name
		output.Ttl = input.Ttl
		output.Type = input.Type
		output.Content = input.Content
		return output
	})

	srv := httptest.NewServer(mux)
	return netbird.New(srv.URL, "ABC")
}

func addHandler[T, U any](mux *http.ServeMux, resource string, convertFn func(string, U, T) T) {
	var itemMx sync.RWMutex
	store := map[string]T{}

	mux.Handle(fmt.Sprintf("GET /api/%s", resource), http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		itemMx.RLock()
		defer itemMx.RUnlock()

		items := make([]T, 0, len(store))
		for _, v := range store {
			items = append(items, v)
		}
		b, err := json.Marshal(items)
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
	mux.Handle(fmt.Sprintf("GET /api/%s/{id}", resource), http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		itemMx.RLock()
		defer itemMx.RUnlock()

		id := req.PathValue("id")
		respData, ok := store[id]
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
		store[id] = respData
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
		respData, ok := store[id]
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
		store[id] = respData
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
		_, ok := store[id]
		if !ok {
			util.WriteErrorResponse("Not Found", http.StatusNotFound, rw)
			return
		}
		delete(store, id)
	}))
}
