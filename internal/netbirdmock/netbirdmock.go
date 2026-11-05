// SPDX-License-Identifier: BSD-3-Clause

package netbirdmock

import (
	"encoding/json"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"sync"
	"time"

	"k8s.io/utils/clock"

	netbird "github.com/netbirdio/netbird/shared/management/client/rest"
	"github.com/netbirdio/netbird/shared/management/http/api"
	"github.com/netbirdio/netbird/shared/management/http/util"
)

// Option configures the mock server.
type Option func(*options)

type options struct {
	clock clock.PassiveClock
}

// WithClock sets the clock the mock server dates setup key expiry from.
func WithClock(c clock.PassiveClock) Option {
	return func(o *options) {
		o.clock = c
	}
}

func Client(opts ...Option) *netbird.Client {
	client, _ := RecordingClient(opts...)
	return client
}

// Recorder counts the requests the mock server has handled, keyed by route pattern
// such as "PUT /api/networks/{id}".
type Recorder struct {
	mx     sync.Mutex
	counts map[string]int
}

// Count returns how many requests matched the given route pattern.
func (r *Recorder) Count(pattern string) int {
	r.mx.Lock()
	defer r.mx.Unlock()
	return r.counts[pattern]
}

// Reset clears all recorded counts.
func (r *Recorder) Reset() {
	r.mx.Lock()
	defer r.mx.Unlock()
	clear(r.counts)
}

// RecordingClient returns a client for a new mock server along with a Recorder
// of the requests that server handles.
func RecordingClient(opts ...Option) (*netbird.Client, *Recorder) {
	o := options{clock: clock.RealClock{}}
	for _, opt := range opts {
		opt(&o)
	}
	mux := &http.ServeMux{}

	addHandler(mux, "groups", func(id string, input api.GroupRequest, output api.Group) api.Group {
		output.Id = id
		output.Name = input.Name
		return output
	})
	addViewedHandler(mux, "setup-keys", func(id string, input setupKeyRequest, output setupKey) setupKey {
		output.Id = id
		output.AutoGroups = input.AutoGroups
		output.Revoked = input.Revoked
		if output.Key == "" {
			output.Key = fmt.Sprintf("%d", rand.Int64())
			if input.ExpiresIn > 0 {
				output.Expires = o.clock.Now().Add(time.Duration(input.ExpiresIn) * time.Second)
			}
		}
		return output
	}, func(key setupKey) setupKey {
		// The state is worked out as of the request, as the server does.
		switch {
		case !key.Expires.IsZero() && o.clock.Now().After(key.Expires):
			key.State = "expired"
		case key.Revoked:
			key.State = "revoked"
		default:
			key.State = "valid"
		}
		key.Valid = key.State == "valid"
		return key
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

	addHandler(mux, "reverse-proxies/services", func(id string, input api.ServiceRequest, output api.Service) api.Service {
		output.Id = id
		output.Name = input.Name
		output.Domain = input.Domain
		output.Enabled = input.Enabled
		if input.Targets != nil {
			output.Targets = *input.Targets
		}
		return output
	})

	rec := &Recorder{counts: map[string]int{}}
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		_, pattern := mux.Handler(req)
		rec.mx.Lock()
		rec.counts[pattern]++
		rec.mx.Unlock()
		mux.ServeHTTP(rw, req)
	}))
	return netbird.New(srv.URL, "ABC"), rec
}

// setupKeyRequest is the body of both creating and updating a setup key.
type setupKeyRequest struct {
	api.SetupKeyRequest
	ExpiresIn int `json:"expires_in"`
}

// setupKey is a stored setup key. api.SetupKeyClear lacks the valid flag the
// server reports along with the state.
type setupKey struct {
	api.SetupKeyClear
	Valid bool `json:"valid"`
}

func addHandler[T, U any](mux *http.ServeMux, resource string, convertFn func(string, U, T) T) {
	addViewedHandler(mux, resource, convertFn, func(item T) T { return item })
}

// addViewedHandler is addHandler with viewFn applied to every item the server
// returns, for what it works out as of the request rather than stores.
func addViewedHandler[T, U any](mux *http.ServeMux, resource string, convertFn func(string, U, T) T, viewFn func(T) T) {
	var itemMx sync.RWMutex
	store := map[string]T{}

	mux.Handle(fmt.Sprintf("GET /api/%s", resource), http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		itemMx.RLock()
		defer itemMx.RUnlock()

		items := make([]T, 0, len(store))
		for _, v := range store {
			items = append(items, viewFn(v))
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
		b, err := json.Marshal(viewFn(respData))
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
		b, err = json.Marshal(viewFn(respData))
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
		b, err = json.Marshal(viewFn(respData))
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
