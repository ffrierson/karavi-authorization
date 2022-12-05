// Copyright © 2021-2022 Dell Inc., or its subsidiaries. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"karavi-authorization/internal/decision"
	"karavi-authorization/internal/quota"
	"karavi-authorization/internal/token"
	"karavi-authorization/internal/web"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"

	"github.com/julienschmidt/httprouter"

	"github.com/dell/gounity"
	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// System holds the log and token for Unity
type UnitySystem struct {
	SystemEntry
	log *logrus.Entry
	tk  interface {
		GetToken(context.Context) (string, error)
	}
}

// UnityHandler is the proxy handler for Unity systems
type UnityHandler struct {
	log      *logrus.Entry
	mu       sync.Mutex // guards systems map
	systems  map[string]*UnitySystem
	enforcer *quota.RedisEnforcement
	opaHost  string
}

// NewUnityHandler returns a new UnityHandler
func NewUnityHandler(log *logrus.Entry, enforcer *quota.RedisEnforcement, opaHost string) *UnityHandler {
	return &UnityHandler{
		log:      log,
		systems:  make(map[string]*UnitySystem),
		enforcer: enforcer,
		opaHost:  opaHost,
	}
}

// GetSystems returns the configured systems
func (h *UnityHandler) GetSystems() map[string]*UnitySystem {
	return h.systems
}

// UpdateSystems updates the UnityHandler via a SystemConfig
func (h *UnityHandler) UpdateSystems(ctx context.Context, r io.Reader, log *logrus.Entry) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	var updated SystemConfig
	if err := json.NewDecoder(r).Decode(&updated); err != nil {
		return err
	}

	unitySystems := updated["unity"]

	// Remove systems
	for k := range h.systems {
		if _, ok := unitySystems[k]; !ok {
			// Removed
			delete(h.systems, k)
		}
	}
	// Update systems
	for k, v := range unitySystems {
		var err error
		if h.systems[k], err = buildSystemUnity(ctx, v, log); err != nil {
			h.log.WithError(err).Error("building unity system")
		}
	}

	for _, arr := range updated {
		for id := range arr {
			h.log.WithField("updated_systems", id).Debug()
		}
	}

	return nil
}

func buildSystemUnity(ctx context.Context, e SystemEntry, log *logrus.Entry) (*UnitySystem, error) {
	_, err := url.Parse(e.Endpoint)
	if err != nil {
		return nil, err
	}

	return &UnitySystem{
		SystemEntry: e,
		log:         log,
	}, nil
}

func splitEndpointUnitySystemID(s string) (string, string) {
	v := strings.Split(s, ";")
	if len(v) == 1 {
		return v[0], ""
	}
	return v[0], v[1]
}

func (h *UnityHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	fwd := forwardedHeader(r)
	fwdFor := fwd["for"]

	ep, systemID := splitEndpointUnitySystemID(fwdFor)
	h.log.WithFields(logrus.Fields{
		"endpoint":  ep,
		"system_id": systemID,
	}).Debug("Serving request")
	r = r.WithContext(context.WithValue(r.Context(), web.SystemIDKey, systemID))
	r = r.WithContext(context.WithValue(r.Context(), web.SystemIDKey, systemID))

	v, ok := h.systems[systemID]
	if !ok {
		writeError(w, "unity", "system id not found", http.StatusBadGateway, h.log)
		return
	}

	// Use the authenticated session.
	token, err := v.tk.GetToken(r.Context())
	if err != nil {
		writeError(w, "unity", "failed to authenticate", http.StatusUnauthorized, h.log)
		return
	}
	r.SetBasicAuth("", token)

	// Instrument the proxy
	attrs := trace.WithAttributes(attribute.String("unity.endpoint", ep), attribute.String("unity.systemid", systemID))
	opts := otelhttp.WithSpanOptions(attrs)
	proxyHandler := otelhttp.NewHandler(nil, "proxy", opts)

	// TODO(ian): Probably shouldn't be building a servemux all the time :)
	mux := http.NewServeMux()
	mux.HandleFunc("/api/types/loginSessionInfo", h.spoofLoginRequest)
	mux.Handle("/api/types/lun/instances/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet:
			proxyHandler.ServeHTTP(w, r)
		case strings.HasSuffix(r.URL.Path, "/action/queryIdByKey/"):
			proxyHandler.ServeHTTP(w, r)
		default:
			v.volumeCreateHandler(proxyHandler, h.enforcer, h.opaHost).ServeHTTP(w, r)
		}
	}))
	mux.Handle("/api/instances/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/action/modifyLun"):
			v.volumeModifyHandler(proxyHandler, h.enforcer, h.opaHost).ServeHTTP(w, r)
		default:
			proxyHandler.ServeHTTP(w, r)
		}
	}))
	mux.Handle("/", proxyHandler)

	// Request policy decision from OPA
	ans, err := decision.Can(func() decision.Query {
		return decision.Query{
			Host:   h.opaHost,
			Policy: "/karavi/authz/url",
			Input: map[string]interface{}{
				"method": r.Method,
				"url":    r.URL.Path,
			},
		}
	})
	if err != nil {
		h.log.WithError(err).Error("requesting policy decision from OPA")
		writeError(w, "unity", err.Error(), http.StatusInternalServerError, h.log)
		return
	}
	var resp struct {
		Result struct {
			Allow bool `json:"allow"`
		} `json:"result"`
	}
	err = json.NewDecoder(bytes.NewReader(ans)).Decode(&resp)
	if err != nil {
		h.log.WithError(err).WithField("opa_policy_decision", string(ans)).Error("decoding json")
		writeError(w, "unity", err.Error(), http.StatusInternalServerError, h.log)
		return
	}
	if !resp.Result.Allow {
		h.log.Debug("Request denied")
		writeError(w, "unity", "request denied for path", http.StatusNotFound, h.log)
		return
	}

	mux.ServeHTTP(w, r)
}

func (h *UnityHandler) spoofLoginRequest(w http.ResponseWriter, r *http.Request) {
	_, span := trace.SpanFromContext(r.Context()).TracerProvider().Tracer("").Start(r.Context(), "spoofLoginRequest")
	defer span.End()
	_, err := w.Write([]byte("hellofromkaravi"))
	if err != nil {
		h.log.WithError(err).Error("writing spoofed login response")
	}
}

func (s *UnitySystem) volumeCreateHandler(next http.Handler, enf *quota.RedisEnforcement, opaHost string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, span := trace.SpanFromContext(r.Context()).TracerProvider().Tracer("").Start(r.Context(), "unityVolumeCreateHandler")
		defer span.End()

		var systemID string
		if v := r.Context().Value(web.SystemIDKey); v != nil {
			var ok bool
			if systemID, ok = v.(string); !ok {
				writeError(w, "unity", http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError, s.log)
				return
			}
		}

		params := httprouter.ParamsFromContext(r.Context())

		// Read the body.
		b, err := ioutil.ReadAll(r.Body)
		if err != nil {
			writeError(w, "unity", "failed to read body", http.StatusInternalServerError, s.log)
			return
		}
		defer r.Body.Close()

		// Decode the body into a known structure.
		body := struct {
			VolumeSize     int64
			VolumeSizeInKb string `json:"volumeSizeInKb"`
			StoragePoolID  string `json:"storagePoolId"`
		}{}
		err = json.NewDecoder(bytes.NewBuffer(b)).Decode(&body)
		if err != nil {
			s.log.WithError(err).Error("proxy: decoding create volume request")
			writeError(w, "unity", "failed to extract cap data", http.StatusBadRequest, s.log)
			return
		}

		// Ask OPA to make a decision
		var requestBody map[string]json.RawMessage
		err = json.NewDecoder(bytes.NewReader(b)).Decode(&requestBody)
		if err != nil {
			writeError(w, "unity", "decoding request body", http.StatusInternalServerError, s.log)
			return
		}

		/* jwtGroup := r.Context().Value(web.JWTTenantName)
		group, ok := jwtGroup.(string)
		if !ok {
			writeError(w, "unity", "incorrect type for JWT group", http.StatusInternalServerError, s.log)
			return
		} */

		jwtValue := r.Context().Value(web.JWTKey)
		jwtToken, ok := jwtValue.(token.Token)
		if !ok {
			writeError(w, "unity", "incorrect type for JWT token", http.StatusInternalServerError, s.log)
			return
		}

		claims, err := jwtToken.Claims()
		if err != nil {
			writeError(w, "unity", "decoding token claims", http.StatusInternalServerError, s.log)
			return
		}

		s.log.Debugln("Asking OPA...")
		// Request policy decision from OPA
		ans, err := decision.Can(func() decision.Query {
			return decision.Query{
				Host: opaHost,
				// TODO(ian): This will need to be namespaced under "unity".
				Policy: "/karavi/volumes/create",
				Input: map[string]interface{}{
					"claims":          claims,
					"request":         requestBody,
					"storagepool":     params.ByName("StoragePool"),
					"storagesystemid": systemID,
					"systemtype":      "unity",
				},
			}
		})
		if err != nil {
			s.log.WithError(err).Error("asking OPA for volume create decision")
			writeError(w, "unity", fmt.Sprintf("asking OPA for volume create decision: %v", err), http.StatusInternalServerError, s.log)
			return
		}

		var opaResp CreateOPAResponseUnity
		err = json.NewDecoder(bytes.NewReader(ans)).Decode(&opaResp)
		if err != nil {
			s.log.WithError(err).Error("decoding opa response")
			writeError(w, "unity", "decoding opa request body", http.StatusInternalServerError, s.log)
			return
		}
		s.log.WithField("opa_response", opaResp).Debug()
		if resp := opaResp.Result; !resp.Allow {
			reason := strings.Join(opaResp.Result.Deny, ",")
			s.log.WithField("reason", reason).Debug("request denied")
			writeError(w, "unity", fmt.Sprintf("request denied: %v", reason), http.StatusBadRequest, s.log)
			return
		}

		// In the scenario where multiple roles are allowing
		// this request, choose the one with the most quota.
		var maxQuotaInKb int
		for _, quota := range opaResp.Result.PermittedRoles {
			if quota >= maxQuotaInKb {
				maxQuotaInKb = quota
			}
		}

		// At this point, the request has been approved.
		qr := quota.Request{
			SystemType:    "unity",
			SystemID:      systemID,
			StoragePoolID: params.ByName("StoragePool"),
			VolumeName:    params.ByName("Name"),
			Capacity:      params.ByName("Size"),
		}

		s.log.Debugln("Approving request...")
		// Ask our quota enforcer if it approves the request.
		ok, err = enf.ApproveRequest(ctx, qr, int64(maxQuotaInKb))
		if err != nil {
			s.log.WithError(err).Error("approving request")
			writeError(w, "unity", "failed to approve request", http.StatusInternalServerError, s.log)
			return
		}
		if !ok {
			s.log.Debugln("request was not approved")
			writeError(w, "unity", "request denied: not enough quota", http.StatusInsufficientStorage, s.log)
			return
		}

		// At this point, the request has been approved.

		// Reset the original request
		err = r.Body.Close()
		if err != nil {
			s.log.WithError(err).Error("closing original request body")
		}
		r.Body = ioutil.NopCloser(bytes.NewBuffer(b))
		sw := &web.StatusWriter{
			ResponseWriter: w,
		}

		s.log.Debugln("Proxying request...")
		// Proxy the request to the backend unity.
		r = r.WithContext(ctx)
		next.ServeHTTP(sw, r)

		// TODO: Determine if when the approved volume fails the volume is
		// cleaned up (releasing capacity).
		s.log.WithFields(logrus.Fields{
			"Response code": sw.Status,
		}).Debug()
		switch sw.Status {
		case http.StatusOK:
			s.log.Debugln("Publish created")
			ok, err := enf.PublishCreated(r.Context(), qr)
			if err != nil {
				s.log.WithError(err).Error("publishing volume created")
				return
			}
			s.log.WithField("publish_result", ok).Debug("Publish volume created")
		default:
			s.log.Debugln("Non 200 response, nothing to publish")
		}
	})
}

func (s *UnitySystem) volumeModifyHandler(next http.Handler, enf *quota.RedisEnforcement, opaHost string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, span := trace.SpanFromContext(r.Context()).TracerProvider().Tracer("").Start(r.Context(), "unityVolumeModifier")
		defer span.End()

		params := httprouter.ParamsFromContext(r.Context())

		s.log.WithFields(logrus.Fields{
			"system_id": params.ByName("systemid"),
			"volume_id": params.ByName("volumeid"),
		}).Debug("Modifying volume")

		// Read the body.
		b, err := ioutil.ReadAll(r.Body)
		if err != nil {
			writeError(w, "unity", "failed to read body", http.StatusInternalServerError, s.log)
			return
		}
		defer r.Body.Close()

		// Decode the body into a known structure.
		body := struct {
			VolumeSize     int64
			VolumeSizeInKb string `json:"volumeSizeInKb"`
			StoragePoolID  string `json:"storagePoolId"`
		}{}
		err = json.NewDecoder(bytes.NewBuffer(b)).Decode(&body)
		if err != nil {
			s.log.WithError(err).Error("proxy: decoding modify volume request")
			writeError(w, "unity", "failed to extract cap data", http.StatusBadRequest, s.log)
			return
		}
		body.VolumeSize, err = strconv.ParseInt(body.VolumeSizeInKb, 0, 64)
		if err != nil {
			writeError(w, "powerflex", "failed to parse capacity", http.StatusBadRequest, s.log)
			return
		}

		var modVolReq unityModifyVolumeRequest
		if err := json.Unmarshal(b, &modVolReq); err != nil {
			writeError(w, "unity", err.Error(), http.StatusInternalServerError, s.log)
			return
		}

		// Determine which pool this SG exists within, as it will form the quota key.
		client, err := gounity.NewClientWithArgs(ctx, s.Endpoint, true)
		if err != nil {
			writeError(w, "unity", "failed to build powermax client", http.StatusInternalServerError, s.log)
			return
		}
		if err := client.Authenticate(ctx, &gounity.ConfigConnect{
			Username: s.User,
			Password: s.Password,
		}); err != nil {
			writeError(w, "unity", "failed to authenticate with unisphere", http.StatusInternalServerError, s.log)
			return
		}

		volumeAPI := gounity.NewVolume(client)
		vol, err := volumeAPI.FindVolumeByID(ctx, params.ByName("volumeid"))
		if err != nil {
			s.log.WithError(err).Error("getting volume by ID")
			return
		}

		jwtValue := r.Context().Value(web.JWTKey)
		jwtToken, ok := jwtValue.(token.Token)
		if !ok {
			writeError(w, "unity", "incorrect type for JWT token", http.StatusInternalServerError, s.log)
			return
		}

		jwtClaims, err := jwtToken.Claims()
		if err != nil {
			writeError(w, "unity", "decoding token claims", http.StatusInternalServerError, s.log)
			return
		}

		storagePoolID := vol.VolumeContent.Pool.ID

		s.log.Debugln("Asking OPA...")
		// Request policy decision from OPA
		ans, err := decision.Can(func() decision.Query {
			return decision.Query{
				Host: opaHost,
				// TODO(ian): This will need to be namespaced under "powerflex".
				Policy: "/karavi/volumes/modify",
				Input: map[string]interface{}{
					"claims":          jwtClaims,
					"request":         body,
					"storagepool":     storagePoolID,
					"storagesystemid": params.ByName("systemid"),
					"systemtype":      "unity",
				},
			}
		})
		if err != nil {
			s.log.WithError(err).Error("asking OPA for volume modify decision")
			writeError(w, "unity", fmt.Sprintf("asking OPA for volume modify decision: %v", err), http.StatusInternalServerError, s.log)
			return
		}

		var opaResp CreateOPAResponse
		err = json.NewDecoder(bytes.NewReader(ans)).Decode(&opaResp)
		if err != nil {
			s.log.WithError(err).Error("decoding opa response")
			writeError(w, "unity", "decoding opa request body", http.StatusInternalServerError, s.log)
			return
		}
		s.log.WithField("opa_response", opaResp).Debug()
		if resp := opaResp.Result; !resp.Allow {
			reason := strings.Join(opaResp.Result.Deny, ",")
			s.log.WithField("reason", reason).Debug("request denied")
			writeError(w, "unity", fmt.Sprintf("request denied: %v", reason), http.StatusBadRequest, s.log)
			return
		}

		// In the scenario where multiple roles are allowing
		// this request, choose the one with the most quota.
		var maxQuotaInKb int
		for _, quota := range opaResp.Result.PermittedRoles {
			if quota >= maxQuotaInKb {
				maxQuotaInKb = quota
			}
		}

		volID := vol.VolumeContent.ResourceID

		qr := quota.Request{
			SystemType:    "unity",
			SystemID:      params.ByName("systemid"),
			StoragePoolID: storagePoolID,
			Group:         jwtClaims.Group,
			VolumeName:    volID,
			Capacity:      body.VolumeSizeInKb,
		}

		ok, err = enf.ValidateOwnership(ctx, qr)
		if err != nil {
			writeError(w, "unity", "validating ownership failed", http.StatusInternalServerError, s.log)
			return
		}
		if !ok {
			writeError(w, "unity", "request was denied", http.StatusBadRequest, s.log)
			return
		}

		// Ask our quota enforcer if it approves the request.
		ok, err = enf.ApproveRequest(ctx, qr, int64(maxQuotaInKb))
		if err != nil {
			s.log.WithError(err).Error("approving request")
			writeError(w, "unity", "failed to approve request", http.StatusInternalServerError, s.log)
			return
		}
		if !ok {
			s.log.Debugln("request was not approved")
			writeError(w, "unity", "request denied: not enough quota", http.StatusInsufficientStorage, s.log)
			return
		}

		// At this point, the request has been approved.

		// Reset the original request
		err = r.Body.Close()
		if err != nil {
			s.log.WithError(err).Error("closing original request body")
		}
		r.Body = ioutil.NopCloser(bytes.NewBuffer(b))
		sw := &web.StatusWriter{
			ResponseWriter: w,
		}

		s.log.Debugln("Proxying request...")
		// Proxy the request to the backend unity.
		r = r.WithContext(ctx)
		next.ServeHTTP(sw, r)

		// TODO(ian): Determine if when the approved volume fails the volume is
		// cleaned up (releasing capacity).
		s.log.WithFields(logrus.Fields{
			"Response code": sw.Status,
		}).Debug()
		switch sw.Status {
		case http.StatusOK:
			s.log.Debugln("Publish created")
			ok, err := enf.PublishCreated(r.Context(), qr)
			if err != nil {
				s.log.WithError(err).Error("publishing volume modified")
				return
			}
			s.log.WithField("publish_result", ok).Debug("Publish volume modified")
		default:
			s.log.Debugln("Non 200 response, nothing to publish")
		}

	})
}

type unityModifyVolumeRequest struct {
	LunModifyParam struct {
		LunParameters struct {
			Name        string `json:"name,omitempty"`
			Size        uint64 `json:"size,omitempty"`
			StoragePool struct {
				PoolID string `json:"id"`
			} `json:"storagePool"`
		} `json:"lunParameters"`
	} `json:"lunModifyParam"`
	Executionoption string `json:"executionOption"`
}

// OPAResponseUnity is the respone payload from OPA
type OPAResponseUnity struct {
	Result struct {
		Response struct {
			Allowed bool `json:"allowed"`
			Status  struct {
				Reason string `json:"reason"`
			} `json:"status"`
		} `json:"response"`
		Claims struct {
			Group string `json:"group"`
		} `json:"claims"`
		Quota int64 `json:"quota"`
	} `json:"result"`
}

// CreateOPAResponseUnity is the response payload from OPA
// when performing a volume create operation.
// The permitted_roles field shall contain a map of
// permitted role names to the appropriate storage
// pool quota.
type CreateOPAResponseUnity struct {
	Result struct {
		Allow          bool           `json:"allow"`
		Deny           []string       `json:"deny"`
		PermittedRoles map[string]int `json:"permitted_roles"`
	} `json:"result"`
}
