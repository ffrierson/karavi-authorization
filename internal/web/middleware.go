// Copyright © 2021 Dell Inc., or its subsidiaries. All Rights Reserved.
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

package web

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httputil"
	"path"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel/trace"
)

// CtxKey wraps the int type and is meant for context values
type CtxKey int

const (
	// JWTKey is the context key for the json web token
	JWTKey CtxKey = iota
	// SystemIDKey is the context key for a system ID
	SystemIDKey
)

// Middleware is a function that accepts an http Handler and returns an http Handler following the middleware pattern
type Middleware func(http.Handler) http.Handler

// Adapt applies the middlewares to the supplied http handler and returns said handler
func Adapt(h http.Handler, mws ...Middleware) http.Handler {
	for _, mw := range mws {
		h = mw(h)
	}
	return h
}

// OtelMW configures OpenTelemetry http instrumentation
func OtelMW(tp trace.TracerProvider, op string, opts ...otelhttp.Option) Middleware {
	return func(next http.Handler) http.Handler {
		opts = append(opts, otelhttp.WithTracerProvider(tp))
		return otelhttp.NewHandler(next, op, opts...)
	}
}

// LoggingMW configures logging incoming requests
func LoggingMW(log *logrus.Entry, showHTTPDump bool) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			log.Printf("Serving %s %s %v", r.RemoteAddr, r.Method, r.URL.Path)
			if showHTTPDump {
				b, err := httputil.DumpRequest(r, true)
				if err != nil {
					panic(err)
				}
				log.Println(string(b))
			}
			next.ServeHTTP(w, r)
		})
	}
}

// CleanMW configures formatting incoming request paths
func CleanMW() Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.URL.Path = cleanPath(r.URL.Path)
			next.ServeHTTP(w, r)
		})
	}
}

func cleanPath(pth string) string {
	pth = path.Clean("/" + pth)
	if pth[len(pth)-1] != '/' {
		pth = pth + "/"
	}
	return pth
}

// AuthMW configures validating the json web token from the request
func AuthMW(log *logrus.Entry, secret string) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authz := r.Header.Get("Authorization")
			parts := strings.Split(authz, " ")
			if len(parts) != 2 {
				log.Println("invalid authz header")
				return
			}
			scheme, token := parts[0], parts[1]

			switch scheme {
			case "Bearer":
				parsedToken, err := jwt.Parse(token, func(tk *jwt.Token) (interface{}, error) {
					if _, ok := tk.Method.(*jwt.SigningMethodHMAC); !ok {
						return nil, fmt.Errorf("unexpected JWT signing method: %v", tk.Header["alg"])
					}
					return []byte(secret), nil
				})
				if err != nil {
					w.WriteHeader(http.StatusUnauthorized)
					if err := JSONErrorResponse(w, err); err != nil {
						log.WithError(err).Println("sending json response")
					}
					return
				}

				ctx := context.WithValue(r.Context(), JWTKey, parsedToken)
				r = r.WithContext(ctx)
			case "Basic":
				log.Println("Basic authentication used")
			}

			next.ServeHTTP(w, r)
		})
	}
}