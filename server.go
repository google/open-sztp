// Copyright 2024 Google LLC

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//     https://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package server provides an HTTP server with handlers for the sZTP bootstrap server.
package server

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"net/http"

	"github.com/google/open_sztp/handlers/bootstrapdata"
	"github.com/google/open_sztp/handlers/issueaikcert"
	"github.com/google/open_sztp/handlers/reportprogress"
	"github.com/google/open_sztp/handlers/verifyattestationcredential"
	"github.com/google/open_sztp/util/constants"
	"github.com/google/open_sztp/util/parser"
)

// DependencyProvider is the interface to get the dependencies for the bootstrap server.
// Embeds the interfaces of each of the handlers.
type DependencyProvider interface {
	bootstrapdata.DependencyProvider
	reportprogress.DependencyProvider
	issueaikcert.DependencyProvider
	verifyattestationcredential.DependencyProvider
	parser.DependencyProvider

	GenerateServerTLSCertificate(crypto.PrivateKey, *x509.Certificate, net.IP) (*tls.Certificate, error)
	CreateSocket(addr string) (l net.Listener, err error)
	ErrorLogger() *log.Logger
}

func healthzHandler(w http.ResponseWriter, _ *http.Request) {
	fmt.Fprintf(w, "ok")
}

// BootstrapActionsHandler sets up the ServeMux for the report-progress, get-bootstrapping-data
// and TPM enrollment calls.
func BootstrapActionsHandler(enableTPMEnrollment bool, dependencyProvider DependencyProvider) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc(constants.ReportProgressPattern, reportprogress.Handler{
		DependencyProvider: dependencyProvider,
	}.Handle)
	mux.HandleFunc(constants.GetBootstrappingDataPattern, bootstrapdata.Handler{
		DependencyProvider: dependencyProvider,
	}.Handle)
	if enableTPMEnrollment {
		mux.HandleFunc(constants.IssueAIKCertPattern, issueaikcert.Handler{
			DependencyProvider: dependencyProvider,
		}.Handle)
		mux.HandleFunc(constants.VerifyAttestationCredentialPattern, verifyattestationcredential.Handler{
			DependencyProvider: dependencyProvider,
		}.Handle)
	}
	mux.HandleFunc(constants.HealthzPattern, healthzHandler)
	mux.HandleFunc(constants.NullzPattern, healthzHandler)
	return mux
}

// tlsCerts generates TLS certificates for the server using the trust anchor and IP from dependencyProvider.
func tlsCerts(ctx context.Context, dependencyProvider DependencyProvider) (*tls.Certificate, error) {
	taPrivateKey, err := dependencyProvider.TrustAnchorPrivateKey(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetching trust anchor private key: %w", err)
	}
	taCert, err := dependencyProvider.TrustAnchorCert(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetching trust anchor certificate: %w", err)
	}
	rawIP := dependencyProvider.RedirectIP(nil)
	ip := net.ParseIP(rawIP)
	if ip == nil {
		return nil, fmt.Errorf("parsing server IP address %q: %w", rawIP, err)
	}
	c, err := dependencyProvider.GenerateServerTLSCertificate(taPrivateKey, taCert, ip)
	if err != nil {
		return nil, fmt.Errorf("generating TLS certificate: %w", err)
	}
	return c, nil
}

// Params contains configurable options for constructing an sZTP bootstrap server.
type Params struct {
	EnableTPMEnrollment   bool
	ListenOnAllInterfaces bool
	DependencyProvider    DependencyProvider
}

// New creates a new http.Server with handlers configured for sZTP.
func New(ctx context.Context, params Params) (*http.Server, net.Listener, error) {
	serverTLSCertKeyPair, err := tlsCerts(ctx, params.DependencyProvider)
	if err != nil {
		return nil, nil, fmt.Errorf("generating server TLS keys: %w", err)
	}

	var addr string
	if params.ListenOnAllInterfaces {
		addr = fmt.Sprintf(":%d", params.DependencyProvider.RedirectPort())
	} else {
		addr = fmt.Sprintf("[%s]:%d", params.DependencyProvider.RedirectIP(nil), params.DependencyProvider.RedirectPort())
	}

	server := &http.Server{
		Addr:      addr,
		Handler:   BootstrapActionsHandler(params.EnableTPMEnrollment, params.DependencyProvider),
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{*serverTLSCertKeyPair}},
		ErrorLog:  params.DependencyProvider.ErrorLogger(),
	}

	l, err := params.DependencyProvider.CreateSocket(server.Addr)
	if err != nil {
		return nil, nil, fmt.Errorf("creating socket: %w", err)
	}
	return server, l, nil
}
