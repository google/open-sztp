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

// Package verifyattestationcredential implements handler functions
// to handle verify attestation credential request.
package verifyattestationcredential

import (
	"bytes"
	"context"
	"fmt"
	"net/http"

	"google.golang.org/protobuf/encoding/protojson"

	tepb "github.com/google/open_sztp/proto/tpm_enrollment_go_proto"
)

// DependencyProvider is the interface to get the dependencies for the verify attestation credential handler.
type DependencyProvider interface {
	VerifyAttestationCredential(ctx context.Context, req *tepb.VerifyAttestationCredentialRequest, httpReq *http.Request) (*tepb.VerifyAttestationCredentialResponse, error)
	LogInfof(format string, v ...any)
	LogErrorf(format string, v ...any)
}

// Handler is the handler of the verify-attestation-credential request.
type Handler struct {
	DependencyProvider DependencyProvider
}

// respondWithError logs the error message and sends an HTTP error response.
func respondWithError(w http.ResponseWriter, dp DependencyProvider, code int, err error) {
	dp.LogErrorf(err.Error())
	http.Error(w, err.Error(), code)
}

// Handle handles the verify-attestation-credential request.
func (h Handler) Handle(w http.ResponseWriter, req *http.Request) {
	// Read the request.
	requestBytes := new(bytes.Buffer)
	requestBytes.ReadFrom(req.Body)
	h.DependencyProvider.LogInfof("verify-attestation-credential received request=%q", requestBytes.String())

	// Convert request from json to proto.
	protoRequest := &tepb.VerifyAttestationCredentialRequest{}
	err := protojson.Unmarshal(requestBytes.Bytes(), protoRequest)
	if err != nil {
		respondWithError(w, h.DependencyProvider, http.StatusBadRequest, fmt.Errorf("Could not unmarshal VerifyAttestationCredentialRequest proto: %w", err))
		return
	}

	// Route the call to the underlying Bootstrap Server backend.
	protoResponse, err := h.DependencyProvider.VerifyAttestationCredential(req.Context(), protoRequest, req)
	if err != nil {
		respondWithError(w, h.DependencyProvider, http.StatusInternalServerError, fmt.Errorf("verify-attestation-credential RPC error: %w", err))
		return
	}

	// Convert the response from proto to json.
	jsonResponse, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(protoResponse)
	if err != nil {
		respondWithError(w, h.DependencyProvider, http.StatusInternalServerError, fmt.Errorf("Could not marshal VerifyAttestationCredentialResponse proto: %w", err))
		return
	}

	// Write the response.
	w.Write(jsonResponse)
	h.DependencyProvider.LogInfof("verify-attestation-credential success response=%q", string(jsonResponse))
}
