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

// Package reportprogress implements handler functions
// to handle report progress request.
package reportprogress

import (
	"context"
	"fmt"
	"net/http"

	"github.com/google/open_sztp/util/parser"
	"github.com/kylelemons/godebug/pretty"
)

// DependencyProvider is the interface to get the dependencies for the report-progress handler.
type DependencyProvider interface {
	ReportProgress(ctx context.Context, req *http.Request, reqParams *parser.ReportProgressRequest) error
	LogInfof(format string, v ...any)
	LogErrorf(format string, v ...any)
}

// Handler is the handler of the report progress request.
type Handler struct {
	DependencyProvider DependencyProvider
}

// respondWithError logs the error message and sends an HTTP error response.
func respondWithError(w http.ResponseWriter, dp DependencyProvider, code int, err error) {
	dp.LogErrorf(err.Error())
	http.Error(w, err.Error(), code)
}

// Handle handles the report progress request.
func (h Handler) Handle(w http.ResponseWriter, req *http.Request) {
	h.DependencyProvider.LogInfof("In report-progress handler. HTTP Request: \n%s", pretty.Sprint(*req))
	ctx := req.Context()

	reqParams, err := parser.ReportProgressArgs(req, h.DependencyProvider)
	if err != nil {
		respondWithError(w, h.DependencyProvider, http.StatusBadRequest, fmt.Errorf("Unable to parse report-progress parameters: %w", err))
		return
	}
	h.DependencyProvider.LogInfof("Report-progress params: \n%s", pretty.Sprint(reqParams))
	err = h.DependencyProvider.ReportProgress(ctx, req, reqParams)
	if err != nil {
		respondWithError(w, h.DependencyProvider, http.StatusInternalServerError, fmt.Errorf("Report-progress could not update progress in bootstrap-server: %w", err))
		return
	}
	h.DependencyProvider.LogInfof("Report-progress successful, returning http 204")
	w.WriteHeader(http.StatusNoContent)
}
