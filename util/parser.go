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

// Package parser contains function to parse HTTP requests.
package parser

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/google/open_sztp/util/constants"
)

// IsJSONRequest returns true if the HTTP request has a JSON Content-Type.
func IsJSONRequest(req http.Request) bool {
	return strings.Contains(req.Header.Get("Content-Type"), "json")
}

const (
	signedDataPreferredRESTCONFName = "signed-data-preferred"
	hwModelRESTCONFName             = "hw-model"
)

// RESTCONFArgs contains the RESTCONF args from the request.
type RESTCONFArgs struct {
	HWModel             string
	SignedDataPreferred bool
}

// restconfArgsJSON parses the hw-model and signed-data-preferred RESTCONF args from a JSON request body.
func restconfArgsJSON(jsonDecoder *json.Decoder, dp DependencyProvider) (RESTCONFArgs, error) {
	args := RESTCONFArgs{
		HWModel:             constants.UnknownHardwareModel,
		SignedDataPreferred: false,
	}

	for {
		token, err := jsonDecoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return RESTCONFArgs{}, err
		}
		if element, ok := token.(string); ok {
			switch element {
			case signedDataPreferredRESTCONFName:
				dp.LogInfof("tag signed-data-preferred exists")
				args.SignedDataPreferred = true
			case hwModelRESTCONFName:
				token, err = jsonDecoder.Token()
				if err != nil {
					return args, fmt.Errorf("invalid JSON token for \"hw-model\" field: %w", err)
				}
				if hwModel, ok := token.(string); ok {
					dp.LogInfof("Found hw-model with value %v", hwModel)
					args.HWModel = hwModel
				}
			}
		}
	}
	return args, nil
}

// restconfArgsXML parses the hw-model and signed-data-preferred RESTCONF args from an XML request body.
func restconfArgsXML(xmlDecoder *xml.Decoder, dp DependencyProvider) (RESTCONFArgs, error) {
	// Set the hw-model name to "unknown", will be overwritten if the device
	// sets its hw-model in the request.
	args := RESTCONFArgs{
		HWModel:             constants.UnknownHardwareModel,
		SignedDataPreferred: false,
	}

	for {
		token, err := xmlDecoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return RESTCONFArgs{}, err
		}
		if startElement, ok := token.(xml.StartElement); ok {
			switch startElement.Name.Local {
			case signedDataPreferredRESTCONFName:
				dp.LogInfof("tag signed-data-preferred exists")
				args.SignedDataPreferred = true
			case hwModelRESTCONFName:
				token, err = xmlDecoder.Token()
				if err != nil {
					return args, fmt.Errorf("invalid XML token for \"hw-model\" field: %w", err)
				}
				if value, ok := token.(xml.CharData); ok {
					args.HWModel = string(value)
					dp.LogInfof("Found hw-model with value %v", args.HWModel)
				}
			}
		}
	}
	return args, nil
}

// DependencyProvider is the interface to get the dependencies for the parser.
type DependencyProvider interface {
	LogInfof(format string, v ...any)
}

// RestconfArgs gets the hw-model and signed-data-preferred RESTCONF args from the request body.
// Used by the get-bootstrapping-data handler.
// After calling RestconfArgs, do not attempt to read from req.Body again, as the stream will
// have been consumed.
func RestconfArgs(req *http.Request, dp DependencyProvider) (RESTCONFArgs, error) {
	requestBytes := new(bytes.Buffer)
	requestBytes.ReadFrom(req.Body)
	dp.LogInfof("HTTP request body: \n%s", requestBytes.String())
	bytesReader := bytes.NewReader(requestBytes.Bytes())

	if IsJSONRequest(*req) {
		dp.LogInfof("Content-Type header is %q. Parsing request body as JSON", req.Header.Get("Content-Type"))
		return restconfArgsJSON(json.NewDecoder(bytesReader), dp)
	}
	dp.LogInfof("Content-Type header is %q. Parsing request body as XML", req.Header.Get("Content-Type"))
	return restconfArgsXML(xml.NewDecoder(bytesReader), dp)
}

// A ReportProgressRequest defines the report-progress https request body structure
// used for JSON and XML decoding.
type ReportProgressRequest struct {
	XMLName      xml.Name `xml:"input" json:"-"`
	ProgressType string   `xml:"progress-type" json:"progress-type"`
	Message      string   `xml:"message" json:"message"`
	XMLNS        string   `xml:"xmlns,attr" json:"-"`
}

// JSONReportProgressWrapper is a container to hold a ProgressRequest with an
// RFC8572-compliant input field name. This functionality is already handled by the xml.Name field for
// XML requests, but an explicit wrapper is required for JSON.
type JSONReportProgressWrapper struct {
	Input ReportProgressRequest `json:"ietf-sztp-bootstrap-server:input"`
}

// ReportProgressArgs parses the report-progress request body in either XML or JSON depending on the Content-Type.
// After calling ReportProgressArgs, do not attempt to read from req.Body again, as the stream will
// have been consumed.
func ReportProgressArgs(req *http.Request, dp DependencyProvider) (*ReportProgressRequest, error) {
	requestBytes := new(bytes.Buffer)
	requestBytes.ReadFrom(req.Body)
	bytesReader := bytes.NewReader(requestBytes.Bytes())
	dp.LogInfof("Parsing report-progress request body: \n%s", requestBytes.String())

	if IsJSONRequest(*req) {
		dp.LogInfof("Content-Type header is %q. Parsing report-progress request body as JSON", req.Header.Get("Content-Type"))
		requestParams := &JSONReportProgressWrapper{}
		if err := json.NewDecoder(bytesReader).Decode(requestParams); err != nil {
			return nil, fmt.Errorf("parse() got error when decoding JSON, request: %v, error: %w", requestBytes.String(), err)
		}
		return &requestParams.Input, nil
	}
	dp.LogInfof("Content-Type header is %q. Parsing report-progress request body as XML", req.Header.Get("Content-Type"))
	requestParams := &ReportProgressRequest{}
	if err := xml.NewDecoder(bytesReader).Decode(requestParams); err != nil {
		return nil, fmt.Errorf("parse() got error when decoding XML, request: %v, error: %w", requestBytes.String(), err)
	}
	return requestParams, nil
}
