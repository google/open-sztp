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

package parser

import (
	"bytes"
	"fmt"
	"net/http"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/open_sztp/util/constants"
)

type mockDependencyProvider struct {
}

func (mockDependencyProvider) LogInfof(format string, v ...any) {
	fmt.Printf(format, v...)
}

func TestIsJSONRequest(t *testing.T) {
	jsonRequest, err := http.NewRequest("POST", "https://[::1]:12345"+constants.GetBootstrappingDataPattern, bytes.NewReader([]byte{}))
	if err != nil {
		t.Fatalf("http.NewRequest() failed: %v", err)
	}
	jsonRequest.Header.Add("Content-Type", "application/yang-data+json")
	xmlRequest, err := http.NewRequest("POST", "https://[::1]:12345"+constants.GetBootstrappingDataPattern, bytes.NewReader([]byte{}))
	if err != nil {
		t.Fatalf("http.NewRequest() failed: %v", err)
	}
	xmlRequest.Header.Add("Content-Type", "application/yang.data+xml")

	tests := []struct {
		req  *http.Request
		want bool
	}{
		{
			req:  jsonRequest,
			want: true,
		},
		{
			req:  xmlRequest,
			want: false,
		},
	}
	for _, tc := range tests {
		got := IsJSONRequest(*tc.req)
		if got != tc.want {
			t.Errorf("IsJSONRequest(%q) = %v, want: %v", tc.req.Header.Get("Content-Type"), got, tc.want)
		}
	}
}

func TestRestconfArgs(t *testing.T) {
	tests := []struct {
		name        string
		requestBody []byte
		contentType string
		want        RESTCONFArgs
	}{
		{
			name: "XML",
			requestBody: []byte(
				`<input
								xmlns="urn:ietf:params:xml:ns:yang:ietf-sztp-bootstrap-server">
								<signed-data-preferred/>
								<hw-model>model_123</hw-model>
								<os-name>unused</os-name>
								<os-version>unused</os-version>
						</input>`),
			contentType: "application/yang.data+xml",
			want: RESTCONFArgs{
				HWModel:             "model_123",
				SignedDataPreferred: true,
			},
		},
		{
			name: "XML no HW info",
			requestBody: []byte(
				`<input
								xmlns="urn:ietf:params:xml:ns:yang:ietf-sztp-bootstrap-server">
								<signed-data-preferred/>
						</input>`),
			contentType: "application/yang.data+xml",
			want: RESTCONFArgs{
				HWModel:             constants.UnknownHardwareModel,
				SignedDataPreferred: true,
			},
		},
		{
			name: "XML no Content-Type",
			requestBody: []byte(
				`<input
								xmlns="urn:ietf:params:xml:ns:yang:ietf-sztp-bootstrap-server">
								<signed-data-preferred/>
								<hw-model>model_123</hw-model>
								<os-name>unused</os-name>
								<os-version>unused</os-version>
						</input>`),
			want: RESTCONFArgs{
				HWModel:             "model_123",
				SignedDataPreferred: true,
			},
		},
		{
			name: "XML no signed-data-preferred",
			requestBody: []byte(
				`<input
								xmlns="urn:ietf:params:xml:ns:yang:ietf-sztp-bootstrap-server">
								<hw-model>model_123</hw-model>
								<os-name>unused</os-name>
								<os-version>unused</os-version>
						</input>`),
			contentType: "application/yang.data+xml",
			want: RESTCONFArgs{
				HWModel:             "model_123",
				SignedDataPreferred: false,
			},
		},
		{
			name: "XML empty body",
			requestBody: []byte(
				`<input
								xmlns="urn:ietf:params:xml:ns:yang:ietf-sztp-bootstrap-server">
						</input>`),
			contentType: "application/yang.data+xml",
			want: RESTCONFArgs{
				HWModel:             constants.UnknownHardwareModel,
				SignedDataPreferred: false,
			},
		},
		{
			name: "JSON",
			requestBody: []byte(
				`{
					"ietf-sztp-bootstrap-server:input" : {
						"signed-data-preferred": true,
						"hw-model": "model_123",
						"os-name": "vendor-os",
						"os-version": "17.3R2.1"
					}
				}`),
			contentType: "application/yang-data+json",
			want: RESTCONFArgs{
				HWModel:             "model_123",
				SignedDataPreferred: true,
			},
		},
		{
			name: "JSON no HW info",
			requestBody: []byte(
				`{
					"ietf-sztp-bootstrap-server:input" : {
						"signed-data-preferred": true
					}
				}`),
			contentType: "application/yang-data+json",
			want: RESTCONFArgs{
				HWModel:             constants.UnknownHardwareModel,
				SignedDataPreferred: true,
			},
		},
		{
			name: "JSON no Content-Type",
			requestBody: []byte(
				`{
					"ietf-sztp-bootstrap-server:input" : {
						"signed-data-preferred": true,
						"hw-model": "model_123",
						"os-name": "vendor-os",
						"os-version": "17.3R2.1"
					}
				}`),
			want: RESTCONFArgs{
				HWModel:             constants.UnknownHardwareModel,
				SignedDataPreferred: false,
			},
		},
		{
			name: "JSON no signed-data-preferred",
			requestBody: []byte(
				`{
					"ietf-sztp-bootstrap-server:input" : {
						"hw-model": "model_123",
						"os-name": "vendor-os",
						"os-version": "17.3R2.1"
					}
				}`),
			contentType: "application/yang-data+json",
			want: RESTCONFArgs{
				HWModel:             "model_123",
				SignedDataPreferred: false,
			},
		},
		{
			name: "JSON empty body",
			requestBody: []byte(
				`{
					"ietf-sztp-bootstrap-server:input" : {
					}
				}`),
			contentType: "application/yang-data+json",
			want: RESTCONFArgs{
				HWModel:             constants.UnknownHardwareModel,
				SignedDataPreferred: false,
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			request, err := http.NewRequest("POST",
				"https://[::1]:12345"+constants.GetBootstrappingDataPattern,
				bytes.NewReader(tc.requestBody))
			if err != nil {
				t.Fatalf("http.NewRequest(%s) got unexpected error: %v", string(tc.requestBody), err)
			}
			if tc.contentType != "" {
				request.Header.Set("Content-Type", tc.contentType)
			}
			got, err := RestconfArgs(request, mockDependencyProvider{})
			if err != nil {
				t.Fatalf("RestconfArgs(%s) got an unexpected error: %v", string(tc.requestBody), err)
			}
			if diff := cmp.Diff(got, tc.want); diff != "" {
				t.Errorf("RestconfArgs(%s) got unexpected result (-got, +want):\n%v", string(tc.requestBody), diff)
			}
		})
	}
}

func TestRestconfArgsError(t *testing.T) {
	tests := []struct {
		name        string
		requestBody []byte
		contentType string
	}{
		{
			name: "XML error",
			requestBody: []byte(
				`<input
								xmlns="urn:ietf:params:xml:ns:yang:ietf-sztp-bootstrap-server">
								<signed-data-preferred/>
								<hw-model>model_123</hw-model>
								<os-name>unused</os-name>
								<os-version>unused
						</input>`),
			contentType: "application/yang.data+xml",
		},
		{
			name: "JSON error",
			requestBody: []byte(
				`{
					"ietf-sztp-bootstrap-server:input" : {
						"signed-data-preferred": true,
						"hw-model": "model_123",
						"os-name": "vendor-os",
						"os-version": "17.3R2.1"}}}}}
				`),
			contentType: "application/yang-data+json",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			request, err := http.NewRequest("POST",
				"https://[::1]:12345"+constants.GetBootstrappingDataPattern,
				bytes.NewReader(tc.requestBody))
			if err != nil {
				t.Fatalf("http.NewRequest(%s) got unexpected error: %v", string(tc.requestBody), err)
			}
			if tc.contentType != "" {
				request.Header.Set("Content-Type", tc.contentType)
			}
			got, err := RestconfArgs(request, mockDependencyProvider{})
			if err == nil {
				t.Fatalf("RestconfArgs(%s) expected error but got:\n%v", string(tc.requestBody), got)
			}
		})
	}
}

func TestReportProgressArgs(t *testing.T) {
	tests := []struct {
		name        string
		requestBody []byte
		contentType string
		want        ReportProgressRequest
	}{
		{
			name: "XML",
			requestBody: []byte(
				`<input xmlns="urn:ietf:params:xml:ns:yang:ietf-sztp-bootstrap-server">
								<progress-type>bootstrap-complete</progress-type>
								<message>example message</message>
				</input>`,
			),
			contentType: "application/yang.data+xml",
			want: ReportProgressRequest{
				ProgressType: "bootstrap-complete",
				Message:      "example message",
			},
		},
		{
			name: "XML_no_progress_type",
			requestBody: []byte(
				`<input xmlns="urn:ietf:params:xml:ns:yang:ietf-sztp-bootstrap-server">
								<message>example message</message>
				</input>`,
			),
			contentType: "application/yang.data+xml",
			want: ReportProgressRequest{
				ProgressType: "",
				Message:      "example message",
			},
		},
		{
			name: "XML_no_message",
			requestBody: []byte(
				`<input xmlns="urn:ietf:params:xml:ns:yang:ietf-sztp-bootstrap-server">
								<progress-type>bootstrap-complete</progress-type>
				</input>`,
			),
			contentType: "application/yang.data+xml",
			want: ReportProgressRequest{
				ProgressType: "bootstrap-complete",
			},
		},
		{
			name: "XML_no_content_type",
			requestBody: []byte(
				`<input xmlns="urn:ietf:params:xml:ns:yang:ietf-sztp-bootstrap-server">
								<progress-type>bootstrap-complete</progress-type>
								<message>example message</message>
				</input>`,
			),
			contentType: "application/yang.data+xml",
			want: ReportProgressRequest{
				ProgressType: "bootstrap-complete",
				Message:      "example message",
			},
		},
		{
			name:        "XML_empty_body",
			requestBody: []byte(`<input xmlns="urn:ietf:params:xml:ns:yang:ietf-sztp-bootstrap-server"></input>`),
			contentType: "application/yang.data+xml",
			want: ReportProgressRequest{
				ProgressType: "",
				Message:      "",
			},
		},
		{
			name: "JSON",
			requestBody: []byte(
				`{
					"ietf-sztp-bootstrap-server:input": {
						"progress-type" : "bootstrap-complete",
						"message" : "example message"
					}
				}`,
			),
			contentType: "application/yang-data+json",
			want: ReportProgressRequest{
				ProgressType: "bootstrap-complete",
				Message:      "example message",
			},
		},
		{
			name: "JSON_no_message",
			requestBody: []byte(
				`{
					"ietf-sztp-bootstrap-server:input" : {
						"progress-type" : "bootstrap-complete"
					}
				}`,
			),
			contentType: "application/yang-data+json",
			want: ReportProgressRequest{
				ProgressType: "bootstrap-complete",
			},
		},
		{
			name: "JSON_no_progress_type",
			requestBody: []byte(
				`{
					"ietf-sztp-bootstrap-server:input" : {
						"message" : "example message"
					}
				}`,
			),
			contentType: "application/yang-data+json",
			want: ReportProgressRequest{
				ProgressType: "",
				Message:      "example message",
			},
		},
		{
			name: "JSON_empty_body",
			requestBody: []byte(
				`{
					"ietf-sztp-bootstrap-server:input" : {}
				}`,
			),
			contentType: "application/yang-data+json",
			want: ReportProgressRequest{
				ProgressType: "",
				Message:      "",
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			url := "https://[::1]:12345" + constants.GetBootstrappingDataPattern
			request, err := http.NewRequest("POST", url, bytes.NewReader(tc.requestBody))
			if err != nil {
				t.Fatalf("http.NewRequest(%s) got unexpected error: %v", string(tc.requestBody), err)
			}
			if tc.contentType != "" {
				request.Header.Set("Content-Type", tc.contentType)
			}
			got, err := ReportProgressArgs(request, mockDependencyProvider{})
			if err != nil {
				t.Fatalf("ReportProgressArgs(%s) got an unexpected error: %v", string(tc.requestBody), err)
			}
			if diff := cmp.Diff(*got, tc.want, cmpopts.IgnoreFields(ReportProgressRequest{}, "XMLName", "XMLNS")); diff != "" {
				t.Errorf("ReportProgressArgs(%s) got unexpected result (-got, +want):\n%v", string(tc.requestBody), diff)
			}
		})
	}
}

func TestReportProgressArgsError(t *testing.T) {
	tests := []struct {
		name        string
		requestBody []byte
		contentType string
	}{
		{
			name: "XML error",
			requestBody: []byte(
				`<input
								xmlns="urn:ietf:params:xml:ns:yang:ietf-sztp-bootstrap-server">
								<progress-type>bootstrap-complete
								<message>example message</message>
						</input>`),
			contentType: "application/yang.data+xml",
		},
		{
			name: "JSON error",
			requestBody: []byte(
				`{
					"ietf-sztp-bootstrap-server:input": 
						"progress-type" : "bootstrap-complete",
						"message" : "example message"
					}
				}`),
			contentType: "application/yang-data+json",
		},
		{
			name: "JSON no Content-Type",
			requestBody: []byte(
				`{
					"ietf-sztp-bootstrap-server:input" : {
						"progress-type" : "bootstrap-complete",
						"message" : "example message"
					}
				}`),
			contentType: "",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			request, err := http.NewRequest("POST",
				"https://[::1]:12345"+constants.GetBootstrappingDataPattern,
				bytes.NewReader(tc.requestBody))
			if err != nil {
				t.Fatalf("http.NewRequest(%s) got unexpected error: %v", string(tc.requestBody), err)
			}
			if tc.contentType != "" {
				request.Header.Set("Content-Type", tc.contentType)
			}
			got, err := ReportProgressArgs(request, mockDependencyProvider{})
			if err == nil {
				t.Fatalf("ReportProgressArgs(%s) expected error but got: %v", string(tc.requestBody), got)
			}
		})
	}
}
