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

// Package constants contains constants used throughout the sZTP bootstrap server.
package constants

import (
	"time"
)

const (
	// BootstrapServerTimeout is the timeout of the Bootstrap Server.
	BootstrapServerTimeout = 60 * time.Second
	// BootstrapServerXMLNamespace is the XML namespace of the Bootstrap Server.
	BootstrapServerXMLNamespace = "urn:ietf:params:xml:ns:yang:ietf-sztp-bootstrap-server"
	// UnknownHardwareModel is the default hardware model if one cannot be parsed.
	UnknownHardwareModel = "unknown-hardware-model"
)

// Patterns of handlers.
const (
	ReportProgressPattern              = "/restconf/operations/ietf-sztp-bootstrap-server:report-progress"
	GetBootstrappingDataPattern        = "/restconf/operations/ietf-sztp-bootstrap-server:get-bootstrapping-data"
	IssueAIKCertPattern                = "/tpm-enrollment:issue-aik-cert"
	VerifyAttestationCredentialPattern = "/tpm-enrollment:verify-attestation-credential"
	HealthzPattern                     = "/healthz"
	NullzPattern                       = "/nullz"
)
