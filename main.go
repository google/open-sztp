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

// main is the executable entry point for the open_sztp test server.
package main

import (
	"context"
	"flag"
	"log"

	"github.com/google/open_sztp/handlers/bootstrapdata"
	"github.com/google/open_sztp/server"
	"github.com/google/open_sztp/testdata/testdata"
	"github.com/google/open_sztp/util/stubdependencies"
)

func main() {
	servingIP := flag.String("ip", "::1", "IP address that this server should listen on (default: ::1)")
	servingPort := flag.Int("port", 12345, "Port that this server should listen on (default: 12345)")
	flag.Parse()
	if *servingIP == "" {
		log.Fatalf("--ip flag must be provided")
	}
	if *servingPort == 0 {
		log.Fatalf("--port flag must be provided")
	}

	ownershipCertificate, ownershipCertificatePrivateKey, err := testdata.ReadOwnershipCertificate()
	if err != nil {
		log.Fatalf("Failed to parse the Ownership Certificate: %v", err)
	}
	trustAnchorCertificate, trustAnchorCertificatePrivateKey, err := testdata.ReadTrustAnchor()
	if err != nil {
		log.Fatalf("Failed to parse the trust anchor: %v", err)
	}
	ownershipVoucherBytes, err := testdata.ReadOwnershipVoucher()
	if err != nil {
		log.Fatalf("Failed to read the Ownership Voucher: %v", err)
	}
	preconfigScript, bootstrapConfig, postconfigScript, err := testdata.ReadConfig()
	if err != nil {
		log.Fatalf("Failed to read the config: %v", err)
	}
	issueAIKCertResponse, verifyAttestationCredentialResponse, err := testdata.ReadTPMResponses()
	if err != nil {
		log.Fatalf("Failed to parse the TPM response protos: %v", err)
	}
	ctx := context.Background()
	bootstrapServer, listener, err := server.New(ctx, server.Params{
		EnableTPMEnrollment:   true,
		ListenOnAllInterfaces: true,
		DependencyProvider: &stubdependencies.Provider{
			StubOwnershipCertificate:             ownershipCertificate,
			StubOwnershipCertificatePrivateKey:   ownershipCertificatePrivateKey,
			StubTrustAnchorCertificate:           trustAnchorCertificate,
			StubTrustAnchorCertificatePrivateKey: trustAnchorCertificatePrivateKey,
			StubOwnershipVoucher:                 string(ownershipVoucherBytes),
			StubRedirectIP:                       *servingIP,
			StubRedirectPort:                     *servingPort,
			StubOnboardingData: bootstrapdata.OnboardingData{
				// ============================== Replace your values here =================================
				OSName:       "VendorOS",
				OSVersion:    "v1.0.0",
				DownloadURIs: []string{"http://www.example.com/your/os/image/here.img"},
				ImageVerifications: []bootstrapdata.ImageVerification{
					bootstrapdata.ImageVerification{
						HashAlgorithm: "ietf-sztp-conveyed-info:sha-256",
						HashValue:     "01:23:45:67:89:ab:cd:ef",
					},
				},
				// ============================== Replace your values here =================================
				ConfigHandling:   "replace",
				PreConfigScript:  preconfigScript,
				Config:           bootstrapConfig,
				PostConfigScript: postconfigScript,
			},
			StubIssueAIKCertResponse:                issueAIKCertResponse,
			StubVerifyAttestationCredentialResponse: verifyAttestationCredentialResponse,
		},
	})
	if err != nil {
		log.Fatalf("Failed to create HTTPS server: %v", err)
	}
	defer listener.Close()
	log.Printf("Listing for requests at address %q on port %d\n", *servingIP, *servingPort)
	if err := bootstrapServer.ServeTLS(listener, "", ""); err != nil {
		log.Fatalf("Encountered error while serving with TLS: %v", err)
	}
	log.Println("Shutting down server")
}
