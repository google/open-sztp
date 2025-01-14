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

// Package bootstrapdata implements handler functions
// to handle get bootstrapping data request.
package bootstrapdata

import (
	"context"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/http"

	"crypto/x509"

	"github.com/google/open_sztp/util/constants"
	"github.com/google/open_sztp/util/parser"
	"github.com/kylelemons/godebug/pretty"
	"go.mozilla.org/pkcs7"
)

// ImageVerification contains the hash algorithm and hash value of an image.
// Used as a part of OnboardingData.
type ImageVerification struct {
	HashAlgorithm string `json:"hash-algorithm"`
	HashValue     string `json:"hash-value"`
}

// OnboardingData encodes the information necessary to populate the sZTP conveyed information for
// the trusted phase of sZTP.
type OnboardingData struct {
	OSName             string              `json:"os-name"`
	OSVersion          string              `json:"os-version"`
	DownloadURIs       []string            `json:"download-uris"`
	ImageVerifications []ImageVerification `json:"image-verifications"`
	ConfigHandling     string              `json:"configuration-handling"`
	PreConfigScript    []byte              `json:"pre-config-script"`
	Config             []byte              `json:"config"`
	PostConfigScript   []byte              `json:"post-config-script"`
}

// DependencyProvider abstracts the dependencies of the bootstrap server and returns the values to populate in the sZTP response.
type DependencyProvider interface {
	// OwnershipCert returns the sZTP ownership certificate used to sign the conveyed information in the sZTP response.
	// The certificate is in PEM format.
	OwnershipCert(ctx context.Context) (*x509.Certificate, error)
	// OwnershipCertPrivateKey returns the private key for the sZTP ownership certificate.
	// The private key is in PEM format.
	OwnershipCertPrivateKey(ctx context.Context) (crypto.PrivateKey, error)
	// TrustAnchorCert returns the trust anchor certificate used to sign the trust anchor CMS in the sZTP response.
	// The certificate is in PEM format.
	TrustAnchorCert(ctx context.Context) (*x509.Certificate, error)
	// TrustAnchorPrivateKey returns the private key for the trust anchor certificate.
	// The private key is in PEM format.
	TrustAnchorPrivateKey(ctx context.Context) (crypto.PrivateKey, error)
	// OwnershipVoucher returns the ownership voucher for the device.
	// The OV is returned as a base64 encoded ASN.1 DER certificate.
	OwnershipVoucher(ctx context.Context, req *http.Request, args parser.RESTCONFArgs) (string, error)
	// RedirectIP returns the IP address of the bootstrap server that the device should redirect
	// back to after the completing the untrusted phase of sZTP.
	// If req is nil, the default IP address of the sZTP server is returned.
	RedirectIP(req *http.Request) string
	// RedirectPort returns the port number of the bootstrap server that the device should redirect
	// back to after the untrusted phase of sZTP.
	RedirectPort() int
	// OnboardingInformation returns the boot image and config to return to the to populate the
	// sZTP conveyed information for the trusted phase of sZTP.
	OnboardingInformation(ctx context.Context, req *http.Request, args parser.RESTCONFArgs) (OnboardingData, error)
	// LogInfof logs a message at INFO severity. Arguments are handled in the manner of fmt.Printf.
	LogInfof(format string, v ...any)
	// LogErrorf logs a message at ERROR severity. Arguments are handled in the manner of fmt.Printf.
	LogErrorf(format string, v ...any)
}

// Handler is the handler of the get bootstrapping data request.
type Handler struct {
	DependencyProvider DependencyProvider
}

// A BootstrapResponse defines the get-bootstrapping-data
// https response body structure used for XML/JSON encoding per https://datatracker.ietf.org/doc/html/rfc8572#section-7.1.
type BootstrapResponse struct {
	XMLName             xml.Name `xml:"output" json:"-"`
	OwnerCertificate    string   `xml:"owner-certificate" json:"owner-certificate"`
	OwnershipVoucher    string   `xml:"ownership-voucher" json:"ownership-voucher"`
	ConveyedInformation string   `xml:"conveyed-information" json:"conveyed-information"`
	XMLNS               string   `xml:"xmlns,attr" json:"-"`
}

// JSONResponseWrapper is a container to hold a BootstrapResponse with an
// RFC8572-compliant output field name. This functionality is already handled by the xml.Name field for
// XML responses, but an explicit wrapper is required for JSON.
type JSONResponseWrapper struct {
	Output BootstrapResponse `json:"ietf-sztp-bootstrap-server:output"`
}

// respondWithError logs the error message and sends an HTTP 500 error response.
func respondWithError(w http.ResponseWriter, dp DependencyProvider, err error) {
	dp.LogErrorf(err.Error())
	http.Error(w, err.Error(), http.StatusInternalServerError)
}

// Handle handles the get-bootstrapping-data request.
func (h Handler) Handle(w http.ResponseWriter, req *http.Request) {
	h.DependencyProvider.LogInfof("In get-bootstrapping-data handler. HTTP Request: \n%+v", pretty.Sprint(*req))
	ctx := req.Context()

	args, err := parser.RestconfArgs(req, h.DependencyProvider)
	if err != nil {
		respondWithError(w, h.DependencyProvider, fmt.Errorf("Could not parse hw-model and signed-data-preferred from request body: %w", err))
		return
	}
	h.DependencyProvider.LogInfof("signed-data-preferred is %t, hw-model is %q", args.SignedDataPreferred, args.HWModel)

	ownershipVoucher, err := h.DependencyProvider.OwnershipVoucher(ctx, req, args)
	if err != nil {
		respondWithError(w, h.DependencyProvider, fmt.Errorf("Could not get ownership voucher: %w", err))
		return
	}

	var respType string
	if args.SignedDataPreferred {
		// Returns the redirect info, as described in https://datatracker.ietf.org/doc/html/rfc8572#appendix-B.
		err = h.respondWithRedirectInfo(ctx, req, w, ownershipVoucher)
		respType = "redirect"
	} else {
		// Returns onboarding information, as described in https://datatracker.ietf.org/doc/html/rfc8572#section-6.1.
		err = h.respondWithOnboardingInfo(ctx, req, w, args, ownershipVoucher)
		respType = "onboarding"
	}
	if err != nil {
		respondWithError(w, h.DependencyProvider, fmt.Errorf("Could not respond with %s information: %w", respType, err))
	}
}

// fetchOwnershipCertKeyPair fetches the owner-cert and owner-cert private key pair from Secrets Depot.
func (h Handler) fetchOwnershipCertKeyPair(ctx context.Context) (*x509.Certificate, crypto.PrivateKey, error) {
	oc, err := h.DependencyProvider.OwnershipCert(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("retrieving ownership certificate: %w", err)
	}
	ocPrivateKey, err := h.DependencyProvider.OwnershipCertPrivateKey(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("retrieving ownership certificate private key: %w", err)
	}
	return oc, ocPrivateKey, nil
}

// respondWithRedirectInfo generates the redirect information for the untrusted phase of sZTP and sends the HTTP response.
func (h Handler) respondWithRedirectInfo(ctx context.Context, req *http.Request, w http.ResponseWriter, ownershipVoucher string) error {
	h.DependencyProvider.LogInfof("In respond-with-redirect-info")
	taCert, err := h.DependencyProvider.TrustAnchorCert(ctx)
	if err != nil {
		return fmt.Errorf("parsing the trust-anchor certificate: %w", err)
	}
	taPrivateKey, err := h.DependencyProvider.TrustAnchorPrivateKey(ctx)
	if err != nil {
		return fmt.Errorf("parsing the trust-anchor private key: %w", err)
	}
	h.DependencyProvider.LogInfof("Using trust anchor public key: \n%s", string(taCert.Raw))
	trustAnchorCms, err := signConveyedInformation([]byte{}, h.DependencyProvider, taCert, taPrivateKey)
	if err != nil {
		return fmt.Errorf("converting the trust anchor into cms format: %w", err)
	}

	ocCert, ocPrivateKey, err := h.fetchOwnershipCertKeyPair(ctx)
	if err != nil {
		return fmt.Errorf("fetching owner-cert and owner-cert private key pair: %w", err)
	}
	conveyedInfoMap := map[string]any{
		"ietf-sztp-conveyed-info:redirect-information": map[string]any{
			"bootstrap-server": [1]any{
				map[string]any{
					"address":      h.DependencyProvider.RedirectIP(req),
					"port":         h.DependencyProvider.RedirectPort(),
					"trust-anchor": trustAnchorCms,
				},
			},
		},
	}
	h.DependencyProvider.LogInfof("respond-with-redirect-info redirect map is %v", conveyedInfoMap)
	conveyedInfoJSON, err := json.MarshalIndent(conveyedInfoMap, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling conveyed info map:\n%v\n: %w", conveyedInfoMap, err)
	}
	h.DependencyProvider.LogInfof("respond-with-redirect-info Responding with the redirect information JSON:\n%v", string(conveyedInfoJSON))
	if err := signAndRespond(w, conveyedInfoJSON, h.DependencyProvider, ownershipVoucher, parser.IsJSONRequest(*req), ocCert, ocPrivateKey); err != nil {
		return fmt.Errorf("signing and responding with redirect information: %w", err)
	}
	h.DependencyProvider.LogInfof("responded with redirect-info %v", conveyedInfoMap)
	return nil
}

// respondWithOnboardingInfo generates the onboarding information for the trusted phase of sZTP and sends the HTTP response.
func (h Handler) respondWithOnboardingInfo(ctx context.Context, req *http.Request, w http.ResponseWriter, args parser.RESTCONFArgs, ownershipVoucher string) error {
	h.DependencyProvider.LogInfof("In respond-with-onboarding-info")
	onboardingInfo, err := h.DependencyProvider.OnboardingInformation(ctx, req, args)
	if err != nil {
		return fmt.Errorf("getting onboarding information: %w", err)
	}

	var imageVerifications []map[string]string
	for _, imageVerification := range onboardingInfo.ImageVerifications {
		imageVerifications = append(imageVerifications, map[string]string{
			"hash-algorithm": imageVerification.HashAlgorithm,
			"hash-value":     imageVerification.HashValue,
		})
	}
	conveyedInfoMap := map[string]any{
		"ietf-sztp-conveyed-info:onboarding-information": map[string]any{
			"boot-image": map[string]any{
				"os-name":            onboardingInfo.OSName,
				"os-version":         onboardingInfo.OSVersion,
				"download-uri":       onboardingInfo.DownloadURIs,
				"image-verification": imageVerifications,
			},
			"configuration-handling":    onboardingInfo.ConfigHandling,
			"pre-configuration-script":  base64.StdEncoding.EncodeToString(onboardingInfo.PreConfigScript),
			"configuration":             base64.StdEncoding.EncodeToString(onboardingInfo.Config),
			"post-configuration-script": base64.StdEncoding.EncodeToString(onboardingInfo.PostConfigScript),
		},
	}
	h.DependencyProvider.LogInfof("respond-with-onboarding-info conveyed info is %v", conveyedInfoMap)
	conveyedInfoJSON, err := json.MarshalIndent(conveyedInfoMap, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling conveyed info map:\n%v\n: %w", conveyedInfoMap, err)
	}
	h.DependencyProvider.LogInfof("respond-with-onboarding-info Responding with the onboarding-info JSON:\n%v", string(conveyedInfoJSON))

	ocCert, ocPrivateKey, err := h.fetchOwnershipCertKeyPair(ctx)
	if err != nil {
		return fmt.Errorf("fetching owner-cert and owner-cert private key pair: %w", err)
	}

	if err := signAndRespond(w, conveyedInfoJSON, h.DependencyProvider, ownershipVoucher, parser.IsJSONRequest(*req), ocCert, ocPrivateKey); err != nil {
		return fmt.Errorf("signing and responding with onboarding information: %w", err)
	}
	h.DependencyProvider.LogInfof("respond-with-onboarding-info completed responding with onboarding information")
	return nil
}

// signAndRespond signs the conveyed information and sends the HTTP response.
func signAndRespond(w http.ResponseWriter, conveyedInformation []byte, dp DependencyProvider, ov string, useJSON bool, ocCert *x509.Certificate, ocPrivateKey crypto.PrivateKey) error {
	dp.LogInfof("In sign-and-respond")
	dp.LogInfof("Using public key \n%v", ocCert)
	dp.LogInfof("Using ownership voucher \n%v", ov)

	signedConveyedInformationBytes, err := signConveyedInformation(conveyedInformation, dp, ocCert, ocPrivateKey)
	if err != nil {
		return fmt.Errorf("serializing signed data: %v", err)
	}
	ocCMS, err := signConveyedInformation([]byte{}, dp, ocCert, ocPrivateKey)
	if err != nil {
		return fmt.Errorf("generating owner certificate cms: %v", err)
	}
	response := BootstrapResponse{
		OwnerCertificate:    ocCMS,
		OwnershipVoucher:    ov,
		ConveyedInformation: signedConveyedInformationBytes,
		XMLNS:               constants.BootstrapServerXMLNamespace,
	}
	dp.LogInfof("get-bootstrapping-data HTTP response: %+v", pretty.Sprint(response))

	var responseBytes []byte
	if useJSON {
		responseBytes, err = json.MarshalIndent(&JSONResponseWrapper{Output: response}, "", "  ")
	} else {
		responseBytes, err = xml.MarshalIndent(&response, "", "  ")
	}
	if err != nil {
		return fmt.Errorf("marshaling response map: %v", err)
	}

	dp.LogInfof("Writing bytes to HTTP response: \n%s", string(responseBytes))
	if _, err := w.Write(responseBytes); err != nil {
		return fmt.Errorf("writing response to http: %v", err)
	}
	dp.LogInfof("completed signing conveyed information")
	return nil
}

// signConveyedInformation generates a cms representation (RFC 5652) in base64 encoding of a certificate key pair.
func signConveyedInformation(conveyedInformation []byte, dp DependencyProvider, certificate *x509.Certificate, privateKey crypto.PrivateKey) (string, error) {
	dp.LogInfof("In SignConveyedInformation")

	signedConveyedInformation, err := pkcs7.NewSignedData(conveyedInformation)
	if err != nil {
		return "", fmt.Errorf("creating PKCS7 SignedData: %w", err)
	}
	signedConveyedInformation.SetDigestAlgorithm(pkcs7.OIDDigestAlgorithmSHA256)
	signedConveyedInformation.SetEncryptionAlgorithm(pkcs7.OIDEncryptionAlgorithmRSA)
	err = signedConveyedInformation.AddSigner(
		certificate, privateKey, pkcs7.SignerInfoConfig{})
	if err != nil {
		return "", fmt.Errorf("signing conveyed information: %w", err)
	}
	signedConveyedInformationBytes, err := signedConveyedInformation.Finish()
	if err != nil {
		return "", fmt.Errorf("signConveyedInformation could not serialize signed data %v", err)
	}
	return base64.StdEncoding.EncodeToString(signedConveyedInformationBytes), nil
}
