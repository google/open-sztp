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

package data

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"slices"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/open_sztp/handlers/bootstrapdata"
	"go.mozilla.org/pkcs7"
)

func NewTestDataReader() Reader {
	return Reader{
		ParentDir: "_main/util/testdata",
	}
}

func TestIsMatchingKeypair(t *testing.T) {
	dataReader := NewTestDataReader()
	ownershipCertificate, ownershipCertificatePrivateKey, err := dataReader.ReadOwnershipCertificate()
	if err != nil {
		t.Fatalf("Failed to parse the Ownership Certificate: %v", err)
	}
	trustAnchorCertificate, trustAnchorCertificatePrivateKey, err := dataReader.ReadTrustAnchor()
	if err != nil {
		t.Fatalf("Failed to parse the trust anchor: %v", err)
	}
	tests := []struct {
		name       string
		cert       *x509.Certificate
		privateKey crypto.PrivateKey
	}{
		{
			name:       "Ownership_Certificate",
			cert:       ownershipCertificate,
			privateKey: ownershipCertificatePrivateKey,
		},
		{
			name:       "Trust_Anchor",
			cert:       trustAnchorCertificate,
			privateKey: trustAnchorCertificatePrivateKey,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			publicKey, ok := tc.cert.PublicKey.(*rsa.PublicKey)
			if !ok {
				t.Fatalf("certificate is not an RSA public key")
			}
			rsaPrivateKey, ok := tc.privateKey.(*rsa.PrivateKey)
			if !ok {
				t.Fatalf("private key is not an RSA private key")
			}
			if publicKey.N.Cmp(rsaPrivateKey.N) != 0 {
				t.Errorf("public and private key RSA moduli do not match. Public key modulus: %v, private key modulus: %v", *publicKey.N, *rsaPrivateKey.N)
			}
			if publicKey.E != rsaPrivateKey.E {
				t.Errorf("public and private key RSA exponents do not match. Public key exponent: %v, private key exponent: %v", publicKey.E, rsaPrivateKey.E)
			}
		})
	}
}

type ownershipVoucher struct {
	OV inner `json:"ietf-voucher:voucher" xml:"voucher"`
}

// Inner defines the Ownership Voucher format. See https://www.rfc-editor.org/rfc/rfc8366.html.
type inner struct {
	XMLName                    xml.Name `xml:"voucher"`
	CreatedOn                  string   `json:"created-on" xml:"created-on"`
	ExpiresOn                  string   `json:"expires-on" xml:"expires-on"`
	SerialNumber               string   `json:"serial-number" xml:"serial-number"`
	Assertion                  string   `json:"assertion" xml:"assertion"`
	PinnedDomainCert           []byte   `json:"pinned-domain-cert" xml:"pinned-domain-cert"`
	DomainCertRevocationChecks bool     `json:"domain-cert-revocation-checks" xml:"domain-cert-revocation-checks"`
}

func TestOwnershipVoucherContainsOwnershipCertificate(t *testing.T) {
	dataReader := NewTestDataReader()
	ov, err := dataReader.ReadOwnershipVoucher("12345")
	if err != nil {
		t.Fatalf("Failed to read the Ownership Voucher: %v", err)
	}
	ovBytes, err := base64.StdEncoding.DecodeString(ov)
	if err != nil {
		t.Fatalf("Failed to decode the Ownership Voucher from base64: %v", err)
	}
	signedData, err := pkcs7.Parse(ovBytes)
	if err != nil {
		t.Fatalf("Failed to parse pkcs7 signed data: %v:", err)
	}
	parsedOV := &ownershipVoucher{}
	err = json.Unmarshal(signedData.Content, parsedOV)
	if err != nil {
		t.Fatalf("Failed to parse JSON content in Ownership Voucher: %v", err)
	}
	ownershipCertificate, _, err := dataReader.ReadOwnershipCertificate()
	if err != nil {
		t.Fatalf("Failed to read the Ownership Certificate: %v", err)
	}
	if !slices.Equal(parsedOV.OV.PinnedDomainCert, ownershipCertificate.Raw) {
		t.Errorf("Ownership Voucher did not contain the Ownership Certificate as the pinned domain cert")
	}
	if parsedOV.OV.SerialNumber != "12345" {
		t.Errorf("Unexpected Ownership Voucher serial number, got: %q, want: \"12345\"", parsedOV.OV.SerialNumber)
	}
}

func TestReadOnboardingData(t *testing.T) {
	dataReader := NewTestDataReader()
	got, err := dataReader.ReadOnboardingData("12345")
	if err != nil {
		t.Fatalf("Failed to read the Onboarding Data: %v", err)
	}
	want := bootstrapdata.OnboardingData{
		OSName:       "VendorOS",
		OSVersion:    "v1.0.0",
		DownloadURIs: []string{"http://www.example.com/your/os/image/here.img"},
		ImageVerifications: []bootstrapdata.ImageVerification{
			bootstrapdata.ImageVerification{
				HashAlgorithm: "ietf-sztp-conveyed-info:sha-256",
				HashValue:     "01:23:45:67:89:ab:cd:ef",
			},
		},
		PreConfigScript:  []byte("pre-config-script"),
		Config:           []byte("bootstrap-config"),
		PostConfigScript: []byte("post-config-script"),
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatalf("Unexpected Onboarding Data diff (-want +got):\n%s", diff)
	}
}

func TestReadTPMResponses(t *testing.T) {
	dataReader := NewTestDataReader()
	issueAIKCertResponse, verifyAttestationCredentialResponse, err := dataReader.ReadTPMResponses("12345")
	if err != nil {
		t.Fatalf("Failed to read the TPM responses: %v", err)
	}
	if issueAIKCertResponse.EncChallenge == "" || issueAIKCertResponse.EncDataEncryptionKey == "" {
		t.Errorf("IssueAIKCertResponse has empty fields: %v", issueAIKCertResponse)
	}
	if verifyAttestationCredentialResponse.AikCert == "" {
		t.Errorf("VerifyAttestationCredentialResponse had an empty AikCert field")
	}
}
