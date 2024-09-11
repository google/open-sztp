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

// Package testdata contains an embed directive for all of the files in the testdata directory
// and functions to read and parse them for use in the sZTP server.
package testdata

import (
	"crypto"
	"crypto/x509"
	"embed"
	"encoding/pem"
	"fmt"

	tepb "github.com/google/open_sztp/proto/tpm_enrollment_go_proto"
	"google.golang.org/protobuf/encoding/prototext"
)

//go:embed *.txt *.pem *.textproto *.base64
var testDataFiles embed.FS

// readPEMFile reads a file and decodes the contents into a PEM block.
func readPEMFile(filename string) (*pem.Block, error) {
	bytes, err := testDataFiles.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("couldn't read PEM file: %w", err)
	}
	pemBlock, _ := pem.Decode(bytes)
	if pemBlock == nil {
		return nil, fmt.Errorf("invalid PEM format in file %q", filename)
	}
	return pemBlock, nil
}

// readCertificate parses a test ASN.1 DER cert in PEM format from the given filepath.
func readCertificate(filename string) (*x509.Certificate, error) {
	pemBlock, err := readPEMFile(filename)
	if err != nil {
		return nil, fmt.Errorf("couldn't parse PEM file: %w", err)
	}
	cert, err := x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("couldn't parse the cert from ASN.1 DER format: %w", err)
	}
	return cert, nil
}

// readCertificatePrivateKey parses a test PKCS#8 ASN.1 DER private key in PEM format from the given filepath.
func readCertificatePrivateKey(filename string) (crypto.PrivateKey, error) {
	pemBlock, err := readPEMFile(filename)
	if err != nil {
		return nil, fmt.Errorf("couldn't parse PEM file: %w", err)
	}
	privateKey, err := x509.ParsePKCS8PrivateKey(pemBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("couldn't parse the private key from PKCS#8 ASN.1 DER format: %w", err)
	}
	return privateKey, nil
}

// ReadOwnershipCertificate reads an ownership certificate and private key from PEM files.
func ReadOwnershipCertificate() (*x509.Certificate, crypto.PrivateKey, error) {
	cert, err := readCertificate("ownershipCertificate.pem")
	if err != nil {
		return nil, nil, fmt.Errorf("couldn't read the Ownership Certificate from testdata: %v", err)
	}
	privateKey, err := readCertificatePrivateKey("ownershipCertificatePrivateKey.pem")
	if err != nil {
		return nil, nil, fmt.Errorf("couldn't parse the Ownership certificate private key from testdata: %v", err)
	}
	return cert, privateKey, nil
}

// ReadTrustAnchor reads a trust anchor certificate and private key from the PEM files.
func ReadTrustAnchor() (*x509.Certificate, crypto.PrivateKey, error) {
	cert, err := readCertificate("trustAnchorCertificate.pem")
	if err != nil {
		return nil, nil, fmt.Errorf("trust anchor certificate could not be read from testdata: %v", err)
	}
	privateKey, err := readCertificatePrivateKey("trustAnchorCertificatePrivateKey.pem")
	if err != nil {
		return nil, nil, fmt.Errorf("trust anchor certificate private key could not be read from testdata: %v", err)
	}
	return cert, privateKey, nil
}

// ReadOwnershipVoucher reads a base64-encoded ownership voucher from the filesystem.
func ReadOwnershipVoucher() (string, error) {
	bytes, err := testDataFiles.ReadFile("ownershipVoucher.base64")
	if err != nil {
		return "", fmt.Errorf("couldn't read the Ownership Voucher from testdata: %v", err)
	}
	return string(bytes), nil
}

// ReadConfig reads the plaintext pre-config script, bootstrap config, and post-config script from text files.
// These value will be base64-encoded later by the sZTP Server.
func ReadConfig() (preconfigScript []byte, bootstrapConfig []byte, postconfigScript []byte, err error) {
	preconfigScript, err = testDataFiles.ReadFile("preConfigScript.txt")
	if err != nil {
		return nil, nil, nil, fmt.Errorf("couldn't read the Pre-Config Script from testdata: %v", err)
	}
	bootstrapConfig, err = testDataFiles.ReadFile("bootstrapConfig.txt")
	if err != nil {
		return nil, nil, nil, fmt.Errorf("couldn't read the Bootstrap Config from testdata: %v", err)
	}
	postconfigScript, err = testDataFiles.ReadFile("postConfigScript.txt")
	if err != nil {
		return nil, nil, nil, fmt.Errorf("couldn't read the Post-Config Script from testdata: %v", err)
	}
	return preconfigScript, bootstrapConfig, postconfigScript, nil
}

// ReadTPMResponses reads and parses the IssueAIKCertResponse and VerifyAttestationCredentialResponse from textproto files.
func ReadTPMResponses() (*tepb.IssueAikCertResponse, *tepb.VerifyAttestationCredentialResponse, error) {
	issueAIKCertResponseBytes, err := testDataFiles.ReadFile("issueAikCertResponse.textproto")
	if err != nil {
		return nil, nil, fmt.Errorf("couldn't read the IssueAIKCertResponse proto from testdata: %v", err)
	}
	issueAIKCertResponse := &tepb.IssueAikCertResponse{}
	if err := prototext.Unmarshal(issueAIKCertResponseBytes, issueAIKCertResponse); err != nil {
		return nil, nil, fmt.Errorf("the IssueAIKCertResponse proto file was not valid proto syntax: %v", err)
	}
	verifyAttestationCredentialResponseBytes, err := testDataFiles.ReadFile("verifyAttestationCredentialResponse.textproto")
	if err != nil {
		return nil, nil, fmt.Errorf("couldn't read the VerifyAttestationCredentialResponse proto from testdata: %v", err)
	}
	verifyAttestationCredentialResponse := &tepb.VerifyAttestationCredentialResponse{}
	if err := prototext.Unmarshal(verifyAttestationCredentialResponseBytes, verifyAttestationCredentialResponse); err != nil {
		return nil, nil, fmt.Errorf("the VerifyAttestationCredentialResponse proto file was not valid proto syntax: %v", err)
	}
	return issueAIKCertResponse, verifyAttestationCredentialResponse, nil
}
