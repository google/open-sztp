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

// Package data provides functions to read sZTP data dependencies from the filesystem
// and parse them for use in the sZTP server.
package data

import (
	"crypto"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/fs"
	"path/filepath"

	"github.com/bazelbuild/rules_go/go/runfiles"
	"github.com/google/open_sztp/handlers/bootstrapdata"
	tepb "github.com/google/open_sztp/proto/tpm_enrollment_go_proto"
	"google.golang.org/protobuf/encoding/prototext"
)

// Reader provides methods to read sZTP data dependencies from the "data/" directory.
type Reader struct {
	ParentDir string
}

// readFile opens the runfiles directory root and reads the file stored under the given path segments.
func (r Reader) readFile(pathSegments ...string) ([]byte, error) {
	runfilesFs, err := runfiles.New()
	if err != nil {
		return nil, fmt.Errorf("couldn't get runfiles directory: %w", err)
	}
	path := filepath.Join(append([]string{r.ParentDir}, pathSegments...)...)
	bytes, err := fs.ReadFile(runfilesFs, path)
	if err != nil {
		return nil, fmt.Errorf("couldn't read file %q: %w", path, err)
	}
	return bytes, nil
}

// readPEMFile reads a file and decodes the contents into a PEM block.
func (r Reader) readPEMFile(filename string) (*pem.Block, error) {
	bytes, err := r.readFile(filename)
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
func (r Reader) readCertificate(filename string) (*x509.Certificate, error) {
	pemBlock, err := r.readPEMFile(filename)
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
func (r Reader) readCertificatePrivateKey(filename string) (crypto.PrivateKey, error) {
	pemBlock, err := r.readPEMFile(filename)
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
func (r Reader) ReadOwnershipCertificate() (*x509.Certificate, crypto.PrivateKey, error) {
	cert, err := r.readCertificate("ownershipCertificate.pem")
	if err != nil {
		return nil, nil, fmt.Errorf("couldn't read the Ownership Certificate from the data directory: %v", err)
	}
	privateKey, err := r.readCertificatePrivateKey("ownershipCertificatePrivateKey.pem")
	if err != nil {
		return nil, nil, fmt.Errorf("couldn't parse the Ownership certificate private key from the data directory: %v", err)
	}
	return cert, privateKey, nil
}

// ReadTrustAnchor reads a trust anchor certificate and private key from the PEM files.
func (r Reader) ReadTrustAnchor() (*x509.Certificate, crypto.PrivateKey, error) {
	cert, err := r.readCertificate("trustAnchorCertificate.pem")
	if err != nil {
		return nil, nil, fmt.Errorf("trust anchor certificate could not be read from the data directory: %v", err)
	}
	privateKey, err := r.readCertificatePrivateKey("trustAnchorCertificatePrivateKey.pem")
	if err != nil {
		return nil, nil, fmt.Errorf("trust anchor certificate private key could not be read from the data directory: %v", err)
	}
	return cert, privateKey, nil
}

// ReadOwnershipVoucher reads a base64-encoded ownership voucher from the filesystem.
func (r Reader) ReadOwnershipVoucher(serialNumber string) (string, error) {
	bytes, err := r.readFile(serialNumber, "ownershipVoucher.base64")
	if err != nil {
		return "", fmt.Errorf("couldn't read the Ownership Voucher from the data directory: %v", err)
	}
	return string(bytes), nil
}

// readConfig reads the plaintext pre-config script, bootstrap config, and post-config script from text files.
// These value will be base64-encoded later by the sZTP Server.
func (r Reader) readConfig(serialNumber string) (preconfigScript []byte, bootstrapConfig []byte, postconfigScript []byte, err error) {
	preconfigScript, err = r.readFile(serialNumber, "preConfigScript.txt")
	if err != nil {
		return nil, nil, nil, fmt.Errorf("couldn't read the Pre-Config Script from the data directory: %v", err)
	}
	bootstrapConfig, err = r.readFile(serialNumber, "bootstrapConfig.txt")
	if err != nil {
		return nil, nil, nil, fmt.Errorf("couldn't read the Bootstrap Config from the data directory: %v", err)
	}
	postconfigScript, err = r.readFile(serialNumber, "postConfigScript.txt")
	if err != nil {
		return nil, nil, nil, fmt.Errorf("couldn't read the Post-Config Script from the data directory: %v", err)
	}
	return preconfigScript, bootstrapConfig, postconfigScript, nil
}

// ReadTPMResponses reads and parses the IssueAIKCertResponse and VerifyAttestationCredentialResponse from textproto files.
func (r Reader) ReadTPMResponses(serialNumber string) (*tepb.IssueAikCertResponse, *tepb.VerifyAttestationCredentialResponse, error) {
	issueAIKCertResponseBytes, err := r.readFile(serialNumber, "issueAikCertResponse.textproto")
	if err != nil {
		return nil, nil, fmt.Errorf("couldn't read the IssueAIKCertResponse proto from the data directory: %v", err)
	}
	issueAIKCertResponse := &tepb.IssueAikCertResponse{}
	if err := prototext.Unmarshal(issueAIKCertResponseBytes, issueAIKCertResponse); err != nil {
		return nil, nil, fmt.Errorf("the IssueAIKCertResponse proto file was not valid proto syntax: %v", err)
	}
	verifyAttestationCredentialResponseBytes, err := r.readFile(serialNumber, "verifyAttestationCredentialResponse.textproto")
	if err != nil {
		return nil, nil, fmt.Errorf("couldn't read the VerifyAttestationCredentialResponse proto from the data directory: %v", err)
	}
	verifyAttestationCredentialResponse := &tepb.VerifyAttestationCredentialResponse{}
	if err := prototext.Unmarshal(verifyAttestationCredentialResponseBytes, verifyAttestationCredentialResponse); err != nil {
		return nil, nil, fmt.Errorf("the VerifyAttestationCredentialResponse proto file was not valid proto syntax: %v", err)
	}
	return issueAIKCertResponse, verifyAttestationCredentialResponse, nil
}

// ReadOnboardingData reads the onboardingData.json, preConfigScript.txt, bootstrapConfig.txt, and postConfigScript.txt files and combines them into a struct.
func (r Reader) ReadOnboardingData(serialNumber string) (bootstrapdata.OnboardingData, error) {
	onboardingDataBytes, err := r.readFile(serialNumber, "onboardingData.json")
	if err != nil {
		return bootstrapdata.OnboardingData{}, fmt.Errorf("couldn't read the OnboardingData JSON from the data directory: %v", err)
	}
	onboardingData := bootstrapdata.OnboardingData{}
	if err := json.Unmarshal(onboardingDataBytes, &onboardingData); err != nil {
		return bootstrapdata.OnboardingData{}, fmt.Errorf("the onboardingData.json file was not valid JSON syntax: %v", err)
	}
	preConfig, config, postConfig, err := r.readConfig(serialNumber)
	if err != nil {
		return bootstrapdata.OnboardingData{}, fmt.Errorf("couldn't read the config files: %v", err)
	}
	onboardingData.PreConfigScript = preConfig
	onboardingData.Config = config
	onboardingData.PostConfigScript = postConfig
	return onboardingData, nil
}
