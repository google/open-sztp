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

// Package stubdependencies provides a stub implementation of the DependencyProvider interface.
package stubdependencies

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"syscall"
	"time"

	"github.com/google/open_sztp/handlers/bootstrapdata"
	tepb "github.com/google/open_sztp/proto/tpm_enrollment_go_proto"
	"github.com/google/open_sztp/util/parser"
	"golang.org/x/sys/unix"
)

// Provider implements the DependencyProvider interface and returns the provided values for sZTP fields.
// Provided for the open source implementation.
type Provider struct {
	StubOwnershipCertificate                *x509.Certificate
	StubOwnershipCertificatePrivateKey      crypto.PrivateKey
	StubTrustAnchorCertificate              *x509.Certificate
	StubTrustAnchorCertificatePrivateKey    crypto.PrivateKey
	StubOwnershipVoucher                    string
	StubRedirectIP                          string
	StubRedirectPort                        int
	StubOnboardingData                      bootstrapdata.OnboardingData
	StubIssueAIKCertResponse                *tepb.IssueAikCertResponse
	StubVerifyAttestationCredentialResponse *tepb.VerifyAttestationCredentialResponse
}

// OwnershipCert returns the sZTP ownership certificate used to sign the conveyed information in the sZTP response.
// The certificate is in PEM format.
func (p Provider) OwnershipCert(context.Context) (*x509.Certificate, error) {
	return p.StubOwnershipCertificate, nil
}

// OwnershipCertPrivateKey returns the private key for the sZTP ownership certificate.
// The private key is in PEM format.
func (p Provider) OwnershipCertPrivateKey(context.Context) (crypto.PrivateKey, error) {
	return p.StubOwnershipCertificatePrivateKey, nil
}

// TrustAnchorCert returns the trust anchor certificate used to sign the trust anchor CMS in the sZTP response.
// The certificate is in PEM format.
func (p Provider) TrustAnchorCert(context.Context) (*x509.Certificate, error) {
	return p.StubTrustAnchorCertificate, nil
}

// TrustAnchorPrivateKey returns the private key for the trust anchor certificate.
// The private key is in PEM format.
func (p Provider) TrustAnchorPrivateKey(context.Context) (crypto.PrivateKey, error) {
	return p.StubTrustAnchorCertificatePrivateKey, nil
}

// OwnershipVoucher returns the ownership voucher for the device.
// The OV is returned as a base64 encoded ASN.1 DER certificate.
func (p Provider) OwnershipVoucher(context.Context, *http.Request, parser.RESTCONFArgs) (string, error) {
	return p.StubOwnershipVoucher, nil
}

// RedirectIP returns the IP address of the bootstrap server that the device should redirect
// back to after the completing the untrusted phase of sZTP.
func (p Provider) RedirectIP(*http.Request) string {
	return p.StubRedirectIP
}

// RedirectPort returns the port number of the bootstrap server that the device should redirect
// back to after the untrusted phase of sZTP.
func (p Provider) RedirectPort() int {
	return p.StubRedirectPort
}

// OnboardingInformation returns the boot image and config to return to the to populate the
// sZTP conveyed information for the trusted phase of sZTP.
func (p Provider) OnboardingInformation(context.Context, *http.Request, parser.RESTCONFArgs) (bootstrapdata.OnboardingData, error) {
	return p.StubOnboardingData, nil
}

// ReportProgress sends the contents of the report-progress message upstream for processing.
func (p Provider) ReportProgress(context.Context, *http.Request, *parser.ReportProgressRequest) error {
	return nil
}

// IssueAIKCert returns a challenge and an encryption key to be used as the
// symmetric CA Attestation Blob and asymmetric CA Contents Blob in the TPM
// ActivateIdentity TSS API on the device.
func (p Provider) IssueAIKCert(context.Context, *tepb.IssueAikCertRequest) (*tepb.IssueAikCertResponse, error) {
	return p.StubIssueAIKCertResponse, nil
}

// VerifyAttestationCredential returns the attestation identity key cert.
func (p Provider) VerifyAttestationCredential(context.Context, *tepb.VerifyAttestationCredentialRequest) (*tepb.VerifyAttestationCredentialResponse, error) {
	return p.StubVerifyAttestationCredentialResponse, nil
}

// GenerateServerTLSCertificate generates a TLS cert for the bootstrap server using the trust anchor and IP.
func (Provider) GenerateServerTLSCertificate(taPrivateKey crypto.PrivateKey, taCert *x509.Certificate, ip net.IP) (*tls.Certificate, error) {
	tlsPrivateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, fmt.Errorf("generating TLS RSA key: %w", err)
	}

	// Calculate the Subject Key Identifier.
	pubKeyBytes := x509.MarshalPKCS1PublicKey(&tlsPrivateKey.PublicKey)
	keyHash := sha256.Sum256(pubKeyBytes)

	template := x509.Certificate{
		SerialNumber: big.NewInt(int64(time.Now().Year())),
		Subject: pkix.Name{
			Organization: []string{"Google Global Networking"},
			Country:      []string{"US"},
			Province:     []string{"CA"},
			Locality:     []string{"Mountain View"},
			CommonName:   "Bootstrap Server TLS Certificate",
		},
		IPAddresses:    []net.IP{ip},
		NotBefore:      time.Now(),
		NotAfter:       time.Now().AddDate(11, 0, 0),
		SubjectKeyId:   keyHash[:],
		AuthorityKeyId: taCert.SubjectKeyId,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:       x509.KeyUsageDigitalSignature,
	}

	tlsCertBytesAsDER, err := x509.CreateCertificate(rand.Reader, &template, taCert, &tlsPrivateKey.PublicKey, taPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("creating TLS certificate %w", err)
	}
	return &tls.Certificate{
		PrivateKey:  tlsPrivateKey,
		Certificate: [][]byte{tlsCertBytesAsDER},
	}, nil
}

func zoneToInt(zone string) int {
	if zone == "" {
		return 0
	}
	if ifi, err := net.InterfaceByName(zone); err == nil {
		return ifi.Index
	}
	numericalZone := 0
	isNegative := false
	if len(zone) > 0 && zone[0] == '-' {
		isNegative = true
		zone = zone[1:]
	}
	clampThreshold := 0xFFFFFF
	var i int
	for i = 0; i < len(zone) && '0' <= zone[i] && zone[i] <= '9'; i++ {
		numericalZone = numericalZone*10 + int(zone[i]-'0')
		if numericalZone >= clampThreshold {
			if isNegative {
				return -clampThreshold
			}
			return clampThreshold
		}
	}
	if i == 0 {
		return 0
	}
	if isNegative {
		return -numericalZone
	}
	return numericalZone
}

// CreateSocket creates a socket for the bootstrap server to listen on.
// This implementation is the same as net.ListenTCP except it uses an AF_INET6 socket and
// accepts both IPv4 and IPv6 connections when listening on IP_ADDRANY or IPV6_ADDRANY address.
func (p Provider) CreateSocket(laddr string) (l net.Listener, err error) {
	// Address could be in any of a number of different form and
	// it has to be resolved to an IP address + port + zone (scope).
	addr, err := net.ResolveTCPAddr("tcp", laddr)
	if err != nil {
		return nil, fmt.Errorf("listen (Resolve): %w", err)
	}

	// Edge conditions which will allow us to correctly listen for IPV6_ADDRANY
	// even if IPv4 0.0.0.0 was specified or no host part at all (i.e. ":80").
	if len(addr.IP) == 0 {
		addr.IP = net.IPv6zero
	}
	if addr.IP.Equal(net.IPv4zero) {
		addr.IP = net.IPv6zero
	}

	// Covert IP address to IPv6 address as the socket will always be AF_INET6.
	ip := addr.IP.To16()
	if ip == nil {
		return nil, fmt.Errorf("listen: non-IPv6 address: %s", addr.IP.String())
	}

	// Create socket using same flags as used by Go net package.
	sock, err := unix.Socket(
		unix.AF_INET6,
		unix.SOCK_STREAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC,
		unix.IPPROTO_TCP)
	if err != nil {
		return nil, fmt.Errorf("listen: error creating socket: %w", err)
	}

	// Socket "s" must be closed if it was created but wasn't yet wrapped in os.File.
	defer func() {
		// Operating system could use sock == 0. However, it is not supposed to use
		// negative numbers.
		if sock < 0 {
			return
		}
		// Close the socket.
		closeErr := unix.Close(sock)
		if closeErr == nil {
			return
		}
		if err == nil {
			err = fmt.Errorf("listen: close raw socket: %w", closeErr)
			// Since the function will return an error, l must be set to nil to prevent
			// handle leaks. Setting it to nil will ensure that garbage collector will
			// clean it up sooner, rather than later or never.
			l = nil
			return
		}
		p.LogWarningf("listen: error closing raw socket: %s", closeErr)
	}()

	if err := syscall.SetsockoptInt(sock, syscall.SOL_IPV6, syscall.IPV6_V6ONLY, 0); err != nil {
		p.LogWarningf("CreateSocket: Unable to force Dualstack on listening socket: %v", err)
	}

	if err := unix.SetsockoptInt(sock, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
		p.LogWarningf("CreateSocket: Unable to set SOL_SOCKET on listening socket: %v", err)
	}

	// Bind the socket to the specified address.
	sockAddr := new(unix.SockaddrInet6)
	for i := 0; i < net.IPv6len; i++ {
		sockAddr.Addr[i] = addr.IP[i]
	}
	sockAddr.Port = addr.Port
	sockAddr.ZoneId = uint32(zoneToInt(addr.Zone))

	if err := unix.Bind(sock, sockAddr); err != nil {
		return nil, fmt.Errorf("listen (Bind) sockAddr (%#v): %w", sockAddr, err)
	}

	// Mark socket as passive - listening for incoming connections.
	if err := unix.Listen(sock, unix.SOMAXCONN); err != nil {
		return nil, fmt.Errorf("listen (Listen): %w", err)
	}

	// Wrap socket in a TCPListener which will be returned to the caller.
	f := os.NewFile(uintptr(sock), fmt.Sprintf("socket:%d", sock))
	sock = -1 // os.File instance in f now owns sock, prevent deferred close from closing the managed resource.
	defer func() {
		closeErr := f.Close()
		if closeErr == nil {
			return
		}
		if err == nil {
			err = fmt.Errorf("listen: error closing file wrapper: %w", closeErr)
			l = nil // See the previous deferred func for explanation of this assignment.
			return
		}
		p.LogWarningf("ListenTCP: error closing file wrapper around socket: %s", closeErr)
	}()

	generic, err := net.FileListener(f)
	if err != nil {
		return nil, fmt.Errorf("listen: FileListener() error: %w", err)
	}

	l, ok := generic.(*net.TCPListener)
	if !ok {
		return nil, fmt.Errorf("listen: not a TCP listener: %#v", generic)
	}
	return l, nil
}

var (
	infoLogger    = log.New(os.Stderr, "INFO", log.LstdFlags|log.Llongfile)
	warningLogger = log.New(os.Stderr, "WARNING", log.LstdFlags|log.Llongfile)
	errorLogger   = log.New(os.Stderr, "ERROR", log.LstdFlags|log.Llongfile)
)

// LogInfof logs a message at INFO severity. Arguments are handled in the manner of fmt.Printf.
func (Provider) LogInfof(format string, v ...any) {
	infoLogger.Printf(format, v...)
}

// LogWarningf logs a message at WARNING severity. Arguments are handled in the manner of fmt.Printf.
func (Provider) LogWarningf(format string, v ...any) {
	warningLogger.Printf(format, v...)
}

// LogErrorf logs a message at ERROR severity. Arguments are handled in the manner of fmt.Printf.
func (Provider) LogErrorf(format string, v ...any) {
	errorLogger.Printf(format, v...)
}

// ErrorLogger returns a logger that writes messages at ERROR severity.
func (Provider) ErrorLogger() *log.Logger {
	return errorLogger
}
