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

	"github.com/google/open_sztp/server"
	"github.com/google/open_sztp/util/data"
	"github.com/google/open_sztp/util/stubdependencies"
)

func main() {
	servingIP := flag.String("ip", "::1", "IP address that this server should listen on (default: ::1)")
	servingPort := flag.Int("port", 12345, "Port that this server should listen on (default: 12345)")
	serialNumberHeader := flag.String("serial_number_header", "X-Mac", "HTTP header that the MAC address should be parsed from (default: X-Mac)")
	dataDirectory := flag.String("data_directory", "_main/data", "Directory that contains the data dependencies for the sZTP server. The provided directory must contain subdirectories named by MAC address containing the data for that device. (default: data)")
	flag.Parse()
	if *servingIP == "" {
		log.Fatalf("--ip flag must be provided")
	}
	if *servingPort == 0 {
		log.Fatalf("--port flag must be provided")
	}
	if *serialNumberHeader == "" {
		log.Fatalf("--serial_number_header flag must be provided")
	}
	if *dataDirectory == "" {
		log.Fatalf("--data_directory flag must be provided")
	}

	ctx := context.Background()
	bootstrapServer, listener, err := server.New(ctx, server.Params{
		EnableTPMEnrollment:   true,
		ListenOnAllInterfaces: true,
		DependencyProvider: &stubdependencies.Provider{
			SerialNumberHeader: *serialNumberHeader,
			StubRedirectIP:     *servingIP,
			StubRedirectPort:   *servingPort,
			DataReader: data.Reader{
				ParentDir: *dataDirectory,
			},
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
