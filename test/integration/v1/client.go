// Copyright (c) 2020 by Farsight Security, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package v1

import (
	"log"
	"net/url"
	"os"

	v1 "github.com/dnsdb/go-dnsdb/pkg/dnsdb/v1"
	"github.com/dnsdb/go-dnsdb/test/integration"
)

func client() *v1.Client {
	server := v1.DefaultDnsdbServer
	if os.Getenv("SERVER") != "" {
		var err error
		server, err = url.Parse(os.Getenv("SERVER"))
		if err != nil {
			log.Fatalf("url parse error: %s", err)
		}
	}

	return &v1.Client{
		HttpClient: integration.HttpClient(),
		Server:     server,
		Apikey:     os.Getenv("APIKEY"),
		ClientId:   "integration-test",
	}
}
