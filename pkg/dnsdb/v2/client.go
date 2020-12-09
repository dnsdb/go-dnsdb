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

package v2

import (
	"net"
	"net/http"
	"net/url"
	"path"

	"github.com/dnsdb/go-dnsdb/pkg/dnsdb"
)

const (
	lookupRRSetPath      = "/dnsdb/v2/lookup/rrset"
	lookupRDataPath      = "/dnsdb/v2/lookup/rdata"
	summarizeRRSetPath   = "/dnsdb/v2/summarize/rrset"
	summarizeRDataPath   = "/dnsdb/v2/summarize/rdata"
	ContentType          = "application/x-ndjson"
	DefaultClientName    = "go-dnsdb"
	DefaultClientVersion = "v0.0"
	SwClientKey          = "swclient"
	VersionKey           = "version"
	IdKey                = "id"
)

var DefaultDnsdbServer *url.URL

func init() {
	var err error
	DefaultDnsdbServer, err = url.Parse("https://api.dnsdb.info")
	if err != nil {
		panic(err)
	}
}

// Client implements the DNSDB API v2
type Client struct {
	// HttpClient is an optional http.Client. `http.DefaultClient` is used if this is nil.
	HttpClient *http.Client
	// Server is an optional server URL. `DefaultDnsdbServer` is used if this is nil.
	Server *url.URL
	// Apikey is required and passed in the `X-API-Key` header to the server.
	Apikey string
	// ClientName is passed as the `swclient` URL parameter.
	ClientName string
	// ClientVersion is passed as the `version ` URL parameter.
	ClientVersion string
	// ClientId is passed as the `id` URL parameter.
	ClientId string
}

var _ dnsdb.Client = &Client{}
var _ dnsdb.SummarizeClient = &Client{}
var _ dnsdb.RateLimitClient = &Client{}
var _ dnsdb.PingClient = &Client{}

func (c *Client) getHttpClient() *http.Client {
	if c.HttpClient != nil {
		return c.HttpClient
	}
	return http.DefaultClient
}

func (c *Client) baseURL() *url.URL {
	u := new(url.URL)
	*u = *c.Server

	v := u.Query()
	if c.ClientName != "" {
		v.Add(SwClientKey, c.ClientName)
	} else {
		v.Add(SwClientKey, DefaultClientName)
	}
	if c.ClientVersion != "" {
		v.Add(VersionKey, c.ClientVersion)
	} else {
		v.Add(VersionKey, DefaultClientVersion)
	}
	if c.ClientId != "" {
		v.Add(IdKey, c.ClientId)
	}
	u.RawQuery = v.Encode()

	return u
}

func (c *Client) headers() http.Header {
	res := make(http.Header)
	res.Add("Accept", ContentType)
	res.Add("X-API-Key", c.Apikey)

	return res
}

func (c *Client) lookupRRSetURL() *url.URL {
	u := c.baseURL()
	u.Path = path.Join(u.Path, lookupRRSetPath)

	return u
}

func (c *Client) summarizeRRSetURL() *url.URL {
	u := c.baseURL()
	u.Path = path.Join(u.Path, summarizeRRSetPath)

	return u
}

func (c *Client) lookupRDataURL() *url.URL {
	u := c.baseURL()
	u.Path = path.Join(u.Path, lookupRDataPath)

	return u
}

func (c *Client) summarizeRDataURL() *url.URL {
	u := c.baseURL()
	u.Path = path.Join(u.Path, summarizeRDataPath)

	return u
}

func (c *Client) LookupRRSet(name string) dnsdb.Query {
	return dnsdb.NewHttpRRSetQuery(name, c.lookupRRSetURL(), c.headers(), c.newResult)
}

func (c *Client) SummarizeRRSet(name string) dnsdb.Query {
	return dnsdb.NewHttpRRSetQuery(name, c.summarizeRRSetURL(), c.headers(), c.newResult)
}

func (c *Client) LookupRDataName(name string) dnsdb.Query {
	return dnsdb.NewHttpRDataNameQuery(name, c.lookupRDataURL(), c.headers(), c.newResult)
}

func (c *Client) LookupRDataIP(ip net.IPNet) dnsdb.Query {
	return dnsdb.NewHttpRDataIPQuery(ip, c.lookupRDataURL(), c.headers(), c.newResult)
}

func (c *Client) LookupRDataIPRange(lower, upper net.IP) dnsdb.Query {
	return dnsdb.NewHttpRDataIPRangeQuery(lower, upper, c.lookupRDataURL(), c.headers(), c.newResult)
}

func (c *Client) LookupRDataRaw(raw []byte) dnsdb.Query {
	return dnsdb.NewHttpRDataRawQuery(raw, c.lookupRDataURL(), c.headers(), c.newResult)
}

func (c *Client) SummarizeRDataName(name string) dnsdb.Query {
	return dnsdb.NewHttpRDataNameQuery(name, c.summarizeRDataURL(), c.headers(), c.newResult)
}

func (c *Client) SummarizeRDataIP(ip net.IPNet) dnsdb.Query {
	return dnsdb.NewHttpRDataIPQuery(ip, c.summarizeRDataURL(), c.headers(), c.newResult)
}

func (c *Client) SummarizeRDataIPRange(lower, upper net.IP) dnsdb.Query {
	return dnsdb.NewHttpRDataIPRangeQuery(lower, upper, c.summarizeRDataURL(), c.headers(), c.newResult)
}

func (c *Client) SummarizeRDataRaw(raw []byte) dnsdb.Query {
	return dnsdb.NewHttpRDataRawQuery(raw, c.summarizeRDataURL(), c.headers(), c.newResult)
}
