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
	"context"
	"encoding/hex"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"path"
	"strings"
	"testing"
	"time"

	. "github.com/onsi/gomega"
)

var (
	testApikey = "123456789"
	testURL    = &url.URL{
		Scheme: "https",
		Host:   "api.dnsdb.info",
		Path:   "/test",
	}
)

type testRoundTripper struct {
	request  *http.Request
	response *http.Response
	err      error
}

func (t *testRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	t.request = request
	return t.response, t.err
}

func newTestClient() (*Client, *testRoundTripper) {
	rt := &testRoundTripper{
		response: &http.Response{
			StatusCode: http.StatusOK,
			Body:       ioutil.NopCloser(strings.NewReader("")),
		},
	}
	client := &Client{
		HttpClient: &http.Client{Transport: rt},
		Server:     testURL,
		Apikey:     testApikey,
	}

	return client, rt
}

func testRequestHeaderContents(g Gomega, h http.Header) {
	g.Expect(h.Get("X-API-Key")).Should(Equal(testApikey))
	g.Expect(h.Get("Accept")).Should(Equal(ContentType))
}

func TestClient_LookupRRSet(t *testing.T) {
	g := NewWithT(t)

	ctx, cancel := context.WithTimeout(context.TODO(), time.Second)
	defer cancel()

	client, rt := newTestClient()

	name := "dnsdb.info"
	q := client.LookupRRSet(name)
	q.Do(ctx)

	g.Eventually(func() *http.Request { return rt.request }).ShouldNot(BeNil())
	g.Expect(rt.request.URL.Path).Should(Equal(path.Join(testURL.Path, lookupRRSetPath, "name", name, "ANY")))
	testRequestHeaderContents(g, rt.request.Header)
}

func TestClient_LookupRDataName(t *testing.T) {
	g := NewWithT(t)

	ctx, cancel := context.WithTimeout(context.TODO(), time.Second)
	defer cancel()

	client, rt := newTestClient()

	name := "dnsdb.info"
	q := client.LookupRDataName(name)
	q.Do(ctx)

	g.Eventually(func() *http.Request { return rt.request }).ShouldNot(BeNil())
	g.Expect(rt.request.URL.Path).Should(Equal(path.Join(testURL.Path, lookupRDataPath, "name", name, "ANY")))
	testRequestHeaderContents(g, rt.request.Header)
}

func TestClient_LookupRDataIP(t *testing.T) {
	g := NewWithT(t)

	ctx, cancel := context.WithTimeout(context.TODO(), time.Second)
	defer cancel()

	client, rt := newTestClient()

	_, cidr, err := net.ParseCIDR("192.168.0.0/16")
	g.Expect(err).ShouldNot(HaveOccurred())

	q := client.LookupRDataIP(*cidr)
	q.Do(ctx)

	g.Eventually(func() *http.Request { return rt.request }).ShouldNot(BeNil())
	g.Expect(rt.request.URL.Path).Should(Equal(path.Join(testURL.Path, lookupRDataPath, "ip", "192.168.0.0,16", "ANY")))
	testRequestHeaderContents(g, rt.request.Header)
}

func TestClient_LookupRDataIPRange(t *testing.T) {
	g := NewWithT(t)

	ctx, cancel := context.WithTimeout(context.TODO(), time.Second)
	defer cancel()

	client, rt := newTestClient()

	lower := net.ParseIP("192.168.0.1")
	upper := net.ParseIP("192.168.0.5")

	q := client.LookupRDataIPRange(lower, upper)
	q.Do(ctx)

	g.Eventually(func() *http.Request { return rt.request }).ShouldNot(BeNil())
	g.Expect(rt.request.URL.Path).Should(Equal(path.Join(testURL.Path, lookupRDataPath, "ip", "192.168.0.1-192.168.0.5", "ANY")))
	testRequestHeaderContents(g, rt.request.Header)
}

func TestClient_LookupRDataRaw(t *testing.T) {
	g := NewWithT(t)

	ctx, cancel := context.WithTimeout(context.TODO(), time.Second)
	defer cancel()

	client, rt := newTestClient()

	raw := []byte("dnsdb.info.")
	q := client.LookupRDataRaw(raw)
	q.Do(ctx)

	g.Eventually(func() *http.Request { return rt.request }).ShouldNot(BeNil())
	g.Expect(rt.request.URL.Path).Should(Equal(path.Join(testURL.Path, lookupRDataPath, "raw", hex.EncodeToString(raw), "ANY")))
	testRequestHeaderContents(g, rt.request.Header)
}

func TestClient_SummarizeRRSet(t *testing.T) {
	g := NewWithT(t)

	ctx, cancel := context.WithTimeout(context.TODO(), time.Second)
	defer cancel()

	client, rt := newTestClient()

	name := "dnsdb.info"
	q := client.SummarizeRRSet(name)
	q.Do(ctx)

	g.Eventually(func() *http.Request { return rt.request }).ShouldNot(BeNil())
	g.Expect(rt.request.URL.Path).Should(Equal(path.Join(testURL.Path, summarizeRRSetPath, "name", name, "ANY")))
	testRequestHeaderContents(g, rt.request.Header)
}

func TestClient_SummarizeRDataName(t *testing.T) {
	g := NewWithT(t)

	ctx, cancel := context.WithTimeout(context.TODO(), time.Second)
	defer cancel()

	client, rt := newTestClient()

	name := "dnsdb.info"
	q := client.SummarizeRDataName(name)
	q.Do(ctx)

	g.Eventually(func() *http.Request { return rt.request }).ShouldNot(BeNil())
	g.Expect(rt.request.URL.Path).Should(Equal(path.Join(testURL.Path, summarizeRDataPath, "name", name, "ANY")))
	testRequestHeaderContents(g, rt.request.Header)
}

func TestClient_SummarizeRDataIP(t *testing.T) {
	g := NewWithT(t)

	ctx, cancel := context.WithTimeout(context.TODO(), time.Second)
	defer cancel()

	client, rt := newTestClient()

	_, cidr, err := net.ParseCIDR("192.168.0.0/16")
	g.Expect(err).ShouldNot(HaveOccurred())

	q := client.SummarizeRDataIP(*cidr)
	q.Do(ctx)

	g.Eventually(func() *http.Request { return rt.request }).ShouldNot(BeNil())
	g.Expect(rt.request.URL.Path).Should(Equal(path.Join(testURL.Path, summarizeRDataPath, "ip", "192.168.0.0,16", "ANY")))
	testRequestHeaderContents(g, rt.request.Header)
}

func TestClient_SummarizeRDataIPRange(t *testing.T) {
	g := NewWithT(t)

	ctx, cancel := context.WithTimeout(context.TODO(), time.Second)
	defer cancel()

	client, rt := newTestClient()

	lower := net.ParseIP("192.168.0.1")
	upper := net.ParseIP("192.168.0.5")

	q := client.SummarizeRDataIPRange(lower, upper)
	q.Do(ctx)

	g.Eventually(func() *http.Request { return rt.request }).ShouldNot(BeNil())
	g.Expect(rt.request.URL.Path).Should(Equal(path.Join(testURL.Path, summarizeRDataPath, "ip", "192.168.0.1-192.168.0.5", "ANY")))
	testRequestHeaderContents(g, rt.request.Header)
}

func TestClient_SummarizeRDataRaw(t *testing.T) {
	g := NewWithT(t)

	ctx, cancel := context.WithTimeout(context.TODO(), time.Second)
	defer cancel()

	client, rt := newTestClient()

	raw := []byte("dnsdb.info.")
	q := client.SummarizeRDataRaw(raw)
	q.Do(ctx)

	g.Eventually(func() *http.Request { return rt.request }).ShouldNot(BeNil())
	g.Expect(rt.request.URL.Path).Should(Equal(path.Join(testURL.Path, summarizeRDataPath, "raw", hex.EncodeToString(raw), "ANY")))
	testRequestHeaderContents(g, rt.request.Header)
}

func TestHeaders(t *testing.T) {
	g := NewWithT(t)

	client := &Client{
		Apikey: testApikey,
	}

	h := client.headers()
	g.Expect(h.Get("X-API-Key")).Should(Equal(testApikey))
	g.Expect(h.Get("Accept")).Should(Equal(ContentType))
}

func TestBaseURL(t *testing.T) {
	t.Run("default", func(t *testing.T) {
		g := NewWithT(t)

		client := &Client{}

		h := client.baseURL()

		g.Expect(h.Path).Should(Equal(""))
		g.Expect(h.Host).Should(Equal(DefaultDnsdbServer.Host))

		v := h.Query()
		g.Expect(v.Get(SwClientKey)).Should(Equal(DefaultClientName))
		g.Expect(v.Get(VersionKey)).Should(Equal(DefaultClientVersion))
		g.Expect(v.Get(IdKey)).Should(BeEmpty())
	})

	t.Run("custom", func(t *testing.T) {
		g := NewWithT(t)

		clientName := "testClient"
		clientVersion := "v1.2.3.4test1"
		clientId := "test-abc-def"
		client := &Client{
			Server: &url.URL{
				Scheme: "https",
				Host:   "api.dnsdb.info",
				Path:   "/test",
			},
			ClientName:    clientName,
			ClientVersion: clientVersion,
			ClientId:      clientId,
		}

		h := client.baseURL()

		g.Expect(h.Path).Should(Equal(client.Server.Path))

		v := h.Query()
		g.Expect(v.Get(SwClientKey)).Should(Equal(clientName))
		g.Expect(v.Get(VersionKey)).Should(Equal(clientVersion))
		g.Expect(v.Get(IdKey)).Should(Equal(clientId))
	})
}
