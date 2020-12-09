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
	"context"
	"fmt"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/dnsdb/go-dnsdb/pkg/dnsdb/flex"

	. "github.com/onsi/gomega"
)

func TestFlexUrl(t *testing.T) {
	g := NewWithT(t)

	client := &Client{
		Server: &url.URL{
			Scheme: "https",
			Host:   "api.dnsdb.info",
			Path:   "/test",
		},
	}

	u := client.flexURL()

	g.Expect(u.Path).Should(HavePrefix(client.Server.Path))
	g.Expect(u.Path).Should(HaveSuffix(flexPath))
	g.Expect(u.RawQuery).ShouldNot(BeEmpty())
}

func TestFlexSearch(t *testing.T) {
	f := func(method flex.Method, key flex.Key, value string, rrtype *string, verbosity bool) func(t *testing.T) {
		return func(t *testing.T) {
			g := NewWithT(t)

			ctx, cancel := context.WithTimeout(context.TODO(), time.Second)
			defer cancel()

			client, rt := newTestClient()

			q := client.Search(method, key, value)
			if rrtype != nil {
				q = q.WithRRType(*rrtype)
			}
			q.Do(ctx)

			g.Eventually(func() *http.Request { return rt.request }).ShouldNot(BeNil())
			g.Expect(rt.request.URL.Path).Should(HavePrefix(client.Server.Path))
			g.Expect(rt.request.URL.Path).Should(ContainSubstring(method.String()))
			g.Expect(rt.request.URL.Path).Should(ContainSubstring(key.String()))
			g.Expect(rt.request.URL.Path).Should(ContainSubstring(url.PathEscape(value)))
			if rrtype != nil {
				g.Expect(rt.request.URL.Path).Should(ContainSubstring(url.PathEscape(*rrtype)))
			}
			testRequestHeaderContents(g, rt.request.Header)
		}
	}

	value := "foo*"
	for _, method := range []flex.Method{flex.MethodRegex, flex.MethodGlob} {
		for _, key := range []flex.Key{flex.KeyRRNames, flex.KeyRData} {
			for _, rrtype := range []*string{nil, strPtr("aa aa")} {
				for _, verbosity := range []bool{false, true} {
					name := fmt.Sprintf("%s/%s/%s", method, key, value)
					if rrtype != nil {
						name += fmt.Sprintf("/%s", *rrtype)
					}
					t.Run(name, f(method, key, value, rrtype, verbosity))
				}
			}
		}
	}
}

func strPtr(s string) *string {
	r := new(string)
	*r = s
	return r
}
