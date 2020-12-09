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

package dnsdb

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"

	. "github.com/onsi/gomega"
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

func TestHttpQuery_Do(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		g := NewWithT(t)

		ctx, cancel := context.WithTimeout(context.TODO(), time.Second)
		defer cancel()

		remaining := 100

		header := make(http.Header)
		header.Add("X-RateLimit-Remaining", fmt.Sprintf("%d", remaining))

		name := "test"

		u := &url.URL{Scheme: "https", Host: "api.dnsdb.info", Path: "/lookup/rrset"}
		headers := make(http.Header)
		headers.Add("Test", "value")
		var resultCalled bool
		resultFunc := func(ctx context.Context, req *http.Request) Result {
			resultCalled = true
			return nil
		}

		q := NewHttpRRSetQuery(name, u, headers, resultFunc).(*httpQuery)

		q.Do(ctx)

		g.Expect(resultCalled).Should(BeTrue(), "result function was called")
	})
}

func TestNewHttpRRSetQuery(t *testing.T) {
	g := NewWithT(t)

	name := "test"
	u := &url.URL{Scheme: "https", Host: "api.dnsdb.info", Path: "/lookup/rrset"}
	headers := make(http.Header)
	headers.Add("Test", "value")
	resultFunc := func(ctx context.Context, req *http.Request) Result { return nil }

	q := NewHttpRRSetQuery(name, u, headers, resultFunc).(*httpQuery)

	g.Expect(q.mode).Should(Equal(modeRRSet))
	g.Expect(q.url).Should(Equal(u))
	g.Expect(q.headers).Should(Equal(headers))
	g.Expect(q.result).ShouldNot(BeZero())
	g.Expect(q.name).Should(Equal(name))
}

func TestNewHttpRDataNameQuery(t *testing.T) {
	g := NewWithT(t)

	name := "test"
	u := &url.URL{Scheme: "https", Host: "api.dnsdb.info", Path: "/lookup/rrset"}
	headers := make(http.Header)
	headers.Add("Test", "value")
	resultFunc := func(ctx context.Context, req *http.Request) Result { return nil }

	q := NewHttpRDataNameQuery(name, u, headers, resultFunc).(*httpQuery)

	g.Expect(q.mode).Should(Equal(modeRDataName))
	g.Expect(q.url).Should(Equal(u))
	g.Expect(q.headers).Should(Equal(headers))
	g.Expect(q.result).ShouldNot(BeZero())
	g.Expect(q.name).Should(Equal(name))
}

func TestNewHttpRDataIPQuery(t *testing.T) {
	g := NewWithT(t)

	_, ip, err := net.ParseCIDR("192.168.0.0/16")
	g.Expect(err).ShouldNot(HaveOccurred())
	u := &url.URL{Scheme: "https", Host: "api.dnsdb.info", Path: "/lookup/rrset"}
	headers := make(http.Header)
	headers.Add("Test", "value")
	resultFunc := func(ctx context.Context, req *http.Request) Result { return nil }

	q := NewHttpRDataIPQuery(*ip, u, headers, resultFunc).(*httpQuery)

	g.Expect(q.mode).Should(Equal(modeRDataIP))
	g.Expect(q.url).Should(Equal(u))
	g.Expect(q.headers).Should(Equal(headers))
	g.Expect(q.result).ShouldNot(BeZero())
	g.Expect(q.ip).Should(Equal(*ip))
}

func TestNewHttpRDataIPRangeQuery(t *testing.T) {
	g := NewWithT(t)

	lower := net.ParseIP("192.168.0.1")
	upper := net.ParseIP("192.168.0.5")
	ipRange := &ipRange{lower, upper}
	u := &url.URL{Scheme: "https", Host: "api.dnsdb.info", Path: "/lookup/rrset"}
	headers := make(http.Header)
	headers.Add("Test", "value")
	resultFunc := func(ctx context.Context, req *http.Request) Result { return nil }

	q := NewHttpRDataIPRangeQuery(lower, upper, u, headers, resultFunc).(*httpQuery)

	g.Expect(q.mode).Should(Equal(modeRDataIPRange))
	g.Expect(q.url).Should(Equal(u))
	g.Expect(q.headers).Should(Equal(headers))
	g.Expect(q.result).ShouldNot(BeZero())
	g.Expect(q.ipRange).Should(Equal(ipRange))
}

func TestNewHttpRDataRawQuery(t *testing.T) {
	g := NewWithT(t)

	raw := []byte("test")
	u := &url.URL{Scheme: "https", Host: "api.dnsdb.info", Path: "/lookup/rrset"}
	headers := make(http.Header)
	headers.Add("Test", "value")
	resultFunc := func(ctx context.Context, req *http.Request) Result { return nil }

	q := NewHttpRDataRawQuery(raw, u, headers, resultFunc).(*httpQuery)

	g.Expect(q.mode).Should(Equal(modeRDataRaw))
	g.Expect(q.url).Should(Equal(u))
	g.Expect(q.headers).Should(Equal(headers))
	g.Expect(q.result).ShouldNot(BeZero())
	g.Expect(q.raw).Should(Equal(raw))
}

func TestQueryMutators(t *testing.T) {
	f := func(t *testing.T) {
		g := NewWithT(t)
		q := &httpQuery{}
		rrtype := "A"
		q2 := q.WithRRType(rrtype).(*httpQuery)
		g.Expect(q2).ShouldNot(Equal(q))
		g.Expect(q.rrtype).Should(BeNil())
		g.Expect(*q2.rrtype).Should(Equal(rrtype))
	}
	t.Run("rrtype", f)

	t.Run("bailiwick", func(t *testing.T) {
		g := NewWithT(t)
		q := &httpQuery{}
		bailiwick := "A"
		q2 := q.WithBailiwick(bailiwick).(*httpQuery)
		g.Expect(q2).ShouldNot(Equal(q))
		g.Expect(q.bailiwick).Should(BeNil())
		g.Expect(*q2.bailiwick).Should(Equal(bailiwick))
	})

	t.Run("limit", func(t *testing.T) {
		g := NewWithT(t)
		q := &httpQuery{}
		limit := 123
		q2 := q.WithLimit(limit).(*httpQuery)
		g.Expect(q2).ShouldNot(Equal(q))
		g.Expect(q.limit).Should(BeNil())
		g.Expect(*q2.limit).Should(Equal(limit))
	})

	t.Run("aggregation", func(t *testing.T) {
		g := NewWithT(t)
		q := &httpQuery{}
		q2 := q.WithAggregation(false).(*httpQuery)
		g.Expect(q2).ShouldNot(Equal(q))
		g.Expect(q.aggregation).Should(BeNil())
		g.Expect(*q2.aggregation).Should(BeFalse())
	})

	t.Run("offset", func(t *testing.T) {
		g := NewWithT(t)
		q := &httpQuery{}
		offset := 123
		q2 := q.WithOffset(offset).(*httpQuery)
		g.Expect(q2).ShouldNot(Equal(q))
		g.Expect(q.offset).Should(BeNil())
		g.Expect(*q2.offset).Should(Equal(offset))
	})

	t.Run("maxcount", func(t *testing.T) {
		g := NewWithT(t)
		q := &httpQuery{}
		maxCount := 123
		q2 := q.WithMaxCount(maxCount).(*httpQuery)
		g.Expect(q2).ShouldNot(Equal(q))
		g.Expect(q.maxCount).Should(BeNil())
		g.Expect(*q2.maxCount).Should(Equal(maxCount))
	})

	t.Run("timeFirstBefore", func(t *testing.T) {
		g := NewWithT(t)
		q := &httpQuery{}
		sec := int64(12345)
		when := time.Unix(sec, 6789)
		q2 := q.WithTimeFirstBefore(when).(*httpQuery)
		g.Expect(q2).ShouldNot(Equal(q))
		g.Expect(q.timeFirstBefore).Should(BeNil())
		g.Expect(*q2.timeFirstBefore).Should(BeNumerically("==", sec))
	})

	t.Run("timeFirstAfter", func(t *testing.T) {
		g := NewWithT(t)
		q := &httpQuery{}
		sec := int64(12345)
		when := time.Unix(sec, 6789)
		q2 := q.WithTimeFirstAfter(when).(*httpQuery)
		g.Expect(q2).ShouldNot(Equal(q))
		g.Expect(q.timeFirstAfter).Should(BeNil())
		g.Expect(*q2.timeFirstAfter).Should(BeNumerically("==", sec))
	})

	t.Run("timeLastBefore", func(t *testing.T) {
		g := NewWithT(t)
		q := &httpQuery{}
		sec := int64(12345)
		when := time.Unix(sec, 6789)
		q2 := q.WithTimeLastBefore(when).(*httpQuery)
		g.Expect(q2).ShouldNot(Equal(q))
		g.Expect(q.timeLastBefore).Should(BeNil())
		g.Expect(*q2.timeLastBefore).Should(BeNumerically("==", sec))
	})

	t.Run("timeLastAfter", func(t *testing.T) {
		g := NewWithT(t)
		q := &httpQuery{}
		sec := int64(12345)
		when := time.Unix(sec, 6789)
		q2 := q.WithTimeLastAfter(when).(*httpQuery)
		g.Expect(q2).ShouldNot(Equal(q))
		g.Expect(q.timeLastAfter).Should(BeNil())
		g.Expect(*q2.timeLastAfter).Should(BeNumerically("==", sec))
	})

	t.Run("relativeTimeFirstBefore", func(t *testing.T) {
		g := NewWithT(t)
		q := &httpQuery{}
		sec := 12345
		when := time.Second * time.Duration(sec)
		q2 := q.WithRelativeTimeFirstBefore(when).(*httpQuery)
		g.Expect(q2).ShouldNot(Equal(q))
		g.Expect(q.timeFirstBefore).Should(BeNil())
		g.Expect(*q2.timeFirstBefore).Should(BeNumerically("==", -sec))
	})

	t.Run("relativeTimeFirstAfter", func(t *testing.T) {
		g := NewWithT(t)
		q := &httpQuery{}
		sec := 12345
		when := time.Second * time.Duration(sec)
		q2 := q.WithRelativeTimeFirstAfter(when).(*httpQuery)
		g.Expect(q2).ShouldNot(Equal(q))
		g.Expect(q.timeFirstAfter).Should(BeNil())
		g.Expect(*q2.timeFirstAfter).Should(BeNumerically("==", -sec))
	})

	t.Run("relativeTimeLastBefore", func(t *testing.T) {
		g := NewWithT(t)
		q := &httpQuery{}
		sec := 12345
		when := time.Second * time.Duration(sec)
		q2 := q.WithRelativeTimeLastBefore(when).(*httpQuery)
		g.Expect(q2).ShouldNot(Equal(q))
		g.Expect(q.timeLastBefore).Should(BeNil())
		g.Expect(*q2.timeLastBefore).Should(BeNumerically("==", -sec))
	})

	t.Run("relativeTimeLastAfter", func(t *testing.T) {
		g := NewWithT(t)
		q := &httpQuery{}
		sec := 12345
		when := time.Second * time.Duration(sec)
		q2 := q.WithRelativeTimeLastAfter(when).(*httpQuery)
		g.Expect(q2).ShouldNot(Equal(q))
		g.Expect(q.timeLastAfter).Should(BeNil())
		g.Expect(*q2.timeLastAfter).Should(BeNumerically("==", -sec))
	})

	t.Run("relativeTime* panics on negative duration", func(t *testing.T) {
		g := NewWithT(t)
		q := &httpQuery{}
		g.Expect(func() { q.WithRelativeTimeFirstBefore(-1) }).Should(Panic())
		g.Expect(func() { q.WithRelativeTimeFirstAfter(-1) }).Should(Panic())
		g.Expect(func() { q.WithRelativeTimeLastBefore(-1) }).Should(Panic())
		g.Expect(func() { q.WithRelativeTimeLastAfter(-1) }).Should(Panic())
	})
}

func TestQuery_MakePath(t *testing.T) {
	t.Run("rrtype", func(t *testing.T) {
		t.Run("default", func(t *testing.T) {
			g := NewWithT(t)
			q := &httpQuery{mode: modeRRSet, name: "test"}
			g.Expect(q.makePath()).Should(Equal("name/test/ANY"))
		})
		t.Run("AAAA", func(t *testing.T) {
			g := NewWithT(t)
			rrtype := "AAAA"
			q := &httpQuery{mode: modeRRSet, name: "test", rrtype: &rrtype}
			g.Expect(q.makePath()).Should(Equal("name/test/AAAA"))
		})
	})

	t.Run("rrset", func(t *testing.T) {
		t.Run("without bailiwick", func(t *testing.T) {
			g := NewWithT(t)
			q := &httpQuery{mode: modeRRSet, name: "test"}
			g.Expect(q.makePath()).Should(Equal("name/test/ANY"))
		})
		t.Run("with bailiwick", func(t *testing.T) {
			g := NewWithT(t)
			bailiwick := "ing"
			q := &httpQuery{mode: modeRRSet, name: "test", bailiwick: &bailiwick}
			g.Expect(q.makePath()).Should(Equal("name/test/ANY/ing"))
		})
	})

	t.Run("rdata", func(t *testing.T) {
		t.Run("name", func(t *testing.T) {
			g := NewWithT(t)
			q := &httpQuery{mode: modeRDataName, name: "test"}
			g.Expect(q.makePath()).Should(Equal("name/test/ANY"))
		})
		t.Run("ip", func(t *testing.T) {
			t.Run("v4", func(t *testing.T) {
				g := NewWithT(t)
				_, ip, err := net.ParseCIDR("192.168.0.1/32")
				g.Expect(err).ShouldNot(HaveOccurred())
				q := &httpQuery{mode: modeRDataIP, ip: *ip}
				g.Expect(q.makePath()).Should(Equal("ip/192.168.0.1/ANY"))
			})
			t.Run("v4 cidr", func(t *testing.T) {
				g := NewWithT(t)
				_, ip, err := net.ParseCIDR("192.168.0.0/24")
				g.Expect(err).ShouldNot(HaveOccurred())
				q := &httpQuery{mode: modeRDataIP, ip: *ip}
				g.Expect(q.makePath()).Should(Equal("ip/192.168.0.0,24/ANY"))
			})
			t.Run("v4 range", func(t *testing.T) {
				g := NewWithT(t)
				lower := net.ParseIP("192.168.0.1")
				upper := net.ParseIP("192.168.0.5")
				q := &httpQuery{mode: modeRDataIPRange, ipRange: &ipRange{
					lower, upper,
				}}
				g.Expect(q.makePath()).Should(Equal("ip/192.168.0.1-192.168.0.5/ANY"))
			})
			t.Run("v6", func(t *testing.T) {
				g := NewWithT(t)
				_, ip, err := net.ParseCIDR("2000::1/128")
				g.Expect(err).ShouldNot(HaveOccurred())
				q := &httpQuery{mode: modeRDataIP, ip: *ip}
				g.Expect(q.makePath()).Should(Equal(fmt.Sprintf("ip/%s/ANY", url.PathEscape("2000::1"))))
			})
			t.Run("v6 cidr", func(t *testing.T) {
				g := NewWithT(t)
				_, ip, err := net.ParseCIDR("2000::/64")
				g.Expect(err).ShouldNot(HaveOccurred())
				q := &httpQuery{mode: modeRDataIP, ip: *ip}
				g.Expect(q.makePath()).Should(Equal(fmt.Sprintf("ip/%s,64/ANY", url.PathEscape("2000::"))))
			})
			t.Run("v6 range", func(t *testing.T) {
				g := NewWithT(t)
				lower := net.ParseIP("2000::1")
				upper := net.ParseIP("2000::5")
				q := &httpQuery{mode: modeRDataIPRange, ipRange: &ipRange{
					lower, upper,
				}}
				g.Expect(q.makePath()).Should(Equal(
					fmt.Sprintf("ip/%s-%s/ANY", url.PathEscape("2000::1"), url.PathEscape("2000::5")),
				))
			})
		})
		t.Run("raw", func(t *testing.T) {
			g := NewWithT(t)
			q := &httpQuery{mode: modeRDataRaw, raw: []byte("test")}
			g.Expect(q.makePath()).Should(Equal(fmt.Sprintf("raw/%s/ANY", hex.EncodeToString(q.raw))))
		})
	})

	t.Run("invalid", func(t *testing.T) {
		g := NewWithT(t)
		q := &httpQuery{mode: -1}
		g.Expect(func() { q.makePath() }).Should(Panic())
	})
}

func TestQuery_MakeValues(t *testing.T) {
	f := func(input Query, key, expected string) func(t *testing.T) {
		return func(t *testing.T) {
			g := NewWithT(t)
			v := make(url.Values)
			g.Expect(input.(*httpQuery).makeValues(v)).Should(Equal(v))
			g.Expect(v.Get(key)).Should(Equal(expected))
		}
	}
	q := func() Query {
		return &httpQuery{}
	}

	t.Run("limit", f(q().WithLimit(100), "limit", "100"))
	t.Run("aggregation", f(q().WithAggregation(false), "aggr", "false"))
	t.Run("aggregation", f(q().WithAggregation(true), "aggr", "true"))
	t.Run("offset", f(q().WithOffset(123), "offset", "123"))
	t.Run("maxCount", f(q().WithMaxCount(456), "max_count", "456"))
	t.Run("timeFirstBefore", f(q().WithRelativeTimeFirstBefore(time.Hour), "time_first_before", "-3600"))
	t.Run("timeFirstAfter", f(q().WithRelativeTimeFirstAfter(time.Hour), "time_first_after", "-3600"))
	t.Run("timeLastBefore", f(q().WithRelativeTimeLastBefore(time.Hour), "time_last_before", "-3600"))
	t.Run("timeLastAfter", f(q().WithRelativeTimeLastAfter(time.Hour), "time_last_after", "-3600"))
}
