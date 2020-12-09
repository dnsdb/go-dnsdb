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

package integration

import (
	"net"
	"testing"

	. "github.com/onsi/gomega"

	"github.com/dnsdb/go-dnsdb/pkg/dnsdb"
)

func SummarizeRRSet(t *testing.T, c dnsdb.SummarizeClient) {
	name := "farsightsecurity.com."
	qf := func() dnsdb.Query { return c.SummarizeRRSet(name) }
	bailiwick := "com."
	rrtype := "NS"

	t.Run("no arguments", executeQuery(qf(), checkSummarizeFields))
	t.Run("bailiwick", executeQuery(qf().WithBailiwick(bailiwick), checkSummarizeFields))
	t.Run("bailiwick and rrtype", executeQuery(
		qf().WithBailiwick(bailiwick).WithRRType(rrtype),
		checkSummarizeFields,
	))

	testSummarizeOptions(t, qf, "NS")
}

func SummarizeRDataName(t *testing.T, c dnsdb.SummarizeClient) {
	name := "ns5.dnsmadeeasy.com."
	qf := func() dnsdb.Query { return c.SummarizeRDataName(name) }

	t.Run("no arguments", executeQuery(qf(), checkSummarizeFields))

	testSummarizeOptions(t, qf, "NS")
}

func SummarizeRDataIP(t *testing.T, c dnsdb.SummarizeClient) {
	ip := net.ParseIP("104.244.13.104")
	cidr := net.IPNet{IP: ip}
	qf := func() dnsdb.Query { return c.SummarizeRDataIP(cidr) }

	t.Run("no arguments", executeQuery(qf(), checkSummarizeFields))

	testSummarizeOptions(t, qf, "A")
}

func SummarizeRDataCIDR(t *testing.T, c dnsdb.SummarizeClient) {
	g := NewWithT(t)

	_, cidr, err := net.ParseCIDR("104.244.13.104/29")
	g.Expect(err).ShouldNot(HaveOccurred())
	qf := func() dnsdb.Query { return c.SummarizeRDataIP(*cidr) }

	t.Run("no arguments", executeQuery(qf(), checkSummarizeFields))

	testSummarizeOptions(t, qf, "A")
}

func SummarizeRDataIPRange(t *testing.T, c dnsdb.SummarizeClient) {
	lower := net.ParseIP("104.244.13.104")
	upper := net.ParseIP("104.244.13.111")
	qf := func() dnsdb.Query { return c.SummarizeRDataIPRange(lower, upper) }

	t.Run("no arguments", executeQuery(qf(), checkSummarizeFields))

	testSummarizeOptions(t, qf, "A")
}

func SummarizeRDataRaw(t *testing.T, c dnsdb.SummarizeClient) {
	raw := []byte("\x03ns5\x0bdnsmadeeasy\x03com\x00")
	qf := func() dnsdb.Query { return c.SummarizeRDataRaw(raw) }

	t.Run("no arguments", executeQuery(qf(), checkSummarizeFields))

	testSummarizeOptions(t, qf, "A")
}

func checkSummarizeFields(g Gomega, r dnsdb.RRSet) {
	g.Expect(r.RRName).Should(BeZero())
	g.Expect(r.RRType).Should(BeZero())
	g.Expect(r.RData).Should(BeEmpty())
	g.Expect(r.Bailiwick).Should(BeZero())
}

func testSummarizeOptions(t *testing.T, qf queryFunc, rrtype string) {
	maxCount := 100

	t.Run("rrtype", executeQuery(qf().WithRRType(rrtype), func(g Gomega, r dnsdb.RRSet) {
		g.Expect(r.RRType).Should(BeZero())
	}))

	t.Run("maxCount", executeQuery(qf().WithMaxCount(maxCount), func(g Gomega, r dnsdb.RRSet) {
	}))

	testOptions(t, qf)
}
