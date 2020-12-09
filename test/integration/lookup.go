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
	"bytes"
	"net"
	"testing"

	. "github.com/onsi/gomega"

	"github.com/dnsdb/go-dnsdb/pkg/dnsdb"
)

func LookupRRSet(t *testing.T, c dnsdb.Client) {
	name := "farsightsecurity.com."
	qf := func() dnsdb.Query { return c.LookupRRSet(name) }
	bailiwick := "com."
	rrtype := "NS"

	t.Run("no arguments", executeQuery(qf(), func(g Gomega, r dnsdb.RRSet) {
		g.Expect(r.RRName).Should(Equal(name))
	}))

	t.Run("bailiwick", executeQuery(qf().WithBailiwick(bailiwick), func(g Gomega, r dnsdb.RRSet) {
		g.Expect(r.Bailiwick).Should(Equal(bailiwick))
	}))

	t.Run("bailiwick and rrtype", executeQuery(qf().WithBailiwick(bailiwick).WithRRType(rrtype),
		func(g Gomega, r dnsdb.RRSet) {
			g.Expect(r.Bailiwick).Should(Equal(bailiwick))
			g.Expect(r.RRType).Should(Equal(rrtype))
		}))

	testLookupOptions(t, qf, "NS")
}

func LookupRDataName(t *testing.T, c dnsdb.Client) {
	name := "ns5.dnsmadeeasy.com."
	qf := func() dnsdb.Query { return c.LookupRDataName(name) }

	t.Run("no arguments", executeQuery(qf(), func(g Gomega, r dnsdb.RRSet) {
		g.Expect(r.RData[0]).Should(HavePrefix(name))
	}))

	testLookupOptions(t, qf, "NS")
}

func LookupRDataIP(t *testing.T, c dnsdb.Client) {
	ip := net.ParseIP("104.244.13.104")
	cidr := net.IPNet{IP: ip}
	qf := func() dnsdb.Query { return c.LookupRDataIP(cidr) }

	t.Run("no arguments", executeQuery(qf(), func(g Gomega, r dnsdb.RRSet) {
		g.Expect(r.RData[0]).Should(Equal(ip.String()))
	}))

	testLookupOptions(t, qf, "A")
}

func LookupRDataCIDR(t *testing.T, c dnsdb.Client) {
	g := NewWithT(t)

	_, cidr, err := net.ParseCIDR("104.244.13.104/29")
	g.Expect(err).ShouldNot(HaveOccurred())
	qf := func() dnsdb.Query { return c.LookupRDataIP(*cidr) }

	t.Run("no arguments", executeQuery(qf(), func(g Gomega, r dnsdb.RRSet) {
		g.Expect(cidr.Contains(net.ParseIP(r.RData[0]))).Should(BeTrue())
	}))

	testLookupOptions(t, qf, "A")
}

func LookupRDataIPRange(t *testing.T, c dnsdb.Client) {
	within := func(ip, lower, upper net.IP) bool {
		ip = ip.To16()
		lower = lower.To16()
		upper = upper.To16()
		return bytes.Compare(ip, lower) >= 0 && bytes.Compare(ip, upper) <= 0
	}

	lower := net.ParseIP("104.244.13.104")
	upper := net.ParseIP("104.244.13.111")
	qf := func() dnsdb.Query { return c.LookupRDataIPRange(lower, upper) }

	t.Run("no arguments", executeQuery(qf(), func(g Gomega, r dnsdb.RRSet) {
		g.Expect(within(net.ParseIP(r.RData[0]), lower, upper)).Should(BeTrue())
	}))

	testLookupOptions(t, qf, "A")
}

func LookupRDataRaw(t *testing.T, c dnsdb.Client) {
	raw := []byte("\x03ns5\x0bdnsmadeeasy\x03com\x00")
	name := "ns5.dnsmadeeasy.com."
	qf := func() dnsdb.Query { return c.LookupRDataRaw(raw) }

	t.Run("no arguments", executeQuery(qf(), func(g Gomega, r dnsdb.RRSet) {
		g.Expect(r.RData[0]).Should(HavePrefix(name))
	}))

	testLookupOptions(t, qf, "A")
}

func testLookupOptions(t *testing.T, qf queryFunc, rrtype string) {
	testOptions(t, qf)

	offset := 1000

	t.Run("rrtype", executeQuery(qf().WithRRType(rrtype), func(g Gomega, r dnsdb.RRSet) {
		g.Expect(r.RRType).Should(Equal(rrtype))
	}))

	t.Run("offset", executeQuery(qf().WithOffset(offset), func(g Gomega, r dnsdb.RRSet) {
	}))
}
