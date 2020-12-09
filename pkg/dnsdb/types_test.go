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
	"encoding/json"
	"testing"

	. "github.com/onsi/gomega"
)

func TestRRSet_UnmarshalJSON(t *testing.T) {
	f := func(input []string, expected []RRSet) func(*testing.T) {
		return func(t *testing.T) {
			g := NewWithT(t)

			g.Expect(input).Should(HaveLen(len(expected)), "input and expected have same length")

			for idx, s := range input {
				e := expected[idx]
				var actual RRSet
				err := json.Unmarshal([]byte(s), &actual)
				g.Expect(err).ShouldNot(HaveOccurred(), "unmarshals correctly")
				g.Expect(actual).Should(Equal(e), "output is as expected")
			}
		}
	}

	t.Run("1. Lookup all RRsets whose owner name is www.farsightsecurity.com", f(
		[]string{
			`{"count":5059,"time_first":1380139330,"time_last":1427881899,"rrname":"www.farsightsecurity.com.","rrtype":"A","bailiwick":"farsightsecurity.com.","rdata":["66.160.140.81"],"raw_rdata":"abcd"}`,
			`{"count":17381,"time_first":1427893644,"time_last":1468329272,"rrname":"www.farsightsecurity.com.","rrtype":"A","bailiwick":"farsightsecurity.com.","rdata":["104.244.13.104"]}`,
		},
		[]RRSet{
			{
				RRName:    "www.farsightsecurity.com.",
				RRType:    "A",
				RData:     []string{"66.160.140.81"},
				RawRData:  []byte{0xab, 0xcd},
				Bailiwick: "farsightsecurity.com.",
				Count:     5059,
				TimeFirst: unix(1380139330),
				TimeLast:  unix(1427881899),
			},
			{
				RRName:    "www.farsightsecurity.com.",
				RRType:    "A",
				RData:     []string{"104.244.13.104"},
				Bailiwick: "farsightsecurity.com.",
				Count:     17381,
				TimeFirst: unix(1427893644),
				TimeLast:  unix(1468329272),
			},
		},
	))
	t.Run("1a. Summarize all RRsets whose owner name is www.farsightsecurity.com", f(
		[]string{
			`{"count":1127,"num_results":2,"time_first":1557859313,"time_last":1560537333}`,
		},
		[]RRSet{
			{
				Count:      1127,
				NumResults: 2,
				TimeFirst:  unix(1557859313),
				TimeLast:   unix(1560537333),
			},
		},
	))
	t.Run("2. Lookup all RRsets whose owner name ends in farsightsecurity.com, of type NS, in the farsightsecurity.com zone", f(
		[]string{
			`{"count":51,"time_first":1372688083,"time_last":1374023864,"rrname":"farsightsecurity.com.","rrtype":"NS","bailiwick":"farsightsecurity.com.","rdata":["ns.lah1.vix.com.","ns1.isc-sns.net.","ns2.isc-sns.com.","ns3.isc-sns.info."]}`,
			`{"count":495241,"time_first":1374096380,"time_last":1468324876,"rrname":"farsightsecurity.com.","rrtype":"NS","bailiwick":"farsightsecurity.com.","rdata":["ns5.dnsmadeeasy.com.","ns6.dnsmadeeasy.com.","ns7.dnsmadeeasy.com."]}`,
		},
		[]RRSet{
			{
				RRName:    "farsightsecurity.com.",
				RRType:    "NS",
				RData:     []string{"ns.lah1.vix.com.", "ns1.isc-sns.net.", "ns2.isc-sns.com.", "ns3.isc-sns.info."},
				Bailiwick: "farsightsecurity.com.",
				Count:     51,
				TimeFirst: unix(1372688083),
				TimeLast:  unix(1374023864),
			},
			{
				RRName:    "farsightsecurity.com.",
				RRType:    "NS",
				RData:     []string{"ns5.dnsmadeeasy.com.", "ns6.dnsmadeeasy.com.", "ns7.dnsmadeeasy.com."},
				Bailiwick: "farsightsecurity.com.",
				Count:     495241,
				TimeFirst: unix(1374096380),
				TimeLast:  unix(1468324876),
			},
		},
	))

	t.Run("3. Lookup all resource records whose Rdata values are the IPv4 address 104.244.13.104", f(
		[]string{
			`{"count":24,"time_first":1433550785,"time_last":1468312116,"rrname":"www.farsighsecurity.com.","rrtype":"A","rdata":"104.244.13.104"}`,
			`{"count":9429,"time_first":1427897872,"time_last":1468333042,"rrname":"farsightsecurity.com.","rrtype":"A","rdata":"104.244.13.104"}`,
		},
		[]RRSet{
			{
				RRName:    "www.farsighsecurity.com.",
				RRType:    "A",
				RData:     []string{"104.244.13.104"},
				Count:     24,
				TimeFirst: unix(1433550785),
				TimeLast:  unix(1468312116),
			},
			{
				RRName:    "farsightsecurity.com.",
				RRType:    "A",
				RData:     []string{"104.244.13.104"},
				Count:     9429,
				TimeFirst: unix(1427897872),
				TimeLast:  unix(1468333042),
			},
		},
	))
	t.Run("4a. Summarize all resource records whose Rdata values are addresses in the 104.244.13.104/29 network prefix", f(
		[]string{
			`{"count":528,"num_results":4,"time_first":1557864746,"time_last":1560524861}`,
		},
		[]RRSet{
			{
				Count:      528,
				NumResults: 4,
				TimeFirst:  unix(1557864746),
				TimeLast:   unix(1560524861),
			},
		},
	))
	t.Run("5. Lookup all resource records whose Rdata values are the IPv6 address 2620:11c:f004::104", f(
		[]string{
			`{"count":14,"time_first":1433845806,"time_last":1467828872,"rrname":"www.farsighsecurity.com.","rrtype":"AAAA","rdata":"2620:11c:f004::104"}`,
			`{"count":5307,"time_first":1427897876,"time_last":1468333042,"rrname":"farsightsecurity.com.","rrtype":"AAAA","rdata":"2620:11c:f004::104"}`,
		},
		[]RRSet{
			{
				RRName:    "www.farsighsecurity.com.",
				RRType:    "AAAA",
				RData:     []string{"2620:11c:f004::104"},
				Count:     14,
				TimeFirst: unix(1433845806),
				TimeLast:  unix(1467828872),
			},
			{
				RRName:    "farsightsecurity.com.",
				RRType:    "AAAA",
				RData:     []string{"2620:11c:f004::104"},
				Count:     5307,
				TimeFirst: unix(1427897876),
				TimeLast:  unix(1468333042),
			},
		},
	))
	t.Run("6. Lookup all resource records whose Rdata values are addresses in the 2620:11c:f000::/36 network prefix\n", f(
		[]string{
			`{"count":5307,"time_first":1427897876,"time_last":1468333042,"rrname":"farsightsecurity.com.","rrtype":"AAAA","rdata":"2620:11c:f004::104"}`,
			`{"count":8046,"time_first":1428586271,"time_last":1468305509,"rrname":"www.farsightsecurity.com.","rrtype":"AAAA","rdata":"2620:11c:f004::104"}`,
		},
		[]RRSet{
			{
				RRName:    "farsightsecurity.com.",
				RRType:    "AAAA",
				RData:     []string{"2620:11c:f004::104"},
				Count:     5307,
				TimeFirst: unix(1427897876),
				TimeLast:  unix(1468333042),
			},
			{
				RRName:    "www.farsightsecurity.com.",
				RRType:    "AAAA",
				RData:     []string{"2620:11c:f004::104"},
				Count:     8046,
				TimeFirst: unix(1428586271),
				TimeLast:  unix(1468305509),
			},
		},
	))

	t.Run("7. Lookup all domain names delegated to the nameserver ns5.dnsmadeeasy.com", f(
		[]string{
			`{"count":1078,"zone_time_first":1374250920,"zone_time_last":1468253883,"rrname":"farsightsecurity.com.","rrtype":"NS","rdata":"ns5.dnsmadeeasy.com."}`,
			`{"count":706617,"time_first":1374096380,"time_last":1468334926,"rrname":"farsightsecurity.com.","rrtype":"NS","rdata":"ns5.dnsmadeeasy.com."}`,
		},
		[]RRSet{
			{
				RRName:        "farsightsecurity.com.",
				RRType:        "NS",
				RData:         []string{"ns5.dnsmadeeasy.com."},
				Count:         1078,
				ZoneTimeFirst: unix(1374250920),
				ZoneTimeLast:  unix(1468253883),
			},
			{
				RRName:    "farsightsecurity.com.",
				RRType:    "NS",
				RData:     []string{"ns5.dnsmadeeasy.com."},
				Count:     706617,
				TimeFirst: unix(1374096380),
				TimeLast:  unix(1468334926),
			},
		},
	))

	t.Run("8. Lookup all domain names whose mail exchanges are the server hq.fsi.io", f(
		[]string{
			`{"count":45644,"time_first":1372706073,"time_last":1468330740,"rrname":"fsi.io.","rrtype":"MX","rdata":"10 hq.fsi.io."}`,
			`{"count":19304,"time_first":1374098929,"time_last":1468333042,"rrname":"farsightsecurity.com.","rrtype":"MX","rdata":"10 hq.fsi.io."}`,
		},
		[]RRSet{
			{
				RRName:    "fsi.io.",
				RRType:    "MX",
				RData:     []string{"10 hq.fsi.io."},
				Count:     45644,
				TimeFirst: unix(1372706073),
				TimeLast:  unix(1468330740),
			},
			{
				RRName:    "farsightsecurity.com.",
				RRType:    "MX",
				RData:     []string{"10 hq.fsi.io."},
				Count:     19304,
				TimeFirst: unix(1374098929),
				TimeLast:  unix(1468333042),
			},
		},
	))

	t.Run("9. Lookup wildcard search for RRsets whose owner name is farsightsecurity.com, rrtype is NS, bailiwick is farsightsecurity.com, last observed after July 11, 2016 with a limit of 100 results.", f(
		[]string{
			`{"count":989291,"time_first":1374096380,"time_last":1499964330,"rrname":"farsightsecurity.com.","rrtype":"NS","bailiwick":"farsightsecurity.com.","rdata":["ns5.dnsmadeeasy.com.","ns6.dnsmadeeasy.com.","ns7.dnsmadeeasy.com."]}`,
		},
		[]RRSet{
			{
				RRName:    "farsightsecurity.com.",
				RRType:    "NS",
				RData:     []string{"ns5.dnsmadeeasy.com.", "ns6.dnsmadeeasy.com.", "ns7.dnsmadeeasy.com."},
				Bailiwick: "farsightsecurity.com.",
				Count:     989291,
				TimeFirst: unix(1374096380),
				TimeLast:  unix(1499964330),
			},
		},
	))

	t.Run("10. Lookup RRtypeAny DNSSEC records under farsightsecurity.com", f(
		[]string{
			`{"count":1696,"zone_time_first":1374250920,"zone_time_last":1521734545,"rrname":"farsightsecurity.com.","rrtype":"DS","bailiwick":"com.","rdata":["60454 5 2 3672C35CFA8FF14C9C223B84277BD645C0AF54BAD5790375FE797161E4801479"]}`,
			`{"count":3,"zone_time_first":1374250920,"zone_time_last":1374423636,"rrname":"farsightsecurity.com.","rrtype":"RRSIG","bailiwick":"com.","rdata":["DS 8 2 86400 1374774350 1374165350 8795 com. cuOdo+2G0yJpBN5ba2zxiljSzgtTzminrVc3CrsNxQPqc5YVQX4eBWMB +kpgSEXPT+DF2D9HwIsPpBDNdJekBpXIRW41Yl7IdZYHySqabn7hgt9M mk5KNy9gqCOK/JLRs07LPAm3wvfyYer8e0/7VCTEjF9/DMbMGsLLH3xr kBA="]}`,
		},
		[]RRSet{
			{
				RRName:        "farsightsecurity.com.",
				RRType:        "DS",
				RData:         []string{"60454 5 2 3672C35CFA8FF14C9C223B84277BD645C0AF54BAD5790375FE797161E4801479"},
				Bailiwick:     "com.",
				Count:         1696,
				ZoneTimeFirst: unix(1374250920),
				ZoneTimeLast:  unix(1521734545),
			},
			{
				RRName:        "farsightsecurity.com.",
				RRType:        "RRSIG",
				RData:         []string{"DS 8 2 86400 1374774350 1374165350 8795 com. cuOdo+2G0yJpBN5ba2zxiljSzgtTzminrVc3CrsNxQPqc5YVQX4eBWMB +kpgSEXPT+DF2D9HwIsPpBDNdJekBpXIRW41Yl7IdZYHySqabn7hgt9M mk5KNy9gqCOK/JLRs07LPAm3wvfyYer8e0/7VCTEjF9/DMbMGsLLH3xr kBA="},
				Bailiwick:     "com.",
				Count:         3,
				ZoneTimeFirst: unix(1374250920),
				ZoneTimeLast:  unix(1374423636),
			},
		},
	))

	t.Run("unmarshal failed", func(t *testing.T) {
		g := NewWithT(t)

		var r RRSet
		err := json.Unmarshal([]byte(
			`{"count":"1"}`,
		), &r)
		g.Expect(err).Should(HaveOccurred())
	})

	t.Run("non-strings in rdata", func(t *testing.T) {
		g := NewWithT(t)

		var r RRSet
		err := json.Unmarshal([]byte(
			`{"rdata":[0]}`,
		), &r)
		g.Expect(err).Should(MatchError(ErrInvalidRData))
	})

	t.Run("invalid rdata type", func(t *testing.T) {
		g := NewWithT(t)

		var r RRSet
		err := json.Unmarshal([]byte(
			`{"rdata":0}`,
		), &r)
		g.Expect(err).Should(MatchError(ErrInvalidRData))
	})
}
