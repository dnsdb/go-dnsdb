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
	"testing"
	"time"

	. "github.com/onsi/gomega"

	"github.com/dnsdb/go-dnsdb/pkg/dnsdb"
)

type queryFunc func() dnsdb.Query

func testOptions(t *testing.T, qf queryFunc) {
	g := NewWithT(t)

	limit := 10
	when, err := time.Parse(time.RFC3339, "2020-01-01T00:00:00Z")
	g.Expect(err).ShouldNot(HaveOccurred())
	duration := time.Hour * 24 * 30
	threshold := time.Minute

	limitCount := 0
	t.Run("limit", executeQuery(qf().WithLimit(limit), func(g Gomega, r dnsdb.RRSet) {
		limitCount++
		g.Expect(limitCount).Should(BeNumerically("<=", limit))
	}))

	t.Run("aggr=true", executeQuery(qf().WithAggregation(true), func(g Gomega, r dnsdb.RRSet) {
	}))

	t.Run("aggr=false", executeQuery(qf().WithAggregation(false), func(g Gomega, r dnsdb.RRSet) {
	}))

	t.Run("timeFirstBefore", executeQuery(qf().WithTimeFirstBefore(when), func(g Gomega, r dnsdb.RRSet) {
		if !r.TimeFirst.IsZero() {
			g.Expect(r.TimeFirst).Should(BeTemporally("<=", when))
		}
		if !r.ZoneTimeFirst.IsZero() {
			g.Expect(r.ZoneTimeFirst).Should(BeTemporally("<=", when))
		}
	}))

	t.Run("timeFirstAfter", executeQuery(qf().WithTimeFirstAfter(when), func(g Gomega, r dnsdb.RRSet) {
		if !r.TimeFirst.IsZero() {
			g.Expect(r.TimeFirst).Should(BeTemporally(">=", when))
		}
		if !r.ZoneTimeFirst.IsZero() {
			g.Expect(r.ZoneTimeFirst).Should(BeTemporally(">=", when))
		}
	}))

	t.Run("timeLastBefore", executeQuery(qf().WithTimeLastBefore(when), func(g Gomega, r dnsdb.RRSet) {
		if !r.TimeLast.IsZero() {
			g.Expect(r.TimeLast).Should(BeTemporally("<=", when))
		}
		if !r.ZoneTimeLast.IsZero() {
			g.Expect(r.ZoneTimeLast).Should(BeTemporally("<=", when))
		}
	}))

	t.Run("timeLastAfter", executeQuery(qf().WithTimeLastAfter(when), func(g Gomega, r dnsdb.RRSet) {
		if !r.TimeLast.IsZero() {
			g.Expect(r.TimeLast).Should(BeTemporally(">=", when))
		}
		if !r.ZoneTimeLast.IsZero() {
			g.Expect(r.ZoneTimeLast).Should(BeTemporally(">=", when))
		}
	}))

	t.Run("relativeTimeFirstBefore", executeQuery(qf().WithRelativeTimeFirstBefore(duration), func(g Gomega, r dnsdb.RRSet) {
		if !r.TimeFirst.IsZero() {
			g.Expect(r.TimeFirst).Should(BeTemporally("<=", time.Now().Add(-duration), threshold))
		}
		if !r.ZoneTimeFirst.IsZero() {
			g.Expect(r.ZoneTimeFirst).Should(BeTemporally("<=", time.Now().Add(-duration), threshold))
		}
	}))

	t.Run("relativeTimeFirstAfter", executeQuery(qf().WithRelativeTimeFirstAfter(duration), func(g Gomega, r dnsdb.RRSet) {
		if !r.TimeFirst.IsZero() {
			g.Expect(r.TimeFirst).Should(BeTemporally(">=", time.Now().Add(-duration), threshold))
		}
		if !r.ZoneTimeFirst.IsZero() {
			g.Expect(r.ZoneTimeFirst).Should(BeTemporally(">=", time.Now().Add(-duration), threshold))
		}
	}))

	t.Run("relativeTimeLastBefore", executeQuery(qf().WithRelativeTimeLastBefore(duration), func(g Gomega, r dnsdb.RRSet) {
		if !r.TimeLast.IsZero() {
			g.Expect(r.TimeLast).Should(BeTemporally("<=", time.Now().Add(-duration), threshold))
		}
		if !r.ZoneTimeLast.IsZero() {
			g.Expect(r.ZoneTimeLast).Should(BeTemporally("<=", time.Now().Add(-duration), threshold))
		}
	}))

	t.Run("relativeTimeLastAfter", executeQuery(qf().WithRelativeTimeLastAfter(duration), func(g Gomega, r dnsdb.RRSet) {
		if !r.TimeLast.IsZero() {
			g.Expect(r.TimeLast).Should(BeTemporally(">=", time.Now().Add(-duration), threshold))
		}
		if !r.ZoneTimeLast.IsZero() {
			g.Expect(r.ZoneTimeLast).Should(BeTemporally(">=", time.Now().Add(-duration), threshold))
		}
	}))
}
