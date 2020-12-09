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
	"context"
	"fmt"
	"testing"

	. "github.com/onsi/gomega"

	"github.com/dnsdb/go-dnsdb/pkg/dnsdb"
	"github.com/dnsdb/go-dnsdb/pkg/dnsdb/flex"
)

func Search(t *testing.T, c flex.Client) {
	regex := `f.rsight.*\.com`
	glob := `f?rsight*.com`

	for _, method := range []flex.Method{flex.MethodRegex, flex.MethodGlob} {
		for _, key := range []flex.Key{flex.KeyRRNames, flex.KeyRData} {
			for _, rrtype := range []*string{nil, strPtr("NS")} {
				value := regex
				if method == flex.MethodGlob {
					value = glob
				}

				query := c.Search(method, key, value)

				name := fmt.Sprintf("%s/%s/%s", method, key, value)
				if rrtype != nil {
					name += fmt.Sprintf("/%s", *rrtype)
					query = query.WithRRType(*rrtype)
				}

				t.Run(name, executeSearch(
					query, func(g Gomega, r flex.Record) {
						g.Expect(r.RRName).Should(MatchRegexp(regex))

						if rrtype != nil {
							g.Expect(r.RRType).Should(Equal(*rrtype))
						}
					},
				))
			}
		}
	}
}

func executeSearch(q flex.Query, valid func(g Gomega, r flex.Record)) func(t *testing.T) {
	return func(t *testing.T) {
		g := NewWithT(t)

		ctx, cancel := context.WithTimeout(context.TODO(), timeout)
		defer cancel()

		res := q.Do(ctx)

		c := 0
		for rrset := range res.Ch() {
			c++
			valid(g, rrset)
		}
		g.Expect(res.Err()).Should(Or(Not(HaveOccurred()), MatchError(dnsdb.ErrResultLimitExceeded)))
	}
}

func strPtr(s string) *string {
	r := new(string)
	*r = s
	return r
}
