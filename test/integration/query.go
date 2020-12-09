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
	"testing"
	"time"

	. "github.com/onsi/gomega"

	"github.com/dnsdb/go-dnsdb/pkg/dnsdb"
)

const (
	timeout = time.Second * 10
)

func executeQuery(q dnsdb.Query, valid func(g Gomega, r dnsdb.RRSet)) func(t *testing.T) {
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
