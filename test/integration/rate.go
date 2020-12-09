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

	"github.com/dnsdb/go-dnsdb/pkg/dnsdb"

	. "github.com/onsi/gomega"
)

func RateLimit(t *testing.T, c dnsdb.RateLimitClient) {
	g := NewWithT(t)

	ctx, cancel := context.WithTimeout(context.TODO(), timeout)
	defer cancel()

	_, err := c.RateLimit().Do(ctx)
	g.Expect(err).ShouldNot(HaveOccurred())
}
