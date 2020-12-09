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
	"testing"

	"github.com/dnsdb/go-dnsdb/test/integration"
)

func TestSummarizeRRSet(t *testing.T) {
	c := client()
	integration.SummarizeRRSet(t, c)
}

func TestSummarizeRDataName(t *testing.T) {
	c := client()
	integration.SummarizeRDataName(t, c)
}

func TestSummarizeRDataIP(t *testing.T) {
	c := client()
	integration.SummarizeRDataIP(t, c)
}

func TestSummarizeRDataCIDR(t *testing.T) {
	c := client()
	integration.SummarizeRDataCIDR(t, c)
}

func TestSummarizeRDataIPRange(t *testing.T) {
	c := client()
	integration.SummarizeRDataIPRange(t, c)
}

func TestSummarizeRDataRaw(t *testing.T) {
	c := client()
	integration.SummarizeRDataRaw(t, c)
}
