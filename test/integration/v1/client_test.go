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

func TestLookupRRSet(t *testing.T) {
	c := client()
	integration.LookupRRSet(t, c)
}

func TestLookupRDataName(t *testing.T) {
	c := client()
	integration.LookupRDataName(t, c)
}

func TestLookupRDataIP(t *testing.T) {
	c := client()
	integration.LookupRDataIP(t, c)
}

func TestLookupRDataCIDR(t *testing.T) {
	c := client()
	integration.LookupRDataCIDR(t, c)
}

func TestLookupRDataIPRange(t *testing.T) {
	c := client()
	integration.LookupRDataIPRange(t, c)
}

func TestLookupRDataRaw(t *testing.T) {
	c := client()
	integration.LookupRDataRaw(t, c)
}
