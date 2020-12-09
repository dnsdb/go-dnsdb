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

package v2

import (
	"net/url"
	"path"

	"github.com/dnsdb/go-dnsdb/pkg/dnsdb/flex"
)

const (
	flexPath = "/dnsdb/v2"
)

func (c *Client) flexURL() *url.URL {
	u := c.baseURL()
	u.Path = path.Join(u.Path, flexPath)

	return u
}

func (c *Client) Search(method flex.Method, key flex.Key, value string) flex.Query {
	return flex.NewQuery(method, key, value, c.flexURL(), c.headers(), c.newFlexResult)
}
