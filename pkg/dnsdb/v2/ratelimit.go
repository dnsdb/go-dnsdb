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
	"context"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"path"

	"github.com/dnsdb/go-dnsdb/pkg/dnsdb"
)

const (
	rateLimitPath = "/dnsdb/v2/rate_limit"
)

func (c *Client) RateLimit() dnsdb.RateLimitQuery {
	return &rateLimitQuery{c}
}

type rateLimitQuery struct {
	c *Client
}

func (r *rateLimitQuery) Do(ctx context.Context) (dnsdb.RateLimit, error) {
	u := r.c.baseURL()
	u.Path = path.Join(u.Path, rateLimitPath)
	u.Path = u.Path

	req := &http.Request{
		Method: http.MethodGet,
		URL:    u,
		Header: r.c.headers(),
	}
	req = req.WithContext(ctx)

	client := r.c.getHttpClient()

	res, err := client.Do(req)
	if err != nil {
		return dnsdb.RateLimit{}, err
	}
	defer res.Body.Close()

	if err := statusError(res.StatusCode); err != nil {
		return dnsdb.RateLimit{}, err
	}

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return dnsdb.RateLimit{}, err
	}

	var rl dnsdb.RateLimit
	err = json.Unmarshal(body, &rl)

	return rl, err
}
