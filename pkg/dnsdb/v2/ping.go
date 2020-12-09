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
	pingPath = "/dnsdb/v2/ping"
)

type pingRequest struct {
	c *Client
}

func (c *Client) Ping() dnsdb.PingRequest {
	return &pingRequest{c}
}

func (p pingRequest) Do(ctx context.Context) error {
	u := p.c.baseURL()
	u.Path = path.Join(u.Path, pingPath)
	u.Path = u.Path

	req := &http.Request{
		Method: http.MethodGet,
		URL:    u,
		Header: p.c.headers(),
	}
	req = req.WithContext(ctx)

	client := p.c.getHttpClient()

	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if err := statusError(res.StatusCode); err != nil {
		return err
	}

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return err
	}

	var pr dnsdb.PingResponse
	err = json.Unmarshal(body, &pr)

	return err
}
