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
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"sync"

	"github.com/dnsdb/go-dnsdb/pkg/dnsdb"
)

type result struct {
	client *Client
	ch     chan dnsdb.RRSet
	rl     *dnsdb.RateLimit
	cancel context.CancelFunc
	err    error
	lock   sync.Mutex
}

var _ dnsdb.Result = &result{}
var _ dnsdb.RateLimitResult = &result{}

func (c *Client) newResult(ctx context.Context, req *http.Request) dnsdb.Result {
	res := &result{
		client: c,
		ch:     make(chan dnsdb.RRSet),
	}
	ctx, res.cancel = context.WithCancel(ctx)
	go res.run(ctx, req)
	return res
}

func (r *result) run(ctx context.Context, req *http.Request) {
	defer close(r.ch)

	req = req.WithContext(ctx)
	httpClient := r.client.getHttpClient()

	res, err := httpClient.Do(req)
	if err != nil {
		r.lock.Lock()
		r.err = err
		r.lock.Unlock()
		return
	}

	r.rl, _ = dnsdb.NewRateLimitFromHeaders(res.Header)

	switch res.StatusCode {
	case http.StatusOK:
	default:
		res.Body.Close()
		r.lock.Lock()
		r.err = statusError(res.StatusCode)
		r.lock.Unlock()
		return
	}

	go r.closer(ctx, res.Body)

	scanner := bufio.NewScanner(res.Body)
	for scanner.Scan() {
		var res dnsdb.RRSet
		err := json.Unmarshal(scanner.Bytes(), &res)
		if err != nil {
			// TODO handle
			continue
		}

		select {
		case <-ctx.Done():
			r.lock.Lock()
			if r.err == nil {
				r.err = ctx.Err()
			}
			r.lock.Unlock()
			return
		case r.ch <- res:
			// write succeeded
		}
	}
}

func (r *result) closer(ctx context.Context, c io.Closer) {
	<-ctx.Done()
	err := c.Close()

	r.lock.Lock()
	if r.err == nil {
		r.err = err
	}
	r.lock.Unlock()
}

func (r *result) Close() {
	r.cancel()
}

func (r *result) Ch() <-chan dnsdb.RRSet {
	return r.ch
}

func (r *result) Err() error {
	return r.err
}

func (r *result) Rate() *dnsdb.RateLimit {
	return r.rl
}
