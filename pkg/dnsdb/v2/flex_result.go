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
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"sync"

	"github.com/dnsdb/go-dnsdb/pkg/dnsdb/flex"

	"github.com/dnsdb/go-dnsdb/pkg/dnsdb/v2/saf"

	"github.com/dnsdb/go-dnsdb/pkg/dnsdb"
)

type flexResult struct {
	client *Client
	stream *saf.Stream
	ch     chan flex.Record
	rl     *dnsdb.RateLimit
	cancel context.CancelFunc
	err    error
	lock   sync.Mutex
}

var _ flex.Result = &flexResult{}

func (c *Client) newFlexResult(ctx context.Context, req *http.Request) flex.Result {
	res := &flexResult{
		client: c,
		stream: &saf.Stream{},
		ch:     make(chan flex.Record),
	}
	ctx, res.cancel = context.WithCancel(ctx)
	go res.run(ctx, req)
	return res
}

func (r *flexResult) run(ctx context.Context, req *http.Request) {
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
		r.lock.Lock()
		r.err = statusError(res.StatusCode)
		fmt.Println(res.Header.Get("content-type"))
		if res.Header.Get("content-type") != "text/html" {
			b, err := ioutil.ReadAll(res.Body)
			if err == nil {
				r.err = fmt.Errorf("%s: %s", r.err, strings.TrimSpace(string(b)))
			}
		}
		res.Body.Close()
		r.lock.Unlock()
		return
	}

	r.stream.Run(ctx, res.Body)

	for {
		var res flex.Record
		select {
		case <-ctx.Done():
			r.lock.Lock()
			if r.err == nil {
				r.err = ctx.Err()
			}
			r.lock.Unlock()
			return
		case raw, ok := <-r.stream.Ch():
			if !ok {
				r.lock.Lock()
				switch {
				case errors.Is(r.stream.Err(), saf.ErrStreamLimited):
					r.err = dnsdb.ErrResultLimitExceeded
				default:
					r.err = r.stream.Err()
				}
				r.lock.Unlock()
				return
			}
			err := json.Unmarshal(raw, &res)
			if err != nil {
				// TODO handle
				continue
			}
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

func (r *flexResult) Close() {
	r.cancel()
}

func (r *flexResult) Ch() <-chan flex.Record {
	return r.ch
}

func (r *flexResult) Err() error {
	return r.err
}

func (r *flexResult) Rate() *dnsdb.RateLimit {
	return r.rl
}
