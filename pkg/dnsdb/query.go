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

package dnsdb

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"golang.org/x/net/idna"
)

const (
	modeRRSet queryMode = iota
	modeRDataName
	modeRDataIP
	modeRDataIPRange
	modeRDataRaw
)

const (
	pathName  = "name"
	pathIP    = "ip"
	pathRaw   = "raw"
	rrTypeAny = "ANY"
)

type queryMode int

type HttpResultFunc func(ctx context.Context, req *http.Request) Result

type ipRange struct {
	lower net.IP
	upper net.IP
}

func httpError(code int) error {
	return fmt.Errorf("status: %d", code)
}

type httpQuery struct {
	mode            queryMode
	url             *url.URL
	headers         http.Header
	result          HttpResultFunc
	name            string
	ip              net.IPNet
	ipRange         *ipRange
	raw             []byte
	rrtype          *string
	bailiwick       *string
	limit           *int
	aggregation     *bool
	offset          *int
	maxCount        *int
	timeFirstBefore *int64
	timeFirstAfter  *int64
	timeLastBefore  *int64
	timeLastAfter   *int64
}

func NewHttpRRSetQuery(name string, url *url.URL, headers http.Header, result HttpResultFunc) Query {
	return &httpQuery{
		mode:    modeRRSet,
		url:     url,
		headers: headers,
		name:    name,
		result:  result,
	}
}

func NewHttpRDataNameQuery(name string, url *url.URL, headers http.Header, result HttpResultFunc) Query {
	return &httpQuery{
		mode:    modeRDataName,
		url:     url,
		headers: headers,
		name:    name,
		result:  result,
	}
}

func NewHttpRDataIPQuery(net net.IPNet, url *url.URL, headers http.Header, result HttpResultFunc) Query {
	return &httpQuery{
		mode:    modeRDataIP,
		url:     url,
		headers: headers,
		ip:      net,
		result:  result,
	}
}

func NewHttpRDataIPRangeQuery(lower, upper net.IP, url *url.URL, headers http.Header, result HttpResultFunc) Query {
	return &httpQuery{
		mode:    modeRDataIPRange,
		url:     url,
		headers: headers,
		ipRange: &ipRange{lower, upper},
		result:  result,
	}
}

func NewHttpRDataRawQuery(raw []byte, url *url.URL, headers http.Header, result HttpResultFunc) Query {
	return &httpQuery{
		mode:    modeRDataRaw,
		url:     url,
		headers: headers,
		raw:     raw,
		result:  result,
	}
}

func (q *httpQuery) WithRRType(rrtype string) Query {
	q2 := *q
	q2.rrtype = new(string)
	*q2.rrtype = rrtype
	return &q2
}

func (q *httpQuery) WithBailiwick(bailiwick string) Query {
	q2 := *q
	q2.bailiwick = new(string)
	*q2.bailiwick = bailiwick
	return &q2
}

func (q *httpQuery) WithLimit(n int) Query {
	q2 := *q
	q2.limit = new(int)
	*q2.limit = n
	return &q2
}

func (q *httpQuery) WithAggregation(aggr bool) Query {
	q2 := *q
	q2.aggregation = new(bool)
	*q2.aggregation = aggr
	return &q2
}

func (q *httpQuery) WithOffset(n int) Query {
	q2 := *q
	q2.offset = new(int)
	*q2.offset = n
	return &q2
}

func (q *httpQuery) WithMaxCount(n int) Query {
	q2 := *q
	q2.maxCount = new(int)
	*q2.maxCount = n
	return &q2
}

func (q *httpQuery) WithTimeFirstBefore(when time.Time) Query {
	q2 := *q
	q2.timeFirstBefore = new(int64)
	*q2.timeFirstBefore = when.Unix()
	return &q2
}

func (q *httpQuery) WithTimeFirstAfter(when time.Time) Query {
	q2 := *q
	q2.timeFirstAfter = new(int64)
	*q2.timeFirstAfter = when.Unix()
	return &q2
}

func (q *httpQuery) WithTimeLastBefore(when time.Time) Query {
	q2 := *q
	q2.timeLastBefore = new(int64)
	*q2.timeLastBefore = when.Unix()
	return &q2
}

func (q *httpQuery) WithTimeLastAfter(when time.Time) Query {
	q2 := *q
	q2.timeLastAfter = new(int64)
	*q2.timeLastAfter = when.Unix()
	return &q2
}

func (q *httpQuery) WithRelativeTimeFirstBefore(since time.Duration) Query {
	if since < 0 {
		panic("negative relative times are not supported")
	}
	q2 := *q
	q2.timeFirstBefore = new(int64)
	*q2.timeFirstBefore = -int64(since.Seconds())
	return &q2
}

func (q *httpQuery) WithRelativeTimeFirstAfter(since time.Duration) Query {
	if since < 0 {
		panic("negative relative times are not supported")
	}
	q2 := *q
	q2.timeFirstAfter = new(int64)
	*q2.timeFirstAfter = -int64(since.Seconds())
	return &q2
}

func (q *httpQuery) WithRelativeTimeLastBefore(since time.Duration) Query {
	if since < 0 {
		panic("negative relative times are not supported")
	}
	q2 := *q
	q2.timeLastBefore = new(int64)
	*q2.timeLastBefore = -int64(since.Seconds())
	return &q2
}

func (q *httpQuery) WithRelativeTimeLastAfter(since time.Duration) Query {
	if since < 0 {
		panic("negative relative times are not supported")
	}
	q2 := *q
	q2.timeLastAfter = new(int64)
	*q2.timeLastAfter = -int64(since.Seconds())
	return &q2
}

func (q *httpQuery) makePath() string {
	rrtype := rrTypeAny
	if q.rrtype != nil {
		rrtype = *q.rrtype
	}

	switch q.mode {
	case modeRRSet:
		p := path.Join(pathName, toASCII(q.name), rrtype)

		if q.bailiwick != nil {
			p = path.Join(p, toASCII(*q.bailiwick))
		}

		return p

	case modeRDataName:
		return path.Join(pathName, toASCII(q.name), rrtype)
	case modeRDataIP:
		ones, bits := q.ip.Mask.Size()
		if ones == bits {
			return path.Join(pathIP, q.ip.IP.String(), rrtype)
		}
		return path.Join(pathIP, strings.Replace(q.ip.String(), "/", ",", 1), rrtype)
	case modeRDataIPRange:
		return path.Join(pathIP, fmt.Sprintf("%s-%s", q.ipRange.lower, q.ipRange.upper), rrtype)
	case modeRDataRaw:
		return path.Join(pathRaw, hex.EncodeToString(q.raw), rrtype)

	default:
		panic("invalid query mode")
	}
}

func (q *httpQuery) makeValues(v url.Values) url.Values {
	// other parameters
	if q.limit != nil {
		v.Add("limit", fmt.Sprintf("%d", *q.limit))
	}

	if q.aggregation != nil {
		switch *q.aggregation {
		case true:
			v.Add("aggr", "true")
		case false:
			v.Add("aggr", "false")
		}
	}

	// lookup parameter
	if q.offset != nil {
		v.Add("offset", fmt.Sprintf("%d", *q.offset))
	}

	// summarize parameter
	if q.maxCount != nil {
		v.Add("max_count", fmt.Sprintf("%d", *q.maxCount))
	}

	// time fencing
	if q.timeFirstBefore != nil {
		v.Add("time_first_before", fmt.Sprintf("%d", *q.timeFirstBefore))
	}
	if q.timeFirstAfter != nil {
		v.Add("time_first_after", fmt.Sprintf("%d", *q.timeFirstAfter))
	}
	if q.timeLastBefore != nil {
		v.Add("time_last_before", fmt.Sprintf("%d", *q.timeLastBefore))
	}
	if q.timeLastAfter != nil {
		v.Add("time_last_after", fmt.Sprintf("%d", *q.timeLastAfter))
	}

	return v
}

func (q *httpQuery) Do(ctx context.Context) Result {
	u := new(url.URL)
	*u = *q.url

	u.Path = path.Join(u.Path, q.makePath())
	u.RawQuery = q.makeValues(u.Query()).Encode()

	req := &http.Request{
		Method: http.MethodGet,
		URL:    u,
		Header: make(http.Header),
	}
	req.Header = q.headers

	return q.result(ctx, req)
}

func toASCII(name string) string {
	encoded, err := idna.ToASCII(name)
	if err != nil {
		return name
	}
	return encoded
}
