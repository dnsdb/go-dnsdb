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

package flex

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"time"
)

type HttpResultFunc func(ctx context.Context, req *http.Request) Result

type flexQuery struct {
	method          Method
	key             Key
	value           string
	rrtype          string
	url             *url.URL
	headers         http.Header
	result          HttpResultFunc
	exclude         *string
	limit           *int
	offset          *int
	timeFirstBefore *int64
	timeFirstAfter  *int64
	timeLastBefore  *int64
	timeLastAfter   *int64
}

func NewQuery(method Method, key Key, value string, url *url.URL, headers http.Header, result HttpResultFunc) Query {
	switch method {
	case MethodRegex, MethodGlob:
	default:
		panic(fmt.Errorf("Invalid method: %d", method))
	}

	switch key {
	case KeyRRNames, KeyRData:
	default:
		panic(fmt.Errorf("Invalid key: %d", key))
	}

	return &flexQuery{
		method:  method,
		key:     key,
		value:   value,
		url:     url,
		headers: headers,
		result:  result,
	}
}

func (f *flexQuery) WithRRType(rrtype string) Query {
	f2 := *f
	f2.rrtype = rrtype
	return &f2
}

func (f *flexQuery) WithExclude(exclude string) Query {
	f2 := *f
	if exclude != "" {
		f2.exclude = new(string)
		*f2.exclude = exclude
	} else {
		f2.exclude = nil
	}
	return &f2
}

func (f *flexQuery) WithLimit(limit int) Query {
	f2 := *f
	f2.limit = new(int)
	*f2.limit = limit
	return &f2
}

func (f *flexQuery) WithOffset(n int) Query {
	f2 := *f
	f2.offset = new(int)
	*f2.offset = n
	return &f2
}

func (f *flexQuery) WithTimeFirstBefore(when time.Time) Query {
	f2 := *f
	f2.timeFirstBefore = new(int64)
	*f2.timeFirstBefore = when.Unix()
	return &f2
}

func (f *flexQuery) WithTimeFirstAfter(when time.Time) Query {
	f2 := *f
	f2.timeFirstAfter = new(int64)
	*f2.timeFirstAfter = when.Unix()
	return &f2
}

func (f *flexQuery) WithTimeLastBefore(when time.Time) Query {
	f2 := *f
	f2.timeLastBefore = new(int64)
	*f2.timeLastBefore = when.Unix()
	return &f2
}

func (f *flexQuery) WithTimeLastAfter(when time.Time) Query {
	f2 := *f
	f2.timeLastAfter = new(int64)
	*f2.timeLastAfter = when.Unix()
	return &f2
}

func (f *flexQuery) WithRelativeTimeFirstBefore(since time.Duration) Query {
	if since < 0 {
		panic("negative relative times are not supported")
	}
	f2 := *f
	f2.timeFirstBefore = new(int64)
	*f2.timeFirstBefore = -int64(since.Seconds())
	return &f2
}

func (f *flexQuery) WithRelativeTimeFirstAfter(since time.Duration) Query {
	if since < 0 {
		panic("negative relative times are not supported")
	}
	f2 := *f
	f2.timeFirstAfter = new(int64)
	*f2.timeFirstAfter = -int64(since.Seconds())
	return &f2
}

func (f *flexQuery) WithRelativeTimeLastBefore(since time.Duration) Query {
	if since < 0 {
		panic("negative relative times are not supported")
	}
	f2 := *f
	f2.timeLastBefore = new(int64)
	*f2.timeLastBefore = -int64(since.Seconds())
	return &f2
}

func (f *flexQuery) WithRelativeTimeLastAfter(since time.Duration) Query {
	if since < 0 {
		panic("negative relative times are not supported")
	}
	f2 := *f
	f2.timeLastAfter = new(int64)
	*f2.timeLastAfter = -int64(since.Seconds())
	return &f2
}

func (f *flexQuery) makePath() string {
	components := []string{
		f.method.String(),
		f.key.String(),
		url.PathEscape(f.value),
	}

	if f.rrtype != "" {
		components = append(components, url.PathEscape(f.rrtype))
	}

	return path.Join(components...)
}

func (f *flexQuery) makeValues(v url.Values) url.Values {
	// exclude pattern
	if f.exclude != nil {
		v.Add("exclude", *f.exclude)
	}

	// other parameters
	if f.limit != nil {
		v.Add("limit", fmt.Sprintf("%d", *f.limit))
	}

	// lookup parameter
	if f.offset != nil {
		v.Add("offset", fmt.Sprintf("%d", *f.offset))
	}

	// time fencing
	if f.timeFirstBefore != nil {
		v.Add("time_first_before", fmt.Sprintf("%d", *f.timeFirstBefore))
	}
	if f.timeFirstAfter != nil {
		v.Add("time_first_after", fmt.Sprintf("%d", *f.timeFirstAfter))
	}
	if f.timeLastBefore != nil {
		v.Add("time_last_before", fmt.Sprintf("%d", *f.timeLastBefore))
	}
	if f.timeLastAfter != nil {
		v.Add("time_last_after", fmt.Sprintf("%d", *f.timeLastAfter))
	}

	return v
}

func (f *flexQuery) Do(ctx context.Context) Result {
	u := new(url.URL)
	*u = *f.url

	u.Path = path.Join(u.Path, f.makePath())
	u.RawQuery = f.makeValues(u.Query()).Encode()

	req := &http.Request{
		Method: http.MethodGet,
		URL:    u,
		Header: make(http.Header),
	}
	req.Header = f.headers

	return f.result(ctx, req)
}
