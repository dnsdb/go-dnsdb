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
	"time"
)

type Client interface {
	Search(method Method, key Key, value string) Query
}

type Query interface {
	// WithRRType sets the rrtype for the query. The default value is ANY.
	WithRRType(rrtype string) Query

	WithExclude(exclude string) Query

	// WithLimit sets the limit for the number of results returned.
	WithLimit(n int) Query

	// WithOffset sets how many rows to skip in the results. This is only applicable to Lookup queries
	// and the API server may return an error if it is set for a Summarize query.
	WithOffset(n int) Query

	// WithTimeFirstBefore selects records with time_first that is before `when`.
	WithTimeFirstBefore(when time.Time) Query
	// WithTimeFirstAfter selects records with time_first that is after `when`.
	WithTimeFirstAfter(when time.Time) Query
	// WithTimeLastBefore selects records with time_last that is before `when`.
	WithTimeLastBefore(when time.Time) Query
	// WithTimeLastAfter selects records with time_last that is after `when`.
	WithTimeLastAfter(when time.Time) Query

	// WithRelativeTimeFirstBefore selects records with time_first that is before now - `since`.
	WithRelativeTimeFirstBefore(since time.Duration) Query
	// WithRelativeTimeFirstAfter selects records with time_first that is after now - `since`.
	WithRelativeTimeFirstAfter(since time.Duration) Query
	// WithRelativeTimeLastBefore selects records with time_last that is before now - `since`.
	WithRelativeTimeLastBefore(since time.Duration) Query
	// WithRelativeTimeLastAfter selects records with time_last that is after now - `since`.
	WithRelativeTimeLastAfter(since time.Duration) Query

	Do(ctx context.Context) Result
}

type Result interface {
	// Close terminates the query and closes the channel returned by `Ch()`
	Close()
	// Ch returns a channel with the results of the query.
	Ch() <-chan Record
	// Err should be called after the channel has been closed to check if any errors have occurred.
	Err() error
}
