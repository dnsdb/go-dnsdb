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
	"net"
	"time"
)

// Client is an implementation of the DNSDB lookup API
type Client interface {
	// LookupRRSet performs the rrset lookup query
	LookupRRSet(name string) Query
	// LookupRDataName performs the rdata name lookup query
	LookupRDataName(name string) Query
	// LookupRDataIP performs the rdata ip lookup query with a cidr. Use net.IPNet{IP: ip} for a
	// single IP.
	LookupRDataIP(ip net.IPNet) Query
	// LookupRDataIPRange performs the rdata ip lookup query with an ip range
	LookupRDataIPRange(lower, upper net.IP) Query
	// LookupRDataRaw performs the rdata raw lookup query
	LookupRDataRaw(raw []byte) Query
}

// SummarizeClient is an implementation of the DNSDB summary API
type SummarizeClient interface {
	// SummarizeRRSet performs the rrset summarize query
	SummarizeRRSet(name string) Query
	// SummarizeRDataName performs the rdata name summarize query
	SummarizeRDataName(name string) Query
	// SummarizeRDataIP performs the rdata ip summarize query with a cidr. Use net.IPNet{IP: ip} for a
	// single IP.
	SummarizeRDataIP(ip net.IPNet) Query
	// SummarizeRDataIPRange performs the rdata ip summarize query with an ip range
	SummarizeRDataIPRange(lower, upper net.IP) Query
	// SummarizeRDataRaw performs the rdata raw summarize query
	SummarizeRDataRaw(raw []byte) Query
}

// Query is used to build parameters for queries and to execute them
type Query interface {
	// WithRRType sets the rrtype for the query. The default value is ANY.
	WithRRType(rrtype string) Query

	// WithBailiwick sets the bailiwick for the query. This is only applicable to
	// RRSet-type queries.
	WithBailiwick(bailiwick string) Query

	// WithLimit sets the limit for the number of results returned.
	WithLimit(n int) Query
	// WithAggregation enables or disables grouping of identical rrsets across all time periods
	WithAggregation(aggr bool) Query

	// WithOffset sets how many rows to skip in the results. This is only applicable to Lookup queries
	// and the API server may return an error if it is set for a Summarize query.
	WithOffset(n int) Query

	// WithMaxCount is an option for Summarize query that instructs the api server to stop counting
	// and return an answer immediately once it has reached this value.
	WithMaxCount(n int) Query

	// WithTimeFirstBefore selects records with time_first that is before `when`.
	WithTimeFirstBefore(when time.Time) Query
	// WithTimeFirstAfter selects records with time_first that is after `when`.
	WithTimeFirstAfter(when time.Time) Query
	// WithTimeLastBefore selects records with time_last that is before `when`.
	WithTimeLastBefore(when time.Time) Query
	// WithTimeLastAfter selects records with time_last that is after `when`.
	WithTimeLastAfter(when time.Time) Query

	// WithRelativeTimeFirstBefore selects records with time_first that is before now - `since`. This will panic
	// if passed a negative Duration.
	WithRelativeTimeFirstBefore(since time.Duration) Query
	// WithRelativeTimeFirstAfter selects records with time_first that is after now - `since`. This will panic
	// if passed a negative Duration.
	WithRelativeTimeFirstAfter(since time.Duration) Query
	// WithRelativeTimeLastBefore selects records with time_last that is before now - `since`. This will panic
	// if passed a negative Duration.
	WithRelativeTimeLastBefore(since time.Duration) Query
	// WithRelativeTimeLastAfter selects records with time_last that is after now - `since`. This will panic
	// if passed a negative Duration.
	WithRelativeTimeLastAfter(since time.Duration) Query

	// Do executes the Query and returns a Result. Do is non-blocking. The caller must call `Result.Close()`.
	Do(ctx context.Context) Result
}

// Result returns the results of the query.
type Result interface {
	// Close terminates the query and closes the channel returned by `Ch()`
	Close()
	// Ch returns a channel with the results of the query.
	Ch() <-chan RRSet
	// Err should be called after the channel has been closed to check if any errors have occurred.
	Err() error
}
