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
	"encoding/json"
	"net/http"
	"testing"

	. "github.com/onsi/gomega"
)

func TestRateLimit(t *testing.T) {
	f := func(input string, expected RateLimit) func(*testing.T) {
		return func(t *testing.T) {
			g := NewWithT(t)

			var actual RateLimit
			err := json.Unmarshal([]byte(input), &actual)
			g.Expect(err).ShouldNot(HaveOccurred(), "unmarshals correctly")
			g.Expect(actual).Should(Equal(expected), "output is as expected")
		}
	}

	t.Run("invalid json", func(t *testing.T) {
		g := NewWithT(t)

		var r Rate
		err := json.Unmarshal([]byte(`{"results_max":"1"}`), &r)
		g.Expect(err).Should(HaveOccurred())
	})

	t.Run("lookup rate_limit", f(
		`{"rate": {"reset": 1539129600,"limit": 1000,"remaining": 990}}`,
		RateLimit{
			Rate: Rate{
				Reset:     unixPtr(1539129600),
				Limit:     intPtr(1000),
				Remaining: intPtr(990),
			},
		},
	))
	t.Run("time-based quota", f(
		`{"rate": {"reset": 1433980800,"limit": 1000,"remaining": 999}}`,
		RateLimit{
			Rate: Rate{
				Reset:     unixPtr(1433980800),
				Limit:     intPtr(1000),
				Remaining: intPtr(999),
			},
		},
	))
	t.Run("block-based quota", f(
		`{"rate": {"reset": "n/a","burst_size": 10,"expires": 1555370914,"burst_window": 300,"offset_max": 3000000,"results_max": 256,"limit": 600,"remaining": 8}}`,
		RateLimit{
			Rate: Rate{
				Reset:       nil,
				BurstSize:   10,
				Expires:     unixPtr(1555370914),
				BurstWindow: 300,
				OffsetMax:   3000000,
				ResultsMax:  256,
				Limit:       intPtr(600),
				Remaining:   intPtr(8),
			},
		},
	))
	t.Run("unlimited quota", f(
		`{"rate": {"reset": "n/a","limit": "unlimited","remaining": "n/a"}}`,
		RateLimit{
			Rate: Rate{
				Reset:     nil,
				Limit:     nil,
				Remaining: nil,
			},
		},
	))
}

func TestNewRateLimitFromHeaders(t *testing.T) {
	f := func(input http.Header, expected RateLimit, expectedErr error) func(t *testing.T) {
		return func(t *testing.T) {
			g := NewWithT(t)

			actual, err := NewRateLimitFromHeaders(input)
			if expectedErr == nil {
				g.Expect(err).ShouldNot(HaveOccurred(), "unmarshals correctly")
				g.Expect(*actual).Should(Equal(expected), "output is as expected")
			} else {
				g.Expect(err).Should(MatchError(HavePrefix(expectedErr.Error())))
			}
		}
	}

	t.Run("empty", f(
		http.Header{},
		RateLimit{},
		nil,
	))
	t.Run("reset int", f(
		makeHeader("reset", "100"),
		RateLimit{
			Rate{
				Reset: unixPtr(100),
			},
		},
		nil,
	))
	t.Run("reset n/a", f(
		makeHeader("reset", "n/a"),
		RateLimit{
			Rate{
				Reset: nil,
			},
		},
		nil,
	))
	t.Run("reset unlimited", f(
		makeHeader("reset", "unlimited"),
		RateLimit{},
		ErrInvalidReset,
	))

	t.Run("limit int", f(
		makeHeader("limit", "100"),
		RateLimit{
			Rate{
				Limit: intPtr(100),
			},
		},
		nil,
	))
	t.Run("limit unlimited", f(
		makeHeader("limit", "unlimited"),
		RateLimit{
			Rate{
				Limit: nil,
			},
		},
		nil,
	))
	t.Run("limit n/a", f(
		makeHeader("limit", "n/a"),
		RateLimit{},
		ErrInvalidLimit,
	))

	t.Run("remaining int", f(
		makeHeader("remaining", "100"),
		RateLimit{
			Rate{
				Remaining: intPtr(100),
			},
		},
		nil,
	))
	t.Run("remaining n/a", f(
		makeHeader("remaining", "n/a"),
		RateLimit{
			Rate{
				Remaining: nil,
			},
		},
		nil,
	))
	t.Run("remaining unlimited", f(
		makeHeader("remaining", "unlimited"),
		RateLimit{},
		ErrInvalidRemaining,
	))

	t.Run("expires int", f(
		makeHeader("expires", "100"),
		RateLimit{
			Rate{
				Expires: unixPtr(100),
			},
		},
		nil,
	))
	t.Run("expires n/a", f(
		makeHeader("expires", "n/a"),
		RateLimit{
			Rate{
				Expires: nil,
			},
		},
		nil,
	))
	t.Run("expires unlimited", f(
		makeHeader("expires", "unlimited"),
		RateLimit{},
		ErrInvalidExpires,
	))
}

func makeHeader(key, value string) http.Header {
	res := http.Header{}
	res.Set("X-RateLimit-"+key, value)
	return res
}

func TestRate_UnmarshalJSON(t *testing.T) {
	f := func(input string, expected Rate, expectedErr error) func(*testing.T) {
		return func(t *testing.T) {
			g := NewWithT(t)

			var actual Rate
			err := json.Unmarshal([]byte(input), &actual)
			if expectedErr == nil {
				g.Expect(err).ShouldNot(HaveOccurred(), "unmarshals correctly")
				g.Expect(actual).Should(Equal(expected), "output is as expected")
			} else {
				g.Expect(err).Should(MatchError(expectedErr))
			}
		}
	}

	t.Run("empty", f(
		"{}",
		Rate{},
		nil,
	))

	t.Run("reset int", f(
		`{"reset": 100}`,
		Rate{
			Reset: unixPtr(100),
		},
		nil,
	))
	t.Run("reset n/a", f(
		`{"reset": "n/a"}`,
		Rate{
			Reset: nil,
		},
		nil,
	))
	t.Run("reset unlimited", f(
		`{"reset": "unlimited"}`,
		Rate{},
		ErrInvalidReset,
	))
	t.Run("reset array", f(
		`{"reset": []}`,
		Rate{},
		ErrInvalidReset,
	))
	t.Run("reset object", f(
		`{"reset": {}}`,
		Rate{},
		ErrInvalidReset,
	))

	t.Run("limit int", f(
		`{"limit": 100}`,
		Rate{
			Limit: intPtr(100),
		},
		nil,
	))
	t.Run("limit unlimited", f(
		`{"limit": "unlimited"}`,
		Rate{
			Limit: nil,
		},
		nil,
	))
	t.Run("limit n/a", f(
		`{"limit": "n/a"}`,
		Rate{},
		ErrInvalidLimit,
	))
	t.Run("limit array", f(
		`{"limit": []}`,
		Rate{},
		ErrInvalidLimit,
	))
	t.Run("limit object", f(
		`{"limit": {}}`,
		Rate{},
		ErrInvalidLimit,
	))

	t.Run("remaining int", f(
		`{"remaining": 100}`,
		Rate{
			Remaining: intPtr(100),
		},
		nil,
	))
	t.Run("remaining n/a", f(
		`{"remaining": "n/a"}`,
		Rate{
			Remaining: nil,
		},
		nil,
	))
	t.Run("remaining unlimited", f(
		`{"remaining": "unlimited"}`,
		Rate{},
		ErrInvalidRemaining,
	))
	t.Run("remaining array", f(
		`{"remaining": []}`,
		Rate{},
		ErrInvalidRemaining,
	))
	t.Run("remaining object", f(
		`{"remaining": {}}`,
		Rate{},
		ErrInvalidRemaining,
	))

	t.Run("expires int", f(
		`{"expires": 100}`,
		Rate{
			Expires: unixPtr(100),
		},
		nil,
	))
	t.Run("expires n/a", f(
		`{"expires": "n/a"}`,
		Rate{
			Expires: nil,
		},
		nil,
	))
	t.Run("expires unlimited", f(
		`{"expires": "unlimited"}`,
		Rate{},
		ErrInvalidExpires,
	))
	t.Run("expires array", f(
		`{"expires": []}`,
		Rate{},
		ErrInvalidExpires,
	))
	t.Run("expires object", f(
		`{"expires": {}}`,
		Rate{},
		ErrInvalidExpires,
	))
}
