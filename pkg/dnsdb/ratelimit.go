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
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"
)

const (
	NA        = "n/a"
	Unlimited = "unlimited"
)

var (
	ErrInvalidReset     = errors.New("invalid reset value")
	ErrInvalidLimit     = errors.New("invalid limit value")
	ErrInvalidRemaining = errors.New("invalid remaining value")
	ErrInvalidExpires   = errors.New("invalid expires value")
)

type RateLimitClient interface {
	RateLimit() RateLimitQuery
}

type RateLimitQuery interface {
	Do(ctx context.Context) (RateLimit, error)
}

type RateLimitResult interface {
	// Rate is non-blocking and should not be called until Ch() has been closed.
	Rate() *RateLimit
}

type RateLimit struct {
	Rate Rate `json:"rate"`
}

type Rate struct {
	Reset       *time.Time `json:"reset"`
	Limit       *int       `json:"limit"`
	Remaining   *int       `json:"remaining"`
	Expires     *time.Time `json:"expires"`
	ResultsMax  int        `json:"results_max"`
	OffsetMax   int        `json:"offset_max"`
	BurstSize   int        `json:"burst_size"`
	BurstWindow int        `json:"burst_window"`
}

func NewRateLimitFromHeaders(header http.Header) (*RateLimit, error) {
	res := &RateLimit{}

	limit := header.Get("X-RateLimit-Limit")
	switch limit {
	case "":
	case Unlimited:
	default:
		value, err := strconv.Atoi(limit)
		if err != nil {
			return nil, fmt.Errorf("%s: %s", ErrInvalidLimit, err)
		}
		res.Rate.Limit = intPtr(value)
	}

	remaining := header.Get("X-RateLimit-Remaining")
	switch remaining {
	case "":
	case NA:
	default:
		value, err := strconv.Atoi(remaining)
		if err != nil {
			return nil, fmt.Errorf("%s: %s", ErrInvalidRemaining, err)
		}
		res.Rate.Remaining = intPtr(value)
	}

	reset := header.Get("X-RateLimit-Reset")
	switch reset {
	case "":
	case NA:
	default:
		value, err := strconv.Atoi(reset)
		if err != nil {
			return nil, fmt.Errorf("%s: %s", ErrInvalidReset, err)
		}
		res.Rate.Reset = unixPtr(int64(value))
	}

	expires := header.Get("X-RateLimit-Expires")
	switch expires {
	case "":
	case NA:
	default:
		value, err := strconv.Atoi(expires)
		if err != nil {
			return nil, fmt.Errorf("%s: %s", ErrInvalidExpires, err)
		}
		res.Rate.Expires = unixPtr(int64(value))
	}

	return res, nil
}

func (r *Rate) UnmarshalJSON(data []byte) error {
	var raw struct {
		Reset       interface{} `json:"reset"`
		Limit       interface{} `json:"limit"`
		Remaining   interface{} `json:"remaining"`
		Expires     interface{} `json:"expires"`
		ResultsMax  int         `json:"results_max"`
		OffsetMax   int         `json:"offset_max"`
		BurstSize   int         `json:"burst_size"`
		BurstWindow int         `json:"burst_window"`
	}

	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	var reset *time.Time
	switch raw.Reset.(type) {
	case nil:
	case string:
		if raw.Reset != NA {
			return ErrInvalidReset
		}
	case float64:
		reset = new(time.Time)
		*reset = unix(int64(raw.Reset.(float64)))
	default:
		return ErrInvalidReset
	}

	var limit *int
	switch raw.Limit.(type) {
	case nil:
	case string:
		if raw.Limit != Unlimited {
			return ErrInvalidLimit
		}
	case float64:
		limit = new(int)
		*limit = int(raw.Limit.(float64))
	default:
		return ErrInvalidLimit
	}

	var remaining *int
	switch raw.Remaining.(type) {
	case nil:
	case string:
		if raw.Remaining != NA {
			return ErrInvalidRemaining
		}
	case float64:
		remaining = new(int)
		*remaining = int(raw.Remaining.(float64))
	default:
		return ErrInvalidRemaining
	}

	var expires *time.Time
	switch raw.Expires.(type) {
	case nil:
	case string:
		if raw.Expires != NA {
			return ErrInvalidExpires
		}
	case float64:
		expires = new(time.Time)
		*expires = unix(int64(raw.Expires.(float64)))
	default:
		return ErrInvalidExpires
	}

	*r = Rate{
		Reset:       reset,
		Limit:       limit,
		Remaining:   remaining,
		Expires:     expires,
		ResultsMax:  raw.ResultsMax,
		OffsetMax:   raw.OffsetMax,
		BurstSize:   raw.BurstSize,
		BurstWindow: raw.BurstWindow,
	}

	return nil
}
