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
	"errors"
	"fmt"
	"net/http"
)

var (
	// ErrResultLimitExceeded is returned if a DNSDB v2 server reports that the query has exceeded
	// its row limit.
	ErrResultLimitExceeded = errors.New("result limit reached")

	// ErrBadRequest The URL is formatted incorrectly.
	ErrBadRequest = errors.New("bad request")
	// ErrUnauthorized The API key is not authorized (usually indicates the block quota is expired), or your API key
	// may not query this API version.
	ErrUnauthorized = errors.New("api key not authorized")
	// ErrForbidden If the X-API-Key header is not present, the provided API key is not valid, or the Client IP address not authorized for this API key.
	ErrForbidden = errors.New("invalid api key or ip not authorized")
	// ErrBadRange If the offset value is greater than the maximum allowed or if an offset value was provided when not permitted.
	ErrBadRange = errors.New("offset is greater than the maximum allowed")
	// ErrQuotaExceeded If you have exceeded your quota and no new requests will be accepted at this time.
	// - For time-based quotas: The API key's daily quota limit is exceeded. The quota will automatically replenish, usually at the start of the next day.
	// - For block-based quotas: The block quota is exhausted. You may need to purchase a larger quota.
	// - For burst rate secondary quotas: There were too many queries within the burst window. The window will automatically reopen at its end.
	ErrQuotaExceeded = errors.New("quota exceeded")
	// ErrConcurrencyLimit If the limit of number of concurrent connections is exceeded.
	ErrConcurrencyLimit = errors.New("concurrency limit exceeded")
)

func HttpStatusError(code int) error {
	return fmt.Errorf("http status %03d: %s", code, http.StatusText(code))
}
