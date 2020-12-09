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
	"net/http"

	"github.com/dnsdb/go-dnsdb/pkg/dnsdb"
)

func statusError(code int) error {
	switch code {
	case http.StatusOK:
		return nil
	case http.StatusNoContent:
		return nil
	case http.StatusBadRequest:
		return dnsdb.ErrBadRequest
	case http.StatusUnauthorized:
		return dnsdb.ErrUnauthorized
	case http.StatusForbidden:
		return dnsdb.ErrForbidden
	case http.StatusRequestedRangeNotSatisfiable:
		return dnsdb.ErrBadRange
	case http.StatusTooManyRequests:
		return dnsdb.ErrQuotaExceeded
	case http.StatusServiceUnavailable:
		return dnsdb.ErrConcurrencyLimit
	default:
		return dnsdb.HttpStatusError(code)
	}
}
