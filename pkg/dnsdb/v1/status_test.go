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
	"fmt"
	"net/http"
	"testing"

	. "github.com/onsi/gomega"
)

func TestStatusError(t *testing.T) {
	f := func(code int, ok bool) func(*testing.T) {
		return func(t *testing.T) {
			g := NewWithT(t)
			err := statusError(code)
			if ok {
				g.Expect(err).ShouldNot(HaveOccurred())
			} else {
				g.Expect(err).Should(HaveOccurred())
			}
		}
	}

	t.Run("ok", f(http.StatusOK, true))
	t.Run("notFound", f(http.StatusNotFound, true))
	for i := 100; i <= 600; i++ {
		switch i {
		case http.StatusOK, http.StatusNotFound:
		default:
			t.Run(fmt.Sprint(http.StatusText(i)), f(i, false))
		}
	}
}
