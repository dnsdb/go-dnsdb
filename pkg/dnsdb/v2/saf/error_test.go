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

package saf

import (
	"errors"
	"testing"

	. "github.com/onsi/gomega"
)

func TestErrorStreamLimited_Is(t *testing.T) {
	f := func(err error, ok bool) func(*testing.T) {
		return func(t *testing.T) {
			g := NewWithT(t)
			g.Expect(errors.Is(err, ErrStreamLimited)).Should(Equal(ok))
		}
	}

	t.Run("limited", f(Error(CondLimited, "foomsg"), true))
	t.Run("failed", f(Error(CondFailed, "foomsg"), false))
}
