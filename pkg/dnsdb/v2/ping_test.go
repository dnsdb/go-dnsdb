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
	"context"
	"errors"
	"io/ioutil"
	"strings"
	"testing"
	"time"

	. "github.com/onsi/gomega"
)

func TestPingRequest_Do(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		g := NewWithT(t)

		ctx, cancel := context.WithTimeout(context.TODO(), time.Second)
		defer cancel()

		client, rt := newTestClient()
		rt.response.Body = ioutil.NopCloser(strings.NewReader(`{"ping":"ok"}`))
		g.Expect(client.Ping().Do(ctx)).ShouldNot(HaveOccurred())
	})

	t.Run("http error", func(t *testing.T) {
		g := NewWithT(t)

		ctx, cancel := context.WithTimeout(context.TODO(), time.Second)
		defer cancel()

		client, rt := newTestClient()
		rt.err = errors.New("test")
		g.Expect(client.Ping().Do(ctx)).Should(HaveOccurred())
	})

	t.Run("read error", func(t *testing.T) {
		g := NewWithT(t)

		ctx, cancel := context.WithTimeout(context.TODO(), time.Second)
		defer cancel()

		client, rt := newTestClient()
		rt.response.Body = failedReader{errors.New("read failed")}
		g.Expect(client.Ping().Do(ctx)).Should(HaveOccurred())
	})
}
