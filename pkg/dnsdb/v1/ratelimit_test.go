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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/dnsdb/go-dnsdb/pkg/dnsdb"

	. "github.com/onsi/gomega"
)

type failedReader struct {
	err error
}

func (f failedReader) Read(_ []byte) (n int, err error) {
	return 0, f.err
}

func (f failedReader) Close() error {
	return f.err
}

func TestClient_RateLimit(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		g := NewWithT(t)

		ctx, cancel := context.WithTimeout(context.TODO(), time.Second)
		defer cancel()

		expected := dnsdb.RateLimit{
			Rate: dnsdb.Rate{
				ResultsMax:  1,
				OffsetMax:   2,
				BurstSize:   3,
				BurstWindow: 4,
			},
		}
		input, err := json.Marshal(expected)

		client, rt := newTestClient()
		rt.response.Body = ioutil.NopCloser(bytes.NewReader(
			input,
		))

		actual, err := client.RateLimit().Do(ctx)
		g.Expect(err).ShouldNot(HaveOccurred())
		g.Expect(actual).Should(Equal(expected))
	})

	t.Run("failed transport", func(t *testing.T) {
		g := NewWithT(t)

		ctx, cancel := context.WithTimeout(context.TODO(), time.Second)
		defer cancel()

		client, rt := newTestClient()
		rt.err = errors.New("error")
		rt.response.Body = ioutil.NopCloser(strings.NewReader(""))

		_, err := client.RateLimit().Do(ctx)
		g.Expect(err).Should(HaveOccurred())
	})

	t.Run("read error", func(t *testing.T) {
		g := NewWithT(t)

		ctx, cancel := context.WithTimeout(context.TODO(), time.Second)
		defer cancel()

		client, rt := newTestClient()
		rt.response.Body = failedReader{errors.New("read failed")}

		_, err := client.RateLimit().Do(ctx)
		g.Expect(err).Should(HaveOccurred())
	})

	t.Run("default client", func(t *testing.T) {
		originalDefaultClient := http.DefaultClient
		defer func() {
			http.DefaultClient = originalDefaultClient
		}()

		g := NewWithT(t)

		ctx, cancel := context.WithTimeout(context.TODO(), time.Second)
		defer cancel()

		client, rt := newTestClient()
		rt.response.Body = ioutil.NopCloser(strings.NewReader("{}"))

		http.DefaultClient = client.HttpClient
		client.HttpClient = nil

		_, err := client.RateLimit().Do(ctx)
		g.Expect(err).ShouldNot(HaveOccurred())
		g.Expect(rt.request).ShouldNot(BeNil(), "default client was used")
	})
}
