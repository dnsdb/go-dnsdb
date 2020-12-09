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
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/dnsdb/go-dnsdb/pkg/dnsdb"

	. "github.com/onsi/gomega"
)

func TestResult(t *testing.T) {
	f := func(input []string, expected []dnsdb.RRSet, statusCode int, ok bool) func(t *testing.T) {
		return func(t *testing.T) {
			g := NewWithT(t)

			ctx, cancel := context.WithTimeout(context.TODO(), time.Second)
			defer cancel()

			httpRes := &http.Response{
				StatusCode: statusCode,
				Body:       ioutil.NopCloser(strings.NewReader(strings.Join(input, "\n"))),
			}
			c := Client{
				HttpClient: &http.Client{
					Transport: &testRoundTripper{
						response: httpRes,
					},
				},
			}

			res := c.newResult(ctx, &http.Request{
				URL: DefaultDnsdbServer,
			})
			defer res.Close()

			for rrSet := range res.Ch() {
				g.Expect(rrSet).Should(Equal(expected[0]))
				expected = expected[1:]
			}
			g.Expect(expected).Should(HaveLen(0))
			if ok {
				g.Expect(res.Err()).ShouldNot(HaveOccurred())
			} else {
				g.Expect(res.Err()).Should(HaveOccurred())
			}
		}
	}

	t.Run("http error", f([]string{"<html>error</html>"}, []dnsdb.RRSet{}, http.StatusInternalServerError, false))

	t.Run("empty", f([]string{}, []dnsdb.RRSet{}, http.StatusNotFound, true))

	t.Run("results with an error and truncation", f(
		[]string{
			`{"count":1}`,
			`{"count":2}}`,
			`{"count":3}`,
			`{"cou`,
		},
		[]dnsdb.RRSet{
			{Count: 1},
			{Count: 3},
		},
		http.StatusOK,
		true,
	))

	t.Run("context cancellation", func(t *testing.T) {
		g := NewWithT(t)

		ctx, cancel := context.WithTimeout(context.TODO(), time.Second)
		defer cancel()

		input := []string{
			`{"count": 1}`,
			`{"count": 2}`,
		}
		httpRes := &http.Response{
			StatusCode: http.StatusOK,
			Body:       ioutil.NopCloser(strings.NewReader(strings.Join(input, "\n"))),
		}
		c := Client{
			HttpClient: &http.Client{
				Transport: &testRoundTripper{
					response: httpRes,
				},
			},
		}
		res := c.newResult(ctx, &http.Request{
			URL: DefaultDnsdbServer,
		})
		defer res.Close()
		cancel()

		g.Eventually(res.Ch).Should(BeClosed())
		g.Eventually(res.Err).Should(HaveOccurred())
	})

	t.Run("rate limit", func(t *testing.T) {
		g := NewWithT(t)

		ctx, cancel := context.WithTimeout(context.TODO(), time.Second)
		defer cancel()

		limit := 100
		expected := &dnsdb.RateLimit{
			Rate: dnsdb.Rate{
				Limit: &limit,
			},
		}
		header := http.Header{}
		header.Add("X-RateLimit-Limit", fmt.Sprintf("%d", limit))
		httpRes := &http.Response{
			StatusCode: http.StatusOK,
			Body:       ioutil.NopCloser(strings.NewReader("")),
			Header:     header,
		}
		c := Client{
			HttpClient: &http.Client{
				Transport: &testRoundTripper{
					response: httpRes,
				},
			},
		}
		res := c.newResult(ctx, &http.Request{
			URL: DefaultDnsdbServer,
		})
		g.Eventually(res.(dnsdb.RateLimitResult).Rate).Should(Equal(expected))
	})
}
