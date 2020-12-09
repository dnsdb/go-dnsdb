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
	"context"
	"encoding/json"
	"io/ioutil"
	"strings"
	"testing"
	"time"

	. "github.com/onsi/gomega"
)

func TestMessage_UnmarshalJSON(t *testing.T) {
	f := func(input string, expected Message) func(*testing.T) {
		return func(t *testing.T) {
			g := NewWithT(t)

			var actual Message
			err := json.Unmarshal([]byte(input), &actual)
			g.Expect(err).ShouldNot(HaveOccurred(), "unmarshals correctly")
			g.Expect(actual).Should(Equal(expected), "output is as expected")
		}
	}

	t.Run("begin", f(
		`{"cond": "begin"}`,
		Message{
			Cond: "begin",
		},
	))

	t.Run("obj", f(
		`{"obj":{"count":271,"time_first":1578076118,"time_last":1580765117,"rrname":"fsi.io.","rrtype":"A","bailiwick":"fsi.io.","rdata":["104.244.14.108"]}}`,
		Message{
			Obj: json.RawMessage(`{"count":271,"time_first":1578076118,"time_last":1580765117,"rrname":"fsi.io.","rrtype":"A","bailiwick":"fsi.io.","rdata":["104.244.14.108"]}`),
		},
	))

	t.Run("succeeded", f(
		`{"cond": "succeeded"}`,
		Message{
			Cond: "succeeded",
		},
	))

	t.Run("limited", f(
		`{"cond": "limited", "msg": "Query limit reached"}`,
		Message{
			Cond: "limited",
			Msg:  "Query limit reached",
		},
	))

	t.Run("failed", f(
		`{"cond": "failed", "msg": "Processing timeout; results may be incomplete"}`,
		Message{
			Cond: "failed",
			Msg:  "Processing timeout; results may be incomplete",
		},
	))
}

func TestStream(t *testing.T) {
	f := func(input []string, expected []json.RawMessage, err error) func(t *testing.T) {
		return func(t *testing.T) {
			g := NewWithT(t)
			ctx, cancel := context.WithTimeout(context.TODO(), time.Second)
			defer cancel()

			r := ioutil.NopCloser(strings.NewReader(strings.Join(input, "\n")))

			stream := &Stream{}
			stream.Run(ctx, r)
			defer stream.Close()

		loop:
			for {
				select {
				case <-ctx.Done():
					t.Fail()
					return
				case msg, ok := <-stream.Ch():
					if !ok {
						break loop
					}
					g.Expect(msg).Should(Equal(expected[0]))
					expected = expected[1:]
				}
			}

			switch err {
			case nil:
				g.Consistently(stream.Err).ShouldNot(HaveOccurred())
			default:
				g.Consistently(stream.Err).Should(MatchError(err))
			}
			g.Expect(expected).Should(HaveLen(0), "all input was consumed")
		}
	}

	t.Run("simple successful example", f(
		[]string{
			`{"cond": "begin"}`,
			`{"obj":{"count":10392,"time_first":138126549}}`,
			`{"cond": "succeeded"}`,
		},
		[]json.RawMessage{
			json.RawMessage(`{"count":10392,"time_first":138126549}`),
		},
		nil,
	))

	t.Run("equivalent simple successful example", f(
		[]string{
			`{"cond": "begin"}`,
			`{"cond": "ongoing", "obj":{"count":10392,"time_first":138126549}}`,
			`{"cond": "succeeded"}`,
		},
		[]json.RawMessage{
			json.RawMessage(`{"count":10392,"time_first":138126549}`),
		},
		nil,
	))

	t.Run("limited example", f(
		[]string{
			`{"cond": "begin"}`,
			`{"obj":{"count":10392,"time_first":138126549}}`,
			`{"obj":{"count":33,"time_first":19126549}}`,
			`{"cond": "limited", "msg": "Query limit reached"}`,
		},
		[]json.RawMessage{
			json.RawMessage(`{"count":10392,"time_first":138126549}`),
			json.RawMessage(`{"count":33,"time_first":19126549}`),
		},
		Error(CondLimited, "Query limit reached"),
	))

	t.Run("limited with object example", f(
		[]string{
			`{"cond": "begin"}`,
			`{"obj":{"count":10392,"time_first":138126549}}`,
			`{"cond": "limited", "msg": "Query limit reached","obj":{"count":33,"time_first":19126549}}`,
		},
		[]json.RawMessage{
			json.RawMessage(`{"count":10392,"time_first":138126549}`),
			json.RawMessage(`{"count":33,"time_first":19126549}`),
		},
		Error(CondLimited, "Query limit reached"),
	))

	t.Run("failure example", f(
		[]string{
			`{"cond": "begin"}`,
			`{"obj":{"count":33,"time_first":19126549}}`,
			`{"cond": "failed", "msg": "Processing timeout; results may be incomplete"}`,
		},
		[]json.RawMessage{
			json.RawMessage(`{"count":33,"time_first":19126549}`),
		},
		Error(CondFailed, "Processing timeout; results may be incomplete"),
	))

	t.Run("successful but empty example", f(
		[]string{
			`{"cond": "begin"}`,
			`{"cond": "succeeded"}`,
		},
		[]json.RawMessage{},
		nil,
	))

	t.Run("truncated stream", f(
		[]string{
			`{"cond": "begin"}`,
		},
		[]json.RawMessage{},
		ErrStreamTruncated,
	))

	t.Run("trailing data", f(
		[]string{
			`{"cond": "begin"}`,
			`{"cond": "succeeded"}`,
			`{"obj":{"count":33,"time_first":19126549}}`,
		},
		[]json.RawMessage{},
		nil,
	))

	t.Run("bad json", f(
		[]string{
			`{"cond": "begin"}`,
			`{"obj":{"count":33,"time_first":19126549...}}`,
			`{"cond": "succeeded"}`,
		},
		[]json.RawMessage{},
		nil,
	))

	t.Run("bad cond", f(
		[]string{
			`{"cond": "invalid"}`,
			`{"cond": "succeeded"}`,
		},
		[]json.RawMessage{},
		nil,
	))

	t.Run("failed with no msg", f(
		[]string{
			`{"cond": "failed"}`,
		},
		[]json.RawMessage{},
		Error(CondFailed, ""),
	))

	t.Run("cancelled mid-stream", func(t *testing.T) {
		g := NewWithT(t)
		ctx, cancel := context.WithTimeout(context.TODO(), time.Second)
		defer cancel()

		input := []string{
			`{"cond": "begin"}`,
			`{"obj":{"count":10392,"time_first":138126549}}`,
			`{"obj":{"count":33,"time_first":19126549}}`,
			`{"cond": "limited", "msg": "Query limit reached"}`,
		}
		r := ioutil.NopCloser(strings.NewReader(strings.Join(input, "\n")))

		stream := &Stream{}
		stream.Run(ctx, r)
		defer stream.Close()

		select {
		case <-ctx.Done():
			t.Fail()
			return
		case msg, ok := <-stream.Ch():
			g.Expect(ok).Should(BeTrue(), "message received")
			g.Expect(msg).Should(Equal(json.RawMessage(`{"count":10392,"time_first":138126549}`)))
		}

		_ = stream.Close()

		g.Eventually(stream.Ch).Should(BeClosed())
		g.Expect(stream.Err()).Should(MatchError(context.Canceled))
	})
}
