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
	"bufio"
	"context"
	"encoding/json"
	"io"
	"sync"
)

const (
	CondBegin     = "begin"
	CondOngoing   = "ongoing"
	CondSucceeded = "succeeded"
	CondLimited   = "limited"
	CondFailed    = "failed"
)

type Message struct {
	Cond string          `json:"cond,omitempty"`
	Msg  string          `json:"msg,omitempty"`
	Obj  json.RawMessage `json:"obj,omitempty"`
}

type Stream struct {
	ch     chan json.RawMessage
	cancel context.CancelFunc
	err    error
	lock   sync.Mutex
}

func (s *Stream) Run(ctx context.Context, r io.ReadCloser) {
	ctx, s.cancel = context.WithCancel(ctx)
	s.ch = make(chan json.RawMessage)

	go s.run(ctx, r)
	go s.closer(ctx, r)
}

func (s *Stream) run(ctx context.Context, r io.Reader) {
	defer close(s.ch)

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		var msg Message
		if err := json.Unmarshal(scanner.Bytes(), &msg); err != nil {
			// TODO error handler
			continue
		}

		if len(msg.Obj) > 0 {
			select {
			case <-ctx.Done():
				s.lock.Lock()
				if s.err == nil {
					s.err = ctx.Err()
				}
				s.lock.Unlock()
				return
			case s.ch <- msg.Obj:
				// write succeeded
			}
		}

		switch msg.Cond {
		case "", CondOngoing:
			continue
		case CondBegin:
			// stream begins
		case CondSucceeded:
			// stream ends successfully
			s.cancel()
			return
		case CondLimited:
			// stream was limited. we report an error but do not cancel
			// the context
			s.lock.Lock()
			s.err = Error(msg.Cond, msg.Msg)
			s.lock.Unlock()

			return
		case CondFailed:
			// stream ended unsuccessfully
			s.lock.Lock()
			s.err = Error(msg.Cond, msg.Msg)
			s.lock.Unlock()

			s.cancel()
			return
		default:
			// TODO error handler
		}
	}

	s.lock.Lock()
	s.err = ErrStreamTruncated
	s.lock.Unlock()
}

func (s *Stream) closer(ctx context.Context, c io.Closer) {
	<-ctx.Done()
	err := c.Close()

	s.lock.Lock()
	if s.err == nil {
		s.err = err
	}
	s.lock.Unlock()
}

func (s *Stream) Close() error {
	s.cancel()
	return nil
}

func (s *Stream) Ch() <-chan json.RawMessage {
	return s.ch
}

func (s *Stream) Err() error {
	return s.err
}
