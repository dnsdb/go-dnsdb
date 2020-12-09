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
	"fmt"
	"strings"
)

var (
	ErrStreamTruncated = errors.New("saf stream truncated")
	ErrStreamLimited   = fmt.Errorf("saf stream %s", CondLimited)
)

type safError string

func (e safError) Error() string {
	return string(e)
}

func (e safError) Is(target error) bool {
	switch target {
	case ErrStreamLimited:
		return strings.HasPrefix(string(e), ErrStreamLimited.Error())
	default:
		return string(e) == e.Error()
	}
}

func Error(cond, msg string) error {
	switch msg {
	case "":
		return safError(cond)
	default:
		return safError(fmt.Sprintf("saf stream %s: %s", cond, msg))
	}
}
