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

package flex

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

const (
	MethodRegex Method = iota
	MethodGlob
	KeyRRNames Key = iota
	KeyRData

	methodRegex = "regex"
	methodGlob  = "glob"
	keyRRnames  = "rrnames"
	keyRData    = "rdata"
)

type Method int

func (m Method) String() string {
	switch m {
	case MethodRegex:
		return methodRegex
	case MethodGlob:
		return methodGlob
	default:
		panic(fmt.Errorf("invalid method: %d", m))
	}
}

type Key int

func (k Key) String() string {
	switch k {
	case KeyRRNames:
		return keyRRnames
	case KeyRData:
		return keyRData
	default:
		panic(fmt.Errorf("invalid key: %d", k))
	}
}

type Record struct {
	RRName    string    `json:"rrname,omitempty"`
	RData     string    `json:"rdata,omitempty"`
	RawRData  []byte    `json:"raw_rdata,omitempty"`
	RRType    string    `json:"rrtype,omitempty"`
	Count     int       `json:"count,omitempty"`
	TimeFirst time.Time `json:"time_first,omitempty"`
	TimeLast  time.Time `json:"time_last,omitempty"`
}

type recordEncoded struct {
	RRName    string `json:"rrname,omitempty"`
	RData     string `json:"rdata,omitempty"`
	RawRData  string `json:"raw_rdata,omitempty"`
	RRType    string `json:"rrtype,omitempty"`
	Count     int    `json:"count,omitempty"`
	TimeFirst int64  `json:"time_first,omitempty"`
	TimeLast  int64  `json:"time_last,omitempty"`
}

func (r *Record) UnmarshalJSON(data []byte) error {
	var raw recordEncoded
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	res := Record{
		RRName:    raw.RRName,
		RData:     raw.RData,
		RRType:    raw.RRType,
		Count:     raw.Count,
		TimeFirst: unix(raw.TimeFirst),
		TimeLast:  unix(raw.TimeLast),
	}

	var err error
	if raw.RawRData != "" {
		res.RawRData, err = hex.DecodeString(raw.RawRData)
	}

	*r = res
	return err
}

func (r Record) MarshalJSON() ([]byte, error) {
	out := recordEncoded{
		RRName:    r.RRName,
		RData:     r.RData,
		RawRData:  hex.EncodeToString(r.RawRData),
		RRType:    r.RRType,
		Count:     r.Count,
		TimeFirst: r.TimeFirst.Unix(),
		TimeLast:  r.TimeLast.Unix(),
	}

	return json.Marshal(out)
}

func unix(secs int64) time.Time {
	if secs == 0 {
		return time.Time{}
	}
	return time.Unix(secs, 0).UTC()
}
