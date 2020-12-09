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

package dnsdb

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"
)

var (
	ErrInvalidRData = errors.New("rdata not []string or string")
)

type RRSet struct {
	// RRName is the owner name of the RRset in DNS presentation format.
	RRName string
	// RRType is esource record type of the RRset, either using the standard DNS type mnemonic, or an RFC 3597 generic
	// type, i.e. the string TYPE immediately followed by the decimal RRtype number.
	RRType string
	// RData is an array of one or more Rdata values. The Rdata values are converted to the standard presentation
	// format based on the rrtype value. If the encoder lacks a type-specific presentation format for the RRset's
	// rrtype, then the RFC 3597 generic Rdata encoding will be used.
	RData []string
	// RawRData is a byte array returned for rdata rows in flex search.
	RawRData  []byte
	Bailiwick string
	// Count is the number of times the RRset was observed via passive DNS replication.
	Count int
	// NumResults is the number of results (RRsets) that would be returned from a Lookup.
	NumResults int
	// TimeFirst is the first time that the record was observed via passive DNS replication.
	TimeFirst time.Time
	// TimeLast is the last time that the record was observed via passive DNS replication.
	TimeLast time.Time
	// ZoneTimeFirst is the first time that the record was observed via zone file import.
	ZoneTimeFirst time.Time
	// ZoneTimeLast is the last time that the record was observed via zone file import.
	ZoneTimeLast time.Time
}

type rrsetEncoded struct {
	RRName        string      `json:"rrname,omitempty"`
	RRType        string      `json:"rrtype,omitempty"`
	RData         interface{} `json:"rdata,omitempty"`
	RawRData      string      `json:"raw_rdata,omitempty"`
	Bailiwick     string      `json:"bailiwick,omitempty"`
	Count         int         `json:"count,omitempty"`
	NumResults    int         `json:"num_results,omitempty"`
	TimeFirst     int64       `json:"time_first,omitempty"`
	TimeLast      int64       `json:"time_last,omitempty"`
	ZoneTimeFirst int64       `json:"zone_time_first,omitempty"`
	ZoneTimeLast  int64       `json:"zone_time_last,omitempty"`
}

func (r *RRSet) UnmarshalJSON(data []byte) error {
	var raw rrsetEncoded
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	res := RRSet{
		RRName:        raw.RRName,
		RRType:        raw.RRType,
		RData:         nil,
		RawRData:      nil,
		Bailiwick:     raw.Bailiwick,
		Count:         raw.Count,
		NumResults:    raw.NumResults,
		TimeFirst:     unix(raw.TimeFirst),
		TimeLast:      unix(raw.TimeLast),
		ZoneTimeFirst: unix(raw.ZoneTimeFirst),
		ZoneTimeLast:  unix(raw.ZoneTimeLast),
	}

	switch raw.RData.(type) {
	case nil:
	case string:
		res.RData = []string{raw.RData.(string)}
	case []interface{}:
		for _, i := range raw.RData.([]interface{}) {
			s, ok := i.(string)
			if !ok {
				return ErrInvalidRData
			}
			res.RData = append(res.RData, s)
		}
	default:
		return ErrInvalidRData
	}

	if raw.RawRData != "" {
		var err error
		res.RawRData, err = hex.DecodeString(raw.RawRData)
		if err != nil {
			return err
		}
	}

	*r = res
	return nil
}

func (r RRSet) MarshalJSON() ([]byte, error) {
	out := make(map[string]interface{})

	if r.RRName != "" {
		out["rrname"] = r.RRName
	}
	if r.RRType != "" {
		out["rrtype"] = r.RRType
	}
	if len(r.RData) > 0 {
		out["rdata"] = r.RData
	}
	if len(r.RawRData) > 0 {
		out["raw_rdata"] = hex.EncodeToString(r.RawRData)
	}
	if r.Bailiwick != "" {
		out["bailiwick"] = r.Bailiwick
	}
	if r.Count > 0 {
		out["count"] = r.Count
	}
	if r.NumResults > 0 {
		out["num_results"] = r.NumResults
	}
	if !r.TimeFirst.IsZero() {
		out["time_first"] = r.TimeFirst
	}
	if !r.TimeLast.IsZero() {
		out["time_last"] = r.TimeLast
	}
	if !r.ZoneTimeFirst.IsZero() {
		out["zone_time_first"] = r.ZoneTimeFirst
	}
	if !r.ZoneTimeLast.IsZero() {
		out["zone_time_last"] = r.ZoneTimeLast
	}

	return json.Marshal(out)
}

func unix(secs int64) time.Time {
	if secs == 0 {
		return time.Time{}
	}
	return time.Unix(secs, 0).UTC()
}

func unixPtr(secs int64) *time.Time {
	u := unix(secs)
	return &u
}

func intPtr(i int) *int {
	return &i
}
