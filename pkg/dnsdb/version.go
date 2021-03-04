// Copyright (c) 2021 by Farsight Security, Inc.
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
	"runtime/debug"
)

const (
	packageName = "github.com/dnsdb/go-dnsdb"
)

var (
	Version = "(unknown)"
)

func init() {
	if bi, ok := debug.ReadBuildInfo(); ok {
		if bi.Main.Path == packageName {
			Version = bi.Main.Version
		} else {
			for _, dep := range bi.Deps {
				if dep.Path == packageName {
					Version = dep.Version
				}
			}
		}
	}
}
