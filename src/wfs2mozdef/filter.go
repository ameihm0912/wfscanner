// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Contributor:
// - Aaron Meihm ameihm@mozilla.com

package main

import (
	"encoding/json"
	"fmt"
	"github.com/ameihm0912/gozdef"
	"io/ioutil"
	"os"
	"regexp"
	"time"
)

type Filter struct {
	Name        string        `json:"name"`
	Entries     []FilterEntry `json:"filters"`
	LastUpdated time.Time     `json:"lastupdated"`
}

type FilterEntry struct {
	Description string    `json:"description"`
	Value       string    `json:"value"`
	Ok          bool      `json:"ok"`
	EntryTS     time.Time `json:"entryts"`
	Impact      string    `json:"impact"`

	valueRegexp *regexp.Regexp
}

var filter Filter
var defaultEntry *FilterEntry

func (f *FilterEntry) apply(v *gozdef.VulnEvent) error {
	if f.Ok {
		v.Vuln.Status = "closed"
	} else {
		v.Vuln.Status = "open"
	}
	if f.Description != "" {
		v.Vuln.Proof = fmt.Sprintf("%v: %v", filter.Name, f.Description)
	}
	ts := filter.LastUpdated.Format("2006-01-02 15:04")
	v.Vuln.Proof = fmt.Sprintf("%v, filter applied from %v", v.Vuln.Proof, ts)
	if f.Impact != "" {
		v.Vuln.ImpactLabel = f.Impact
	}
	return nil
}

func applyFilter(v *gozdef.VulnEvent) error {
	for _, x := range filter.Entries {
		if x.valueRegexp == nil {
			continue
		}
		if x.valueRegexp.MatchString(v.Vuln.Description) {
			if err := x.apply(v); err != nil {
				return err
			}
			return nil
		}
	}
	if defaultEntry != nil {
		if err := defaultEntry.apply(v); err != nil {
			return nil
		}
	}
	return nil
}

func loadFilter(path string) error {
	fmt.Fprintf(os.Stderr, "loading filter from %v\n", path)
	buf, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}
	err = json.Unmarshal(buf, &filter)
	if err != nil {
		return err
	}
	for i := range filter.Entries {
		if filter.Entries[i].Value == "" {
			defaultEntry = &filter.Entries[i]
			continue
		}
		filter.Entries[i].valueRegexp, err = regexp.Compile(filter.Entries[i].Value)
		if err != nil {
			return err
		}
	}
	return nil
}