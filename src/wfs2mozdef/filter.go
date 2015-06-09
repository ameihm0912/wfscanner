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
	"github.com/ameihm0912/govfeed/src/govfeed"
	"github.com/ameihm0912/gozdef"
	"io/ioutil"
	"os"
	"regexp"
	"time"
)

type Filter struct {
	Name        string    `json:"name"`
	Entries     []Lineage `json:"lineage"`
	LastUpdated time.Time `json:"lastupdated"`
}

type Lineage struct {
	Value   string        `json:"value"`
	Entries []FilterEntry `json:"filters"`

	defaultEntry *FilterEntry
	valueRegexp  *regexp.Regexp
}

type FilterEntry struct {
	Description string    `json:"description"`
	Value       string    `json:"value"`
	Type        string    `json:"type"`
	Ok          bool      `json:"ok"`
	EntryTS     time.Time `json:"entryts"`
	Impact      string    `json:"impact"`
	CVEList     []string  `json:"cves"`

	valueRegexp *regexp.Regexp
}

var cveCache map[string]govfeed.GVCVE

var filter Filter
var defaultLineage *Lineage

func getCVE(cve string) (govfeed.GVCVE, error) {
	x, ok := cveCache[cve]
	if ok {
		return x, nil
	}
	x, err := govfeed.GVQuery(cve)
	if err != nil {
		return x, err
	}
	cveCache[cve] = x
	return x, nil
}

func (f *FilterEntry) apply(v *gozdef.VulnEvent, cves []string) error {
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
	v.Vuln.CVE = cves

	if useVFeed != "" {
		maxcvss := 0.0
		for _, x := range v.Vuln.CVE {
			if x == "others" {
				maxcvss = 10.0
				v.Vuln.CVEText = append(v.Vuln.CVEText, "others: Other CVEs are also applicable")
				continue
			}
			cvedata, err := getCVE(x)
			if err != nil {
				return err
			}
			if cvedata.CVSS > maxcvss {
				maxcvss = cvedata.CVSS
			}

			cvedesc := fmt.Sprintf("%v: %v", x, cvedata.Description)
			v.Vuln.CVEText = append(v.Vuln.CVEText, cvedesc)
		}
		v.Vuln.CVSS = maxcvss
	}

	if v.Vuln.CVSS == 0.0 && v.Vuln.ImpactLabel != "" {
		switch v.Vuln.ImpactLabel {
		case "maximum":
			v.Vuln.CVSS = 10.0
		case "high":
			v.Vuln.CVSS = 9.0
		case "mediumlow":
			v.Vuln.CVSS = 7.0
		}
	}

	return nil
}

func (l *Lineage) applyLineage(v *gozdef.VulnEvent) error {
	cveRunning := make([]string, 0)

	for _, x := range l.Entries {
		if x.Type != "anchor" {
			if x.Type == "cve" {
				cveRunning = append(cveRunning, x.CVEList...)
			}
			continue
		}
		if x.valueRegexp == nil {
			continue
		}
		if x.valueRegexp.MatchString(v.Vuln.Description) {
			if err := x.apply(v, cveRunning); err != nil {
				return err
			}
			return nil
		}
	}
	if l.defaultEntry != nil {
		if err := l.defaultEntry.apply(v, cveRunning); err != nil {
			return err
		}
	}
	return nil
}

func applyFilter(v *gozdef.VulnEvent) error {
	for _, x := range filter.Entries {
		if x.valueRegexp == nil {
			continue
		}
		if x.valueRegexp.MatchString(v.Vuln.Description) {
			if err := x.applyLineage(v); err != nil {
				return err
			}
			return nil
		}
	}
	if defaultLineage != nil {
		if err := defaultLineage.applyLineage(v); err != nil {
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
			defaultLineage = &filter.Entries[i]
			continue
		}
		filter.Entries[i].valueRegexp, err = regexp.Compile(filter.Entries[i].Value)
		if err != nil {
			return err
		}
		for j := range filter.Entries[i].Entries {
			var eptr *FilterEntry
			eptr = &filter.Entries[i].Entries[j]
			if eptr.Type != "anchor" {
				// Only process regexp for anchors
				continue
			}
			if eptr.Value == "" {
				filter.Entries[i].defaultEntry = eptr
				continue
			}
			eptr.valueRegexp, err = regexp.Compile(eptr.Value)
			if err != nil {
				return err
			}
		}
	}
	return nil
}
