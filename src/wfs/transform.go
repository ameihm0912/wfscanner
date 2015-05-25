// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Contributor:
// - Aaron Meihm ameihm@mozilla.com

package main

import (
	"fmt"
	"regexp"
)

type transformTableEnt struct {
	name string
	fn   func(string) (string, error)
}

var transformTable = []transformTableEnt{
	{"none", transformNone},
	{"django-python", transformDjangoPython},
	{"mediawiki-mwver", transformMediaWikimwVer},
}

func transform(inbuf string, t string) (string, error) {
	for _, i := range transformTable {
		if i.name == t {
			return i.fn(inbuf)
		}
	}
	return "", fmt.Errorf("invalid transform specified: %v", t)
}

func transformNone(inbuf string) (string, error) {
	return inbuf, nil
}

func transformMediaWikimwVer(inbuf string) (string, error) {
	re := regexp.MustCompile("= '(\\S+)';")
	buf := re.FindStringSubmatch(inbuf)
	if len(buf) != 2 {
		return "", fmt.Errorf("transform mediawiki-mwver: invalid input \"%v\"", inbuf)
	}
	return buf[1], nil
}

func transformDjangoPython(inbuf string) (string, error) {
	re := regexp.MustCompile("= \\((\\S+), (\\S+), (\\S+),")
	buf := re.FindStringSubmatch(inbuf)
	if len(buf) != 4 {
		return "", fmt.Errorf("transform python-django: invalid input \"%v\"", inbuf)
	}
	ret := fmt.Sprintf("%v.%v.%v", buf[1], buf[2], buf[3])
	return ret, nil
}
