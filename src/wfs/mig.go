// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Contributor:
// - Aaron Meihm ameihm@mozilla.com

package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

func migGetCandidates(desc descriptorMig) (cand []fileCandidate, err error) {
	fmt.Fprintf(os.Stderr, "[descriptor] executing mig query\n")

	var pfre *regexp.Regexp
	if desc.PostFilter != "" {
		pfre = regexp.MustCompile(desc.PostFilter)
	}

	migargs, err := desc.buildMigArguments()
	if err != nil {
		return cand, err
	}

	cmd := exec.Command(config.Main.MIG, migargs...)
	out, err := cmd.Output()
	if err != nil {
		return cand, err
	}

	rdr := strings.NewReader(string(out))
	scanner := bufio.NewScanner(rdr)
	for scanner.Scan() {
		buf := scanner.Text()
		if buf == "" {
			continue
		}
		elem := strings.Fields(buf)
		if len(elem) < 2 {
			return cand, fmt.Errorf("malformed output from mig: %v", buf)
		}
		// XXX Probably want to add some additional validation of the
		// data that is being returned by mig, to make sure it is a
		// valid hostname and file path.
		if pfre != nil {
			if !pfre.MatchString(elem[1]) {
				continue
			}
		}
		cand = append(cand, fileCandidate{elem[0], elem[1]})
	}
	fmt.Fprintf(os.Stderr, "[descriptor] %v candidates returned by mig\n", len(cand))
	return cand, err
}
