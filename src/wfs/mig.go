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
	"strings"
)

func migGetCandidates(desc descriptorMig) (cand []fileCandidate, err error) {
	fmt.Fprintf(os.Stdout, "[descriptor] executing mig query\n")
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
		cand = append(cand, fileCandidate{elem[0], elem[1]})
	}
	fmt.Fprintf(os.Stdout, "[descriptor] %v candidates returned by mig\n", len(cand))
	return cand, err
}
