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

// XXX This function expects the GPG passphrase used by mig to have already
// been cached by the GPG agent. If it's not, pinentry will be called in this
// function and depending on the system the input dialog may not show up.
//
// When this happens the process will be waiting for the call into GPG
// agent to return. We need a workaround to detect this scenario, or a way
// to tell MIG to immediately return if the key needs to be decrypted.
func migGetCandidates(desc descriptorMig) (cand []fileCandidate, err error) {
	fmt.Fprintf(os.Stdout, "[descriptor] executing mig query\n")

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
	fmt.Fprintf(os.Stdout, "[descriptor] %v candidates returned by mig\n", len(cand))
	return cand, err
}
