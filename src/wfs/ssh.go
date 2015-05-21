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
	"syscall"
)

func sshQuery(cand fileCandidate, desc *descriptor) (ret string, err error) {
	fmt.Fprintf(os.Stdout, "[ssh] %v (%v) [%v]\n", cand.hostname, cand.path, desc.SSH.Pattern)

	sshArguments := make([]string, 0)

	configArgs := strings.Fields(config.Main.SSHArgs)
	sshArguments = append(sshArguments, configArgs...)
	sshArguments = append(sshArguments, cand.hostname)
	sshArguments = append(sshArguments, "egrep", desc.SSH.Pattern, cand.path)

	cmd := exec.Command("/usr/bin/ssh", sshArguments...)
	outpipe, err := cmd.StdoutPipe()
	if err != nil {
		return ret, err
	}
	rdr := bufio.NewReader(outpipe)
	err = cmd.Start()
	if err != nil {
		return ret, err
	}
	linebuf, _ := rdr.ReadString('\n')
	err = cmd.Wait()
	if err != nil {
		if exerr, ok := err.(*exec.ExitError); ok {
			if status, ok := exerr.Sys().(syscall.WaitStatus); ok {
				exitcode := status.ExitStatus()
				if exitcode == 1 {
					// egrep did not find the content, this
					// is not treated as an error.
					return ret, nil
				}
				fmt.Fprintf(os.Stdout, "[warn] %v (ssh ret: %v)\n", cand.hostname, exitcode)
				return ret, nil
			}
		}
		return ret, err
	}
	ret, err = transform(linebuf, desc.SSH.OVT)
	if err != nil {
		return "", err
	}
	return ret, nil
}
