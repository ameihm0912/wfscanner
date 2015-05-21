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
	"os/exec"
	"strings"
	"syscall"
)

type retCodeError struct {
	s       string
	retcode int
}

func (e *retCodeError) Error() string {
	return e.s
}

type sshResult struct {
	err          error
	resultString string
	hostname     string
	path         string
}

func sshQuery(cand fileCandidate, desc *descriptor, resch chan sshResult) {
	ret := sshResult{}
	ret.hostname = cand.hostname
	ret.path = cand.path

	sshArguments := make([]string, 0)

	configArgs := strings.Fields(config.Main.SSHArgs)
	sshArguments = append(sshArguments, configArgs...)
	sshArguments = append(sshArguments, cand.hostname)
	sshArguments = append(sshArguments, "egrep", desc.SSH.Pattern, cand.path)

	cmd := exec.Command("/usr/bin/ssh", sshArguments...)
	outpipe, err := cmd.StdoutPipe()
	if err != nil {
		ret.err = err
		resch <- ret
		return
	}
	rdr := bufio.NewReader(outpipe)
	err = cmd.Start()
	if err != nil {
		ret.err = err
		resch <- ret
		return
	}
	linebuf, _ := rdr.ReadString('\n')
	linebuf = strings.Trim(linebuf, "\r\n")
	err = cmd.Wait()
	if err != nil {
		if exerr, ok := err.(*exec.ExitError); ok {
			if status, ok := exerr.Sys().(syscall.WaitStatus); ok {
				exitcode := status.ExitStatus()
				if exitcode == 1 {
					// egrep did not find the content, this
					// is not treated as an error.
					resch <- ret
					return
				}
				// Some other return code was returned we
				// did not expect, return this as a result
				// to the main routine. This can occur for
				// example of the SSH connection fails.
				nerr := retCodeError{}
				nerr.retcode = exitcode
				nerr.s = fmt.Sprintf("command failed with return code %v", exitcode)
				ret.err = &nerr
				resch <- ret
				return
			}
		}
		ret.err = err
		resch <- ret
		return
	}
	linebuf, err = transform(linebuf, desc.SSH.OVT)
	if err != nil {
		ret.err = err
		resch <- ret
		return
	}
	ret.resultString = linebuf
	resch <- ret
}
