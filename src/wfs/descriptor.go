// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Contributor:
// - Aaron Meihm ameihm@mozilla.com

package main

import (
	"errors"
	"fmt"
	"os"
	"regexp"
)

type descriptorSSH struct {
	Action  string `json:"action"`
	Pattern string `json:"pattern"`
	OVT     string `json:"outputtransform"`
}

type descriptorMig struct {
	Filename    string `json:"filename"`
	FileContent string `json:"filecontent"`
	FilePath    string `json:"filepath"`
	Target      string `json:"target"`
	Expiry      string `json:"expiry"`
	PostFilter  string `json:"postfilter"`
}

func (d *descriptorMig) buildMigArguments() (ret []string, err error) {
	// Note err is unused here and will always be nil, but may be used
	// in the future.
	ret = append(ret, "file")
	if d.Target != "" {
		ret = append(ret, "-t", d.Target)
	}
	if d.Expiry != "" {
		ret = append(ret, "-e", d.Expiry)
	}
	if d.Filename != "" {
		ret = append(ret, "-name", d.Filename)
	}
	if d.FilePath != "" {
		ret = append(ret, "-path", d.FilePath)
	}
	if d.FileContent != "" {
		ret = append(ret, "-content", d.FileContent)
	}
	return ret, err
}

type descriptor struct {
	Name string        `json:"name"`
	Mig  descriptorMig `json:"mig"`
	SSH  descriptorSSH `json:"ssh"`
}

func (d *descriptor) validate() error {
	if d.Name == "" {
		return errors.New("descriptor must have a name")
	}
	if d.SSH.Action != "egrep" {
		return errors.New("invalid ssh action specified in descriptor")
	}
	if d.SSH.Pattern == "" {
		return errors.New("ssh egrep pattern value must be set in descriptor")
	}
	if d.SSH.OVT == "" {
		return errors.New("ssh section must have output transform specified")
	}
	if d.Mig.Expiry == "" {
		return errors.New("mig section must have an expiry specified")
	}
	if d.Mig.Filename == "" {
		return errors.New("mig section must have filename specified")
	}

	_, err := regexp.Compile(d.SSH.Pattern)
	if err != nil {
		return err
	}
	if d.Mig.FileContent != "" {
		_, err := regexp.Compile(d.Mig.FileContent)
		if err != nil {
			return err
		}
	}

	return nil
}

func (d *descriptor) run() (err error) {
	fmt.Fprintf(os.Stderr, "[descriptor] running %v\n", d.Name)
	clist, err := migGetCandidates(d.Mig)
	if err != nil {
		return err
	}

	curworkers := 0
	maxworkers := config.Main.SSHWorkers
	resultChan := make(chan sshResult)
	results := make([]sshResult, 0)
	left := len(clist)
	for i, x := range clist {
		for {
			nodata := false
			select {
			case res := <-resultChan:
				results = append(results, res)
				curworkers--
				left--
			default:
				nodata = true
			}
			if nodata {
				break
			}
		}

		if left == 0 {
			break
		}

		rem := len(clist) - i
		fmt.Fprintf(os.Stderr, "[descriptor] new worker for %v (%v left)\n", x.hostname, rem)
		go sshQuery(x, d, resultChan)
		curworkers++

		if curworkers == maxworkers {
			res := <-resultChan
			results = append(results, res)
			curworkers--
			left--
		}
	}

	for left > 0 {
		res := <-resultChan
		results = append(results, res)
		curworkers--
		left--
	}

	printResults(results)
	return err
}
