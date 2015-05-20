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
}

func (d *descriptorMig) buildMigArguments() (ret []string, err error) {
	// Note err is unused here and will always be nil, but may be used
	// in the future.
	ret = append(ret, "file")
	if d.Target != "" {
		ret = append(ret, "-t", d.Target)
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

func (d *descriptor) validate() (err error) {
	if d.Name == "" {
		return errors.New("descriptor must have a name")
	}
	if d.SSH.Action != "egrep" {
		return errors.New("invalid ssh action specified in descriptor")
	}
	if d.SSH.Pattern == "" {
		return errors.New("ssh egrep pattern value must be set in descriptor")
	}
	return err
}

func (d *descriptor) run() (err error) {
	fmt.Fprintf(os.Stdout, "[descriptor] running %v\n", d.Name)
	clist, err := migGetCandidates(d.Mig)
	if err != nil {
		return err
	}
	for _, x := range clist {
		outbuf, err := sshQuery(x, d)
		if err != nil {
			return err
		}
		if outbuf == "" {
			outbuf = "none"
		}
		fmt.Fprintf(os.Stdout, "[result] %v %v (%v) %v\n", d.Name, x.hostname, x.path, outbuf)
	}
	return err
}
