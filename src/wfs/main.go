// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Contributor:
// - Aaron Meihm ameihm@mozilla.com

package main

import (
	"code.google.com/p/gcfg"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path"
	"strings"
)

type WFSConfig struct {
	Main struct {
		Descriptors string
		MIG         string
		SSHArgs     string
		SSHWorkers  int
		KeyID       string
		SecRing     string
	}
}

type fileCandidate struct {
	hostname string
	path     string
}

var config WFSConfig

func printResults(res []sshResult) {
	for _, x := range res {
		outbuf := make([]string, 0)
		outbuf = append(outbuf, x.hostname)
		outbuf = append(outbuf, x.path)

		if x.err != nil {
			outbuf = append(outbuf, "error")
			outbuf = append(outbuf, x.err.Error())
		} else {
			outbuf = append(outbuf, "ok")
			outbuf = append(outbuf, x.resultString)
		}

		fmt.Fprintf(os.Stdout, "%v\n", strings.Join(outbuf, " "))
	}
}

func loadConfiguration(path string) (err error) {
	err = gcfg.ReadFileInto(&config, path)
	return err
}

func loadDescriptor(descname string, dirpath string) (ret descriptor, err error) {
	fpath := path.Join(dirpath, descname+".json")
	fd, err := os.Open(fpath)
	if err != nil {
		return ret, err
	}
	dec := json.NewDecoder(fd)
	err = dec.Decode(&ret)
	fd.Close()
	if err != nil {
		return ret, err
	}
	err = ret.validate()
	if err != nil {
		return ret, err
	}
	return ret, err
}

func main() {
	var confpath string

	flag.StringVar(&confpath, "c", "./wfs.cfg", "path to wfs.cfg")
	flag.Parse()
	args := flag.Args()

	if len(args) != 1 {
		fmt.Fprint(os.Stderr, "error: must specify descriptor name as argument\n")
		os.Exit(1)
	}
	descname := args[0]

	err := loadConfiguration(confpath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	desc, err := loadDescriptor(descname, config.Main.Descriptors)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	err = pgpCacheKeys(config.Main.SecRing)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	err = desc.run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
