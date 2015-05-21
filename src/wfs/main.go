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
	"io/ioutil"
	"os"
	"path"
	"strings"
)

type WFSConfig struct {
	Main struct {
		Descriptors string
		MIG         string
		SSHArgs     string
	}
}

type fileCandidate struct {
	hostname string
	path     string
}

var config WFSConfig
var descmap map[string]descriptor

func loadConfiguration(path string) (err error) {
	err = gcfg.ReadFileInto(&config, path)
	return err
}

func loadDescriptors(dirpath string) (err error) {
	files, err := ioutil.ReadDir(dirpath)
	if err != nil {
		return err
	}
	for _, x := range files {
		fpath := path.Join(dirpath, x.Name())
		if !strings.HasSuffix(fpath, ".json") {
			continue
		}
		fd, err := os.Open(fpath)
		if err != nil {
			return err
		}
		dec := json.NewDecoder(fd)
		newdesc := descriptor{}
		err = dec.Decode(&newdesc)
		fd.Close()
		if err != nil {
			return err
		}
		err = newdesc.validate()
		if err != nil {
			return err
		}
		descmap[newdesc.Name] = newdesc
		fmt.Fprintf(os.Stdout, "[info] loaded descriptor %v\n", newdesc.Name)
	}
	return err
}

func main() {
	var confpath string

	descmap = make(map[string]descriptor)

	flag.StringVar(&confpath, "c", "./wfs.cfg", "path to wfs.cfg")
	flag.Parse()

	err := loadConfiguration(confpath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	err = loadDescriptors(config.Main.Descriptors)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	for i := range descmap {
		mapentry := descmap[i]
		err = mapentry.run()
		if err != nil {
			fmt.Fprintf(os.Stderr, "error running %v: %v\n", i, err)
			os.Exit(1)
		}
	}
}
