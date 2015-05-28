// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Contributor:
// - Aaron Meihm ameihm@mozilla.com

package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/ameihm0912/gozdef"
	"os"
	"strconv"
	"strings"
)

var apic gozdef.ApiConf

var mozdef string
var aidFile string
var checkName string
var sourceName string
var vulnEvents []gozdef.VulnEvent

func makeEvent(args []string) (gozdef.VulnEvent, error) {
	e, err := gozdef.NewVulnEvent()
	if err != nil {
		return e, err
	}

	e.Description = fmt.Sprintf("wfs check for %v", checkName)
	e.SourceName = sourceName

	e.Asset.AssetID, err = getAssetID(args[0], args[3])
	if err != nil {
		return e, err
	}
	e.Asset.Hostname = args[0]

	e.Vuln.Status = "unknown"
	e.Vuln.VulnID = checkName
	e.Vuln.Title = args[3]

	e.Vuln.Description = strings.Join(args[4:len(args)], " ")

	return e, e.Validate()
}

func getAssetID(hostname string, title string) (int, error) {
	h := 0
	fd, err := os.Open(aidFile)
	if err != nil {
		return 0, err
	}
	scanner := bufio.NewScanner(fd)
	for scanner.Scan() {
		buf := scanner.Text()
		bufargs := strings.Fields(buf)
		if len(bufargs) != 3 {
			return 0, errors.New("malformed asset id file")
		}
		ret, err := strconv.Atoi(bufargs[2])
		if err != nil {
			return 0, err
		}
		if ret > h {
			h = ret
		}
		if bufargs[0] == hostname && bufargs[1] == title {
			return ret, nil
		}
	}
	fd.Close()

	// Add a new entry if not present
	h++
	fmt.Fprintf(os.Stderr, "adding new asset %v %v\n", h, title)
	fd, err = os.OpenFile(aidFile, os.O_RDWR|os.O_APPEND, 0644)
	if err != nil {
		return 0, err
	}
	buf := fmt.Sprintf("%v %v %v\n", hostname, title, h)
	fd.WriteString(buf)
	fd.Close()

	return h, nil
}

func main() {
	var filterPath string

	flag.StringVar(&aidFile, "a", "", "asset id file")
	flag.StringVar(&filterPath, "f", "", "load and use filter at path")
	flag.StringVar(&checkName, "n", "", "name describing output")
	flag.StringVar(&mozdef, "m", "", "post json data to MozDef")
	flag.Parse()
	args := flag.Args()

	if len(args) != 1 {
		fmt.Fprintf(os.Stderr, "error: must specify wfs results output as argument\n")
		os.Exit(1)
	}

	if aidFile == "" {
		fmt.Fprint(os.Stderr, "must specify asset id file with -a\n")
		os.Exit(1)
	}
	if checkName == "" {
		checkName = "default"
	}
	if sourceName == "" {
		sourceName = "wfs"
	}

	if filterPath != "" {
		err := loadFilter(filterPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	}

	fd, err := os.Open(args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	defer fd.Close()
	scanner := bufio.NewScanner(fd)
	for scanner.Scan() {
		buf := scanner.Text()
		bufargs := strings.Fields(buf)
		if len(bufargs) < 5 {
			fmt.Fprint(os.Stderr, "warning: not enough fields in input, skipped\n")
		}
		newevent, err := makeEvent(bufargs)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		vulnEvents = append(vulnEvents, newevent)
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	for i := range vulnEvents {
		err := applyFilter(&vulnEvents[i])
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	}

	var pub gozdef.Publisher
	if mozdef != "" {
		ac := gozdef.ApiConf{Url: mozdef}
		pub, err = gozdef.InitApi(ac)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	}

	for _, x := range vulnEvents {
		if mozdef == "" {
			jb, err := json.Marshal(x)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error: %v\n", err)
				os.Exit(1)
			}
			fmt.Fprintf(os.Stdout, "%v\n", string(jb))
		} else {
			err := pub.Send(x)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error: %v\n", err)
				os.Exit(1)
			}
		}
	}
}
