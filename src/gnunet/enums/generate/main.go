// This file is part of gnunet-go, a GNUnet-implementation in Golang.
// Copyright (C) 2019-2022 Bernd Fix  >Y<
//
// gnunet-go is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License,
// or (at your option) any later version.
//
// gnunet-go is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
//
// SPDX-License-Identifier: AGPL3.0-or-later

//go:build ignore

package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"text/template"
)

// Record in the GANA registry (for a given type)
type Record struct {
	Number      string
	Name        string
	Comment     string
	Package     string
	References  string
	Value       string
	Description string
}

// String returns a readable record string
func (rec *Record) String() string {
	return fmt.Sprintf("[%s:%s]", rec.Number, rec.Name)
}

// go:generate generator to read recfiles and fill templates (not exactly
// build on recutils but on recfiles).
func main() {
	// handle command-line arguments
	flag.Parse()
	args := flag.Args()
	if len(args) != 3 {
		log.Fatal("not enough arguments")
	}

	// read template
	tpl, err := template.ParseFiles(args[1])
	if err != nil {
		log.Fatal(err)
	}

	// parse recfile
	in, err := os.Open(args[0])
	if err != nil {
		log.Fatal(err)
	}
	defer in.Close()

	rdr := bufio.NewReader(in)
	state := 0
	var recs []*Record
	var rec *Record
	for {
		// read next line from recfile
		buf, _, err := rdr.ReadLine()
		if err != nil {
			if err == io.EOF {
				break
			}
		}
		line := strings.TrimSpace(string(buf))

		// perform state machine:
		switch state {

		// wait for record to start
		case 0:
			if len(line) == 0 || strings.Index("%#", string(line[0])) != -1 {
				continue
			}
			// new record starts here
			rec = new(Record)
			state = 1
			fallthrough

		// read record data
		case 1:
			if len(line) == 0 {
				// record done
				if rec.Package == "GNUnet" || rec.Package == "" {
					log.Println("Record: " + rec.String())
					recs = append(recs, rec)
				}
				rec = nil
				state = 0
				continue
			}
			// set attribute
			kv := strings.SplitN(line, ":", 2)
			switch kv[0] {
			case "Number":
				rec.Number = strings.TrimSpace(kv[1])
			case "Value":
				rec.Value = strings.TrimSpace(kv[1])
			case "Name":
				rec.Name = strings.TrimSpace(kv[1])
			case "Comment":
				rec.Comment = strings.TrimSpace(kv[1])
			case "Description":
				rec.Description = strings.TrimSpace(kv[1])
			case "Package":
				rec.Package = strings.TrimSpace(kv[1])
			case "References":
				rec.References = strings.TrimSpace(kv[1])
			}
		}
	}

	// open output file
	out, err := os.Create(args[2])
	if err != nil {
		log.Fatal(err)
	}
	defer out.Close()

	// Exeute template on data
	if err := tpl.Execute(out, recs); err != nil {
		log.Fatal(err)
	}
}
