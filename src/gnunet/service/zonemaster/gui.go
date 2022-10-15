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

package zonemaster

import (
	"bytes"
	"context"
	"crypto/rand"
	"embed"
	"fmt"
	"gnunet/crypto"
	"gnunet/enums"
	"gnunet/service/store"
	"gnunet/util"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/bfix/gospel/logger"
	"github.com/gorilla/mux"
)

var (
	// list of managed RR types
	rrtypes = []enums.GNSType{
		enums.GNS_TYPE_PKEY,
		enums.GNS_TYPE_EDKEY,
		enums.GNS_TYPE_LEHO,
		enums.GNS_TYPE_VPN,
		enums.GNS_TYPE_GNS2DNS,
		enums.GNS_TYPE_PHONE,
		enums.GNS_TYPE_DNS_A,
		enums.GNS_TYPE_DNS_CNAME,
		enums.GNS_TYPE_DNS_MX,
		enums.GNS_TYPE_DNS_TXT,
		enums.GNS_TYPE_DNS_AAAA,
		enums.GNS_TYPE_DNS_SRV,
		enums.GNS_TYPE_DNS_TLSA,
	}
)

//======================================================================
// HTTP service
//======================================================================

//go:embed gui.htpl
var fsys embed.FS

var (
	tpl *template.Template // HTML templates
)

// ----------------------------------------------------------------------
// Start HTTP server to provide GUI
func (zm *ZoneMaster) startGUI(ctx context.Context) {
	logger.Println(logger.INFO, "[zonemaster] Starting HTTP GUI backend...")

	// read and prepare templates
	tpl = template.New("gui")
	tpl.Funcs(template.FuncMap{
		"date": func(ts util.AbsoluteTime) string {
			if ts.Compare(util.AbsoluteTimeNever()) == 0 {
				return "Never"
			}
			return time.UnixMicro(int64(ts.Val)).Format("02.01.06 15:04")
		},
		"keytype": func(t enums.GNSType) string {
			switch t {
			case enums.GNS_TYPE_PKEY:
				return "PKEY"
			case enums.GNS_TYPE_EDKEY:
				return "EDKEY"
			}
			return "???"
		},
		"rrtype": func(r *store.Record) string {
			return strings.Replace(r.RType.String(), "GNS_TYPE_", "", -1)
		},
		"rrflags": func(r *store.Record) string {
			flags := make([]string, 0)
			if r.Flags&enums.GNS_FLAG_PRIVATE != 0 {
				flags = append(flags, "Private")
			}
			if r.Flags&enums.GNS_FLAG_SHADOW != 0 {
				flags = append(flags, "Shadow")
			}
			if r.Flags&enums.GNS_FLAG_SUPPL != 0 {
				flags = append(flags, "Suppl")
			}
			if len(flags) == 0 {
				return "None"
			}
			return strings.Join(flags, ",")
		},
		"rrdata": func(r *store.Record) string {
			return string(r.Data)
		},
	})
	if _, err := tpl.ParseFS(fsys, "gui.htpl"); err != nil {
		logger.Println(logger.ERROR, "[zonemaster] GUI templates failed: "+err.Error())
		return
	}

	// start HTTP server
	router := mux.NewRouter()
	router.HandleFunc("/new/{mode}/{id}", zm.new)
	router.HandleFunc("/edit/{mode}/{id}", zm.edit)
	router.HandleFunc("/del/{mode}/{id}", zm.remove)
	router.HandleFunc("/action/{cmd}/{mode}/{id}", zm.action)
	router.HandleFunc("/", zm.dashboard)
	srv := &http.Server{
		Addr:              zm.cfg.ZoneMaster.GUI,
		ReadTimeout:       10 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		Handler:           router,
		BaseContext: func(l net.Listener) context.Context {
			return ctx
		},
	}
	go func() {
		if err := srv.ListenAndServe(); err != http.ErrServerClosed {
			logger.Printf(logger.ERROR, "[zonemaster] Failed to start GUI: "+err.Error())
		}
	}()
}

// ----------------------------------------------------------------------
// Handle GUI actions (add, edit and remove)
// ----------------------------------------------------------------------

// action dispatcher
func (zm *ZoneMaster) action(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := strconv.ParseInt(vars["id"], 10, 64)
	if err != nil {
		_, _ = io.WriteString(w, "ERROR: "+err.Error())
		return
	}
	switch vars["cmd"] {
	case "new":
		err = zm.actionNew(w, r, vars["mode"], id)
	case "upd":
		err = zm.actionUpd(w, r, vars["mode"], id)
	case "del":
		err = zm.actionDel(w, r, vars["mode"], id)
	}
	if err != nil {
		_, _ = io.WriteString(w, "ERROR: "+err.Error())
		return
	}
}

func (zm *ZoneMaster) actionNew(w http.ResponseWriter, r *http.Request, mode string, id int64) (err error) {
	switch mode {
	case "zone":
		name := r.FormValue("name")
		// create private key
		seed := make([]byte, 32)
		if _, err = rand.Read(seed); err != nil {
			return
		}
		var zp *crypto.ZonePrivate
		kt := enums.GNS_TYPE_PKEY
		if r.FormValue("keytype") == "EDKEY" {
			kt = enums.GNS_TYPE_EDKEY
		}
		zp, err = crypto.NewZonePrivate(kt, seed)
		if err != nil {
			return
		}
		// add zone to database
		zone := store.NewZone(name, zp)
		if err = zm.zdb.SetZone(zone); err != nil {
			return
		}
		// zone added
		zm.dashboard(w, r)

	case "label":
		name := r.FormValue("name")
		// add label to database
		label := store.NewLabel(name)
		label.Zone = id
		if err = zm.zdb.SetLabel(label); err != nil {
			return
		}
		// label added
		zm.dashboard(w, r)
	}
	return nil
}

func (zm *ZoneMaster) actionUpd(w http.ResponseWriter, r *http.Request, mode string, id int64) error {
	return nil
}

func (zm *ZoneMaster) actionDel(w http.ResponseWriter, r *http.Request, mode string, id int64) error {
	return nil
}

// ----------------------------------------------------------------------

func (zm *ZoneMaster) dashboard(w http.ResponseWriter, r *http.Request) {
	// collect information for the GUI
	zg, err := zm.zdb.GetContent()
	if err != nil {
		_, _ = io.WriteString(w, "ERROR: "+err.Error())
		return
	}
	// show dashboard
	renderPage(w, zg, "dashboard")
}

// ----------------------------------------------------------------------

type NewData struct {
	Ref     int64           // database id of reference object
	Names   []string        // list of names in use (ZONE,LABEL)
	RRtypes []enums.GNSType // list of allowed record types (REC)
}

func (zm *ZoneMaster) new(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	var dialog string
	var err error
	data := new(NewData)
	switch vars["mode"] {
	case "zone":
		dialog = "new_zone"
		if data.Names, err = zm.zdb.GetNames("zones"); err != nil {
			_, _ = io.WriteString(w, "ERROR: "+err.Error())
			return
		}
	case "label":
		dialog = "new_label"
		id, err := strconv.ParseInt(vars["id"], 10, 64)
		if err != nil {
			_, _ = io.WriteString(w, "ERROR: "+err.Error())
			return
		}
		stmt := fmt.Sprintf("labels where zid=%d", id)
		if data.Names, err = zm.zdb.GetNames(stmt); err != nil {
			_, _ = io.WriteString(w, "ERROR: "+err.Error())
			return
		}
		data.Ref = id
	case "record":
		dialog = "new_record"
		// get all rrtypes used under given label
		rrs, err := zm.zdb.GetRRTypes(vars["id"])
		if err != nil {
			_, _ = io.WriteString(w, "ERROR: "+err.Error())
			return
		}
		// compile a list of acceptable types for new records
		data.RRtypes = compatibleRR(rrs)
	default:
		zm.dashboard(w, r)
		return
	}
	// show dialog
	renderPage(w, data, dialog)
}

// ----------------------------------------------------------------------

func (zm *ZoneMaster) edit(w http.ResponseWriter, r *http.Request) {
	// show dialog
	renderPage(w, nil, "new")
}

// ----------------------------------------------------------------------

func (zm *ZoneMaster) remove(w http.ResponseWriter, r *http.Request) {
	// show dialog
	renderPage(w, nil, "new")
}

//======================================================================
// Helper methods
//======================================================================

// render a webpage with given data and template reference
func renderPage(w io.Writer, data interface{}, page string) {
	// create content section
	t := tpl.Lookup(page)
	if t == nil {
		_, _ = io.WriteString(w, "No template '"+page+"' found")
		return
	}
	content := new(bytes.Buffer)
	if err := t.Execute(content, data); err != nil {
		_, _ = io.WriteString(w, err.Error())
		return
	}
	// emit final page
	t = tpl.Lookup("main")
	if t == nil {
		_, _ = io.WriteString(w, "No main template found")
		return
	}
	if err := t.Execute(w, content.String()); err != nil {
		_, _ = io.WriteString(w, err.Error())
	}
}

// Create a list of compatible record types from list of
// existing record types.
func compatibleRR(list []enums.GNSType) []enums.GNSType {
	return rrtypes
}
