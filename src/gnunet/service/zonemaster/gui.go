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
	"errors"
	"fmt"
	"gnunet/crypto"
	"gnunet/enums"
	"gnunet/service/gns/rr"
	"gnunet/service/store"
	"gnunet/util"
	"io"
	"net"
	"net/http"
	"strings"
	"text/template"
	"time"

	"github.com/bfix/gospel/data"
	"github.com/bfix/gospel/logger"
	"github.com/gorilla/mux"
)

//======================================================================
// HTTP service
//======================================================================

//go:embed *.htpl
var fsys embed.FS

var (
	tpl      *template.Template   // HTML templates
	timeHTML = "2006-01-02T15:04" // time format (defined by HTML, don't change!)
	timeGUI  = "02.01.06 15:04"   // time format for GUI
)

//----------------------------------------------------------------------

// Start HTTP server to provide GUI
func (zm *ZoneMaster) startGUI(ctx context.Context) {
	logger.Println(logger.INFO, "[zonemaster] Starting HTTP GUI backend...")

	// read and prepare templates
	tpl = template.New("gui")
	tpl.Funcs(template.FuncMap{
		"date": func(ts util.AbsoluteTime) string {
			return guiTime(ts)
		},
		"keytype": func(t enums.GNSType) string {
			return guiKeyType(t)
		},
		"rrtype": func(t enums.GNSType) string {
			return strings.Replace(t.String(), "GNS_TYPE_", "", -1)
		},
		"rrflags": func(f enums.GNSFlag) string {
			flags := make([]string, 0)
			if f&enums.GNS_FLAG_PRIVATE != 0 {
				flags = append(flags, "Private")
			}
			if f&enums.GNS_FLAG_SHADOW != 0 {
				flags = append(flags, "Shadow")
			}
			if f&enums.GNS_FLAG_SUPPL != 0 {
				flags = append(flags, "Suppl")
			}
			if len(flags) == 0 {
				return "None"
			}
			return strings.Join(flags, ",<br>")
		},
		"rrdata": func(t enums.GNSType, buf []byte) string {
			params := RRData2Map(t, buf)
			list := make([]string, 0)
			for k, v := range params {
				list = append(list, fmt.Sprintf("<span title='%s'>%v</span>", k, v))
			}
			return strings.Join(list, ",<br>")
		},
	})
	if _, err := tpl.ParseFS(fsys, "*.htpl"); err != nil {
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

//----------------------------------------------------------------------

// dashboard is the main entry point for the GUI
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

//======================================================================
// Handle GUI actions (add, edit and remove)
//======================================================================

// action dispatcher
func (zm *ZoneMaster) action(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	mode := vars["mode"]
	id, ok := util.CastFromString[int64](vars["id"])
	var err error
	if ok {
		switch vars["cmd"] {
		case "new":
			err = zm.actionNew(w, r, mode, id)
		case "upd":
			err = zm.actionUpd(w, r, mode, id)
		case "del":
			err = zm.actionDel(w, r, mode, id)
		}
	} else {
		err = errors.New("action: missing object id")
	}
	if err != nil {
		_, _ = io.WriteString(w, "ERROR: "+err.Error())
		return
	}
	// redirect back to dashboard
	http.Redirect(w, r, "/", http.StatusMovedPermanently)
}

//----------------------------------------------------------------------
// NEW: create zone, label or resource record
//----------------------------------------------------------------------

func (zm *ZoneMaster) actionNew(w http.ResponseWriter, r *http.Request, mode string, id int64) (err error) {
	switch mode {

	// new zone
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
		err = zm.zdb.SetZone(zone)

	// new label
	case "label":
		name := r.FormValue("name")
		// add label to database
		label := store.NewLabel(name)
		label.Zone = id
		err = zm.zdb.SetLabel(label)

	// new resource record
	case "rr":
		err = zm.newRec(w, r, id)
	}
	return
}

//----------------------------------------------------------------------

// create new resource record from dialog data
func (zm *ZoneMaster) newRec(w http.ResponseWriter, r *http.Request, label int64) error {
	// get list of parameters from resource record dialog
	_ = r.ParseForm()
	params := make(map[string]string)
	for key, val := range r.Form {
		params[key] = strings.Join(val, ",")
	}
	// parse RR type (and set prefix for map keys)
	t, ok := util.CastFromString[enums.GNSType](params["type"])
	if !ok {
		return errors.New("new: missing resource record type")
	}
	pf := dlgPrefix[t]

	// parse expiration
	exp := util.AbsoluteTimeNever()
	if _, ok := params[pf+"never"]; !ok {
		ts, _ := time.Parse(timeHTML, params[pf+"expires"])
		exp.Val = uint64(ts.UnixMicro())
	}
	// parse flags
	var flags enums.GNSFlag
	if _, ok := params[pf+"private"]; ok {
		flags |= enums.GNS_FLAG_PRIVATE
	}
	if _, ok := params[pf+"shadow"]; ok {
		flags |= enums.GNS_FLAG_SHADOW
	}
	if _, ok := params[pf+"suppl"]; ok {
		flags |= enums.GNS_FLAG_SUPPL
	}
	// construct RR data
	rrdata, err := Map2RRData(t, params)
	if err == nil {
		// assemble record and store in database
		rr := store.NewRecord(exp, t, flags, rrdata)
		rr.Label = label
		err = zm.zdb.SetRecord(rr)
	}
	return err
}

//----------------------------------------------------------------------
// UPD: update zone, label or resource record
//----------------------------------------------------------------------

func (zm *ZoneMaster) actionUpd(w http.ResponseWriter, r *http.Request, mode string, id int64) error {
	return nil
}

//----------------------------------------------------------------------
// NEW: create zone, label or resource record
//----------------------------------------------------------------------

func (zm *ZoneMaster) actionDel(w http.ResponseWriter, r *http.Request, mode string, id int64) error {
	return nil
}

//----------------------------------------------------------------------
// Create new zone. label or resource record
//----------------------------------------------------------------------

type NewEditData struct {
	// shared attributes (new/edit)
	Ref    int64    // database id of reference object
	Action string   // "Add" or "Edit" action
	Names  []string // list of names in use (ZONE,LABEL)

	// "new" attributes
	RRtypes []*enums.GNSSpec // list of allowed record types (REC)

	// "edit" attributes
	Params map[string]string // list of current values
}

func (zm *ZoneMaster) new(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	var err error
	data := new(NewEditData)
	data.Action = "Add"
	switch vars["mode"] {

	// new zone dialog
	case "zone":
		if data.Names, err = zm.zdb.GetNames("zones"); err != nil {
			break
		}
		renderPage(w, data, "new_zone")
		return

	// new label dialog
	case "label":
		// get reference id
		id, ok := util.CastFromString[int64](vars["id"])
		if !ok {
			err = errors.New("new label: missing zone id")
			break
		}
		// get all existing label names for zone
		stmt := fmt.Sprintf("labels where zid=%d", id)
		if data.Names, err = zm.zdb.GetNames(stmt); err == nil {
			data.Ref = id
			renderPage(w, data, "new_label")
			return
		}

	// new resource record dialog
	case "rr":
		// get reference id
		id, ok := util.CastFromString[int64](vars["id"])
		if !ok {
			err = errors.New("new record: missing label id")
			break
		}
		// get all rrtypes used under given label
		var rrs []*enums.GNSSpec
		var label string
		if rrs, label, err = zm.zdb.GetRRTypes(id); err == nil {
			// compile a list of acceptable types for new records
			data.RRtypes = compatibleRR(rrs, label)
			data.Ref = id
			renderPage(w, data, "new_record")
			return
		}
	}
	// handle error
	if err != nil {
		_, _ = io.WriteString(w, "ERROR: "+err.Error())
		return
	}
	// redirect back to dashboard
	http.Redirect(w, r, "/", http.StatusMovedPermanently)
}

//----------------------------------------------------------------------
// Edit zone. label or resource record
//----------------------------------------------------------------------

func (zm *ZoneMaster) edit(w http.ResponseWriter, r *http.Request) {
	// get database id of edited object
	vars := mux.Vars(r)
	var err error
	id, ok := util.CastFromString[int64](vars["id"])
	if !ok {
		err = errors.New("missing edit id")
	} else {
		// create edit data instance
		data := new(NewEditData)
		data.Ref = id
		data.Action = "Edit"
		data.Params = make(map[string]string)

		switch vars["mode"] {

		// edit zone name (type can't be changed)
		case "zone":
			// get all existing zone names (including the edited one!)
			if data.Names, err = zm.zdb.GetNames("zones"); err != nil {
				break
			}
			// get edited zone
			var zone *store.Zone
			if zone, err = zm.zdb.GetZone(id); err != nil {
				break
			}
			// set edit attributes
			data.Params["name"] = zone.Name
			data.Params["keytype"] = guiKeyType(zone.Key.Type)
			data.Params["created"] = guiTime(zone.Created)
			data.Params["modified"] = guiTime(zone.Modified)

			// show dialog
			renderPage(w, data, "edit_zone")
			return

		// edit label name
		case "label":
			// get existing label names (including the edited label!)
			stmt := fmt.Sprintf("labels where zid=%d", id)
			if data.Names, err = zm.zdb.GetNames(stmt); err != nil {
				break
			}
			// get edited label
			var label *store.Label
			if label, err = zm.zdb.GetLabel(id); err != nil {
				return
			}
			// set edit parameters
			data.Params["name"] = label.Name
			data.Params["created"] = guiTime(label.Created)
			data.Params["modified"] = guiTime(label.Modified)

			// show dialog
			renderPage(w, data, "edit_label")
			return

		// edit resource record
		case "rr":
			if err = zm.editRec(w, r, id); err == nil {
				return
			}
		}
	}
	// handle error
	if err != nil {
		_, _ = io.WriteString(w, "ERROR: "+err.Error())
		return
	}
	// redirect back to dashboard
	http.Redirect(w, r, "/", http.StatusMovedPermanently)
}

//----------------------------------------------------------------------

func (zm *ZoneMaster) editRec(w http.ResponseWriter, r *http.Request, id int64) (err error) {
	// get edited resource record
	var rec *store.Record
	if rec, err = zm.zdb.GetRecord(id); err != nil {
		return
	}
	// build map of attribute values
	params := make(map[string]string)
	pf := dlgPrefix[rec.RType]

	// save shared attributes
	params["id"] = util.CastToString(id)
	params["type"] = util.CastToString(rec.RType)
	params["created"] = guiTime(rec.Created)
	params["modified"] = guiTime(rec.Modified)
	if rec.Expire.IsNever() {
		params[pf+"never"] = "on"
	} else {
		params[pf+"expire"] = guiTime(rec.Expire)
	}
	if rec.Flags&enums.GNS_FLAG_PRIVATE != 0 {
		params[pf+"private"] = "on"
	}
	if rec.Flags&enums.GNS_FLAG_SHADOW != 0 {
		params[pf+"shadow"] = "on"
	}
	if rec.Flags&enums.GNS_FLAG_SUPPL != 0 {
		params[pf+"suppl"] = "on"
	}
	// get record instance
	if rr := rr.NewRR(rec.RType); rr != nil {
		// reconstruct record
		if err = data.Unmarshal(rr, rec.Data); err != nil {
			return
		}
		// add RR attributes to list
		rr.ToMap(params)
	}

	// show dialog
	renderPage(w, params, "debug")

	return
}

//----------------------------------------------------------------------
// Remove zone. label or resource record
//----------------------------------------------------------------------

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

// convert GNUnet time to string for GUI
func guiTime(ts util.AbsoluteTime) string {
	if ts.IsNever() {
		return "Never"
	}
	return time.UnixMicro(int64(ts.Val)).Format(timeGUI)
}

// convert zone key type to string
func guiKeyType(t enums.GNSType) string {
	switch t {
	case enums.GNS_TYPE_PKEY:
		return "PKEY"
	case enums.GNS_TYPE_EDKEY:
		return "EDKEY"
	}
	return "???"
}

type DebugData struct {
	Params map[string]string
	RR     string
	Err    error
}
