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
	"gnunet/config"
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

	"github.com/bfix/gospel/logger"
	"github.com/gorilla/mux"
)

//======================================================================
// HTTP service
//======================================================================

//go:embed gui.htpl gui_css.htpl gui_rr.htpl gui_debug.htpl gui_edit.htpl gui_new.htpl
var fsys embed.FS

var (
	tpl      *template.Template   // HTML templates
	timeHTML = "2006-01-02T15:04" // time format (defined by HTML, don't change!)
	timeGUI  = "02.01.06 15:04"   // time format for GUI
)

// state-change constants
const (
	ChangeNew = iota
	ChangeUpdate
	ChangeDelete
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
		"setspecs": func(data map[string]string, spec enums.GNSSpec) string {
			pf := guiPrefix(spec.Type)
			data["prefix"] = pf
			if spec.Flags&enums.GNS_FLAG_PRIVATE != 0 {
				data[pf+"private"] = "on"
			}
			if spec.Flags&enums.GNS_FLAG_SHADOW != 0 {
				data[pf+"shadow"] = "on"
			}
			if spec.Flags&enums.GNS_FLAG_SUPPL != 0 {
				data[pf+"suppl"] = "on"
			}
			return pf
		},
		"boxprotos": func() map[uint16]string {
			return rr.GetProtocols()
		},
		"boxsvcs": func() map[uint16]string {
			return rr.GetServices()
		},
		"rrtype": func(t enums.GNSType) string {
			return strings.Replace(t.String(), "GNS_TYPE_", "", -1)
		},
		"rritype": func(ts string) string {
			t, _ := util.CastFromString[enums.GNSType](ts)
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
			return guiRRdata(t, buf)
		},
		"tabSetList": func(num int) (list map[int]int) {
			list = make(map[int]int)
			for i := 0; i < num; i++ {
				list[i+1] = 2*i + 1
			}
			return
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
		Addr:              config.Cfg.ZoneMaster.GUI,
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
	// prepare variables and form values
	vars := mux.Vars(r)
	mode := vars["mode"]
	id, ok := util.CastFromString[int64](vars["id"])
	_ = r.ParseForm()

	var err error
	if ok {
		switch vars["cmd"] {
		case "new":
			err = zm.actionNew(w, r, mode, id)
		case "upd":
			err = zm.actionUpd(w, r, mode, id)
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

		// notify listeners
		zm.OnChange("zones", zone.ID, ChangeNew)

	// new label
	case "label":
		name := r.FormValue("name")
		// add label to database
		label := store.NewLabel(name)
		label.Zone = id
		err = zm.zdb.SetLabel(label)

		// notify listeners
		zm.OnChange("labels", label.ID, ChangeNew)

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

	// construct RR data
	exp, flags := guiParse(params, pf)
	rrdata, err := Map2RRData(t, params)
	if err == nil {
		// assemble record and store in database
		rr := store.NewRecord(exp, t, flags, rrdata)
		rr.Label = label
		err = zm.zdb.SetRecord(rr)

		// notify listeners
		zm.OnChange("records", rr.ID, ChangeNew)
	}
	return err
}

//----------------------------------------------------------------------
// UPD: update zone, label or resource record
//----------------------------------------------------------------------

func (zm *ZoneMaster) actionUpd(w http.ResponseWriter, r *http.Request, mode string, id int64) (err error) {
	// handle type
	switch mode {
	case "zone":
		// update zone name in database
		var zone *store.Zone
		if zone, err = zm.zdb.GetZone(id); err != nil {
			return
		}
		zone.Name = r.FormValue("name")
		zone.Modified = util.AbsoluteTimeNow()
		err = zm.zdb.SetZone(zone)

		// notify listeners
		zm.OnChange("zones", zone.ID, ChangeUpdate)

	case "label":
		// update label name
		label := store.NewLabel(r.FormValue("name"))
		label.ID = id
		label.Modified = util.AbsoluteTimeNow()
		err = zm.zdb.SetLabel(label)

		// notify listeners
		zm.OnChange("labels", label.ID, ChangeUpdate)

	case "rr":
		// update record
		err = zm.updRec(w, r, id)
	}
	return
}

//----------------------------------------------------------------------

// update resource record
func (zm *ZoneMaster) updRec(w http.ResponseWriter, r *http.Request, id int64) error {
	// get list of parameters from resource record dialog
	oldParams := make(map[string]string)
	newParams := make(map[string]string)
	for key, val := range r.Form {
		v := strings.Join(val, ",")
		if strings.HasPrefix(key, "old_") {
			oldParams[key[4:]] = v
		} else {
			newParams[key] = v
		}
	}
	// parse RR type (and set prefix for map keys)
	t, ok := util.CastFromString[enums.GNSType](oldParams["type"])
	if !ok {
		return errors.New("new: missing resource record type")
	}
	pf := guiPrefix(t)

	// check for changed resource record
	changed := false
	for key, val := range newParams {
		old, ok := oldParams[key]
		if ok && old != val {
			changed = true
			break
		}
	}
	if changed {
		// reconstruct record from GUI parameters
		rrData, err := Map2RRData(t, newParams)
		if err != nil {
			return err
		}
		exp, flags := guiParse(newParams, pf)
		rec := store.NewRecord(exp, t, flags, rrData)
		rec.ID = id
		rec.Label, _ = util.CastFromString[int64](newParams["lid"])

		// update in database
		if err := zm.zdb.SetRecord(rec); err != nil {
			return err
		}

		// notify listeners
		zm.OnChange("records", rec.ID, ChangeUpdate)
	}
	return nil
}

//----------------------------------------------------------------------
// Create new zone. label or resource record
//----------------------------------------------------------------------

type NewEditData struct {
	Ref     int64             // database id of reference object
	Action  string            // "new" or "upd" action
	Button  string            // "Add new" or "Update"
	Names   []string          // list of names in use (ZONE,LABEL)
	RRspecs []*enums.GNSSpec  // list of allowed record types and flags (REC)
	Params  map[string]string // list of current values
}

func (zm *ZoneMaster) new(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	var err error
	data := new(NewEditData)
	data.Action = "new"
	data.Button = "Add new"
	data.Params = make(map[string]string)
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
			data.Params["zone"], _ = zm.zdb.GetName("zones", id)
			data.Params["zid"] = util.CastToString(id)
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
			data.RRspecs = compatibleRR(rrs, label)
			data.Ref = id
			data.Params["label"] = label
			data.Params["lid"] = util.CastToString(id)
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
// Edit zone, label or resource record
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
		data.Action = "upd"
		data.Button = "Update"
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
			data.Params["keydata"] = zone.Key.Public().ID()
			data.Params["prvdata"] = zone.Key.ID()
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
			data.Params["zone"], _ = zm.zdb.GetName("zones", id)
			data.Params["zid"] = util.CastToString(label.Zone)
			data.Params["name"] = label.Name
			data.Params["created"] = guiTime(label.Created)
			data.Params["modified"] = guiTime(label.Modified)

			// show dialog
			renderPage(w, data, "edit_label")
			return

		// edit resource record
		case "rr":
			if err = zm.editRec(w, r, data); err == nil {
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

func (zm *ZoneMaster) editRec(w http.ResponseWriter, r *http.Request, data *NewEditData) (err error) {
	// get edited resource record
	var rec *store.Record
	if rec, err = zm.zdb.GetRecord(data.Ref); err != nil {
		return
	}
	// build map of attribute values
	pf := dlgPrefix[rec.RType]

	// save shared attributes
	data.Params["prefix"] = pf
	data.Params["type"] = util.CastToString(int(rec.RType))
	data.Params["created"] = guiTime(rec.Created)
	data.Params["modified"] = guiTime(rec.Modified)
	data.Params["label"], _ = zm.zdb.GetName("labels", rec.Label)
	data.Params["lid"] = util.CastToString(rec.Label)
	if rec.Expire.IsNever() {
		data.Params[pf+"never"] = "on"
	} else {
		data.Params[pf+"expires"] = htmlTime(rec.Expire)
	}
	if rec.Flags&enums.GNS_FLAG_PRIVATE != 0 {
		data.Params[pf+"private"] = "on"
	}
	if rec.Flags&enums.GNS_FLAG_SHADOW != 0 {
		data.Params[pf+"shadow"] = "on"
	}
	if rec.Flags&enums.GNS_FLAG_SUPPL != 0 {
		data.Params[pf+"suppl"] = "on"
	}
	// get record instance
	var inst rr.RR
	if inst, err = rr.ParseRR(rec.RType, rec.Data); err == nil {
		// add RR attributes to list
		inst.ToMap(data.Params, pf)
	}
	// show dialog
	renderPage(w, data, "edit_rec")
	return
}

//----------------------------------------------------------------------
// Remove zone. label or resource record
//----------------------------------------------------------------------

func (zm *ZoneMaster) remove(w http.ResponseWriter, r *http.Request) {
	// get database id of edited object
	vars := mux.Vars(r)
	var err error
	id, ok := util.CastFromString[int64](vars["id"])
	if !ok {
		err = errors.New("missing remove id")
	} else {
		switch vars["mode"] {

		// remove zone
		case "zone":
			// get zone from database
			var zone *store.Zone
			if zone, err = zm.zdb.GetZone(id); err != nil {
				return
			}
			// remove zone in database
			zone.Name = ""
			if err = zm.zdb.SetZone(zone); err != nil {
				return
			}
			zm.OnChange("zones", id, ChangeDelete)

		// remove label
		case "label":
			label := store.NewLabel("")
			label.ID = id
			if err = zm.zdb.SetLabel(label); err != nil {
				return
			}
			zm.OnChange("labels", id, ChangeDelete)

		// remove resource record
		case "rr":
			rec := new(store.Record)
			rec.ID = id
			rec.Label = 0
			if err = zm.zdb.SetRecord(rec); err != nil {
				return
			}
			zm.OnChange("records", id, ChangeDelete)
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

//======================================================================
// Helper methods
//======================================================================

// MainData for the template "main"
type MainData struct {
	Content string // Page content
	Params  any    // reference to parameters
	NumRR   int    // number of RR types supported
}

// render a webpage with given data and template reference
func renderPage(w io.Writer, data any, page string) {
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
	md := new(MainData)
	md.Params = data
	md.Content = content.String()
	md.NumRR = len(rrtypes)
	if err := t.Execute(w, md); err != nil {
		_, _ = io.WriteString(w, err.Error())
	}
}

//----------------------------------------------------------------------
// Debug rendering
//----------------------------------------------------------------------

// DebugData for error page
type DebugData struct {
	Params map[string]string
	RR     string
	Err    error
}
