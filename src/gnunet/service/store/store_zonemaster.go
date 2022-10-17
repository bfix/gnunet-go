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

package store

import (
	"database/sql"
	_ "embed"
	"errors"
	"fmt"
	"gnunet/crypto"
	"gnunet/enums"
	"gnunet/message"
	"gnunet/util"
	"os"
	// "https://github.com/go-zeromq/zmq4"
)

//============================================================
// Local zone records stored in SQLite3 database
//============================================================

// Zone is the definition of a local GNS zone
// and is stored in a SQL database for faster access.
type Zone struct {
	ID       int64               // database identifier
	Name     string              // zone name
	Created  util.AbsoluteTime   // date of creation
	Modified util.AbsoluteTime   // date of last modification
	Key      *crypto.ZonePrivate // private zone key (ztype|zdata)
}

// NewZone creates a new zone for the given private key. The zone is not stored
// in the database automatically.
func NewZone(name string, sk *crypto.ZonePrivate) *Zone {
	// create zone instance
	return &Zone{
		Name:     name,
		Created:  util.AbsoluteTimeNow(),
		Modified: util.AbsoluteTimeNow(),
		Key:      sk,
	}
}

//----------------------------------------------------------------------

type Label struct {
	ID       int64             // database id of label
	Zone     int64             // database ID of parent zone
	Name     string            // label name
	Created  util.AbsoluteTime // date of creation
	Modified util.AbsoluteTime // date of last modification
}

func NewLabel(label string) *Label {
	lbl := new(Label)
	lbl.ID = 0
	lbl.Zone = 0
	lbl.Name = label
	lbl.Created = util.AbsoluteTimeNow()
	lbl.Modified = util.AbsoluteTimeNow()
	return lbl
}

//----------------------------------------------------------------------

// Record for GNS resource in a zone (generic). It is the responsibility
// of the caller to provide valid resource data in binary form.
type Record struct {
	ID       int64             // database id of record
	Label    int64             // database ID of parent label
	Created  util.AbsoluteTime // date of creation
	Modified util.AbsoluteTime // date of last modification

	message.ResourceRecord
}

// NewRecord creates a new record for given data. The record is not
// automatically added to the database.
func NewRecord(expire util.AbsoluteTime, rtype enums.GNSType, flags enums.GNSFlag, data []byte) *Record {
	rec := new(Record)
	rec.ID = 0
	rec.Label = 0
	rec.Expire = expire
	rec.RType = rtype
	rec.Flags = flags
	rec.Data = data
	rec.Size = uint32(len(rec.Data))
	rec.Created = util.AbsoluteTimeNow()
	rec.Modified = util.AbsoluteTimeNow()
	return rec
}

//======================================================================
// Zone database: A SQLite3 database to hold metadata about
// managed local zones (see "namestore" in gnunet).
//======================================================================

//go:embed store_zonemaster.sql
var initScriptZM []byte

// ZoneDB is a SQLite3 database for locally managed zones
type ZoneDB struct {
	conn *DBConn // database connection
}

// OpenZoneDB opens a zone database in the given filename (including
// path). If the database file does not exist, it is created and
// set up with empty tables.
func OpenZoneDB(fname string) (db *ZoneDB, err error) {
	// connect to database
	if _, err = os.Stat(fname); err != nil {
		var file *os.File
		if file, err = os.Create(fname); err != nil {
			return
		}
		file.Close()
	}
	db = new(ZoneDB)
	if db.conn, err = DBPool.Connect("sqlite3:" + fname); err != nil {
		return
	}
	// check for initialized database
	res := db.conn.QueryRow("select name from sqlite_master where type='table' and name='zones'")
	var s string
	if res.Scan(&s) != nil {
		// initialize database
		if _, err = db.conn.Exec(string(initScriptZM)); err != nil {
			return
		}
	}
	return
}

// Close zone database
func (db *ZoneDB) Close() error {
	return db.conn.Close()
}

//----------------------------------------------------------------------
// Zone handling
//----------------------------------------------------------------------

// SetZone inserts, updates or deletes a zone in the database.
// The function does not change timestamps which are in the
// responsibility of the caller.
//   - insert: Zone.ID is nil (0)
//   - update: Zone.Name is set
//   - remove: otherwise
func (db *ZoneDB) SetZone(z *Zone) error {
	// check for zone insert
	if z.ID == 0 {
		stmt := "insert into zones(name,created,modified,ztype,zdata) values(?,?,?,?,?)"
		result, err := db.conn.Exec(stmt, z.Name, z.Created.Val, z.Modified.Val, z.Key.Type, z.Key.KeyData)
		if err != nil {
			return err
		}
		z.ID, err = result.LastInsertId()
		return err
	}
	// check for zone update
	if len(z.Name) > 0 {
		stmt := "update zones set name=?,created=?,modified=?,ztype=?,zdata=? where id=?"
		result, err := db.conn.Exec(stmt, z.Name, z.Created.Val, z.Modified.Val, z.Key.Type, z.Key.KeyData, z.ID)
		if err != nil {
			return err
		}
		var num int64
		if num, err = result.RowsAffected(); err == nil {
			if num != 1 {
				err = errors.New("update zone failed")
			}
		}
		return err
	}
	// remove zone from database: also move all dependent labels to "trash bin"
	// (parent zone reference is nil)
	if _, err := db.conn.Exec("update labels set zid=null where zid=?", z.ID); err != nil {
		return err
	}
	_, err := db.conn.Exec("delete from zones where id=?", z.ID)
	return err
}

// GetZones retrieves zone instances from database matching a filter
// ("where" clause)
func (db *ZoneDB) GetZones(filter string, args ...any) (list []*Zone, err error) {
	// assemble querey
	stmt := "select id,name,created,modified,ztype,zdata from zones"
	if len(filter) > 0 {
		stmt += " where " + fmt.Sprintf(filter, args...)
	}
	// select zones
	var rows *sql.Rows
	if rows, err = db.conn.Query(stmt); err != nil {
		return
	}
	// process zones
	defer rows.Close()
	for rows.Next() {
		// assemble zone from database row
		zone := new(Zone)
		var ztype enums.GNSType
		var zdata []byte
		if err = rows.Scan(&zone.ID, &zone.Name, &zone.Created.Val, &zone.Modified.Val, &ztype, &zdata); err != nil {
			// terminate on error; return list so far
			return
		}
		// reconstruct private zone key
		if zone.Key, err = crypto.NewZonePrivate(ztype, zdata); err != nil {
			return
		}
		// append to result list
		list = append(list, zone)
	}
	return
}

//----------------------------------------------------------------------
// Label handling
//----------------------------------------------------------------------

// SetLabel inserts, updates or deletes a zone label in the database.
// The function does not change timestamps which are in the
// responsibility of the caller.
//   - insert: Label.ID is nil (0)
//   - update: Label.Name is set (eventually modified)
//   - remove: otherwise
func (db *ZoneDB) SetLabel(l *Label) error {
	// check for label insert
	if l.ID == 0 {
		stmt := "insert into labels(zid,name,created,modified) values(?,?,?,?)"
		result, err := db.conn.Exec(stmt, l.Zone, l.Name, l.Created.Val, l.Modified.Val)
		if err != nil {
			return err
		}
		l.ID, err = result.LastInsertId()
		return err
	}
	// check for label update
	if len(l.Name) > 0 {
		stmt := "update labels set zid=?,name=?,created=?,modified=? where id=?"
		result, err := db.conn.Exec(stmt, l.Zone, l.Name, l.Created.Val, l.Modified.Val, l.ID)
		if err != nil {
			return err
		}
		var num int64
		if num, err = result.RowsAffected(); err == nil {
			if num != 1 {
				err = errors.New("update label failed")
			}
		}
		return err
	}
	// remove label from database; move dependent records to trash bin
	// (label id set to nil)
	if _, err := db.conn.Exec("update records set lid=null where lid=?", l.ID); err != nil {
		return err
	}
	_, err := db.conn.Exec("delete from labels where id=?", l.ID)
	return err
}

// GetLabels retrieves record instances from database matching a filter
// ("where" clause)
func (db *ZoneDB) GetLabels(filter string, args ...any) (list []*Label, err error) {
	// assemble querey
	stmt := "select id,zid,name,created,modified from labels"
	if len(filter) > 0 {
		stmt += " where " + fmt.Sprintf(filter, args...)
	}
	// select labels
	var rows *sql.Rows
	if rows, err = db.conn.Query(stmt); err != nil {
		return
	}
	// process labels
	defer rows.Close()
	for rows.Next() {
		// assemble label from database row
		lbl := new(Label)
		if err = rows.Scan(&lbl.ID, &lbl.Zone, &lbl.Name, &lbl.Created.Val, &lbl.Modified.Val); err != nil {
			// terminate on error; return list so far
			return
		}
		// append to result list
		list = append(list, lbl)
	}
	return
}

//----------------------------------------------------------------------
// Record handling
//----------------------------------------------------------------------

// SetRecord inserts, updates or deletes a record in the database.
// The function does not change timestamps which are in the
// responsibility of the caller.
//   - insert: Record.ID is nil (0)
//   - update: Record.ZID is set (eventually modified)
//   - remove: otherwise
func (db *ZoneDB) SetRecord(r *Record) error {
	// work around a SQLite3 bug when storing uint64 with high bit set
	var exp *uint64
	if !r.Expire.IsNever() {
		*exp = r.Expire.Val
	}
	// check for record insert
	if r.ID == 0 {
		stmt := "insert into records(lid,expire,created,modified,flags,rtype,rdata) values(?,?,?,?,?,?,?)"
		result, err := db.conn.Exec(stmt, r.Label, exp, r.Created.Val, r.Modified.Val, r.Flags, r.RType, r.Data)
		if err != nil {
			return err
		}
		r.ID, err = result.LastInsertId()
		return err
	}
	// check for record update
	if r.Label != 0 {
		stmt := "update records set lid=?,expire=?,created=?,modified=?,flags=?,rtype=?,rdata=? where id=?"
		result, err := db.conn.Exec(stmt, r.Label, exp, r.Created.Val, r.Modified.Val, r.Flags, r.RType, r.Data, r.ID)
		if err != nil {
			return err
		}
		var num int64
		if num, err = result.RowsAffected(); err == nil {
			if num != 1 {
				err = errors.New("update record failed")
			}
		}
		return err
	}
	// remove record from database
	_, err := db.conn.Exec("delete from records where id=?", r.ID)
	return err
}

// GetRecords retrieves record instances from database matching a filter
// ("where" clause)
func (db *ZoneDB) GetRecords(filter string, args ...any) (list []*Record, err error) {
	// assemble querey
	stmt := "select id,lid,expire,created,modified,flags,rtype,rdata from records"
	if len(filter) > 0 {
		stmt += " where " + fmt.Sprintf(filter, args...)
	}
	// select records
	var rows *sql.Rows
	if rows, err = db.conn.Query(stmt); err != nil {
		return
	}
	// process records
	defer rows.Close()
	for rows.Next() {
		// assemble record from database row
		rec := new(Record)
		var exp *uint64
		if err = rows.Scan(&rec.ID, &rec.Label, &exp, &rec.Created.Val, &rec.Modified.Val, &rec.Flags, &rec.RType, &rec.Data); err != nil {
			// terminate on error; return list so far
			return
		}
		rec.Size = uint32(len(rec.Data))
		if exp != nil {
			rec.Expire.Val = *exp
		} else {
			rec.Expire = util.AbsoluteTimeNever()
		}
		// append to result list
		list = append(list, rec)
	}
	return
}

//----------------------------------------------------------------------
// Retrieve database content as a nested struct
//----------------------------------------------------------------------

// LabelGroup is a nested label entry (with records)
type LabelGroup struct {
	Label   *Label
	Records []*Record
}

// ZoneGroup is a nested zone entry (with labels)
type ZoneGroup struct {
	Zone   *Zone
	Labels []*LabelGroup
}

// GetContent returns the database content as a nested list of zones, labels
// and records. Since the use-case for the ZoneManager is the management of
// local zones, the number of entries is limited.
func (db *ZoneDB) GetContent() (zg []*ZoneGroup, err error) {
	// get all zones
	var zones []*Zone
	if zones, err = db.GetZones(""); err != nil {
		return
	}
	for _, z := range zones {
		// create group instance for zone
		zGroup := &ZoneGroup{
			Zone:   z,
			Labels: make([]*LabelGroup, 0),
		}
		zg = append(zg, zGroup)

		// get all labels for zone
		var labels []*Label
		if labels, err = db.GetLabels("zid=%d", z.ID); err != nil {
			return
		}
		for _, l := range labels {
			// create group instance for label
			lGroup := &LabelGroup{
				Label:   l,
				Records: make([]*Record, 0),
			}
			// link to zone group
			zGroup.Labels = append(zGroup.Labels, lGroup)

			// get all records for label
			lGroup.Records, err = db.GetRecords("lid=%d", l.ID)
		}
	}
	return
}

//----------------------------------------------------------------------
// Retrieve list of used names (Zone,Label) or RR types (Record)
//----------------------------------------------------------------------

// GetNames returns a list of used names (table "zones" and "labels")
func (db *ZoneDB) GetNames(tbl string) (names []string, err error) {
	// select all zone names
	stmt := fmt.Sprintf("select name from %s", tbl)
	var rows *sql.Rows
	if rows, err = db.conn.Query(stmt); err != nil {
		return
	}
	// process zones
	defer rows.Close()
	var name string
	for rows.Next() {
		if err = rows.Scan(&name); err != nil {
			// terminate on error; return list so far
			return
		}
		// append to result list
		names = append(names, name)
	}
	return
}

// RRData contains the type and flags of a resource record
type RRData struct {
	Type  enums.GNSType
	Flags enums.GNSFlag
}

// GetRRTypes returns a list record types stored under a label
func (db *ZoneDB) GetRRTypes(lid int64) (rrtypes []*RRData, err error) {
	// select all record types under label
	stmt := fmt.Sprintf("select rtype,flags from records where lid=%d", lid)
	var rows *sql.Rows
	if rows, err = db.conn.Query(stmt); err != nil {
		return
	}
	// process records
	defer rows.Close()
	for rows.Next() {
		e := new(RRData)
		if err = rows.Scan(&e.Type, &e.Flags); err != nil {
			// terminate on error; return list so far
			return
		}
		// append to result list
		rrtypes = append(rrtypes, e)
	}
	return
}
