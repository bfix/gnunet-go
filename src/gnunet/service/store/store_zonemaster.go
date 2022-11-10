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
	"gnunet/service/dht/blocks"
	"gnunet/util"
	"os"
	// "https://github.com/go-zeromq/zmq4"
)

//============================================================
// Zones are named ZonePrivate keys that act as a container
// for labeled resource record sets in GNS.
//============================================================

// Zone is the definition of a local GNS zone
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

// Label is a named container for resource records in a GNS zone.
type Label struct {
	ID       int64             // database id of label
	Zone     int64             // database ID of parent zone
	Name     string            // label name
	Created  util.AbsoluteTime // date of creation
	Modified util.AbsoluteTime // date of last modification
	KeyHash  *crypto.HashCode  // hashcode of the label under zone
}

// NewLabel returns a new label with given name. It is not
// associated with a zone yet.
func NewLabel(label string) *Label {
	lbl := new(Label)
	lbl.ID = 0
	lbl.Zone = 0
	lbl.Name = label
	lbl.Created = util.AbsoluteTimeNow()
	lbl.Modified = util.AbsoluteTimeNow()
	return lbl
}

// SetZone links a label with a zone
func (l *Label) SetZone(z *Zone) error {
	pk, _, err := z.Key.Public().Derive(l.Name, "gns")
	if err != nil {
		return err
	}
	l.Zone = z.ID
	l.KeyHash = crypto.Hash(pk.KeyData)
	return nil
}

//----------------------------------------------------------------------

// Record for GNS resource in a zone (generic). It is the responsibility
// of the caller to provide valid resource data in binary form.
type Record struct {
	ID       int64             // database id of record
	Label    int64             // database ID of parent label
	Created  util.AbsoluteTime // date of creation
	Modified util.AbsoluteTime // date of last modification

	blocks.ResourceRecord
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
	rec.Size = uint16(len(rec.Data))
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
		stmt := "insert into zones(name,created,modified,ztype,zdata,pdata) values(?,?,?,?,?,?)"
		result, err := db.conn.Exec(stmt, z.Name, z.Created.Val, z.Modified.Val, z.Key.Type, z.Key.KeyData, z.Key.Public().KeyData)
		if err != nil {
			return err
		}
		z.ID, err = result.LastInsertId()
		return err
	}
	// check for zone update (name only)
	if len(z.Name) > 0 {
		stmt := "update zones set name=?,modified=? where id=?"
		result, err := db.conn.Exec(stmt, z.Name, z.Modified.Val, z.ID)
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

// GetZone gets a zone with given identifier
func (db *ZoneDB) GetZone(id int64) (zone *Zone, err error) {
	// assemble zone from database row
	stmt := "select name,created,modified,ztype,zdata from zones where id=?"
	zone = new(Zone)
	zone.ID = id
	var ztype enums.GNSType
	var zdata []byte
	row := db.conn.QueryRow(stmt, id)
	if err = row.Scan(&zone.Name, &zone.Created.Val, &zone.Modified.Val, &ztype, &zdata); err == nil {
		// reconstruct private zone key
		zone.Key, err = crypto.NewZonePrivate(ztype, zdata)
	}
	return
}

// GetZones retrieves zone instances from database matching a filter
// ("where" clause)
func (db *ZoneDB) GetZones(filter string, args ...any) (list []*Zone, err error) {
	// assemble query
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

// GetZoneByName gets an identifier with given name
func (db *ZoneDB) GetZoneByName(name string) (ident *Zone, err error) {
	// assemble zone from database row
	stmt := "select id,created,modified,ztype,zdata from zones where name=?"
	row := db.conn.QueryRow(stmt, name)
	ident = new(Zone)
	ident.Name = name
	var ztype enums.GNSType
	var zdata []byte
	if err = row.Scan(&ident.ID, &ident.Created.Val, &ident.Modified.Val, &ztype, &zdata); err == nil {
		// reconstruct private zone key
		ident.Key, err = crypto.NewZonePrivate(ztype, zdata)
	}
	return
}

// GetZoneByKey returns an identifier with given key
func (db *ZoneDB) GetZoneByKey(zk *crypto.ZonePrivate) (ident *Zone, err error) {
	// assemble zone from database row
	stmt := "select id,name,created,modified from zones where zdata=?"
	row := db.conn.QueryRow(stmt, zk.KeyData)
	ident = new(Zone)
	ident.Key = zk
	err = row.Scan(&ident.ID, &ident.Name, &ident.Created.Val, &ident.Modified.Val)
	return
}

// GetZoneByPublicKey returns an identifier with given key
func (db *ZoneDB) GetZoneByPublicKey(zk *crypto.ZoneKey) (ident *Zone, err error) {
	// assemble zone from database row
	stmt := "select id,name,created,modified,ztype,zdata from zones where pdata=?"
	row := db.conn.QueryRow(stmt, zk.KeyData)
	ident = new(Zone)
	var ztype enums.GNSType
	var zdata []byte
	if err = row.Scan(&ident.ID, &ident.Name, &ident.Created.Val, &ident.Modified.Val, &ztype, &zdata); err == nil {
		ident.Key, err = crypto.NewZonePrivate(ztype, zdata)
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
		stmt := "insert into labels(zid,name,created,modified,keyhash) values(?,?,?,?,?)"
		result, err := db.conn.Exec(stmt, l.Zone, l.Name, l.Created.Val, l.Modified.Val, l.KeyHash.Data)
		if err != nil {
			return err
		}
		l.ID, err = result.LastInsertId()
		return err
	}
	// check for label update (name only)
	if len(l.Name) > 0 {
		stmt := "update labels set name=?,modified=? where id=?"
		result, err := db.conn.Exec(stmt, l.Name, l.Modified.Val, l.ID)
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

// GetLabel gets a label with given identifier
func (db *ZoneDB) GetLabel(id int64) (label *Label, err error) {
	// assemble label from database row
	stmt := "select zid,name,created,modified from labels where id=?"
	label = new(Label)
	row := db.conn.QueryRow(stmt, id)
	err = row.Scan(&label.Zone, &label.Name, &label.Created.Val, &label.Modified.Val)
	return
}

// GetLabelByKeyHash returns a label with given query hash
func (db *ZoneDB) GetLabelByKeyHash(hsh *crypto.HashCode) (label *Label, err error) {
	// assemble label from database row
	stmt := "select id,zid,name,created,modified from labels where keyhash=?"
	label = new(Label)
	label.KeyHash = hsh
	row := db.conn.QueryRow(stmt, hsh)
	err = row.Scan(&label.ID, &label.Zone, &label.Name, &label.Created.Val, &label.Modified.Val)
	return
}

// GetLabelByName gets a label with given name and zone. Create label on
// demand ('create' flag) if 'zid' is not 0.
func (db *ZoneDB) GetLabelByName(name string, zid int64, create bool) (label *Label, err error) {
	// assemble label from database row
	stmt := "select id,created,modified from labels where name=? and zid=?"
	label = new(Label)
	label.Name = name
	label.Zone = zid
	row := db.conn.QueryRow(stmt, name, zid)
	if err = row.Scan(&label.ID, &label.Created.Val, &label.Modified.Val); err != nil {
		// check for "does not exist"
		if err == sql.ErrNoRows && create {
			err = nil
			label.Created = util.AbsoluteTimeNow()
			label.Modified = util.AbsoluteTimeNow()
			if zid != 0 {
				// yes: create label
				label.Zone = zid
				stmt = "insert into labels(zid,name,created,modified) values(?,?,?,?)"
				var res sql.Result
				if res, err = db.conn.Exec(stmt, zid, name, label.Created.Val, label.Modified.Val); err != nil {
					return
				}
				label.ID, err = res.LastInsertId()
			}
		}
	}
	return
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

func (db *ZoneDB) GetLabelIDs(zk *crypto.ZonePrivate) (list []int64, zid int64, err error) {
	// get zone database id
	row := db.conn.QueryRow("select id from zones where ztype=? and zdata=?", zk.Type, zk.KeyData)
	if err = row.Scan(&zid); err != nil {
		return
	}
	// select all labels for zone
	var rows *sql.Rows
	if rows, err = db.conn.Query("select id from labels where zid=?", zid); err != nil {
		return
	}
	defer rows.Close()
	var id int64
	for rows.Next() {
		if err = rows.Scan(&id); err != nil {
			return
		}
		list = append(list, id)
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
		exp = new(uint64)
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
		stmt := "update records set lid=?,expire=?,modified=?,flags=?,rtype=?,rdata=? where id=?"
		result, err := db.conn.Exec(stmt, r.Label, exp, r.Modified.Val, r.Flags, r.RType, r.Data, r.ID)
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

// GetRecord gets a resource record with given identifier
func (db *ZoneDB) GetRecord(id int64) (rec *Record, err error) {
	// assemble resource record from database row
	stmt := "select lid,expire,created,modified,flags,rtype,rdata from records where id=?"
	rec = new(Record)
	row := db.conn.QueryRow(stmt, id)
	var exp *uint64
	if err = row.Scan(&rec.Label, &exp, &rec.Created.Val, &rec.Modified.Val, &rec.Flags, &rec.RType, &rec.Data); err != nil {
		// terminate on error
		return
	}
	// setup missing fields
	rec.Size = uint16(len(rec.Data))
	if exp != nil {
		rec.Expire.Val = *exp
	} else {
		rec.Expire = util.AbsoluteTimeNever()
	}
	return
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
		rec.Size = uint16(len(rec.Data))
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
	PubID  string
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
			PubID:  z.Key.Public().ID(),
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

// GetName returns an object name (zone,label) for given id
func (db *ZoneDB) GetName(tbl string, id int64) (name string, err error) {
	row := db.conn.QueryRow("select name from "+tbl+" where id=?", id)
	err = row.Scan(&name)
	return
}

// GetNames returns a list of used names (table "zones" and "labels")
func (db *ZoneDB) GetNames(tbl string) (names []string, err error) {
	// select all table names
	var rows *sql.Rows
	if rows, err = db.conn.Query("select name from " + tbl); err != nil {
		return
	}
	// process names
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

// GetRRTypes returns a list record types stored under a label
func (db *ZoneDB) GetRRTypes(lid int64) (rrtypes []*enums.GNSSpec, label string, err error) {
	// select label name
	row := db.conn.QueryRow("select name from labels where id=?", lid)
	if err = row.Scan(&label); err != nil {
		return
	}
	// select all record types under label
	stmt := "select rtype,flags from records where lid=?"
	var rows *sql.Rows
	if rows, err = db.conn.Query(stmt, lid); err != nil {
		return
	}
	// process records
	defer rows.Close()
	for rows.Next() {
		e := new(enums.GNSSpec)
		if err = rows.Scan(&e.Type, &e.Flags); err != nil {
			// terminate on error; return list so far
			return
		}
		// append to result list
		rrtypes = append(rrtypes, e)
	}
	return
}
