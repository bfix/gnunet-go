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

// Record for GNS resource in a zone (generic). It is the responsibility
// of the caller to provide valid resource data in binary form.
type Record struct {
	ID       int64             // database id of record
	Zone     int64             // database ID of parent zone
	Name     string            // record name
	Created  util.AbsoluteTime // date of creation
	Modified util.AbsoluteTime // date of last modification

	message.ResourceRecord
}

// NewRecord creates a new record for given data. The record is not
// automatically added to the database.
func NewRecord(expire util.AbsoluteTime, rtype enums.GNSType, flags enums.GNSFlag, data []byte) *Record {
	rec := new(Record)
	rec.Zone = 0
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
	// remove zone from database: also move all dependent resource
	// records into "trash bin" (parent zone reference is nil)
	if _, err := db.conn.Exec("update records set zid=null where zid=?", z.ID); err != nil {
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
// Record handling handling
//----------------------------------------------------------------------

// SetRecord inserts, updates or deletes a record in the database.
// The function does not change timestamps which are in the
// responsibility of the caller.
//   - insert: Record.ID is nil (0)
//   - update: Record.ZID is set (eventually modified)
//   - remove: otherwise
func (db *ZoneDB) SetRecord(r *Record) error {
	// check for record insert
	if r.ID == 0 {
		stmt := "insert into records(zid,name,expire,created,modified,flags,rtype,rdata) values(?,?,?,?,?,?,?,?)"
		result, err := db.conn.Exec(stmt, r.Zone, r.Name, r.Expire.Val, r.Created.Val, r.Modified.Val, r.Flags, r.RType, r.Data)
		if err != nil {
			return err
		}
		r.ID, err = result.LastInsertId()
		return err
	}
	// check for record update
	if r.Zone != 0 {
		stmt := "update records set zid=?,name=?,expire=?,created=?,modified=?,flags=?,rtype=?,rdata=? where id=?"
		result, err := db.conn.Exec(stmt, r.Zone, r.Name, r.Expire.Val, r.Created.Val, r.Modified.Val, r.Flags, r.RType, r.Data, r.ID)
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
	stmt := "select id,zid,expire,created,modified,flags,rtype,rdata from records"
	if len(filter) > 0 {
		stmt += " where " + fmt.Sprintf(filter, args...)
	}
	// select records
	var rows *sql.Rows
	if rows, err = db.conn.Query(stmt); err != nil {
		return
	}
	// process zones
	defer rows.Close()
	for rows.Next() {
		// assemble zone from database row
		rec := new(Record)
		if err = rows.Scan(&rec.ID, &rec.Zone, &rec.Expire.Val, &rec.Created.Val, &rec.Modified.Val, &rec.Flags, &rec.RType, &rec.Data); err != nil {
			// terminate on error; return list so far
			return
		}
		rec.Size = uint32(len(rec.Data))
		// append to result list
		list = append(list, rec)
	}
	return
}
