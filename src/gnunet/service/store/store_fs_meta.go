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
	"gnunet/util"
	"os"
)

//============================================================
// Metadata handling for file storage
//============================================================

// FileMetadata holds information about a file (raw block data)
// and is stored in a SQL database for faster access.
type FileMetadata struct {
	key       []byte            // storage key
	size      uint64            // size of file
	btype     uint16            // block type
	stored    util.AbsoluteTime // time added to store
	expires   util.AbsoluteTime // expiration time
	lastUsed  util.AbsoluteTime // time last used
	usedCount uint64            // usage count
}

//------------------------------------------------------------
// Metadata database: A SQLite3 database to hold metadata about
// blocks in file storage
//------------------------------------------------------------

//go:embed store_fs_meta.sql
var initScript []byte

// FileMetaDB is a SQLite3 database for block metadata
type FileMetaDB struct {
	conn *DbConn // database connection
}

// OpenMetaDB opens a metadata database in the given path. The name of the
// database is "access.db".
func OpenMetaDB(path string) (db *FileMetaDB, err error) {
	// connect to database
	dbFile := path + "/acccess.db"
	if _, err = os.Stat(path + "/acccess.db"); err != nil {
		var file *os.File
		if file, err = os.Create(dbFile); err != nil {
			return
		}
		file.Close()
	}
	db = new(FileMetaDB)
	if db.conn, err = DbPool.Connect("sqlite3:" + dbFile); err != nil {
		return
	}
	// check for initialized database
	res := db.conn.QueryRow("select name from sqlite_master where type='table' and name='meta'")
	var s string
	if res.Scan(&s) != nil {
		// initialize database
		if _, err = db.conn.Exec(string(initScript)); err != nil {
			return
		}
	}
	return
}

// Store metadata in database: creates or updates a record for the metadata
// in the database; primary key is the query key
func (db *FileMetaDB) Store(md *FileMetadata) (err error) {
	sql := "replace into meta(qkey,btype,size,stored,expires,lastUsed,usedCount) values(?,?,?,?,?,?,?)"
	_, err = db.conn.Exec(sql, md.key, md.btype, md.size, md.stored.Epoch(), md.expires.Epoch(), md.lastUsed.Epoch(), md.usedCount)
	return
}

// Get block metadata from database
func (db *FileMetaDB) Get(key []byte, btype uint16) (md *FileMetadata, err error) {
	md = new(FileMetadata)
	md.key = util.Clone(key)
	md.btype = btype
	stmt := "select size,stored,expires,lastUsed,usedCount from meta where qkey=? and btype=?"
	row := db.conn.QueryRow(stmt, key, btype)
	var st, exp, lu uint64
	if err = row.Scan(&md.size, &st, &exp, &lu, &md.usedCount); err == sql.ErrNoRows {
		md = nil
		err = nil
	} else {
		md.stored.Val = st * 1000000
		md.expires.Val = exp * 1000000
		md.lastUsed.Val = lu * 1000000
	}
	return
}

// Drop metadata for block from database
func (db *FileMetaDB) Drop(key []byte, btype uint16) error {
	_, err := db.conn.Exec("delete from meta where qkey=? and btype=?", key, btype)
	return err
}

// Used a block from store: increment usage count and lastUsed time.
func (db *FileMetaDB) Used(key []byte, btype uint16) error {
	_, err := db.conn.Exec("update meta set usedCount=usedCount+1,lastUsed=unixepoch() where qkey=? and btype=?", key, btype)
	return err
}

// Obsolete collects records from the meta database that are considered
// "removable". Entries are rated by the value of "(lifetime * size) / usedCount"
func (db *FileMetaDB) Obsolete(n int) (removable []*FileMetadata, err error) {
	// get obsolete records from database
	rate := "(unixepoch()-unixepoch(stored))*size/usedCount"
	stmt := "select qkey,btype from meta order by " + rate + " limit ?"
	var rows *sql.Rows
	if rows, err = db.conn.Query(stmt, n); err != nil {
		return
	}
	var md *FileMetadata
	for rows.Next() {
		var st, exp, lu uint64
		if err = rows.Scan(&md.key, &md.btype, &md.size, &st, &exp, &lu, &md.usedCount); err != nil {
			return
		}
		md.stored.Val = st * 1000000
		md.expires.Val = exp * 1000000
		md.lastUsed.Val = lu * 1000000
		removable = append(removable, md)
	}
	return
}

// Traverse metadata records and call function on each record
func (db *FileMetaDB) Traverse(f func(*FileMetadata)) error {
	sql := "select qkey,btype,size,stored,expires,lastUsed,usedCount from meta"
	rows, err := db.conn.Query(sql)
	if err != nil {
		return err
	}
	md := new(FileMetadata)
	for rows.Next() {
		var st, exp, lu uint64
		err = rows.Scan(&md.key, &md.btype, &md.size, &st, &exp, &lu, &md.usedCount)
		if err != nil {
			return err
		}
		md.stored.Val = st * 1000000
		md.expires.Val = exp * 1000000
		md.lastUsed.Val = lu * 1000000
		// call process function
		f(md)
	}
	return nil
}

// Close metadata database
func (db *FileMetaDB) Close() error {
	return db.conn.Close()
}
