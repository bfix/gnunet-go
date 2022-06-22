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
	"context"
	"database/sql"
	"fmt"
	"gnunet/util"
	"os"
	"strings"

	_ "github.com/go-sql-driver/mysql" // init MySQL driver
	_ "github.com/mattn/go-sqlite3"    // init SQLite3 driver
)

// Error messages related to databases
var (
	ErrSQLInvalidDatabaseSpec = fmt.Errorf("Invalid database specification")
	ErrSQLNoDatabase          = fmt.Errorf("Database not found")
)

//----------------------------------------------------------------------
// Connection to a database instance. There can be multiple connections
// on the same instance, managed by the database pool.
//----------------------------------------------------------------------

// DbConn is a database connection suitable for executing SQL commands.
type DbConn struct {
	conn   *sql.Conn // connection to database instance
	key    string    // database connect string (identifier for pool)
	engine string    // database engine
}

// Close database connection.
func (db *DbConn) Close() (err error) {
	if err = db.conn.Close(); err != nil {
		return
	}
	err = DbPool.remove(db.key)
	return
}

// QueryRow returns a single record for a query
func (db *DbConn) QueryRow(query string, args ...any) *sql.Row {
	return db.conn.QueryRowContext(DbPool.ctx, query, args...)
}

// Query returns all matching records for a query
func (db *DbConn) Query(query string, args ...any) (*sql.Rows, error) {
	return db.conn.QueryContext(DbPool.ctx, query, args...)
}

// Exec a SQL statement
func (db *DbConn) Exec(query string, args ...any) (sql.Result, error) {
	return db.conn.ExecContext(DbPool.ctx, query, args...)
}

// TODO: add more SQL methods

//----------------------------------------------------------------------
// DbPool holds all database instances used: Connecting with the same
// connect string returns the same instance.
//----------------------------------------------------------------------

// global instance for the database pool (singleton)
var (
	DbPool *dbPool
)

// DbPoolEntry holds information about a database instance.
type DbPoolEntry struct {
	db      *sql.DB // reference to the database engine
	refs    int     // number of open connections (reference count)
	connect string  // SQL connect string
}

// package initialization
func init() {
	// construct database pool
	DbPool = new(dbPool)
	DbPool.insts = util.NewMap[string, *DbPoolEntry]()
	DbPool.ctx, DbPool.cancel = context.WithCancel(context.Background())
}

// dbPool keeps a mapping between connect string and database instance
type dbPool struct {
	ctx    context.Context                 // connection context
	cancel context.CancelFunc              // cancel function
	insts  *util.Map[string, *DbPoolEntry] // map of database instances
}

// remove a database instance from the pool based on its connect string.
func (p *dbPool) remove(key string) error {
	return p.insts.Process(func() (err error) {
		// get pool entry
		pe, ok := p.insts.Get(key)
		if !ok {
			return nil
		}
		// decrement ref count
		pe.refs--
		if pe.refs == 0 {
			// no more refs: close database
			err = pe.db.Close()
			p.insts.Delete(key)
		}
		return
	}, false)
}

// Connect to a SQL database (various types and flavors):
// The 'spec' option defines the arguments required to connect to a database;
// the meaning and format of the arguments depends on the specific SQL database.
// The arguments are seperated by the '+' character; the first (and mandatory)
// argument defines the SQL database type. Other arguments depend on the value
// of this first argument.
// The following SQL types are implemented:
// * 'sqlite3': SQLite3-compatible database; the second argument specifies the
//              file that holds the data (e.g. "sqlite3+/home/user/store.db")
// * 'mysql':   A MySQL-compatible database; the second argument specifies the
//              information required to log into the database (e.g.
//              "[user[:passwd]@][proto[(addr)]]/dbname[?param1=value1&...]").
func (p *dbPool) Connect(spec string) (db *DbConn, err error) {
	err = p.insts.Process(func() error {
		// check if we have a connection to this database.
		db = new(DbConn)
		inst, ok := p.insts.Get(spec)
		if !ok {
			inst = new(DbPoolEntry)
			inst.refs = 0
			inst.connect = spec

			// No: create new database instance.
			// split spec string into segments
			specs := strings.Split(spec, ":")
			if len(specs) < 2 {
				return ErrSQLInvalidDatabaseSpec
			}
			// create database object
			db.engine = specs[0]
			switch db.engine {
			case "sqlite3":
				// check if the database file exists
				var fi os.FileInfo
				if fi, err = os.Stat(specs[1]); err != nil {
					return ErrSQLNoDatabase
				}
				if fi.IsDir() {
					return ErrSQLNoDatabase
				}
				// open the database file
				inst.db, err = sql.Open("sqlite3", specs[1])
			case "mysql":
				// just connect to the database
				inst.db, err = sql.Open("mysql", specs[1])
			default:
				return ErrSQLInvalidDatabaseSpec
			}
			// save database in pool
			p.insts.Put(spec, inst)
			ok = true
		}
		// increment reference count
		inst.refs++
		// return a new connection to the database.
		db.conn, err = inst.db.Conn(p.ctx)
		return err
	}, false)
	return
}
