// This file is part of gnunet-go, a GNUnet-implementation in Golang.
// Copyright (C) 2019, 2020 Bernd Fix  >Y<
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

package util

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"
	"strings"

	redis "github.com/go-redis/redis/v8"
)

// Error messages related to the key/value-store implementations
var (
	ErrKVSInvalidSpec  = fmt.Errorf("Invalid KVStore specification")
	ErrKVSNotAvailable = fmt.Errorf("KVStore not available")
)

// KeyValueStore interface for implementations that store and retrieve
// key/value pairs. Keys and values are strings.
type KeyValueStore interface {
	Put(key string, value string) error // put a key/value pair into store
	Get(key string) (string, error)     // retrieve a value for a key from store
	List() ([]string, error)            // get all keys from the store
}

// OpenKVStore opens a key/value store for further put/get operations.
// The 'spec' option specifies the arguments required to connect to a specific
// persistence mechanism. The arguments in the 'spec' string are separated by
// the '+' character.
// The first argument specifies the type of key/value store to be used; the
// meaning and format of the following arguments depend on this type.
//
// Key/Value Store types defined:
// * 'redis':   Use a Redis server for persistance; the specification is
//              "redis+addr+[passwd]+db". 'db' must be an integer value.
// * 'mysql':   MySQL-compatible database (see 'database.go' for details)
// * 'sqlite3': SQLite3-compatible database (see 'database.go' for details)
func OpenKVStore(spec string) (KeyValueStore, error) {
	// check specification string
	specs := strings.Split(spec, "+")
	if len(specs) < 2 {
		return nil, ErrKVSInvalidSpec
	}
	switch specs[0] {
	case "redis":
		//--------------------------------------------------------------
		// NoSQL-based persistance
		//--------------------------------------------------------------
		if len(specs) < 4 {
			return nil, ErrKVSInvalidSpec
		}
		db, err := strconv.Atoi(specs[3])
		if err != nil {
			return nil, ErrKVSInvalidSpec
		}
		kvs := new(KvsRedis)
		kvs.db = db
		kvs.client = redis.NewClient(&redis.Options{
			Addr:     specs[1],
			Password: specs[2],
			DB:       db,
		})
		if kvs.client == nil {
			err = ErrKVSNotAvailable
		}
		return kvs, err

	case "sqlite3", "mysql":
		//--------------------------------------------------------------
		// SQL-based persistance
		//--------------------------------------------------------------
		kvs := new(KvsSQL)
		var err error

		// connect to SQL database
		kvs.db, err = ConnectSQLDatabase(spec)
		if err != nil {
			return nil, err
		}
		// get number of key/value pairs (as a check for existing table)
		row := kvs.db.QueryRow("select count(*) from store")
		var num int
		if row.Scan(&num) != nil {
			return nil, ErrKVSNotAvailable
		}
		return kvs, nil
	}
	return nil, ErrKVSInvalidSpec
}

//======================================================================
// NoSQL-based key-value-stores
//======================================================================

// KvsRedis represents a redis-based key/value store
type KvsRedis struct {
	client *redis.Client // client connection
	db     int           // index to database
}

// Put a key/value pair into the store
func (kvs *KvsRedis) Put(key string, value string) error {
	return kvs.client.Set(context.TODO(), key, value, 0).Err()
}

// Get a value for a given key from store
func (kvs *KvsRedis) Get(key string) (value string, err error) {
	return kvs.client.Get(context.TODO(), key).Result()
}

// List all keys in store
func (kvs *KvsRedis) List() (keys []string, err error) {
	var (
		crs  uint64
		segm []string
		ctx  = context.TODO()
	)
	for {
		segm, crs, err = kvs.client.Scan(ctx, crs, "*", 10).Result()
		if err != nil {
			return nil, err
		}
		if crs == 0 {
			break
		}
		keys = append(keys, segm...)
	}
	return
}

//======================================================================
// SQL-based key-value-store
//======================================================================

// KvsSQL represents a SQL-based key/value store
type KvsSQL struct {
	db *sql.DB
}

// Put a key/value pair into the store
func (kvs *KvsSQL) Put(key string, value string) error {
	_, err := kvs.db.Exec("insert into store(key,value) values(?,?)", key, value)
	return err
}

// Get a value for a given key from store
func (kvs *KvsSQL) Get(key string) (value string, err error) {
	row := kvs.db.QueryRow("select value from store where key=?", key)
	err = row.Scan(&value)
	return
}

// List all keys in store
func (kvs *KvsSQL) List() (keys []string, err error) {
	var (
		rows *sql.Rows
		key  string
	)
	rows, err = kvs.db.Query("select key from store")
	if err == nil {
		for rows.Next() {
			if err = rows.Scan(&key); err != nil {
				break
			}
			keys = append(keys, key)
		}
	}
	return
}
