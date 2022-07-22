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
	_ "embed" // use embedded filesystem
	"errors"
	"fmt"
	"gnunet/service/dht/blocks"
	"gnunet/service/dht/path"
	"gnunet/util"

	redis "github.com/go-redis/redis/v8"
)

// Error messages related to the key/value-store implementations
var (
	ErrStoreInvalidSpec  = fmt.Errorf("invalid Store specification")
	ErrStoreUnknown      = fmt.Errorf("unknown Store type")
	ErrStoreNotAvailable = fmt.Errorf("store not available")
	ErrStoreNoApprox     = fmt.Errorf("no approx search for store defined")
	ErrStoreNoList       = fmt.Errorf("no key listing for store defined")
)

//------------------------------------------------------------
// Generic storage interface. Can be used for persistent or
// transient (caching) storage of key/value data.
//------------------------------------------------------------

// Store is a key/value storage where the type of the key is either
// a SHA512 hash value or a string and the value is either a DHT
// block or a string. It is possiblle to mix any key/value types,
// but not used in this implementation.
type Store[K, V any] interface {
	// Put value into storage under given key
	Put(key K, val V) error

	// Get value with given key from storage
	Get(key K) (V, error)

	// GetApprox returns the best-matching value with given key from storage
	// that is not excluded.
	GetApprox(key K, excl func(V) bool) (V, any, error)

	// List all store keys
	List() ([]K, error)

	// Close store
	Close() error
}

//------------------------------------------------------------
// Types for custom store requirements
//------------------------------------------------------------

// DHTEntry to be stored/retrieved
type DHTEntry struct {
	Blk  blocks.Block
	Path *path.Path
}

// DHTStore for DHT queries and blocks
type DHTStore Store[blocks.Query, *DHTEntry]

// KVStore for key/value string pairs
type KVStore Store[string, string]

//------------------------------------------------------------
// NewDHTStore creates a new storage handler with given spec
// for use with DHT queries and blocks
func NewDHTStore(spec util.ParameterSet) (DHTStore, error) {
	// get the mode parameter
	mode, ok := util.GetParam[string](spec, "mode")
	if !ok {
		return nil, ErrStoreInvalidSpec
	}
	switch mode {
	//------------------------------------------------------------------
	// File-base storage
	//------------------------------------------------------------------
	case "file":
		return NewFileStore(spec)
	}
	return nil, ErrStoreUnknown
}

//------------------------------------------------------------
// NewKVStore creates a new storage handler with given spec
// for use with key/value string pairs.
func NewKVStore(spec util.ParameterSet) (KVStore, error) {
	// get the mode parameter
	mode, ok := util.GetParam[string](spec, "mode")
	if !ok {
		return nil, ErrStoreInvalidSpec
	}
	switch mode {
	//--------------------------------------------------------------
	// Redis service
	//--------------------------------------------------------------
	case "redis":
		return NewRedisStore(spec)

	//--------------------------------------------------------------
	// SQL database service
	//--------------------------------------------------------------
	case "sql":
		return NewSQLStore(spec)
	}
	return nil, errors.New("unknown storage mechanism")
}

//------------------------------------------------------------
// Redis: only use for caching purposes on key/value strings
//------------------------------------------------------------

// RedisStore uses a (local) Redis server for key/value storage
type RedisStore struct {
	client *redis.Client // client connection
	db     int           // index to database
}

// NewRedisStore creates a Redis service client instance.
func NewRedisStore(spec util.ParameterSet) (s KVStore, err error) {
	// get connection parameters
	addr, ok := util.GetParam[string](spec, "addr")
	if !ok {
		return nil, ErrStoreInvalidSpec
	}
	passwd, ok := util.GetParam[string](spec, "passwd")
	if !ok {
		passwd = ""
	}
	db, ok := util.GetParam[int](spec, "db")
	if !ok {
		return nil, ErrStoreInvalidSpec
	}

	// create new Redis store
	kvs := new(RedisStore)
	kvs.db = db
	kvs.client = redis.NewClient(&redis.Options{
		Addr:     addr,
		Password: passwd,
		DB:       db,
	})
	if kvs.client == nil {
		err = ErrStoreNotAvailable
	}
	s = kvs
	return
}

// Put value into storage under given key
func (s *RedisStore) Put(key string, value string) (err error) {
	return s.client.Set(context.TODO(), key, value, 0).Err()
}

// Get value with given key from storage
func (s *RedisStore) Get(key string) (value string, err error) {
	return s.client.Get(context.TODO(), key).Result()
}

// GetApprox returns the best-matching value for given key from storage
func (s *RedisStore) GetApprox(key string, crit func(string) bool) (value string, vkey any, err error) {
	return "", "", ErrStoreNoApprox
}

// List all keys in store
func (s *RedisStore) List() (keys []string, err error) {
	var (
		crs  uint64
		segm []string
		ctx  = context.TODO()
	)
	keys = make([]string, 0)
	for {
		segm, crs, err = s.client.Scan(ctx, crs, "*", 10).Result()
		if err != nil {
			return
		}
		if crs == 0 {
			break
		}
		keys = append(keys, segm...)
	}
	return
}

// Close redis connection
func (s *RedisStore) Close() error {
	return s.client.Close()
}

//------------------------------------------------------------
// SQL-based key-value-store
//------------------------------------------------------------

// SQLStore for generic SQL database handling
type SQLStore struct {
	db *DBConn
}

// NewSQLStore creates a new SQL-based key/value store.
func NewSQLStore(spec util.ParameterSet) (s KVStore, err error) {
	// get connection parameters
	connect, ok := util.GetParam[string](spec, "connect")
	if !ok {
		return nil, ErrStoreInvalidSpec
	}
	// create SQL store
	kvs := new(SQLStore)

	// connect to SQL database
	kvs.db, err = DBPool.Connect(connect)
	if err != nil {
		return nil, err
	}
	// get number of key/value pairs (as a check for existing table)
	row := kvs.db.QueryRow("select count(*) from store")
	var num int
	if row.Scan(&num) != nil {
		return nil, ErrStoreNotAvailable
	}
	return kvs, nil
}

// Put a key/value pair into the store
func (s *SQLStore) Put(key string, value string) error {
	_, err := s.db.Exec("insert into store(key,value) values(?,?)", key, value)
	return err
}

// Get a value for a given key from store
func (s *SQLStore) Get(key string) (value string, err error) {
	row := s.db.QueryRow("select value from store where key=?", key)
	err = row.Scan(&value)
	return
}

// GetApprox returns the best-matching value for given key from storage
func (s *SQLStore) GetApprox(key string, crit func(string) bool) (value string, vkey any, err error) {
	return "", "", ErrStoreNoApprox
}

// List all keys in store
func (s *SQLStore) List() (keys []string, err error) {
	var (
		rows *sql.Rows
		key  string
	)
	keys = make([]string, 0)
	rows, err = s.db.Query("select key from store")
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

// Close redis connection
func (s *SQLStore) Close() error {
	return s.db.Close()
}
