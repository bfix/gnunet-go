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

package service

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"gnunet/crypto"
	"gnunet/service/dht/blocks"
	"gnunet/util"
	"io/ioutil"
	"os"
	"strconv"
	"strings"

	redis "github.com/go-redis/redis/v8"
)

// Error messages related to the key/value-store implementations
var (
	ErrStoreInvalidSpec  = fmt.Errorf("Invalid Store specification")
	ErrStoreUnknown      = fmt.Errorf("Unknown Store type")
	ErrStoreNotAvailable = fmt.Errorf("Store not available")
)

//------------------------------------------------------------
// Generic storage interface. Can be used for persistent or
// transient (caching) storage of key/value data.
// One set of methods (Get/Put) work on DHT queries and blocks,
// the other set (GetS, PutS) work on key/value strings.
// Each custom implementation can decide which sets to support.
//------------------------------------------------------------

// Store is a key/value storage where the type of the key is either
// a SHA512 hash value or a string and the value is either a DHT
// block or a string.
type Store[K, V any] interface {
	// Put block into storage under given key
	Put(key K, val V) error

	// Get block with given key from storage
	Get(key K) (V, error)

	// List all store queries
	List() ([]K, error)
}

//------------------------------------------------------------
// Types for custom store requirements
//------------------------------------------------------------

// DHTStore for DHT queries and blocks
type DHTStore Store[blocks.Query, blocks.Block]

// KVStore for key/value string pairs
type KVStore Store[string, string]

//------------------------------------------------------------
// NewDHTStore creates a new storage handler with given spec
// for use with DHT queries and blocks
func NewDHTStore(spec string) (DHTStore, error) {
	specs := strings.SplitN(spec, "+", 2)
	if len(specs) < 2 {
		return nil, ErrStoreInvalidSpec
	}
	switch specs[0] {
	//------------------------------------------------------------------
	// File-base storage
	//------------------------------------------------------------------
	case "file_store":
		return NewFileStore(specs[1])
	case "file_cache":
		if len(specs) < 3 {
			return nil, ErrStoreInvalidSpec
		}
		return NewFileCache(specs[1], specs[2])
	}
	return nil, ErrStoreUnknown
}

//------------------------------------------------------------
// NewKVStore creates a new storage handler with given spec
// for use with key/value string pairs.
func NewKVStore(spec string) (KVStore, error) {
	specs := strings.SplitN(spec, "+", 2)
	if len(specs) < 2 {
		return nil, ErrStoreInvalidSpec
	}
	switch specs[0] {
	//--------------------------------------------------------------
	// Redis service
	//--------------------------------------------------------------
	case "redis":
		if len(specs) < 4 {
			return nil, ErrStoreInvalidSpec
		}
		return NewRedisStore(specs[1], specs[2], specs[3])

	//--------------------------------------------------------------
	// SQL database service
	//--------------------------------------------------------------
	case "sql":
		if len(specs) < 4 {
			return nil, ErrStoreInvalidSpec
		}
		return NewSQLStore(specs[1])
	}
	return nil, errors.New("unknown storage mechanism")
}

//------------------------------------------------------------
// Filesystem-based storage
//------------------------------------------------------------

// FileStore implements a filesystem-based storage mechanism for
// DHT queries and blocks.
type FileStore struct {
	path   string         // storage path
	perm   bool           // permanent storage?
	cached []blocks.Query // list of cached entries
	wrPos  int            // write position in cyclic list
}

// NewFileStore instantiates a new file storage.
func NewFileStore(path string) (DHTStore, error) {
	// create file store
	return &FileStore{
		path: path,
		perm: true,
	}, nil
}

// NewFileCache instantiates a new file-based cache.
func NewFileCache(path, param string) (DHTStore, error) {
	// remove old cache content
	os.RemoveAll(path)

	// get number of cache entries
	num, err := strconv.ParseUint(param, 10, 32)
	if err != nil {
		return nil, err
	}

	// create file store
	return &FileStore{
		path:   path,
		cached: make([]blocks.Query, num),
		wrPos:  0,
	}, nil
}

// Put block into storage under given key
func (s *FileStore) Put(key blocks.Query, val blocks.Block) (err error) {
	// get path and filename from key
	path, fname := s.expandPath(key.Key())
	// make sure the path exists
	if err = os.MkdirAll(path, 0755); err != nil {
		return
	}
	// create file for storage
	var fp *os.File
	if fp, err = os.Create(path + "/" + fname); err == nil {
		defer fp.Close()
		// write block data
		_, err = fp.Write(val.Data())
	}
	return
}

// Get block with given key from storage
func (s *FileStore) Get(key blocks.Query) (val blocks.Block, err error) {
	// get path and filename from key
	path, fname := s.expandPath(key.Key())
	// read file content (block data)
	var buf []byte
	if buf, err = ioutil.ReadFile(path + "/" + fname); err != nil {
		return
	}
	// assemble Block object
	val = blocks.NewGenericBlock(buf)
	return
}

// Get a list of all stored block keys (generic query).
func (s *FileStore) List() ([]blocks.Query, error) {
	return make([]blocks.Query, 0), nil
}

// expandPath returns the full path to the file for given key.
func (s *FileStore) expandPath(key *crypto.HashCode) (string, string) {
	h := hex.EncodeToString(key.Bits)
	return fmt.Sprintf("%s/%s/%s", s.path, h[:2], h[2:4]), h[4:]
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
func NewRedisStore(addr, passwd, db string) (s KVStore, err error) {
	kvs := new(RedisStore)
	if kvs.db, err = strconv.Atoi(db); err != nil {
		err = ErrStoreInvalidSpec
		return
	}
	kvs.client = redis.NewClient(&redis.Options{
		Addr:     addr,
		Password: passwd,
		DB:       kvs.db,
	})
	if kvs.client == nil {
		err = ErrStoreNotAvailable
	}
	s = kvs
	return
}

// Put block into storage under given key
func (s *RedisStore) Put(key string, value string) (err error) {
	return s.client.Set(context.TODO(), key, value, 0).Err()
}

// Get block with given key from storage
func (s *RedisStore) Get(key string) (value string, err error) {
	return s.client.Get(context.TODO(), key).Result()
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

//------------------------------------------------------------
// SQL-based key-value-store
//------------------------------------------------------------

// SQLStore for generic SQL database handling
type SQLStore struct {
	db *util.DbConn
}

// NewSQLStore creates a new SQL-based key/value store.
func NewSQLStore(spec string) (s KVStore, err error) {
	kvs := new(SQLStore)

	// connect to SQL database
	kvs.db, err = util.DbPool.Connect(spec)
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
