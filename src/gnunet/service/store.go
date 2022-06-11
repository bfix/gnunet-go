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
	"encoding/binary"
	"encoding/gob"
	"encoding/hex"
	"errors"
	"fmt"
	"gnunet/config"
	"gnunet/crypto"
	"gnunet/service/dht/blocks"
	"gnunet/util"
	"io/ioutil"
	"os"
	"sort"
	"sync"

	"github.com/bfix/gospel/logger"
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

	// List all store keys
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
func NewDHTStore(spec config.ParameterConfig) (DHTStore, error) {
	// get the mode parameter
	mode, ok := config.GetParam[string](spec, "mode")
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
func NewKVStore(spec config.ParameterConfig) (KVStore, error) {
	// get the mode parameter
	mode, ok := config.GetParam[string](spec, "mode")
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
// Filesystem-based storage
//------------------------------------------------------------

// FileHeader is the layout of a file managed by the storage handler.
// On start-up the file store recreates the list of file entries from
// traversing the actual filesystem. This is done in the background.
type FileHeader struct {
	key       string            // storage key
	size      uint64            // size of file
	btype     uint16            // block type
	stored    util.AbsoluteTime // time added to store
	expires   util.AbsoluteTime // expiration time
	lastUsed  util.AbsoluteTime // time last used
	usedCount uint64            // usage count
}

// FileStore implements a filesystem-based storage mechanism for
// DHT queries and blocks.
type FileStore struct {
	path  string                 // storage path
	cache bool                   // storage works as cache
	args  config.ParameterConfig // arguments / settings

	totalSize uint64                 // total storage size (logical, not physical)
	files     map[string]*FileHeader // list of file headers
	wrPos     int                    // write position in cyclic list
	mtx       sync.Mutex             // serialize operations (prune)
}

// NewFileStore instantiates a new file storage.
func NewFileStore(spec config.ParameterConfig) (DHTStore, error) {
	// get path parameter
	path, ok := config.GetParam[string](spec, "path")
	if !ok {
		return nil, ErrStoreInvalidSpec
	}
	isCache, ok := config.GetParam[bool](spec, "cache")
	if !ok {
		isCache = false
	}
	// remove old cache content
	if isCache {
		os.RemoveAll(path)
	}
	// create file store handler
	fs := &FileStore{
		path:  path,
		args:  spec,
		cache: isCache,
		files: make(map[string]*FileHeader),
	}
	// load file header list
	if !isCache {
		if fp, err := os.Open(path + "/files.db"); err == nil {
			dec := gob.NewDecoder(fp)
			for {
				hdr := new(FileHeader)
				if dec.Decode(hdr) == nil {
					fs.files[hdr.key] = hdr
					fs.totalSize += hdr.size
				}
			}
			fp.Close()
		}
	}
	return fs, nil
}

// Close file storage. write metadata to file
func (s *FileStore) Close() (err error) {
	if !s.cache {
		if fp, err := os.Create(s.path + "/files.db"); err == nil {
			defer fp.Close()
			enc := gob.NewEncoder(fp)
			for _, hdr := range s.files {
				if err = enc.Encode(hdr); err != nil {
					break
				}
			}
		}
	}
	return
}

// Put block into storage under given key
func (s *FileStore) Put(query blocks.Query, block blocks.Block) (err error) {
	// check for free space
	if s.cache {
		// caching is limited by explicit number of files
		num, ok := config.GetParam[int](s.args, "num")
		if !ok {
			num = 100
		}
		if len(s.files) >= num {
			// make space for at least one new entry
			s.prune(1)
		}
	} else {
		// normal storage is limited by quota (default: 10GB)
		max, ok := config.GetParam[int](s.args, "maxGB")
		if !ok {
			max = 10
		}
		if int(s.totalSize>>30) > max {
			// drop a significant number of blocks
			s.prune(20)
		}
	}
	// get query parameters for entry
	var btype uint16 // block type
	query.Get("blkType", &btype)
	var expire util.AbsoluteTime // block expiration
	query.Get("expire", &expire)

	// get path and filename from key
	path, fname := s.expandPath(query.Key())
	// make sure the path exists
	if err = os.MkdirAll(path, 0755); err != nil {
		return
	}
	// write to file for storage
	var fp *os.File
	var fpSize int
	if fp, err = os.Create(path + "/" + fname); err == nil {
		defer fp.Close()
		// write block data
		if err = binary.Write(fp, binary.BigEndian, btype); err == nil {
			if err = binary.Write(fp, binary.BigEndian, expire); err == nil {
				_, err = fp.Write(block.Data())
			}
		}
	}
	// add header to internal list
	now := util.AbsoluteTimeNow()
	hdr := &FileHeader{
		key:       hex.EncodeToString(query.Key().Bits),
		size:      uint64(fpSize),
		btype:     btype,
		expires:   expire,
		stored:    now,
		lastUsed:  now,
		usedCount: 1,
	}
	s.files[hdr.key] = hdr
	return
}

// Get block with given key from storage
func (s *FileStore) Get(query blocks.Query) (block blocks.Block, err error) {
	// get requested block type
	var (
		btype  uint16            = blocks.DHT_BLOCK_ANY
		blkt   uint16            // actual block type
		expire util.AbsoluteTime // expiration date
		data   []byte            // block data
	)
	query.Get("blkType", &btype)

	// get path and filename from key
	path, fname := s.expandPath(query.Key())
	// read file content (block data)
	var file *os.File
	if file, err = os.Open(path + "/" + fname); err != nil {
		return
	}
	// read block data
	if err = binary.Read(file, binary.BigEndian, &blkt); err == nil {
		if btype != blocks.DHT_BLOCK_ANY && btype != blkt {
			// block types not matching
			return
		}
		if err = binary.Read(file, binary.BigEndian, &expire); err == nil {
			if data, err = ioutil.ReadAll(file); err == nil {
				block = blocks.NewGenericBlock(data)
			}
		}
	}
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

// Prune list of file headers so we drop at least n entries.
// returns number of removed entries.
func (s *FileStore) prune(n int) (del int) {
	// get list of headers; remove expired entries on the fly
	list := make([]*FileHeader, 0)
	for key, hdr := range s.files {
		// remove expired entry
		if hdr.expires.Expired() {
			s.dropFile(key)
			del++
		}
		// append to list
		list = append(list, hdr)
	}
	// check if we are already done.
	if del >= n {
		return
	}
	// sort list by decending rate "(lifetime * size) / usedCount"
	sort.Slice(list, func(i, j int) bool {
		ri := (list[i].stored.Elapsed().Val * list[i].size) / list[i].usedCount
		rj := (list[j].stored.Elapsed().Val * list[j].size) / list[j].usedCount
		return ri > rj
	})
	// remove from start of list until prune limit is reached
	for _, hdr := range list {
		s.dropFile(hdr.key)
		del++
		if del == n {
			break
		}
	}
	return
}

// drop file removes a file from the internal list and the physical storage.
func (s *FileStore) dropFile(key string) {
	// remove for internal list
	delete(s.files, key)
	// remove from filesystem
	path := fmt.Sprintf("%s/%s/%s/%s", s.path, key[:2], key[2:4], key[4:])
	if err := os.Remove(path); err != nil {
		logger.Printf(logger.ERROR, "[store] can't remove file %s: %s", path, err.Error())
		return
	}
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
func NewRedisStore(spec config.ParameterConfig) (s KVStore, err error) {
	// get connection parameters
	addr, ok := config.GetParam[string](spec, "addr")
	if !ok {
		return nil, ErrStoreInvalidSpec
	}
	passwd, ok := config.GetParam[string](spec, "passwd")
	if !ok {
		passwd = ""
	}
	db, ok := config.GetParam[int](spec, "db")
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
func NewSQLStore(spec config.ParameterConfig) (s KVStore, err error) {
	// get connection parameters
	connect, ok := config.GetParam[string](spec, "connect")
	if !ok {
		return nil, ErrStoreInvalidSpec
	}
	// create SQL store
	kvs := new(SQLStore)

	// connect to SQL database
	kvs.db, err = util.DbPool.Connect(connect)
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
