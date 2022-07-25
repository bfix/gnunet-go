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
	"encoding/hex"
	"fmt"
	"gnunet/service/dht/blocks"
	"gnunet/service/dht/path"
	"gnunet/util"
	"os"

	"github.com/bfix/gospel/data"
	"github.com/bfix/gospel/logger"
	"github.com/bfix/gospel/math"
)

//============================================================
// Filesystem-based storage
//============================================================

// FileStore implements a filesystem-based storage mechanism for
// DHT queries and blocks.
type FileStore struct {
	path      string            // storage path
	cache     bool              // storage works as cache
	args      util.ParameterSet // arguments / settings
	totalSize uint64            // total storage size (logical, not physical)

	// storage-mode metadata
	meta     *FileMetaDB // database for metadata
	maxSpace int         // max. storage space in GB

	// cache-mode metadata
	cacheMeta []*FileMetadata // cached metadata
	wrPos     int             // write position in cyclic list
	size      int             // size of cache (number of entries)
}

// NewFileStore instantiates a new file storage.
func NewFileStore(spec util.ParameterSet) (DHTStore, error) {
	// create file store handler
	fs := new(FileStore)
	fs.args = spec

	// get parameter
	var ok bool
	if fs.path, ok = util.GetParam[string](spec, "path"); !ok {
		return nil, ErrStoreInvalidSpec
	}
	if fs.cache, ok = util.GetParam[bool](spec, "cache"); !ok {
		fs.cache = false
	}

	// setup file store depending on mode (storage/cache)
	if fs.cache {
		// remove old cache content
		os.RemoveAll(fs.path)
		// get number of cache entries
		if fs.size, ok = util.GetParam[int](spec, "num"); !ok {
			// defaults to 1000 entries
			fs.size = 1000
		}
		fs.cacheMeta = make([]*FileMetadata, fs.size)
	} else {
		// connect to metadata database
		var err error
		if fs.meta, err = OpenMetaDB(fs.path); err != nil {
			return nil, err
		}
		// normal storage is limited by quota (default: 10GB)
		if fs.maxSpace, ok = util.GetParam[int](spec, "maxGB"); !ok {
			fs.maxSpace = 10
		}
	}
	return fs, nil
}

// Close file storage.
func (s *FileStore) Close() (err error) {
	if !s.cache {
		// close database connection
		err = s.meta.Close()
	}
	return
}

// Put block into storage under given key
func (s *FileStore) Put(query blocks.Query, entry *DHTEntry) (err error) {
	// check for free space
	if !s.cache {
		if int(s.totalSize>>30) > s.maxSpace {
			// drop a significant number of blocks
			s.prune(20)
		}
	}
	// get parameters
	btype := query.Type()
	expire := entry.Blk.Expire()
	blkSize := len(entry.Blk.Bytes())

	// write entry to file for storage
	if err = s.writeEntry(query.Key().Bits, entry); err != nil {
		return
	}
	// compile metadata
	now := util.AbsoluteTimeNow()
	meta := &FileMetadata{
		key:       query.Key().Bits,
		size:      uint64(blkSize),
		btype:     btype,
		expires:   expire,
		stored:    now,
		lastUsed:  now,
		usedCount: 1,
	}
	if s.cache {
		// store in cyclic list
		s.cacheMeta[s.wrPos] = meta
		s.wrPos = (s.wrPos + 1) % s.size
	} else {
		// store metadata in database
		if err = s.meta.Store(meta); err != nil {
			return
		}
		// add to total storage size
		s.totalSize += meta.size
	}
	return
}

// Get block with given key from storage
func (s *FileStore) Get(query blocks.Query) (entry *DHTEntry, err error) {
	// check if we have metadata for the query
	key := query.Key().Bits
	btype := query.Type()
	var md *FileMetadata
	if md, err = s.meta.Get(key, btype); err != nil || md == nil {
		return
	}
	// check for expired entry
	if md.expires.Expired() {
		err = s.dropFile(md)
		return
	}
	// mark the block as newly used
	if err = s.meta.Used(key, btype); err != nil {
		return
	}
	return s.readEntry(key)
}

// GetApprox returns the best-matching value with given key from storage
// that is not excluded
func (s *FileStore) GetApprox(query blocks.Query, excl func(*DHTEntry) bool) (entry *DHTEntry, key any, err error) {
	var bestKey []byte
	var bestEntry *DHTEntry
	var bestDist *math.Int
	// distance function
	dist := func(a, b []byte) *math.Int {
		c := make([]byte, len(a))
		for i := range a {
			c[i] = a[i] ^ b[i]
		}
		return math.NewIntFromBytes(c)
	}
	// iterate over all keys
	check := func(md *FileMetadata) {
		// check for better match
		d := dist(md.key, query.Key().Bits)
		var entry *DHTEntry
		if bestKey == nil || d.Cmp(bestDist) < 0 {
			// we might have a match. check block for exclusion
			if entry, err = s.readEntry(md.key); err != nil {
				logger.Printf(logger.ERROR, "[dhtstore] failed to retrieve block for %s", hex.EncodeToString(md.key))
				return
			}
			if excl(entry) {
				return
			}
			// remember best match
			bestKey = md.key
			bestEntry = entry
			bestDist = d
		}
	}
	if err = s.meta.Traverse(check); err != nil {
		return
	}
	if bestEntry != nil {
		// mark the block as newly used
		if err = s.meta.Used(bestKey, bestEntry.Blk.Type()); err != nil {
			return
		}
	}
	return bestEntry, bestDist, nil
}

// Get a list of all stored block keys (generic query).
func (s *FileStore) List() ([]blocks.Query, error) {
	return nil, ErrStoreNoList
}

//----------------------------------------------------------------------

type entryLayout struct {
	SizeBlk uint16 `order:"big"`    // size of block data
	SizePth uint16 `order:"big"`    // size of path data
	Block   []byte `size:"SizeBlk"` // block data
	Path    []byte `size:"SizePth"` // path data
}

// read entry from storage for given key
func (s *FileStore) readEntry(key []byte) (entry *DHTEntry, err error) {
	// get path and filename from key
	folder, fname := s.expandPath(key)

	// open file for reading
	var file *os.File
	if file, err = os.Open(folder + "/" + fname); err != nil {
		return
	}
	defer file.Close()

	// get file size
	fi, _ := file.Stat()
	size := int(fi.Size())

	// read data
	val := new(entryLayout)
	if err = data.UnmarshalStream(file, val, size); err != nil {
		return
	}
	// assemble entry
	entry = new(DHTEntry)
	entry.Blk = blocks.NewGenericBlock(val.Block)
	entry.Path, err = path.NewPathFromBytes(val.Path)
	return
}

// write entry to storage for given key
func (s *FileStore) writeEntry(key []byte, entry *DHTEntry) (err error) {
	// get folder and filename from key
	folder, fname := s.expandPath(key)
	// make sure the folder exists
	if err = os.MkdirAll(folder, 0755); err != nil {
		return
	}
	// write to file content (block data)
	var file *os.File
	if file, err = os.Create(folder + "/" + fname); err != nil {
		return
	}
	defer file.Close()

	// assemble and write entry
	val := new(entryLayout)
	val.Block = entry.Blk.Bytes()
	val.SizeBlk = uint16(len(val.Block))
	if entry.Path != nil {
		val.Path = entry.Path.Bytes()
		val.SizePth = uint16(len(val.Path))
	} else {
		val.Path = nil
		val.SizePth = 0
	}
	err = data.MarshalStream(file, val)
	return
}

//----------------------------------------------------------------------

// expandPath returns the full path to the file for given key.
func (s *FileStore) expandPath(key []byte) (string, string) {
	h := hex.EncodeToString(key)
	return fmt.Sprintf("%s/%s/%s", s.path, h[:2], h[2:4]), h[4:]
}

// Prune list of file headers so we drop at least n entries.
// returns number of removed entries.
func (s *FileStore) prune(n int) (del int) {
	// collect obsolete records
	obsolete, err := s.meta.Obsolete(n)
	if err != nil {
		logger.Println(logger.ERROR, "[FileStore] failed to collect obsolete records: "+err.Error())
		return
	}
	for _, md := range obsolete {
		if err := s.dropFile(md); err != nil {
			return
		}
		del++
	}
	return
}

// drop file removes a file from metadatabase and the physical storage.
func (s *FileStore) dropFile(md *FileMetadata) (err error) {
	// adjust total size
	s.totalSize -= md.size
	// remove from database
	if err = s.meta.Drop(md.key, md.btype); err != nil {
		logger.Printf(logger.ERROR, "[store] can't remove metadata (%s,%d): %s", md.key, md.btype, err.Error())
		return
	}
	// remove from filesystem
	path := fmt.Sprintf("%s/%s/%s/%s", s.path, md.key[:2], md.key[2:4], md.key[4:])
	if err = os.Remove(path); err != nil {
		logger.Printf(logger.ERROR, "[store] can't remove file %s: %s", path, err.Error())
	}
	return
}
