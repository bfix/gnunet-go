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
	"gnunet/crypto"
	"gnunet/enums"
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

//------------------------------------------------------------
// DHT entry is an entity stored in the DHT
//------------------------------------------------------------

// DHTEntry to be stored to/retrieved from local storage
type DHTEntry struct {
	Blk  blocks.Block // reference to DHT block
	Path *path.Path   // associated put path
}

// String returns a human-readable representation
func (e *DHTEntry) String() string {
	return fmt.Sprintf("DHTEntry{%s,path=%s}", e.Blk, e.Path)
}

//------------------------------------------------------------
// DHT result is a single DHT result
//------------------------------------------------------------

// Result as returned by local DHT queries
type DHTResult struct {
	Entry *DHTEntry // reference to DHT entry
	Dist  *math.Int // distance of entry to query key
}

// String returns a human-readable representation
func (r *DHTResult) String() string {
	return fmt.Sprintf("DHTResult{%s,dist=%d}", r.Entry, 512-r.Dist.BitLen())
}

//------------------------------------------------------------

// DHTResultSet is a list of results
type DHTResultSet struct {
	list []*DHTResult // list of DHT results
	pos  int          // iterator position
}

// NewDHTResultSet allocates a new result set.
func NewDHTResultSet() *DHTResultSet {
	return &DHTResultSet{
		list: make([]*DHTResult, 0),
		pos:  0,
	}
}

// Add result to set
func (rs *DHTResultSet) Add(r *DHTResult) {
	rs.list = append(rs.list, r)
}

// Next result from set (iterator)
func (rs *DHTResultSet) Next() (result *DHTResult) {
	if rs.pos == len(rs.list) {
		return nil
	}
	result = rs.list[rs.pos]
	rs.pos++
	return
}

//------------------------------------------------------------
// DHT store
//------------------------------------------------------------

// DHTStore implements a filesystem-based storage mechanism for
// DHT queries and blocks.
type DHTStore struct {
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

// NewDHTStore instantiates a new file storage handler.
func NewDHTStore(spec util.ParameterSet) (*DHTStore, error) {
	// create file store handler
	fs := new(DHTStore)
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
func (s *DHTStore) Close() (err error) {
	if !s.cache {
		// close database connection
		err = s.meta.Close()
	}
	return
}

// Put block into storage under given key
func (s *DHTStore) Put(query blocks.Query, entry *DHTEntry) (err error) {
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

	logger.Printf(logger.INFO, "[dht-store] storing %d bytes @ %s (path %s), expires %s",
		blkSize, query.Key().Short(), entry.Path, expire)

	// write entry to file for storage
	if err = s.writeEntry(query.Key().Data, entry); err != nil {
		return
	}
	// compile metadata
	now := util.AbsoluteTimeNow()
	meta := &FileMetadata{
		key:       query.Key(),
		size:      uint64(blkSize),
		btype:     btype,
		bhash:     crypto.Hash(entry.Blk.Bytes()),
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
func (s *DHTStore) Get(label string, query blocks.Query, rf blocks.ResultFilter) (results []*DHTEntry, err error) {
	// check if we have metadata for the query
	var mds []*FileMetadata
	if mds, err = s.meta.Get(query); err != nil || len(mds) == 0 {
		return
	}
	// traverse list of results
	for _, md := range mds {
		// check for expired entry
		if md.expires.Expired() {
			if err = s.dropFile(md); err != nil {
				logger.Printf(logger.ERROR, "[%s] can't drop DHT file: %s", label, err)
			}
			continue
		}
		// check for filtered block
		if rf.ContainsHash(md.bhash) {
			continue
		}
		// read entry from storage
		var entry *DHTEntry
		if entry, err = s.readEntry(md); err != nil {
			logger.Printf(logger.ERROR, "[%s] can't read DHT entry: %s", label, err)
			continue
		}
		results = append(results, entry)
		// mark the block as newly used
		if err = s.meta.Used(md.key.Data, md.btype); err != nil {
			logger.Printf(logger.ERROR, "[%s] can't flag DHT entry as used: %s", label, err)
			continue
		}
		logger.Printf(logger.INFO, "[dht-store] retrieving %d bytes @ %s (path %s)",
			len(entry.Blk.Bytes()), query.Key().Short(), entry.Path)
	}
	return
}

// GetApprox returns the best-matching value with given key from storage
// that is not excluded
func (s *DHTStore) GetApprox(label string, query blocks.Query, rf blocks.ResultFilter) (results []*DHTResult, err error) {
	btype := query.Type()

	// iterate over all keys; process each metadata instance
	// (append to results if appropriate)
	process := func(md *FileMetadata) {
		// filter by block type
		if btype != enums.BLOCK_TYPE_ANY && btype != md.btype {
			// block type not matching
			return
		}
		// check for filtered block.
		if rf.ContainsHash(md.bhash) {
			// filtered out...
			return
		}
		// check distance (max. 16 bucktes off)
		dist := util.Distance(md.key.Data, query.Key().Data)
		if (512 - dist.BitLen()) > 16 {
			return
		}
		// read entry from storage
		var entry *DHTEntry
		if entry, err = s.readEntry(md); err != nil {
			logger.Printf(logger.ERROR, "[%s] failed to retrieve block for %s", label, md.key.String())
			return
		}
		// add to result list
		result := &DHTResult{
			Entry: entry,
			Dist:  dist,
		}
		results = append(results, result)
	}
	// traverse mestadata database
	err = s.meta.Traverse(process)
	return
}

//----------------------------------------------------------------------

type _EntryLayout struct {
	SizeBlk uint16 `order:"big"`    // size of block data
	SizePth uint16 `order:"big"`    // size of path data
	Block   []byte `size:"SizeBlk"` // block data
	Path    []byte `size:"SizePth"` // path data
}

// read entry from storage for given key
func (s *DHTStore) readEntry(md *FileMetadata) (entry *DHTEntry, err error) {
	// get path and filename from key
	folder, fname := s.expandPath(md.key.Data)

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
	val := new(_EntryLayout)
	if err = data.UnmarshalStream(file, val, size); err != nil {
		return
	}
	// assemble entry
	entry = new(DHTEntry)
	if entry.Blk, err = blocks.NewBlock(md.btype, md.expires, val.Block); err != nil {
		return
	}
	entry.Path, err = path.NewPathFromBytes(val.Path)
	return
}

// write entry to storage for given key
func (s *DHTStore) writeEntry(key []byte, entry *DHTEntry) (err error) {
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
	val := new(_EntryLayout)
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
func (s *DHTStore) expandPath(key []byte) (string, string) {
	h := hex.EncodeToString(key)
	return fmt.Sprintf("%s/%s/%s", s.path, h[:2], h[2:4]), h[4:]
}

// Prune list of file headers so we drop at least n entries.
// returns number of removed entries.
func (s *DHTStore) prune(n int) (del int) {
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
func (s *DHTStore) dropFile(md *FileMetadata) (err error) {
	// adjust total size
	s.totalSize -= md.size
	// remove from database
	if err = s.meta.Drop(md.key.Data, md.btype); err != nil {
		logger.Printf(logger.ERROR, "[store] can't remove metadata (%s,%d): %s", md.key, md.btype, err.Error())
		return
	}
	// remove from filesystem
	h := hex.EncodeToString(md.key.Data)
	path := fmt.Sprintf("%s/%s/%s/%s", s.path, h[:2], h[2:4], h[4:])
	if err = os.Remove(path); err != nil {
		logger.Printf(logger.ERROR, "[store] can't remove file %s: %s", path, err.Error())
	}
	return
}
