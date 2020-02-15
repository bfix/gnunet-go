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

package gns

import (
	"encoding/hex"
	"fmt"

	"gnunet/enums"
	"gnunet/message"
	"gnunet/util"

	"github.com/bfix/gospel/crypto/ed25519"
	"github.com/bfix/gospel/logger"
)

// HdlrInst is the type for functions that instanciate custom block handlers.
type HdlrInst func(*message.GNSResourceRecord, []string) (BlockHandler, error)

// Error codes
var (
	ErrInvalidRecordType = fmt.Errorf("Invalid resource record type")
	ErrInvalidRecordBody = fmt.Errorf("Invalid resource record body")
	ErrInvalidPKEY       = fmt.Errorf("Invalid PKEY resource record")
	ErrInvalidCNAME      = fmt.Errorf("Invalid CNAME resource record")
	ErrInvalidVPN        = fmt.Errorf("Invalid VPN resource record")
	ErrInvalidRecordMix  = fmt.Errorf("Invalid mix of RR types in block")
	ErrBlockHandler      = fmt.Errorf("Internal block handler failure")
)

// Mapping of RR types to BlockHandler instanciation functions
var (
	customHandler = map[int]HdlrInst{
		enums.GNS_TYPE_PKEY:      NewPkeyHandler,
		enums.GNS_TYPE_GNS2DNS:   NewGns2DnsHandler,
		enums.GNS_TYPE_BOX:       NewBoxHandler,
		enums.GNS_TYPE_LEHO:      NewLehoHandler,
		enums.GNS_TYPE_DNS_CNAME: NewCnameHandler,
		enums.GNS_TYPE_VPN:       NewVpnHandler,
	}
)

//======================================================================
// GNS blocks that contain special records (PKEY, GNS2DNS, BOX, LEHO...)
// require special treatment with respect to other resource records with
// different types in the same block. Usually only certain other types
// (or none at all) are allowed.
//======================================================================

// BlockHandler interface.
type BlockHandler interface {
	// AddRecord inserts an associated RR into the BlockHandler for (later)
	// processing. The handler can inspect the remaining labels in a path
	// if required. The method returns an error if a record is not accepted
	// by the block handler (RR not of required type).
	AddRecord(rr *message.GNSResourceRecord, labels []string) error

	// Coexist checks if a custom block handler can co-exist with other
	// resource records in the same block. 'cm' maps the resource type
	// to an integer count (how many records of a type are present in the
	// GNS block).
	Coexist(cm util.CounterMap) bool

	// Records returns a list of RR of the given types associated with
	// the custom handler
	Records(kind RRTypeList) *message.GNSRecordSet

	// Name returns the human-readable name of the handler
	Name() string
}

//----------------------------------------------------------------------
// Manage list of block handlers
// Under normal circumstances there is only one (or none) block handler
// per block, but future constructs may allow multiple block handlers
// to be present. The block handler list implements the BlockHandler
// interface.
// The BlockHandlerList maintains a map of actually instantiated handlers
// (indexed by record type) and a list of record types (with occurrence
// count) in the block.
// The instance is also responsible for any required post-processing like
// filtering out expired records (and eventually "activating" associated
// shadow records collect from the same block).
//----------------------------------------------------------------------

// BlockHandlerList is a list of block handlers instantiated.
type BlockHandlerList struct {
	list   map[int]BlockHandler // list of handler instances
	counts util.CounterMap      // count number of RRs by type
}

// NewBlockHandlerList instantiates an a list of active block handlers
// for a given set of records (GNS block).
func NewBlockHandlerList(records []*message.GNSResourceRecord, labels []string) (*BlockHandlerList, []*message.GNSResourceRecord, error) {
	// initialize block handler list
	hl := &BlockHandlerList{
		list:   make(map[int]BlockHandler),
		counts: make(util.CounterMap),
	}

	// first pass: build list of shadow records in this block
	shadows := make([]*message.GNSResourceRecord, 0)
	for _, rec := range records {
		// filter out shadow records...
		if (int(rec.Flags) & enums.GNS_FLAG_SHADOW) != 0 {
			shadows = append(shadows, rec)
		}
	}
	// second pass: normalize block by filtering out expired records (and
	// replacing them with shadow records if available
	active := make([]*message.GNSResourceRecord, 0)
	for _, rec := range records {
		// don't process shadow records again
		if (int(rec.Flags) & enums.GNS_FLAG_SHADOW) != 0 {
			continue
		}
		// check for expired record
		if rec.Expires.Expired() {
			// do we have an associated shadow record?
			for _, shadow := range shadows {
				if shadow.Type == rec.Type && !shadow.Expires.Expired() {
					// deliver un-expired shadow record instead.
					shadow.Flags &^= uint32(enums.GNS_FLAG_SHADOW)
					active = append(active, shadow)
				}
			}
		} else {
			active = append(active, rec)
		}
	}

	// Third pass: Traverse active list and build list of handler instances.
	for _, rec := range active {
		// update counter map for non-supplemental records
		rrType := int(rec.Type)
		if (rrType & enums.GNS_FLAG_SUPPL) == 0 {
			hl.counts.Add(rrType)
		}

		// check for custom handler type
		if creat, ok := customHandler[rrType]; ok {
			// check if a handler for given type already exists
			var (
				hdlr BlockHandler
				err  error
			)
			if hdlr, ok = hl.list[rrType]; ok {
				// add record to existing handler
				if err = hdlr.AddRecord(rec, labels); err != nil {
					return nil, active, err
				}
				continue
			}
			// create a new handler instance
			if hdlr, err = creat(rec, labels); err != nil {
				return nil, active, err
			}
			// store handler in list
			hl.list[rrType] = hdlr
		}
	}

	// Check if all registered handlers in list can co-exist with
	// all the other records of varying type
	for _, hdlr := range hl.list {
		if !hdlr.Coexist(hl.counts) {
			logger.Printf(logger.ERROR, "[gns] %s.Coexist() failed!\n", hdlr.Name())
			return nil, active, ErrInvalidRecordMix
		}
	}
	// return assembled handler list
	return hl, active, nil
}

// GetHandler returns a BlockHandler for the given key. If no block handler exists
// under the given name, a new one is created and stored in the list. The type of
// the new block handler is derived from the key value.
func (hl *BlockHandlerList) GetHandler(t int) BlockHandler {
	// return handler for given key if it exists
	if hdlr, ok := hl.list[t]; ok {
		return hdlr
	}
	return nil
}

// FinalizeRecord post-processes records
func (hl *BlockHandlerList) FinalizeRecord(rec *message.GNSResourceRecord) *message.GNSResourceRecord {
	// no implementation yet
	return rec
}

//----------------------------------------------------------------------
// PKEY handler: Only one PKEY as sole record in a block
//----------------------------------------------------------------------

// PkeyHandler implementing the BlockHandler interface
type PkeyHandler struct {
	pkey *ed25519.PublicKey         // Zone key
	rec  *message.GNSResourceRecord // associated recource record
}

// NewPkeyHandler returns a new BlockHandler instance
func NewPkeyHandler(rec *message.GNSResourceRecord, labels []string) (BlockHandler, error) {
	if int(rec.Type) != enums.GNS_TYPE_PKEY {
		return nil, ErrInvalidRecordType
	}
	h := &PkeyHandler{
		pkey: nil,
	}
	if err := h.AddRecord(rec, labels); err != nil {
		return nil, err
	}
	return h, nil
}

// AddRecord inserts a PKEY record into the handler.
func (h *PkeyHandler) AddRecord(rec *message.GNSResourceRecord, labels []string) error {
	if int(rec.Type) != enums.GNS_TYPE_PKEY {
		return ErrInvalidRecordType
	}
	// check for sole PKEY record in block
	if h.pkey != nil {
		return ErrInvalidPKEY
	}
	// check for sane key data
	if len(rec.Data) != 32 {
		return ErrInvalidPKEY
	}
	// set a PKEY handler
	h.pkey = ed25519.NewPublicKeyFromBytes(rec.Data)
	h.rec = rec
	return nil
}

// Coexist return a flag indicating how a resource record of a given type
// is to be treated (see BlockHandler interface)
func (h *PkeyHandler) Coexist(cm util.CounterMap) bool {
	// only one type (GNS_TYPE_PKEY) is present
	return len(cm) == 1 && cm.Num(enums.GNS_TYPE_PKEY) == 1
}

// Records returns a list of RR of the given type associated with this handler
func (h *PkeyHandler) Records(kind RRTypeList) *message.GNSRecordSet {
	rs := message.NewGNSRecordSet()
	if kind.HasType(enums.GNS_TYPE_PKEY) {
		rs.AddRecord(h.rec)
	}
	return rs
}

// Name returns the human-readable name of the handler.
func (h *PkeyHandler) Name() string {
	return "PKEY_Handler"
}

//----------------------------------------------------------------------
// GNS2DNS handler
//----------------------------------------------------------------------

// Gns2DnsHandler implementing the BlockHandler interface
type Gns2DnsHandler struct {
	Query   string                       // DNS query name
	Servers []string                     // DNS servers to ask
	recs    []*message.GNSResourceRecord // list of rersource records
}

// NewGns2DnsHandler returns a new BlockHandler instance
func NewGns2DnsHandler(rec *message.GNSResourceRecord, labels []string) (BlockHandler, error) {
	if int(rec.Type) != enums.GNS_TYPE_GNS2DNS {
		return nil, ErrInvalidRecordType
	}
	h := &Gns2DnsHandler{
		Query:   "",
		Servers: make([]string, 0),
		recs:    make([]*message.GNSResourceRecord, 0),
	}
	if err := h.AddRecord(rec, labels); err != nil {
		return nil, err
	}
	return h, nil
}

// AddRecord inserts a GNS2DNS record into the handler.
func (h *Gns2DnsHandler) AddRecord(rec *message.GNSResourceRecord, labels []string) error {
	if int(rec.Type) != enums.GNS_TYPE_GNS2DNS {
		return ErrInvalidRecordType
	}
	logger.Printf(logger.DBG, "[gns] GNS2DNS data: %s\n", hex.EncodeToString(rec.Data))

	// extract list of names in DATA block:
	next, dnsQuery := DNSNameFromBytes(rec.Data, 0)
	dnsServer := string(rec.Data[next : len(rec.Data)-1])
	logger.Printf(logger.DBG, "[gns] GNS2DNS query '%s'@'%s'\n", dnsQuery, dnsServer)
	if len(dnsServer) == 0 || len(dnsQuery) == 0 {
		return ErrInvalidRecordBody
	}

	// check if all GNS2DNS records refer to the same query name
	if len(h.Servers) == 0 {
		h.Query = dnsQuery
	}
	if dnsQuery != h.Query {
		return ErrInvalidRecordBody
	}
	h.Servers = append(h.Servers, dnsServer)
	h.recs = append(h.recs, rec)
	return nil
}

// Coexist return a flag indicating how a resource record of a given type
// is to be treated (see BlockHandler interface)
func (h *Gns2DnsHandler) Coexist(cm util.CounterMap) bool {
	// only one type (GNS_TYPE_GNS2DNS) is present
	return len(cm) == 1 && cm.Num(enums.GNS_TYPE_GNS2DNS) > 0
}

// Records returns a list of RR of the given type associated with this handler
func (h *Gns2DnsHandler) Records(kind RRTypeList) *message.GNSRecordSet {
	rs := message.NewGNSRecordSet()
	if kind.HasType(enums.GNS_TYPE_GNS2DNS) {
		for _, rec := range h.recs {
			rs.AddRecord(rec)
		}
	}
	return rs
}

// Name returns the human-readable name of the handler.
func (h *Gns2DnsHandler) Name() string {
	return "GNS2DNS_Handler"
}

//----------------------------------------------------------------------
// BOX handler
//----------------------------------------------------------------------

// BoxHandler implementing the BlockHandler interface
type BoxHandler struct {
	boxes map[string]*Box // map of found boxes
}

// NewBoxHandler returns a new BlockHandler instance
func NewBoxHandler(rec *message.GNSResourceRecord, labels []string) (BlockHandler, error) {
	if int(rec.Type) != enums.GNS_TYPE_BOX {
		return nil, ErrInvalidRecordType
	}
	h := &BoxHandler{
		boxes: make(map[string]*Box),
	}
	if err := h.AddRecord(rec, labels); err != nil {
		return nil, err
	}
	return h, nil
}

// AddRecord inserts a BOX record into the handler.
func (h *BoxHandler) AddRecord(rec *message.GNSResourceRecord, labels []string) error {
	if int(rec.Type) != enums.GNS_TYPE_BOX {
		return ErrInvalidRecordType
	}
	logger.Printf(logger.DBG, "[box-rr] for labels %v\n", labels)
	// check if we need to process the BOX record:
	// (1) only two remaining labels
	if len(labels) != 2 {
		return nil
	}
	// (2) remaining labels must start with '_'
	if labels[0][0] != '_' || labels[1][0] != '_' {
		return nil
	}
	// (3) check of "svc" and "proto" match values in the BOX
	box := NewBox(rec)
	if box.Matches(labels) {
		logger.Println(logger.DBG, "[box-rr] MATCH -- adding record")
		h.boxes[box.key] = box
	}
	return nil
}

// Coexist return a flag indicating how a resource record of a given type
// is to be treated (see BlockHandler interface)
func (h *BoxHandler) Coexist(cm util.CounterMap) bool {
	// anything goes...
	return true
}

// Records returns a list of RR of the given type associated with this handler
func (h *BoxHandler) Records(kind RRTypeList) *message.GNSRecordSet {
	rs := message.NewGNSRecordSet()
	for _, box := range h.boxes {
		if kind.HasType(int(box.Type)) {
			// valid box found: assemble new resource record.
			rr := new(message.GNSResourceRecord)
			rr.Expires = box.rec.Expires
			rr.Flags = box.rec.Flags
			rr.Type = box.Type
			rr.Size = uint32(len(box.RR))
			rr.Data = box.RR
			rs.AddRecord(rr)
		}
	}
	return rs
}

// Name returns the human-readable name of the handler.
func (h *BoxHandler) Name() string {
	return "BOX_Handler"
}

//----------------------------------------------------------------------
// LEHO handler
//----------------------------------------------------------------------

// LehoHandler implementing the BlockHandler interface
type LehoHandler struct {
	name string
	rec  *message.GNSResourceRecord
}

// NewLehoHandler returns a new BlockHandler instance
func NewLehoHandler(rec *message.GNSResourceRecord, labels []string) (BlockHandler, error) {
	if int(rec.Type) != enums.GNS_TYPE_LEHO {
		return nil, ErrInvalidRecordType
	}
	h := &LehoHandler{
		name: "",
	}
	if err := h.AddRecord(rec, labels); err != nil {
		return nil, err
	}
	return h, nil
}

// AddRecord inserts a LEHO record into the handler.
func (h *LehoHandler) AddRecord(rec *message.GNSResourceRecord, labels []string) error {
	if int(rec.Type) != enums.GNS_TYPE_LEHO {
		return ErrInvalidRecordType
	}
	h.name = string(rec.Data)
	h.rec = rec
	return nil
}

// Coexist return a flag indicating how a resource record of a given type
// is to be treated (see BlockHandler interface)
func (h *LehoHandler) Coexist(cm util.CounterMap) bool {
	// requires exactly one LEHO and any number of other records.
	return cm.Num(enums.GNS_TYPE_LEHO) == 1
}

// Records returns a list of RR of the given type associated with this handler
func (h *LehoHandler) Records(kind RRTypeList) *message.GNSRecordSet {
	rs := message.NewGNSRecordSet()
	if kind.HasType(enums.GNS_TYPE_LEHO) {
		rs.AddRecord(h.rec)
	}
	return rs
}

// Name returns the human-readable name of the handler.
func (h *LehoHandler) Name() string {
	return "LEHO_Handler"
}

//----------------------------------------------------------------------
// CNAME handler
//----------------------------------------------------------------------

// CnameHandler implementing the BlockHandler interface
type CnameHandler struct {
	name string
	rec  *message.GNSResourceRecord
}

// NewCnameHandler returns a new BlockHandler instance
func NewCnameHandler(rec *message.GNSResourceRecord, labels []string) (BlockHandler, error) {
	if int(rec.Type) != enums.GNS_TYPE_DNS_CNAME {
		return nil, ErrInvalidRecordType
	}
	h := &CnameHandler{
		name: "",
	}
	if err := h.AddRecord(rec, labels); err != nil {
		return nil, err
	}
	return h, nil
}

// AddRecord inserts a CNAME record into the handler.
func (h *CnameHandler) AddRecord(rec *message.GNSResourceRecord, labels []string) error {
	if int(rec.Type) != enums.GNS_TYPE_DNS_CNAME {
		return ErrInvalidRecordType
	}
	if h.rec != nil {
		return ErrInvalidCNAME
	}
	_, h.name = DNSNameFromBytes(rec.Data, 0)
	h.rec = rec
	return nil
}

// Coexist return a flag indicating how a resource record of a given type
// is to be treated (see BlockHandler interface)
func (h *CnameHandler) Coexist(cm util.CounterMap) bool {
	// only a single CNAME allowed
	return len(cm) == 1 && cm.Num(enums.GNS_TYPE_DNS_CNAME) == 1
}

// Records returns a list of RR of the given type associated with this handler
func (h *CnameHandler) Records(kind RRTypeList) *message.GNSRecordSet {
	rs := message.NewGNSRecordSet()
	if kind.HasType(enums.GNS_TYPE_DNS_CNAME) {
		rs.AddRecord(h.rec)
	}
	return rs
}

// Name returns the human-readable name of the handler.
func (h *CnameHandler) Name() string {
	return "CNAME_Handler"
}

//----------------------------------------------------------------------
// VPN handler
//----------------------------------------------------------------------

// VpnHandler implementing the BlockHandler interface
type VpnHandler struct {
	rec *message.GNSResourceRecord
}

// NewVpnHandler returns a new BlockHandler instance
func NewVpnHandler(rec *message.GNSResourceRecord, labels []string) (BlockHandler, error) {
	if int(rec.Type) != enums.GNS_TYPE_VPN {
		return nil, ErrInvalidRecordType
	}
	h := &VpnHandler{}
	if err := h.AddRecord(rec, labels); err != nil {
		return nil, err
	}
	return h, nil
}

// AddRecord inserts a VPN record into the handler.
func (h *VpnHandler) AddRecord(rec *message.GNSResourceRecord, labels []string) error {
	if int(rec.Type) != enums.GNS_TYPE_VPN {
		return ErrInvalidRecordType
	}
	if h.rec != nil {
		return ErrInvalidVPN
	}
	h.rec = rec
	return nil
}

// Coexist return a flag indicating how a resource record of a given type
// is to be treated (see BlockHandler interface)
func (h *VpnHandler) Coexist(cm util.CounterMap) bool {
	// anything goes
	return true
}

// Records returns a list of RR of the given type associated with this handler
func (h *VpnHandler) Records(kind RRTypeList) *message.GNSRecordSet {
	rs := message.NewGNSRecordSet()
	if kind.HasType(enums.GNS_TYPE_VPN) {
		rs.AddRecord(h.rec)
	}
	return rs
}

// Name returns the human-readable name of the handler.
func (h *VpnHandler) Name() string {
	return "VPN_Handler"
}
