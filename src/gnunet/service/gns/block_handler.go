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

package gns

import (
	"encoding/hex"
	"fmt"

	"gnunet/crypto"
	"gnunet/enums"
	"gnunet/message"
	"gnunet/util"

	"github.com/bfix/gospel/logger"
)

// HdlrInst is the type for functions that instanciate custom block handlers.
type HdlrInst func(*message.ResourceRecord, []string) (BlockHandler, error)

// Error codes
var (
	ErrInvalidRecordType = fmt.Errorf("invalid resource record type")
	ErrInvalidRecordBody = fmt.Errorf("invalid resource record body")
	ErrInvalidZoneKey    = fmt.Errorf("invalid zone key resource record")
	ErrInvalidCNAME      = fmt.Errorf("invalid CNAME resource record")
	ErrInvalidVPN        = fmt.Errorf("invalid VPN resource record")
	ErrInvalidRecordMix  = fmt.Errorf("invalid mix of RR types in block")
	ErrBlockHandler      = fmt.Errorf("internal block handler failure")
)

// Mapping of RR types to BlockHandler instanciation functions
var (
	customHandler = map[enums.GNSType]HdlrInst{
		enums.GNS_TYPE_PKEY:      NewZoneHandler,
		enums.GNS_TYPE_EDKEY:     NewZoneHandler,
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
	AddRecord(rr *message.ResourceRecord, labels []string) error

	// Coexist checks if a custom block handler can co-exist with other
	// resource records in the same block. 'cm' maps the resource type
	// to an integer count (how many records of a type are present in the
	// GNS block).
	Coexist(cm util.Counter[enums.GNSType]) bool

	// Records returns a list of RR of the given types associated with
	// the custom handler
	Records(kind RRTypeList) *message.RecordSet

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
	list   map[enums.GNSType]BlockHandler // list of handler instances
	counts util.Counter[enums.GNSType]    // count number of RRs by type
}

// NewBlockHandlerList instantiates an a list of active block handlers
// for a given set of records (GNS block).
func NewBlockHandlerList(records []*message.ResourceRecord, labels []string) (*BlockHandlerList, []*message.ResourceRecord, error) {
	// initialize block handler list
	hl := &BlockHandlerList{
		list:   make(map[enums.GNSType]BlockHandler),
		counts: make(util.Counter[enums.GNSType]),
	}

	// first pass: build list of shadow records in this block
	shadows := make([]*message.ResourceRecord, 0)
	for _, rec := range records {
		// filter out shadow records...
		if (int(rec.Flags) & enums.GNS_FLAG_SHADOW) != 0 {
			shadows = append(shadows, rec)
		}
	}
	// second pass: normalize block by filtering out expired records (and
	// replacing them with shadow records if available
	active := make([]*message.ResourceRecord, 0)
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
		if (int(rec.Flags) & enums.GNS_FLAG_SUPPL) != 0 {
			logger.Printf(logger.DBG, "[gns] handler_list: skip %v\n", rec)
			continue
		}
		rrType := enums.GNSType(rec.Type)
		hl.counts.Add(rrType)

		// check for custom handler type
		if creat, ok := customHandler[enums.GNSType(rrType)]; ok {
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

// GetHandler returns a BlockHandler for the given GNS block type.
// If more than one type is given, the first matching hanlder is
// returned.
func (hl *BlockHandlerList) GetHandler(types ...enums.GNSType) BlockHandler {
	for _, t := range types {
		// return handler for given type if it exists
		if hdlr, ok := hl.list[t]; ok {
			return hdlr
		}
	}
	return nil
}

// FinalizeRecord post-processes records
func (hl *BlockHandlerList) FinalizeRecord(rec *message.ResourceRecord) *message.ResourceRecord {
	// no implementation yet
	return rec
}

//----------------------------------------------------------------------
// Zone key handler: Only one zone key as sole record in a block
//----------------------------------------------------------------------

// ZoneKeyHandler implementing the BlockHandler interface
type ZoneKeyHandler struct {
	ztype uint32                  // zone type
	zkey  *crypto.ZoneKey         // Zone key
	rec   *message.ResourceRecord // associated recource record
}

// NewZoneHandler returns a new BlockHandler instance
func NewZoneHandler(rec *message.ResourceRecord, labels []string) (BlockHandler, error) {
	// check if we have an implementation for the zone type
	if crypto.GetImplementation(rec.Type) == nil {
		return nil, ErrInvalidRecordType
	}
	// assemble handler
	h := &ZoneKeyHandler{
		ztype: rec.Type,
		zkey:  nil,
	}
	// add the record to the handler
	if err := h.AddRecord(rec, labels); err != nil {
		return nil, err
	}
	return h, nil
}

// AddRecord inserts a PKEY record into the handler.
func (h *ZoneKeyHandler) AddRecord(rec *message.ResourceRecord, labels []string) (err error) {
	// check record type
	if rec.Type != h.ztype {
		return ErrInvalidRecordType
	}
	// check for sole zone key record in block
	if h.zkey != nil {
		return ErrInvalidZoneKey
	}
	// set zone key
	h.zkey, err = crypto.NewZoneKey(rec.Data)
	if err != nil {
		return
	}
	h.rec = rec
	return
}

// Coexist return a flag indicating how a resource record of a given type
// is to be treated (see BlockHandler interface)
func (h *ZoneKeyHandler) Coexist(cm util.Counter[enums.GNSType]) bool {
	// only one type (GNS_TYPE_PKEY) is present
	return len(cm) == 1 && cm.Num(enums.GNS_TYPE_PKEY) == 1
}

// Records returns a list of RR of the given type associated with this handler
func (h *ZoneKeyHandler) Records(kind RRTypeList) *message.RecordSet {
	rs := message.NewRecordSet()
	if kind.HasType(enums.GNS_TYPE_PKEY) {
		rs.AddRecord(h.rec)
	}
	return rs
}

// Name returns the human-readable name of the handler.
func (h *ZoneKeyHandler) Name() string {
	return "PKEY_Handler"
}

//----------------------------------------------------------------------
// GNS2DNS handler
//----------------------------------------------------------------------

// Gns2DnsHandler implementing the BlockHandler interface
type Gns2DnsHandler struct {
	Query   string                    // DNS query name
	Servers []string                  // DNS servers to ask
	recs    []*message.ResourceRecord // list of rersource records
}

// NewGns2DnsHandler returns a new BlockHandler instance
func NewGns2DnsHandler(rec *message.ResourceRecord, labels []string) (BlockHandler, error) {
	if enums.GNSType(rec.Type) != enums.GNS_TYPE_GNS2DNS {
		return nil, ErrInvalidRecordType
	}
	h := &Gns2DnsHandler{
		Query:   "",
		Servers: make([]string, 0),
		recs:    make([]*message.ResourceRecord, 0),
	}
	if err := h.AddRecord(rec, labels); err != nil {
		return nil, err
	}
	return h, nil
}

// AddRecord inserts a GNS2DNS record into the handler.
func (h *Gns2DnsHandler) AddRecord(rec *message.ResourceRecord, labels []string) error {
	if enums.GNSType(rec.Type) != enums.GNS_TYPE_GNS2DNS {
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
func (h *Gns2DnsHandler) Coexist(cm util.Counter[enums.GNSType]) bool {
	// only one type (GNS_TYPE_GNS2DNS) is present
	return len(cm) == 1 && cm.Num(enums.GNS_TYPE_GNS2DNS) > 0
}

// Records returns a list of RR of the given type associated with this handler
func (h *Gns2DnsHandler) Records(kind RRTypeList) *message.RecordSet {
	rs := message.NewRecordSet()
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
func NewBoxHandler(rec *message.ResourceRecord, labels []string) (BlockHandler, error) {
	if enums.GNSType(rec.Type) != enums.GNS_TYPE_BOX {
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
func (h *BoxHandler) AddRecord(rec *message.ResourceRecord, labels []string) error {
	if enums.GNSType(rec.Type) != enums.GNS_TYPE_BOX {
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
func (h *BoxHandler) Coexist(cm util.Counter[enums.GNSType]) bool {
	// anything goes...
	return true
}

// Records returns a list of RR of the given type associated with this handler
func (h *BoxHandler) Records(kind RRTypeList) *message.RecordSet {
	rs := message.NewRecordSet()
	for _, box := range h.boxes {
		if kind.HasType(enums.GNSType(box.Type)) {
			// valid box found: assemble new resource record.
			rr := new(message.ResourceRecord)
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
	rec  *message.ResourceRecord
}

// NewLehoHandler returns a new BlockHandler instance
func NewLehoHandler(rec *message.ResourceRecord, labels []string) (BlockHandler, error) {
	if enums.GNSType(rec.Type) != enums.GNS_TYPE_LEHO {
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
func (h *LehoHandler) AddRecord(rec *message.ResourceRecord, labels []string) error {
	if enums.GNSType(rec.Type) != enums.GNS_TYPE_LEHO {
		return ErrInvalidRecordType
	}
	h.name = string(rec.Data)
	h.rec = rec
	return nil
}

// Coexist return a flag indicating how a resource record of a given type
// is to be treated (see BlockHandler interface)
func (h *LehoHandler) Coexist(cm util.Counter[enums.GNSType]) bool {
	// requires exactly one LEHO and any number of other records.
	return cm.Num(enums.GNS_TYPE_LEHO) == 1
}

// Records returns a list of RR of the given type associated with this handler
func (h *LehoHandler) Records(kind RRTypeList) *message.RecordSet {
	rs := message.NewRecordSet()
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
	rec  *message.ResourceRecord
}

// NewCnameHandler returns a new BlockHandler instance
func NewCnameHandler(rec *message.ResourceRecord, labels []string) (BlockHandler, error) {
	if enums.GNSType(rec.Type) != enums.GNS_TYPE_DNS_CNAME {
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
func (h *CnameHandler) AddRecord(rec *message.ResourceRecord, labels []string) error {
	if enums.GNSType(rec.Type) != enums.GNS_TYPE_DNS_CNAME {
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
func (h *CnameHandler) Coexist(cm util.Counter[enums.GNSType]) bool {
	// only a single CNAME allowed
	return len(cm) == 1 && cm.Num(enums.GNS_TYPE_DNS_CNAME) == 1
}

// Records returns a list of RR of the given type associated with this handler
func (h *CnameHandler) Records(kind RRTypeList) *message.RecordSet {
	rs := message.NewRecordSet()
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
	rec *message.ResourceRecord
}

// NewVpnHandler returns a new BlockHandler instance
func NewVpnHandler(rec *message.ResourceRecord, labels []string) (BlockHandler, error) {
	if enums.GNSType(rec.Type) != enums.GNS_TYPE_VPN {
		return nil, ErrInvalidRecordType
	}
	h := &VpnHandler{}
	if err := h.AddRecord(rec, labels); err != nil {
		return nil, err
	}
	return h, nil
}

// AddRecord inserts a VPN record into the handler.
func (h *VpnHandler) AddRecord(rec *message.ResourceRecord, labels []string) error {
	if enums.GNSType(rec.Type) != enums.GNS_TYPE_VPN {
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
func (h *VpnHandler) Coexist(cm util.Counter[enums.GNSType]) bool {
	// anything goes
	return true
}

// Records returns a list of RR of the given type associated with this handler
func (h *VpnHandler) Records(kind RRTypeList) *message.RecordSet {
	rs := message.NewRecordSet()
	if kind.HasType(enums.GNS_TYPE_VPN) {
		rs.AddRecord(h.rec)
	}
	return rs
}

// Name returns the human-readable name of the handler.
func (h *VpnHandler) Name() string {
	return "VPN_Handler"
}
