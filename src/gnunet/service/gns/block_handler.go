package gns

import (
	"encoding/hex"
	"fmt"

	"gnunet/enums"
	"gnunet/message"

	"github.com/bfix/gospel/crypto/ed25519"
	"github.com/bfix/gospel/logger"
)

// HdlrInst is the type for functions that instanciate custom block handlers.
type HdlrInst func(*message.GNSResourceRecord, []string) (BlockHandler, error)

// Error codes
var (
	ErrInvalidRecordMix = fmt.Errorf("Invalid mix of RR types in block")
	ErrBlockHandler     = fmt.Errorf("Internal block handler failure")
)

// Mapping of RR types to BlockHandler instanciation functions
var (
	customHandler = map[int]HdlrInst{
		enums.GNS_TYPE_PKEY:    NewPkeyHandler,
		enums.GNS_TYPE_GNS2DNS: NewGns2DnsHandler,
		enums.GNS_TYPE_BOX:     NewBoxHandler,
		enums.GNS_TYPE_LEHO:    NewLehoHandler,
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
	// AddRecord inserts a RR into the BlockHandler for (later) processing.
	// The handler can inspect the remaining labels in a path if required.
	// It returns an error if a record is not accepted by the block handler.
	AddRecord(rr *message.GNSResourceRecord, labels []string) error

	// TypeAction returns a flag indicating how a resource record of a
	// given type is to be treated by a custom block handler:
	//   = -1: Record is not allowed
	//   =  0: Record is allowed but will be ignored
	//   =  1: Record is allowed and will be processed
	TypeAction(t int) int

	// Records returns a list of RR of the given types associated with
	// the custom handler
	Records(kind RRTypeList) *GNSRecordSet
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
//----------------------------------------------------------------------

// BlockHandlerList is a list of block handlers instantiated.
type BlockHandlerList struct {
	list map[int]BlockHandler // list of handler instances
}

// NewBlockHandlerList instantiates an a list of active block handlers
// for a given set of records (GNS block).
func NewBlockHandlerList(records []*message.GNSResourceRecord, labels []string) (*BlockHandlerList, error) {
	// initialize block handler list
	hl := &BlockHandlerList{
		list: make(map[int]BlockHandler),
	}
	// build a list of record types that are handled by a custom handler.
	rrList := NewRRTypeList(
		enums.GNS_TYPE_PKEY,
		enums.GNS_TYPE_GNS2DNS,
		enums.GNS_TYPE_BOX,
		enums.GNS_TYPE_LEHO)

	// Traverse record list and build list of handler instances
	for _, rec := range records {
		// check for custom handler type
		rrType := int(rec.Type)
		if rrList.HasType(rrType) {
			// check if a handler for given type already exists
			var (
				hdlr BlockHandler
				ok   bool
				err  error
			)
			if hdlr, ok = hl.list[rrType]; ok {
				// add record to existing handler
				if err = hdlr.AddRecord(rec, labels); err != nil {
					return nil, err
				}
				continue
			}
			// create a new handler instance
			switch rrType {
			case enums.GNS_TYPE_PKEY:
				hdlr, err = NewPkeyHandler(rec, labels)
			case enums.GNS_TYPE_GNS2DNS:
				hdlr, err = NewGns2DnsHandler(rec, labels)
			case enums.GNS_TYPE_BOX:
				hdlr, err = NewBoxHandler(rec, labels)
			case enums.GNS_TYPE_LEHO:
				hdlr, err = NewLehoHandler(rec, labels)
			}
			if err != nil {
				return nil, err
			}
			// store handler in list
			hl.list[rrType] = hdlr
		}
	}
	return hl, nil
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

// TypeAction return a flag indicating how a resource record of a given type
// is to be treated (see BlockHandler interface)
func (h *PkeyHandler) TypeAction(t int) int {
	// no other resource record type is not allowed
	if t == enums.GNS_TYPE_PKEY {
		return 1
	}
	return -1
}

// Records returns a list of RR of the given type associated with this handler
func (h *PkeyHandler) Records(kind RRTypeList) *GNSRecordSet {
	rs := NewGNSRecordSet()
	if kind.HasType(enums.GNS_TYPE_PKEY) {
		rs.AddRecord(h.rec)
	}
	return rs
}

//----------------------------------------------------------------------
// GNS2DNS handler
//----------------------------------------------------------------------

// Gns2DnsHandler implementing the BlockHandler interface
type Gns2DnsHandler struct {
	Name    string                       // DNS query name
	Servers []string                     // DNS servers to ask
	recs    []*message.GNSResourceRecord // list of rersource records
}

// NewGns2DnsHandler returns a new BlockHandler instance
func NewGns2DnsHandler(rec *message.GNSResourceRecord, labels []string) (BlockHandler, error) {
	if int(rec.Type) != enums.GNS_TYPE_GNS2DNS {
		return nil, ErrInvalidRecordType
	}
	h := &Gns2DnsHandler{
		Name:    "",
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
		h.Name = dnsQuery
	}
	if dnsQuery != h.Name {
		return ErrInvalidRecordBody
	}
	h.Servers = append(h.Servers, dnsServer)
	h.recs = append(h.recs, rec)
	return nil
}

// TypeAction return a flag indicating how a resource record of a given type
// is to be treated (see BlockHandler interface)
func (h *Gns2DnsHandler) TypeAction(t int) int {
	// anything goes...
	return 1
}

// Records returns a list of RR of the given type associated with this handler
func (h *Gns2DnsHandler) Records(kind RRTypeList) *GNSRecordSet {
	rs := NewGNSRecordSet()
	if kind.HasType(enums.GNS_TYPE_GNS2DNS) {
		for _, rec := range h.recs {
			rs.AddRecord(rec)
		}
	}
	return rs
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

// TypeAction return a flag indicating how a resource record of a given type
// is to be treated (see BlockHandler interface)
func (h *BoxHandler) TypeAction(t int) int {
	// anything goes...
	return 1
}

// Records returns a list of RR of the given type associated with this handler
func (h *BoxHandler) Records(kind RRTypeList) *GNSRecordSet {
	rs := NewGNSRecordSet()
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

// TypeAction return a flag indicating how a resource record of a given type
// is to be treated (see BlockHandler interface)
func (h *LehoHandler) TypeAction(t int) int {
	// only A and AAAA records allowed beside LEHO
	switch t {
	case enums.GNS_TYPE_LEHO, enums.GNS_TYPE_DNS_A, enums.GNS_TYPE_DNS_AAAA:
		return 1
	default:
		return -1
	}
}

// Records returns a list of RR of the given type associated with this handler
func (h *LehoHandler) Records(kind RRTypeList) *GNSRecordSet {
	rs := NewGNSRecordSet()
	if kind.HasType(enums.GNS_TYPE_LEHO) {
		rs.AddRecord(h.rec)
	}
	return rs
}
