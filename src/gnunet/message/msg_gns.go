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

package message

import (
	"fmt"

	"gnunet/crypto"
	"gnunet/enums"
	"gnunet/service/dht/blocks"
	"gnunet/util"

	"github.com/bfix/gospel/logger"
)

//----------------------------------------------------------------------
// GNS_LOOKUP
//----------------------------------------------------------------------

// LookupMsg is a request message for a GNS name lookup
type LookupMsg struct {
	MsgHeader
	ID       uint32          `order:"big"` // Unique identifier for this request (for key collisions).
	Zone     *crypto.ZoneKey ``            // Zone that is to be used for lookup
	Options  uint16          `order:"big"` // Local options for where to look for results
	Reserved uint16          `order:"big"` // Always 0
	RType    enums.GNSType   `order:"big"` // the type of record to look up
	Name     []byte          `size:"*"`    // zero-terminated name to look up
}

// NewGNSLookupMsg creates a new default message.
func NewGNSLookupMsg() *LookupMsg {
	return &LookupMsg{
		MsgHeader: MsgHeader{48, enums.MSG_GNS_LOOKUP},
		ID:        0,
		Zone:      nil,
		Options:   uint16(enums.GNS_LO_DEFAULT),
		Reserved:  0,
		RType:     enums.GNS_TYPE_ANY,
		Name:      nil,
	}
}

// SetName appends the name to lookup to the message
func (m *LookupMsg) SetName(name string) {
	m.Name = util.Clone(append([]byte(name), 0))
	m.MsgSize = uint16(48 + len(m.Name))
}

// GetName returns the name to lookup from the message
func (m *LookupMsg) GetName() string {
	size := len(m.Name)
	if m.Name[size-1] != 0 {
		logger.Println(logger.WARN, "GNS_LOOKUP name not NULL-terminated")
	} else {
		size--
	}
	return string(m.Name[:size])
}

// String returns a human-readable representation of the message.
func (m *LookupMsg) String() string {
	return fmt.Sprintf(
		"GNSLookupMsg{Id=%d,Zone=%s,Options=%d,Type=%d,Name=%s}",
		m.ID, m.Zone.ID(), m.Options, m.RType, m.GetName())
}

//----------------------------------------------------------------------
// GNS_LOOKUP_RESULT
//----------------------------------------------------------------------

// LookupResultMsg is a response message for a GNS name lookup request
type LookupResultMsg struct {
	MsgHeader
	ID      uint32                   `order:"big"`  // Unique identifier for this request (for key collisions).
	Count   uint32                   `order:"big"`  // The number of records contained in response
	Records []*blocks.ResourceRecord `size:"Count"` // GNS resource records
}

// NewGNSLookupResultMsg returns a new lookup result message
func NewGNSLookupResultMsg(id uint32) *LookupResultMsg {
	return &LookupResultMsg{
		MsgHeader: MsgHeader{12, enums.MSG_GNS_LOOKUP_RESULT},
		ID:        id,
		Count:     0,
		Records:   make([]*blocks.ResourceRecord, 0),
	}
}

// AddRecord adds a GNS resource recordto the response message.
func (m *LookupResultMsg) AddRecord(rec *blocks.ResourceRecord) error {
	recSize := 20 + int(rec.Size)
	if int(m.MsgSize)+recSize > enums.GNS_MAX_BLOCK_SIZE {
		return fmt.Errorf("gns.AddRecord(): MAX_BLOCK_SIZE reached")
	}
	m.Records = append(m.Records, rec)
	m.MsgSize += uint16(recSize)
	m.Count++
	return nil
}

// String returns a human-readable representation of the message.
func (m *LookupResultMsg) String() string {
	return fmt.Sprintf("GNSLookupResultMsg{Id=%d,Count=%d}", m.ID, m.Count)
}

// Header returns the message header in a separate instance.
func (m *LookupResultMsg) Header() *MsgHeader {
	return &MsgHeader{m.MsgSize, m.MsgType}
}
