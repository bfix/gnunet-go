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

package path

import (
	"gnunet/crypto"
	"gnunet/util"
)

//----------------------------------------------------------------------
// Path handling
//----------------------------------------------------------------------

// Verify path: if 'truncOrigin' is not nil, the path was truncated on the left.
// Returns the position of the first invalid signature (from right) or -1 if the
// whole path is verified OK.
//
// The following synatx is used:
//     Pi              // peer id of i.th peer (hop)
//     Si = sig(D,Pi)  // signature over D=(...|Pi-1|Pi+1) with privkey Pi
//     ver(D,Si,Pi)    // verify Si over data D with pubkey Pi
//
// A path is composed of three elements:
//   (1) TO: peer id of truncated origin (iff truncated)
//   (2) PP: A list of path elements [ (P1,S2), (P2,S3), (P3,S4), ... ]
//           path element = struct { predecessor, signature }
//   (3) LS: Last hop signature
//
// The path is processed from right to left (decreasing index) using the
// following procedure on a peer:
//
//     vk := peer id of message sender
//     succ := local peer id
//     for n := len(PP)-1; n > 0; n-- {
//         pred := PP[n].predecessor
//         if !verify(...|pred|succ, PP[n].signature, vk)
//             return n
//         succ = vk
//         vk = pred
//     }
//     return -1
//
func Verify(
	sender, local, truncOrigin *util.PeerID,
	path []*ElementWire,
	lastSig *util.PeerSignature,
	bh *crypto.HashCode,
	expire util.AbsoluteTime,
) int {

	vk := sender
	succ := local
	for i := len(path) - 1; i > 0; i-- {
		peWire := path[i]
		pred := peWire.Predecessor
		pe := NewElement(bh, pred, succ, expire)
		ok, err := pred.Verify(pe.SignedData(), peWire.Signature)
		if err != nil || !ok {
			return i
		}
		succ = vk
		vk = pred
	}
	return -1
}
