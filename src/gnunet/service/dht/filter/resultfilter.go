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

package filter

// ResultFilter return values
const (
	RF_MORE       = iota // Valid result, and there may be more.
	RF_LAST              // Last possible valid result.
	RF_DUPLICATE         // Valid result, but duplicate (was filtered by the result filter).
	RF_IRRELEVANT        // Block does not satisfy the constraints imposed by the XQuery.
)

//----------------------------------------------------------------------

// ResultFilter is used to indicate to other peers which results are not of
// interest when processing a GetMessage. Any peer which is processing
// GetMessages and has a result which matches the query key MUST check the
// result filter and only send a reply message if the result does not test
// positive under the result filter. Before forwarding the GetMessage, the
// result filter MUST be updated to filter out all results already returned
// by the local peer.
type ResultFilter interface {

	// Add entry (binary representation) to filter
	Add([]byte)

	// Contains returns true if entry (binary representation) is filtered
	Contains([]byte) bool
}
