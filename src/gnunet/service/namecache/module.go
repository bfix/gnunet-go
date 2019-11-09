package namecache

import (
	"gnunet/service/gns"
)

//======================================================================
// "GNS name cache" implementation
//======================================================================

//----------------------------------------------------------------------
// Put and get GNS blocks into/from a cache (transient storage)
//----------------------------------------------------------------------

// Namecache handles the transient storage of GNS blocks under the query key.
type NamecacheModule struct {
}

func (nc *NamecacheModule) Get(query *gns.Query) (*gns.GNSBlock, error) {
	return nil, nil
}

func (nc *NamecacheModule) Put(query *gns.Query, block *gns.GNSBlock) error {
	return nil
}
