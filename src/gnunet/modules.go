//======================================================================
// Standalone (all-in-one) implementation of GNUnet:
// -------------------------------------------------
// Instead of running GNUnet services like GNS or DHT in separate
// processes communicating (exchanging messages) with each other over
// Unix Domain Sockets, the standalone implementation combines all
// service modules into a single binary running go-routines to
// concurrently performing their tasks.
//======================================================================

package gnunet

import (
	"gnunet/service/gns"
	"gnunet/service/namecache"
)

// List of all GNUnet service module instances
type Instances struct {
	GNS       *gns.GNSModule
	Namecache *namecache.NamecacheModule
}

// Local reference to instance list
var (
	Modules Instances
)

// Initialize instance list and link module functions as required.
func init() {

	// Namecache (no calls to other modules)
	Modules.Namecache = new(namecache.NamecacheModule)

	// GNS (calls Namecache, DHT and Identity)
	Modules.GNS = &gns.GNSModule{
		LookupLocal: Modules.Namecache.Get,
		StoreLocal:  Modules.Namecache.Put,
	}
}
