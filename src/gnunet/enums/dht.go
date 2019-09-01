package enums

var (
	DHT_RO_NONE                   = 0  // Default.  Do nothing special.
	DHT_RO_DEMULTIPLEX_EVERYWHERE = 1  // Each peer along the way should look at 'enc'
	DHT_RO_RECORD_ROUTE           = 2  // keep track of the route that the message took in the P2P network.
	DHT_RO_FIND_PEER              = 3  // This is a 'FIND-PEER' request, so approximate results are fine.
	DHT_RO_BART                   = 4  // Possible message option for query key randomization.
	DHT_RO_LAST_HOP               = 16 // Flag given to monitors if this was the last hop for a GET/PUT.

	DHT_GNS_REPLICATION_LEVEL = 10
)
