package gns

///////////////////////////////////////////////////////////////////////
// GNS configuration

// Config
type Config struct {
	Endpoint     string `json:"endpoint"`     // end-point of GNS service
	DHTReplLevel int    `json:"dhtReplLevel"` // DHT replication level
}
