package main

import (
	"flag"
	"log"

	"gnunet/crypto"
	"gnunet/enums"
	"gnunet/message"
	"gnunet/service/gns"
	"gnunet/transport"
	"gnunet/util"
)

func main() {
	var (
		dhtService string
		pkey       string
		label      string
	)
	// handle command line arguments
	flag.StringVar(&dhtService, "s", "", "DHT service end-point")
	flag.StringVar(&pkey, "p", "", "PKEY for resolution")
	flag.StringVar(&label, "l", "", "Label to be resolved")
	flag.Parse()

	// compute query
	kd, err := util.DecodeStringToBinary(pkey, 32)
	if err != nil {
		log.Fatal(err)
	}
	_ = crypto.NewPublicKey(kd)
	query := crypto.NewHashCode() // gns.QueryFromPublickeyDerive(pk, label)

	// create and set-up DHT GET message
	raw, err := message.NewEmptyMessage(message.DHT_CLIENT_GET)
	if err != nil {
		log.Fatal(err)
	}
	msg := raw.(*message.DHTClientGetMsg)
	msg.ReplLevel = uint32(gns.DHT_GNS_REPLICATION_LEVEL)
	msg.Type = uint32(enums.BLOCK_TYPE_GNS_NAMERECORD)
	msg.Options = uint32(enums.DHT_RO_DEMULTIPLEX_EVERYWHERE)
	msg.Key = query
	log.Printf("Assembled DHT GET message: %v\n", msg)

	// start a new DHT client: open new channel to DHT service.
	ch, err := transport.NewChannel(dhtService)
	if err != nil {
		log.Fatal(err)
	}
	defer ch.Close()
	log.Printf("Opened channel to DHT service at '%s'\n", dhtService)

}
