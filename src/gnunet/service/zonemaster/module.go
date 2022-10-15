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

package zonemaster

import (
	"context"
	"gnunet/config"
	"gnunet/enums"
	"gnunet/message"
	"gnunet/service"
	"gnunet/service/dht/blocks"
	"gnunet/service/store"
	"gnunet/util"
	"time"

	"github.com/bfix/gospel/logger"
)

//======================================================================
// "GNS ZoneMaster" implementation:
// Manage and publish local zone records
//======================================================================

// ZoneMaster instance
type ZoneMaster struct {
	cfg *config.Config
	zdb *store.ZoneDB
}

// NewZoneMaster initializes a new zone master instance.
func NewZoneMaster(cfg *config.Config) *ZoneMaster {
	zm := new(ZoneMaster)
	zm.cfg = cfg
	return zm
}

// Run zone master: connect to zone database and start the RPC/HTTP
// services as background processes. Periodically publish GNS blocks
// into the DHT.
func (zm *ZoneMaster) Run(ctx context.Context) {
	// connect to database
	logger.Println(logger.INFO, "[zonemaster] Connecting to zone database...")
	dbFile, ok := util.GetParam[string](zm.cfg.ZoneMaster.Storage, "file")
	if !ok {
		logger.Printf(logger.ERROR, "[zonemaster] missing database file specification")
		return
	}
	var err error
	if zm.zdb, err = store.OpenZoneDB(dbFile); err != nil {
		logger.Printf(logger.ERROR, "[zonemaster] open database: %v", err)
		return
	}
	defer zm.zdb.Close()

	// start HTTP GUI
	zm.startGUI(ctx)

	// periodically publish GNS blocks to the DHT
	tick := time.NewTicker(time.Duration(zm.cfg.ZoneMaster.Period) * time.Second)
loop:
	for {
		select {
		case <-tick.C:
			if err := zm.Publish(ctx); err != nil {
				logger.Printf(logger.ERROR, "[zonemaster] periodic publish failed: %s", err.Error())
			}

		// check for termination
		case <-ctx.Done():
			break loop
		}
	}
}

// OnChange is called if a zone or record has changed or was inserted
func (zm *ZoneMaster) OnChange(table string, id int64) {

}

// Publish all zone labels to the DHT
func (zm *ZoneMaster) Publish(ctx context.Context) error {
	// collect all zones
	zones, err := zm.zdb.GetZones("")
	if err != nil {
		return err
	}
	for _, z := range zones {
		// collect labels for zone
		var labels []*store.Label
		if labels, err = zm.zdb.GetLabels("zid=%d", z.ID); err != nil {
			return err
		}
		for _, l := range labels {
			// publish label
			if err = zm.PublishZoneLabel(ctx, z, l); err != nil {
				return err
			}
		}
	}
	return nil
}

// PublishZoneLabel with public records
func (zm *ZoneMaster) PublishZoneLabel(ctx context.Context, zone *store.Zone, label *store.Label) error {
	// collect public records for zone label
	recs, err := zm.zdb.GetRecords("lid=%d and flags&%d = 0", label.ID, enums.GNS_FLAG_PRIVATE)
	if err != nil {
		return err
	}
	// compute derived key
	sk, _, err := zone.Key.Derive(label.Name, "gns")
	if err != nil {
		return err
	}
	// assemble record set and find earliest expiration
	expire := util.AbsoluteTimeNever()
	rrSet := message.NewRecordSet()
	for _, r := range recs {
		if r.Expire.Compare(expire) < 0 {
			expire = r.Expire
		}
		rrSet.AddRecord(&r.ResourceRecord)
	}
	rrSet.SetPadding()

	// assemble and sign GNS block
	blk, _ := blocks.NewGNSBlock().(*blocks.GNSBlock)
	blk.SetData(rrSet.Bytes())
	blk.Body.Expire = expire
	if err = blk.Sign(sk); err != nil {
		return err
	}
	// publish GNS block to DHT
	// key := sk.Public()
	return nil
}

func (zm *ZoneMaster) InitRPC(rpc *service.JRPCServer) error {
	return nil
}
