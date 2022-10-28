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
	"gnunet/core"
	"gnunet/enums"
	"gnunet/service/dht/blocks"
	"gnunet/service/store"
	"gnunet/util"
	"plugin"
	"time"

	"github.com/bfix/gospel/logger"
)

//======================================================================
// "GNS ZoneMaster" implementation (extended):
// Manage local identities for subsystems. Manage and publish
// local GNS zone records.
//======================================================================

// ZoneMaster implements
type ZoneMaster struct {
	Module

	zdb       *store.ZoneDB            // ZoneDB connection
	plugins   []Plugin                 // list of loaded plugins
	hdlrs     map[enums.GNSType]Plugin // maps record types to handling plugin
	namestore *NamestoreService        // namestore subservice
	identity  *IdentityService         // identity subservice
}

// NewService initializes a new zone master service.
func NewService(ctx context.Context, c *core.Core, plugins []string) *ZoneMaster {
	mod := NewModule(ctx, c)
	srv := &ZoneMaster{
		Module:  *mod,
		plugins: make([]Plugin, 0),
		hdlrs:   make(map[enums.GNSType]Plugin),
	}

	// set external function references (external services)
	srv.StoreLocal = srv.StoreNamecache
	srv.StoreRemote = srv.StoreDHT

	// instantiate sub-services
	srv.namestore = NewNamestoreService(srv)
	srv.identity = NewIdentityService(srv)

	// load all plugins
	for _, pn := range plugins {
		// get handle to plugin
		plugin, err := plugin.Open(pn)
		if err != nil {
			logger.Printf(logger.ERROR, "[zonemaster] %v", err)
			continue
		}
		// get plugin instance
		sym, err := plugin.Lookup("Plugin")
		if err != nil {
			logger.Printf(logger.ERROR, "[zonemaster] can't lookup plugin instance: %v", err)
			continue
		}
		inst, ok := sym.(Plugin)
		if !ok {
			logger.Println(logger.ERROR, "[zonemaster] can't cast plugin instance")
			continue
		}
		logger.Printf(logger.ERROR, "[zonemaster] plugin '%s' loaded.", inst.Name())

		// add plugin to resource record type handler
		srv.plugins = append(srv.plugins, inst)
		for t := range inst.CanHandle() {
			srv.hdlrs[enums.GNSType(t)] = inst
		}
	}
	return srv
}

// Run zone master: connect to zone database and start the RPC/HTTP
// services as background processes. Periodically publish GNS blocks
// into the DHT.
func (zm *ZoneMaster) Run(ctx context.Context) {
	// connect to database
	logger.Println(logger.INFO, "[zonemaster] Connecting to zone database...")
	var err error
	dbFile, _ := util.GetParam[string](config.Cfg.ZoneMaster.Storage, "file")
	if zm.zdb, err = store.OpenZoneDB(dbFile); err != nil {
		logger.Printf(logger.ERROR, "[zonemaster] open database: %v", err)
		return
	}
	defer zm.zdb.Close()

	// start HTTP GUI
	zm.startGUI(ctx)

	// publish on start-up
	if err = zm.Publish(ctx); err != nil {
		logger.Printf(logger.ERROR, "[zonemaster] initial publish failed: %s", err.Error())
	}

	// periodically publish GNS blocks to the DHT
	tick := time.NewTicker(time.Duration(config.Cfg.ZoneMaster.Period) * time.Second)
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
func (zm *ZoneMaster) OnChange(table string, id int64, mode int) {
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
	zk := zone.Key.Public()
	logger.Printf(logger.INFO, "[zonemaster] Publishing label '%s' of zone %s", label.Name, zk.ID())

	// collect all records for label
	rrSet, expire, err := zm.getRecords(zk, label.ID)
	if err != nil {
		return err
	}
	if rrSet.Count == 0 {
		logger.Println(logger.INFO, "[zonemaster] No resource records -- skipped")
		return nil
	}

	// assemble GNS query (common for DHT and Namecache)
	query := blocks.NewGNSQuery(zk, label.Name)

	//------------------------------------------------------------------
	// Publish to DHT
	//------------------------------------------------------------------

	// filter out private resource records.
	recsDHT := util.Clone(rrSet.Records)
	num := uint32(len(recsDHT))
	for i, rec := range recsDHT {
		if rec.Flags&enums.GNS_FLAG_PRIVATE != 0 {
			copy(recsDHT[i:], recsDHT[i+1:])
			num--
			recsDHT = recsDHT[:num]
		}
	}
	rrsDHT := &blocks.RecordSet{
		Count:   num,
		Records: recsDHT,
		Padding: nil,
	}
	rrsDHT.SetPadding()

	// build block for DHT
	blkDHT, _ := blocks.NewGNSBlock().(*blocks.GNSBlock)
	blkDHT.Body.Expire = expire
	blkDHT.Body.Data, err = zk.Encrypt(rrSet.Bytes(), label.Name, expire)
	if err != nil {
		return err
	}
	dzk, _, err := zone.Key.Derive(label.Name, "gns")
	if err != nil {
		return err
	}
	if err = blkDHT.Sign(dzk); err != nil {
		return err
	}
	// publish GNS block to DHT
	if err = zm.StoreDHT(ctx, query, blkDHT); err != nil {
		return err
	}

	// DEBUG
	/*
		logger.Printf(logger.DBG, "[zonemaster] pub = %s", util.EncodeBinaryToString(zk.Bytes()))
		logger.Printf(logger.DBG, "[zonemaster] query = %s", hex.EncodeToString(query.Key().Data))
		logger.Printf(logger.DBG, "[zonemaster] blk = %s", hex.EncodeToString(blkDHT.Bytes()))
	*/

	//------------------------------------------------------------------
	// Publish to Namecache
	//------------------------------------------------------------------

	// build block for Namecache
	blkNC, _ := blocks.NewGNSBlock().(*blocks.GNSBlock)
	blkNC.Body.Expire = expire
	blkNC.Body.Data = rrSet.Bytes()
	// sign block
	if dzk, _, err = zone.Key.Derive(label.Name, "gns"); err != nil {
		return err
	}
	if err = blkNC.Sign(dzk); err != nil {
		return err
	}

	// publish GNS block to namecache
	if err = zm.StoreNamecache(ctx, query, blkNC); err != nil {
		return err
	}
	return nil
}
