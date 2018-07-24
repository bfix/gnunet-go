package main

import (
	"gnunet/core"
	"gnunet/message"
	"gnunet/util"
)

func setupPeers(rnd bool) (err error) {

	//------------------------------------------------------------------
	// create local peer
	//------------------------------------------------------------------
	secret := []byte{
		0x78, 0xde, 0xcf, 0xc0, 0x26, 0x9e, 0x62, 0x3d,
		0x17, 0x24, 0xe6, 0x1b, 0x98, 0x25, 0xec, 0x2f,
		0x40, 0x6b, 0x1e, 0x39, 0xa5, 0x19, 0xac, 0x9b,
		0xb2, 0xdd, 0xf4, 0x6c, 0x12, 0x83, 0xdb, 0x86,
	}
	if rnd {
		util.RndArray(secret)
	}
	p, err = core.NewPeer(secret, true)
	if err != nil {
		return
	}
	addr, _ := message.Marshal(util.NewIPAddress([]byte{172, 17, 0, 6}, 2086))
	p.AddAddress(util.NewAddress("tcp", addr))

	//------------------------------------------------------------------
	// create remote peer
	//------------------------------------------------------------------
	id := []byte{
		0x92, 0xdc, 0xbf, 0x39, 0x40, 0x2d, 0xc6, 0x3c,
		0x97, 0xa6, 0x81, 0xe0, 0xfc, 0xd8, 0x7c, 0x74,
		0x17, 0xd3, 0xa3, 0x8c, 0x52, 0xfd, 0xe0, 0x49,
		0xbc, 0xd0, 0x1c, 0x0a, 0x0b, 0x8c, 0x02, 0x51,
	}
	t, err = core.NewPeer(id, false)
	if err != nil {
		return
	}
	addr, _ = message.Marshal(util.NewIPAddress([]byte{172, 17, 0, 5}, 2086))
	t.AddAddress(util.NewAddress("tcp", addr))
	return
}
