package core

import (
	"fmt"

	"gnunet/crypto"
	"gnunet/message"
	"gnunet/util"
)

/*
type Peer interface {
	GetID() []byte
	GetIDString() string
	GetAddressList() []*util.Address
	Sign(msg []byte) ([]byte, error)
	Verify(msg, sig []byte) bool
}
*/

type Peer struct {
	pub      *crypto.PublicKey
	idString string
	addrList []*util.Address
	prv      *crypto.PrivateKey       // long-term signing key
	ephPrv   *crypto.PrivateKey       // ephemeral signing key
	ephMsg   *message.EphemeralKeyMsg // ephemeral signing key message
}

func NewPeer(data []byte, local bool) (p *Peer, err error) {
	p = new(Peer)
	if local {
		p.prv = crypto.PrivateKeyFromSeed(data)
		p.pub = p.prv.Public()
		p.ephPrv, p.ephMsg, err = message.NewEphemeralKey(p.pub.Bytes(), p.prv)
		if err != nil {
			return
		}
	} else {
		p.prv = nil
		p.pub = crypto.NewPublicKey(data)
	}
	p.idString = util.EncodeBinaryToString(p.pub.Bytes())
	p.addrList = make([]*util.Address, 0)
	return
}

func (p *Peer) EphKeyMsg() *message.EphemeralKeyMsg {
	return p.ephMsg
}

func (p *Peer) SetEphKeyMsg(msg *message.EphemeralKeyMsg) {
	p.ephMsg = msg
}

func (p *Peer) EphPrvKey() *crypto.PrivateKey {
	return p.ephPrv
}

func (p *Peer) PrvKey() *crypto.PrivateKey {
	return p.prv
}

func (p *Peer) PubKey() *crypto.PublicKey {
	return p.pub
}

func (p *Peer) GetID() []byte {
	return p.pub.Bytes()
}

func (p *Peer) GetIDString() string {
	return p.idString
}

func (p *Peer) GetAddressList() []*util.Address {
	return p.addrList
}

func (p *Peer) AddAddress(a *util.Address) {
	p.addrList = append(p.addrList, a)
}

func (p *Peer) Sign(msg []byte) (*crypto.Signature, error) {
	if p.prv == nil {
		return nil, fmt.Errorf("No private key")
	}
	return p.prv.Sign(msg)
}

func (p *Peer) Verify(msg []byte, sig *crypto.Signature) (bool, error) {
	return p.pub.Verify(msg, sig)
}
