package core

import (
	"fmt"

	"github.com/bfix/gospel/crypto/ed25519"
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
	pub      *ed25519.PublicKey
	idString string
	addrList []*util.Address
	prv      *ed25519.PrivateKey      // long-term signing key
	ephPrv   *ed25519.PrivateKey      // ephemeral signing key
	ephMsg   *message.EphemeralKeyMsg // ephemeral signing key message
}

func NewPeer(data []byte, local bool) (p *Peer, err error) {
	p = new(Peer)
	if local {
		p.prv = ed25519.NewPrivateKeyFromSeed(data)
		p.pub = p.prv.Public()
		p.ephPrv, p.ephMsg, err = message.NewEphemeralKey(p.pub.Bytes(), p.prv)
		if err != nil {
			return
		}
	} else {
		p.prv = nil
		p.pub = ed25519.NewPublicKeyFromBytes(data)
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

func (p *Peer) EphPrvKey() *ed25519.PrivateKey {
	return p.ephPrv
}

func (p *Peer) PrvKey() *ed25519.PrivateKey {
	return p.prv
}

func (p *Peer) PubKey() *ed25519.PublicKey {
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

func (p *Peer) Sign(msg []byte) (*ed25519.EdSignature, error) {
	if p.prv == nil {
		return nil, fmt.Errorf("No private key")
	}
	return p.prv.EdSign(msg)
}

func (p *Peer) Verify(msg []byte, sig *ed25519.EdSignature) (bool, error) {
	return p.pub.EdVerify(msg, sig)
}
