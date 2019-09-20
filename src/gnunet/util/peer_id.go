package util

type PeerID struct {
	Key []byte `size:"32"`
}

func NewPeerID(data []byte) *PeerID {
	if data == nil {
		data = make([]byte, 32)
	} else {
		size := len(data)
		if size > 32 {
			data = data[:32]
		} else if size < 32 {
			buf := make([]byte, 32)
			CopyBlock(buf, data)
			data = buf
		}
	}
	return &PeerID{
		Key: data,
	}
}

func (p *PeerID) String() string {
	return EncodeBinaryToString(p.Key)
}
