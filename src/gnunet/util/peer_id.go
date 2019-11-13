package util

// PeerID is the 32-byte binary representation od a Ed25519 key
type PeerID struct {
	Key []byte `size:"32"`
}

// NewPeerID creates a new object from the data.
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

// String returns a human-readable representation of a peer id.
func (p *PeerID) String() string {
	return EncodeBinaryToString(p.Key)
}
