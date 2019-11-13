package transport

// Session states
const (
	KX_STATE_DOWN         = iota // No handshake yet.
	KX_STATE_KEY_SENT            // We've sent our session key.
	KX_STATE_KEY_RECEIVED        // We've received the other peers session key.
	KX_STATE_UP                  // Key exchange is done.
	KX_STATE_REKEY_SENT          // We're rekeying (or had a timeout).
	KX_PEER_DISCONNECT           // Last state of a KX (when it is being terminated).
)
