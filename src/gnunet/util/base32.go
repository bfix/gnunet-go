package util

import (
	"errors"
	"strings"
)

//------------------------------------------------------------------------
// Base32 conversion between binary data and string representation
//------------------------------------------------------------------------
//
// A binary array of size m is viewed as a consecutive stream of bits
// from left to right. Bytes are ordered with ascending address, while
// bits (in a byte) are ordered MSB to LSB.

// For encoding the stream is partitioned into 5-bit chunks; the last chunk
// is right-padded with 0's if 8*m is not divisible by 5. Each chunk (value
// between 0 and 31) is encoded into a character; the mapping for encoding
// is the same as in [https://www.crockford.com/wrmg/base32.html].
//
// For decoding each character is converted to a 5-bit chunk based on the
// encoder mapping (with one addition: the character 'U' maps to the value
// 27). The chunks are concatenated to produce the bit stream to be stored
// in the output array.

// character set used for encoding/decoding
const xlate = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

var (
	// ErrInvalidEncoding signals an invalid encoding
	ErrInvalidEncoding = errors.New("Invalid encoding")
	// ErrBufferTooSmall signalsa too small buffer for decoding
	ErrBufferTooSmall = errors.New("Buffer to small")
)

// EncodeBinaryToString encodes a byte array into a string.
func EncodeBinaryToString(data []byte) string {
	size, pos, bits, n := len(data), 0, 0, 0
	out := ""
	for {
		if n < 5 {
			if pos < size {
				bits = (bits << 8) | (int(data[pos]) & 0xFF)
				pos++
				n += 8
			} else if n > 0 {
				bits <<= uint(5 - n)
				n = 5
			} else {
				break
			}
		}
		out += string(xlate[(bits>>uint(n-5))&0x1F])
		n -= 5
	}
	return out
}

// DecodeStringToBinary decodes a string into a byte array.
// The function expects the size of the output buffer to be sepcified as an
// argument ('num'); the function returns an error if the buffer is overrun
// or if an invalid character is found in the encoded string. If the decoded
// bit stream is smaller than the output buffer, it is padded with 0's.
func DecodeStringToBinary(s string, num int) ([]byte, error) {
	size := len(s)
	out := make([]byte, num)
	rpos, wpos, n, bits := 0, 0, 0, 0
	for {
		if n < 8 {
			if rpos < size {
				c := rune(s[rpos])
				rpos++
				v := strings.IndexRune(xlate, c)
				if v == -1 {
					switch c {
					case 'O':
						v = 0
					case 'I', 'L':
						v = 1
					case 'U':
						v = 27
					default:
						return nil, ErrInvalidEncoding
					}
				}
				bits = (bits << 5) | (v & 0x1F)
				n += 5
			} else {
				if wpos < num {
					out[wpos] = byte(bits & ((1 << uint(n+1)) - 1))
					wpos++
					for i := wpos; i < num; i++ {
						out[i] = 0
					}
				}
				break
			}
		} else {
			if wpos < num {
				out[wpos] = byte((bits >> uint(n-8)) & 0xFF)
				wpos++
				n -= 8
			} else {
				return nil, ErrBufferTooSmall
			}
		}
	}
	return out, nil
}
