// Minimal pure-Go Keccak-256 (the original Keccak, NOT NIST SHA3-256).
//
// EIP-55 Ethereum address checksums use Keccak-256, which uses the original
// Keccak padding (0x01 … 0x80). NIST SHA3-256 uses a different padding
// (0x06 … 0x80) and produces a different digest, so it cannot be used here.
// Faithful port of the reference src/entviz/keccak.py (via entviz-rs/keccak.rs).

package entviz

import (
	"encoding/hex"
	"math/bits"
)

var keccakRC = [24]uint64{
	0x0000000000000001,
	0x0000000000008082,
	0x800000000000808a,
	0x8000000080008000,
	0x000000000000808b,
	0x0000000080000001,
	0x8000000080008081,
	0x8000000000008009,
	0x000000000000008a,
	0x0000000000000088,
	0x0000000080008009,
	0x000000008000000a,
	0x000000008000808b,
	0x800000000000008b,
	0x8000000000008089,
	0x8000000000008003,
	0x8000000000008002,
	0x8000000000000080,
	0x000000000000800a,
	0x800000008000000a,
	0x8000000080008081,
	0x8000000000008080,
	0x0000000080000001,
	0x8000000080008008,
}

// Rho rotation offsets, indexed keccakROT[y][x].
var keccakROT = [5][5]uint{
	{0, 1, 62, 28, 27},
	{36, 44, 6, 55, 20},
	{3, 10, 43, 25, 39},
	{41, 45, 15, 21, 8},
	{18, 2, 61, 56, 14},
}

func keccakF1600(state *[5][5]uint64) {
	for _, rc := range keccakRC {
		// Theta
		var c [5]uint64
		for x := 0; x < 5; x++ {
			c[x] = state[x][0] ^ state[x][1] ^ state[x][2] ^ state[x][3] ^ state[x][4]
		}
		var d [5]uint64
		for x := 0; x < 5; x++ {
			d[x] = c[(x+4)%5] ^ bits.RotateLeft64(c[(x+1)%5], 1)
		}
		for x := 0; x < 5; x++ {
			for y := 0; y < 5; y++ {
				state[x][y] ^= d[x]
			}
		}

		// Rho + Pi
		var b [5][5]uint64
		for x := 0; x < 5; x++ {
			for y := 0; y < 5; y++ {
				b[y][(2*x+3*y)%5] = bits.RotateLeft64(state[x][y], int(keccakROT[y][x]&63))
			}
		}

		// Chi
		for x := 0; x < 5; x++ {
			for y := 0; y < 5; y++ {
				state[x][y] = b[x][y] ^ ((^b[(x+1)%5][y]) & b[(x+2)%5][y])
			}
		}

		// Iota
		state[0][0] ^= rc
	}
}

func keccakAbsorbBlock(state *[5][5]uint64, block []byte) {
	for i, by := range block {
		laneIndex := i / 8
		x := laneIndex % 5
		y := laneIndex / 5
		byteInLane := i % 8
		state[x][y] ^= uint64(by) << (8 * byteInLane)
	}
}

// keccak256 returns the 32-byte Keccak-256 digest of data.
func keccak256(data []byte) [32]byte {
	const rate = 136
	var state [5][5]uint64

	offset := 0
	n := len(data)
	for n-offset >= rate {
		keccakAbsorbBlock(&state, data[offset:offset+rate])
		keccakF1600(&state)
		offset += rate
	}

	// Final block: 0x01 … 0x80 padding.
	last := make([]byte, 0, rate)
	last = append(last, data[offset:]...)
	last = append(last, 0x01)
	for len(last) < rate {
		last = append(last, 0x00)
	}
	last[len(last)-1] |= 0x80
	keccakAbsorbBlock(&state, last)
	keccakF1600(&state)

	var out [32]byte
	for i := range out {
		laneIndex := i / 8
		x := laneIndex % 5
		y := laneIndex / 5
		byteInLane := i % 8
		out[i] = byte((state[x][y] >> (8 * byteInLane)) & 0xFF)
	}
	return out
}

// keccak256Hex returns the lowercase hex of the Keccak-256 digest of data.
func keccak256Hex(data []byte) string {
	d := keccak256(data)
	return hex.EncodeToString(d[:])
}
