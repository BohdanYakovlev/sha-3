package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

const (
	stateSize    = 25
	rate         = 136
	capacity     = 64
	hashByteSize = 32
)

var shiftTable = []uint{
	0, 36, 3, 41, 18,
	1, 44, 10, 45, 2,
	62, 6, 43, 15, 61,
	28, 55, 25, 21, 56,
	27, 20, 39, 8, 14,
}

var state [stateSize]uint64

func rightShift(x uint64, n uint) uint64 {
	return (x >> n) | (x << (64 - n))
}

func theta() {
	c := make([]uint64, 5)
	for i := range c {
		c[i] = state[i*5] ^ state[i*5+1] ^ state[i*5+2] ^ state[i*5+3] ^ state[i*5+4]
	}

	d := make([]uint64, 5)
	for i := range d {
		d[i] = c[(i+4)%5] ^ rightShift(c[(i+1)%5], 1)
	}

	for i := range state {
		state[i] = state[i] ^ d[i/5]
	}
}

func ro() {
	for i := range state {
		state[i] = rightShift(state[i], shiftTable[i])
	}
}

func pi() {
	for i := range state {
		x := i % 5
		y := i / 5
		state[i] = state[x*5+(x+3*y)%5]
	}
}

func chi() {
	for i := range state {
		x := i % 5
		y := i / 5
		state[i] = state[i] ^ ((^state[y*5+(x+1)%5]) & state[y*5+(x+2)%5])
	}
}

func iOta(LFSRConst uint64) {
	state[0] = state[0] ^ LFSRConst
}

func newLFSRConst(LFSRConst uint64) uint64 {
	tap := uint64(0xC000000000000001)
	newBit := (LFSRConst >> 63) & 1
	res := LFSRConst << 1
	if newBit == 1 {
		res ^= tap
	}
	return res
}

func keccak() {
	LFSRConst := uint64(0x01)
	for i := 0; i < 24; i++ {
		theta()
		ro()
		pi()
		chi()
		iOta(LFSRConst)
		LFSRConst = newLFSRConst(LFSRConst)
	}
}

func absorb(block []uint64) {
	for i := 0; i < len(block); i++ {
		state[i] = state[i] ^ block[i]
	}
}

func padding(messageLen int) []byte {
	var result []byte

	result = append(result, 0x80)

	count := rate - (messageLen+2)%rate

	for i := 0; i < count; i++ {
		result = append(result, 0x00)
	}

	result = append(result, 0x01)

	return result
}

func getNewPaddingBlock(block []byte) []uint64 {
	byteBlock := make([]byte, len(block))
	copy(byteBlock, block)
	byteBlock = append(byteBlock, make([]byte, capacity)...)

	result := make([]uint64, stateSize)

	for i := 0; i < len(result); i++ {
		result[i] = binary.LittleEndian.Uint64(byteBlock[i*8 : (i+1)*8])
	}
	return result
}

func uint64ToBytes(uint64Slice []uint64) []byte {
	var byteSlice []byte
	for _, v := range uint64Slice {
		// Каждый элемент uint64 в байтовый срез (8 байт)
		for i := 0; i < 8; i++ {
			byteSlice = append(byteSlice, byte(v>>(uint64(8*i))&0xFF))
		}
	}
	return byteSlice
}

func sha3256(message []byte) []byte {
	paddingMessage := append(message, padding(len(message))...)

	for i := 0; i < len(paddingMessage); i += rate {
		block := getNewPaddingBlock(paddingMessage[i : i+rate])
		absorb(block)
		keccak()
	}
	stateByte := uint64ToBytes(state[:])
	res := make([]byte, hashByteSize)
	copy(res, stateByte[:hashByteSize])
	return res
}

func main() {
	message := "2025"
	fmt.Println(hex.EncodeToString(sha3256([]byte(message))))

	/*hash := sha3.New256()
	hash.Write([]byte(message))
	hashBytes := hash.Sum(nil)
	fmt.Println(hex.EncodeToString(hashBytes))*/
}
