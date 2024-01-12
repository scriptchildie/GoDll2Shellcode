package main

import "encoding/binary"

func uint64ToBytes(num uint64) []byte {
	bytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(bytes, num)
	return bytes
}
