package main

import "math/bits"

func HashCalculator(funcName string) uint32 {

	var hash uint32 = 0
	// Convert string to byte slice
	byteSlice := []byte(funcName)

	for _, byte := range byteSlice {
		hash = bits.RotateLeft32(hash, -0x0d)
		hash += uint32(byte)

	}
	return hash
}
