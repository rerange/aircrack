// By Orange
// The original Python implementation can be found here:
//     https://github.com/nicholastoddsmith/PyCrack/blob/master/pywd.py

package eap

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"

	"golang.org/x/crypto/pbkdf2"
)

func max(a, b []byte) []byte {
	if bytes.Compare(a, b) >= 0 {
		return a
	} else {
		return b
	}
}

func min(a, b []byte) []byte {
	if bytes.Compare(a, b) >= 0 {
		return b
	} else {
		return a
	}
}

func MakeAB(aNonce, sNonce, apMac, cliMac []byte) ([]byte, []byte) {
	B := make([]byte, 0)
	A := []byte("Pairwise key expansion")
	B = append(B, min(apMac, cliMac)...)
	B = append(B, max(apMac, cliMac)...)
	B = append(B, min(aNonce, sNonce)...)
	B = append(B, max(aNonce, sNonce)...)
	return A, B
}

func PRF(key, A, B []byte) []byte {
	// Number of bytes in the PTK
	nByte := 64
	i := 0
	R := make([]byte, 0)
	// Each iteration produces 160-bit value and 512 bits are required
	for i <= ((nByte*8 + 159) / 160) {
		mac := hmac.New(sha1.New, key)
		mac.Write(A)
		mac.Write([]byte{0})
		mac.Write(B)
		mac.Write([]byte{byte(i)})
		R = append(R, mac.Sum(nil)...)
		i += 1
	}
	return R[0:nByte]
}

func MakeMIC(pwd, ssid string, A, B, data []byte, isWpa bool) ([]byte, []byte, []byte) {
	// Create the pairwise master key
	pmk := pbkdf2.Key([]byte(pwd), []byte(ssid), 4096, 32, sha1.New)
	// Make the pairwise transient key (PTK)
	ptk := PRF(pmk, A, B)
	// WPA uses md5 to compute the MIC while WPA2 uses sha1
	hmacFunc := sha1.New
	if isWpa {
		hmacFunc = md5.New
	}
	// Create the MIC using HMAC-SHA1 of data and return computed value
	mac := hmac.New(hmacFunc, ptk[0:16])
	mac.Write(data)
	mic := mac.Sum(nil)
	return mic, ptk, pmk
}
