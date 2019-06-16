// Copyright 2019 Orange. All rights reserved.
// A Generic WPA implementation in Go
//
// Use of this source code is governed by a MIT license
// that can be found in the LICENSE file in the root of the source
// tree.

package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"log"

	"./eap"
)

func main() {
	pwd := "081503wq"
	ssid := "980Ti"
	// ANonce
	aNonce := h2b("9ab1c8bee4337354cf34f85df19152fdaf07e29476678e0cad70041880a9b5ae")
	// SNonce
	sNonce := h2b("4a14b0d1e27aea0c6afa69a6d537e494e826bff71d0cc1c7c952654aa7d7af06")
	// Authenticator MAC (AP)
	apMac := h2b("8825936ad864")
	// Station address: MAC of client
	cliMac := h2b("00ec0ae82965")
	// The first MIC
	mic := h2b("b86a499d6fa31c693490f5745734d906")
	// The entire 802.1x frame of the second handshake message with the MIC field set to all zeros
	data := h2b("0103007502010a000000000000000000014a14b0d1e27aea0c6afa69a6d537e494e826bff71d0cc1c7c952654aa7d7af06000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001630140100000fac040100000fac040100000fac020000")
	mic1, _, _, match := Verify(pwd, ssid, aNonce, sNonce, apMac, cliMac, data, mic, false)
	if match {
		fmt.Println("MATCH")
		fmt.Printf("actual mic: %x\n", mic1)
		fmt.Printf("desired mic: %x\n", mic)
	} else {
		fmt.Println("MISMATCH")
		fmt.Printf("actual mic: %x\n", mic1)
		fmt.Printf("desired mic: %x\n", mic)
	}
	//fmt.Printf("%x\n", ptk)
	//fmt.Printf("%x\n", pmk)
}

func Verify(pwd, ssid string, aNonce, sNonce, apMac, cliMac, data, mic []byte, isWpa bool) ([]byte, []byte, []byte, bool) {
	A, B := eap.MakeAB(aNonce, sNonce, apMac, cliMac)
	mic1, ptk, pmk := eap.MakeMIC(pwd, ssid, A, B, data, isWpa)
	mic1 = mic1[:16]
	return mic1, ptk, pmk, bytes.Equal(mic, mic1)
}

func h2b(h string) []byte {
	src := []byte(h)
	dst := make([]byte, hex.DecodedLen(len(src)))
	n, err := hex.Decode(dst, src)
	if err != nil {
		log.Fatal(err)
	}
	return dst[:n]
}

func b2h(b []byte) string {
	return hex.EncodeToString(b)
}
