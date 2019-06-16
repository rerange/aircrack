// Copyright 2019 Orange. All rights reserved.
// A Generic WPA implementation in Go
//
// Use of this source code is governed by a MIT license
// that can be found in the LICENSE file in the root of the source
// tree.

package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	"./eap"
)

var wordlist = flag.String("w", "", "Filename of password list to crack wpa handshake")
var filename = flag.String("f", "", "Filename of dump file to read from")

var e2s = map[string]string{}
var stations = map[string][]string{}
var handshakes = map[string]Handshake{}

type Handshake struct {
	SSID   string
	ANonce []byte
	SNonce []byte
	ApMac  net.HardwareAddr
	CliMac net.HardwareAddr
	MIC    []byte
	Data   []byte
	WPA    bool
	Valid  bool
}

func main() {
	flag.Parse()
	if flag.NFlag() < 2 {
		fmt.Printf("Usage: %s\n", "aircrack -f wifi.pcap -w wordlist.txt")
		flag.PrintDefaults()
		return
	}

	handle, err := pcap.OpenOffline(*filename)

	if err != nil {
		fmt.Printf("%s\n", err)
		return
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	var eapolPhase = 0
	var eapolStart = 0
	var i = 0
	var handshake = Handshake{}
	for packet := range packetSource.Packets() {
		i++
		var apAddr net.HardwareAddr
		var cliAddr net.HardwareAddr

		dot11 := packet.Layer(layers.LayerTypeDot11)
		if dot11 != nil {
			dot11, _ := dot11.(*layers.Dot11)

			if dot11.Type == layers.Dot11TypeMgmtProbeReq {
				apAddr = dot11.Address1
				cliAddr = dot11.Address2
			} else if dot11.Type == layers.Dot11TypeMgmtProbeResp {
				apAddr = dot11.Address2
				cliAddr = dot11.Address1
			} else if dot11.Type == layers.Dot11TypeMgmtBeacon {
				apAddr = dot11.Address2
				cliAddr = dot11.Address1
			}
		}

		apAddrStr := fmt.Sprintf("%s", apAddr)
		cliAddrStr := fmt.Sprintf("%s", cliAddr)
		if _, ok := stations[apAddrStr]; !ok && len(apAddrStr) > 0 && apAddrStr != "ff:ff:ff:ff:ff:ff" {
			stations[apAddrStr] = make([]string, 0)
		}
		var exist = false
		for _, cli := range stations[apAddrStr] {
			if cli == cliAddrStr {
				exist = true
			}
		}
		if _, ok := stations[apAddrStr]; ok && !exist && len(apAddrStr) > 0 && cliAddrStr != "ff:ff:ff:ff:ff:ff" {
			stations[apAddrStr] = append(stations[apAddrStr], cliAddrStr)
		}

		dot11info := packet.Layer(layers.LayerTypeDot11InformationElement)
		if dot11info != nil {
			dot11info, _ := dot11info.(*layers.Dot11InformationElement)
			if dot11info.ID == layers.Dot11InformationElementIDSSID && apAddr != nil && apAddrStr != "ff:ff:ff:ff:ff:ff" {
				if _, ok := e2s[apAddrStr]; !ok {
					e2s[apAddrStr] = fmt.Sprintf("%s", dot11info.Info)
					fmt.Printf("Found station - ESSID: %s, SSID: %s\n", apAddrStr, dot11info.Info)
				}
			}
		}

		eapolKey := packet.Layer(layers.LayerTypeEAPOLKey)
		if eapolKey == nil {
			eapol := packet.Layer(layers.LayerTypeEAPOL)
			if eapol != nil {
				eapol, _ := eapol.(*layers.EAPOL)
				p := gopacket.NewPacket(append(append(eapol.LayerContents(), eapol.LayerPayload()...), []byte{0, 0, 0, 0}...), layers.LayerTypeEAPOL, gopacket.Default)
				eapolKey = p.Layer(layers.LayerTypeEAPOLKey).(*layers.EAPOLKey)
			}
		}
		if eapolKey != nil && dot11 != nil {
			dot11, _ := dot11.(*layers.Dot11)
			eapolKey, _ := eapolKey.(*layers.EAPOLKey)
			if eapolStart < i-25 {
				if eapolPhase > 2 {
					var newHandshake = handshake
					if _, ok := handshakes[newHandshake.SSID]; !ok {
						handshakes[newHandshake.SSID] = newHandshake
						fmt.Printf("Found handshake: (SSID: %s, AA: %s, SPA: %s)\n", handshake.SSID, handshake.ApMac, handshake.CliMac)
					}
				}
				eapolPhase = 0
				handshake = Handshake{}
			}

			if eapolPhase == 0 && bytes.Equal(eapolKey.MIC[:4], []byte{0, 0, 0, 0}) && eapolKey.KeyDataLength == 0 {
				handshake.ANonce = eapolKey.Nonce
				handshake.ApMac = dot11.Address2
				handshake.CliMac = dot11.Address1
				ssid, ok := e2s[fmt.Sprintf("%s", handshake.ApMac)]
				if ok && len(ssid) > 0 {
					eapolStart = i
					eapolPhase = 1
					handshake.SSID = ssid
				} else {
					continue
				}
			}

			if eapolPhase == 1 && !bytes.Equal(eapolKey.MIC[:4], []byte{0, 0, 0, 0}) && eapolKey.KeyDataLength > 0 {
				if fmt.Sprintf("%s", handshake.ApMac) != fmt.Sprintf("%s", dot11.Address1) && fmt.Sprintf("%s", handshake.CliMac) != fmt.Sprintf("%s", dot11.Address2) {
					continue
				}
				eapolPhase = 2
				handshake.SNonce = eapolKey.Nonce
				handshake.MIC = append([]byte{}, eapolKey.MIC...)
				data := dot11.LayerPayload()[8:]
				zero := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
				data = append(data[:81], append(zero, data[97:]...)...)
				handshake.Data = data

			}

			if eapolPhase == 2 && !bytes.Equal(eapolKey.MIC[:4], []byte{0, 0, 0, 0}) && eapolKey.KeyDataLength > 0 {
				if fmt.Sprintf("%s", handshake.ApMac) != fmt.Sprintf("%s", dot11.Address2) && fmt.Sprintf("%s", handshake.CliMac) != fmt.Sprintf("%s", dot11.Address1) {
					continue
				}
				eapolPhase = 3
				handshake.Valid = true
			}

			if eapolPhase == 3 && !bytes.Equal(eapolKey.MIC[:4], []byte{0, 0, 0, 0}) && eapolKey.KeyDataLength == 0 {
				if fmt.Sprintf("%s", handshake.ApMac) != fmt.Sprintf("%s", dot11.Address1) && fmt.Sprintf("%s", handshake.CliMac) != fmt.Sprintf("%s", dot11.Address2) {
					continue
				}
				var newHandshake = handshake
				if _, ok := handshakes[newHandshake.SSID]; !ok {
					handshakes[newHandshake.SSID] = newHandshake
					fmt.Printf("Found handshake: (SSID: %s, AA: %s, SPA: %s)\n", handshake.SSID, handshake.ApMac, handshake.CliMac)
				}
				eapolPhase = 0
				handshake = Handshake{}
			}
		}
	}
	var j = 0
	var handshakeId = make([]string, 0)
	for k, v := range handshakes {
		if !v.Valid {
			continue
		}
		if j == 0 {
			fmt.Printf("Handshake: \n")
		}
		handshakeId = append(handshakeId, k)
		fmt.Printf("\t%d: (SSID: %s, AA: %s, SPA: %s)\n", j, k, v.ApMac, v.CliMac)
		j++
	}

	if len(handshakes) == 0 {
		fmt.Printf("No useful handshake found\n")
		return
	}

	fmt.Printf("Input handshake to crack[0~%d]: ", len(handshakes)-1)
	numReader := bufio.NewReader(os.Stdin)
	numStr, _ := numReader.ReadString('\n')
	numStr = strings.TrimSpace(numStr)
	num, err := strconv.Atoi(numStr)
	if err != nil {
		fmt.Println(err)
		return
	}

	if num > len(handshakes)-1 || num < 0 {
		fmt.Printf("Id %d out of range 0~%d\n", num, len(handshakes)-1)
		return
	}

	wordFile, err := os.Open(*wordlist)
	if err != nil {
		fmt.Println(err)
		return
	}

	handshake = handshakes[handshakeId[num]]
	apMac := h2b(strings.Replace(handshake.ApMac.String(), ":", "", -1))
	cliMac := h2b(strings.Replace(handshake.CliMac.String(), ":", "", -1))
	scanner := bufio.NewScanner(wordFile)
	for scanner.Scan() {
		word := strings.TrimSpace(scanner.Text())
		mic, _, _, match := Verify(word, handshake.SSID, handshake.ANonce, handshake.SNonce, apMac, cliMac, handshake.Data, handshake.MIC, handshake.WPA)
		if match {
			fmt.Printf("\033[2K\r%s:%x:%x:%s", handshake.SSID, handshake.MIC[:4], mic[:4], word)
			fmt.Printf("\n\nPassword Found: %s\n", word)
			fmt.Printf("\tActual mic:  %x\n", mic)
			fmt.Printf("\tDesired mic: %x\n\n", handshake.MIC)
			return
		} else {
			fmt.Printf("\033[2K\r%s:%x:%x:%s", handshake.SSID, handshake.MIC[:4], mic[:4], word)
		}
	}
	fmt.Printf("\n\nPassword Not Found!\n")
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
