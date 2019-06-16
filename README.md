# AirCrack
 
A Generic WPA implementation in Go By [Orange](https://github.com/rerange)

## Prerequisite

Install [WinPcap_4_1_3](https://www.winpcap.org/install/default.htm) for Windows or [libpcap](https://formulae.brew.sh/formula/libpcap) for MacOS or other linux distributions

For MacOS users:

```sh
brew install tcpdump
```


## Usage

```bash
aircrack -f wifi.pcap -w wordlist.txt
```

>-f string  Filename of dump file to read from

>-w string Filename of password list to crack wpa handshake