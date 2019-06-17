<h1 align="center">Welcome to aircrack 👋</h1>
<p>
  <img src="https://img.shields.io/badge/version-0.1-blue.svg?cacheSeconds=2592000" />
</p>

> A Generic WPA implementation in Go

### 🏠 [Homepage](https://github.com/rerange/aircrack)

## Install

```sh
make install
```

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

## Run tests

```sh
make test
```

## Author

👤 **orange**

* Github: [@rerange](https://github.com/rerange)

## 🤝 Contributing

Contributions, issues and feature requests are welcome!<br />Feel free to check [issues page](https://github.com/rerange/aircrack/issues).

## Show your support

Give a ⭐️ if this project helped you!