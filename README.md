# Simple Go Shadowsocks

## Usage

### Run server and client

```bash
./shadowsocks-server -c config.server.json 
./shadowsocks-client -c config.client.json

curl --socks5 127.0.0.1:1080 http://ip.sb/
```

### Build from source

```bash
go build -o shadowsocks-server cmd/server/main.go
go build -o shadowsocks-client cmd/client/main.go
```

### Run server

```bash
./shadowsocks-server -c config.server.json
```

### Run client

```bash
./shadowsocks-client -c config.client.json
```