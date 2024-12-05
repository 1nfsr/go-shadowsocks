package cipher

import (
	"net"
)

// Cipher interface defines basic encryption operations
type Cipher interface {
	StreamConn(net.Conn) net.Conn
	GetMethod() string
}

const (
	MaxPayloadSize = 16384 // Maximum payload size
	SaltSize      = 32    // Salt size
	SubKeyInfo    = "ss-subkey" // Subkey info
)

// SupportedCiphers lists all supported encryption methods
var SupportedCiphers = map[string]struct{}{
	"chacha20-ietf-poly1305": {},
	"aes-128-gcm":           {},
	"aes-192-gcm":           {},
	"aes-256-gcm":           {},
}
