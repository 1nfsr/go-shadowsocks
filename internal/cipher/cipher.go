package cipher

import (
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"fmt"
	"io"
	"net"
	
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
	"crypto/aes"
)

// Cipher interface defines basic encryption operations
type Cipher interface {
	StreamConn(net.Conn) net.Conn
	GetMethod() string
}

// aeadCipher implements AEAD encryption
type aeadCipher struct {
	psk      []byte                                // Pre-shared key
	makeAEAD func(key []byte) (cipher.AEAD, error) // AEAD constructor
	method   string                                // Encryption method name
}

func (aead *aeadCipher) StreamConn(c net.Conn) net.Conn {
	return newStreamConn(c, aead)
}

func (aead *aeadCipher) GetMethod() string {
	return aead.method
}

const (
	MaxPayloadSize = 16384 // Maximum payload size
	SaltSize      = 32    // Salt size
	SubKeyInfo    = "ss-subkey" // Subkey info
)

var SupportedCiphers = map[string]struct{}{
	"chacha20-ietf-poly1305": {},
	"aes-128-gcm":           {},
	"aes-192-gcm":           {},
	"aes-256-gcm":           {},
}

// NewCipher creates a new encryption instance
func NewCipher(method, password string) (Cipher, error) {
	if _, ok := SupportedCiphers[method]; !ok {
		return nil, fmt.Errorf("unsupported method: %s", method)
	}

	// Select key size based on the encryption method
	var keySize int
	switch method {
	case "chacha20-ietf-poly1305":
		keySize = chacha20poly1305.KeySize
	case "aes-128-gcm":
		keySize = 16
	case "aes-192-gcm":
		keySize = 24
	case "aes-256-gcm":
		keySize = 32
	}

	key := kdf(password, keySize)
	var makeAEAD func([]byte) (cipher.AEAD, error)
	
	// Select the appropriate AEAD constructor
	if method == "chacha20-ietf-poly1305" {
		makeAEAD = chacha20poly1305.New
	} else {
		makeAEAD = aesGCM(keySize)
	}

	return &aeadCipher{
		psk:      key,
		makeAEAD: makeAEAD,
		method:   method,
	}, nil
}

// aesGCM returns a function to create an AES-GCM AEAD instance
func aesGCM(keySize int) func(key []byte) (cipher.AEAD, error) {
	return func(key []byte) (cipher.AEAD, error) {
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		return cipher.NewGCM(block)
	}
}

type streamConn struct {
	net.Conn
	cipher     *aeadCipher
	reader     *reader
	writer     *writer
}

type reader struct {
	conn   net.Conn
	cipher *aeadCipher
	aead   cipher.AEAD
	nonce  []byte
	buf    []byte
	offset int
}

type writer struct {
	conn   net.Conn
	cipher *aeadCipher
	aead   cipher.AEAD
	nonce  []byte
}

func newStreamConn(conn net.Conn, cipher *aeadCipher) net.Conn {
	sc := &streamConn{
		Conn:   conn,
		cipher: cipher,
		reader: &reader{
			conn:   conn,
			cipher: cipher,
			nonce:  make([]byte, chacha20poly1305.NonceSize),
		},
		writer: &writer{
			conn:   conn,
			cipher: cipher,
			nonce:  make([]byte, chacha20poly1305.NonceSize),
		},
	}
	return sc
}

func (c *streamConn) Read(b []byte) (n int, err error) {
	if c.reader.aead == nil {
		err := c.initReader()
		if err != nil {
			return 0, err
		}
	}
	return c.reader.Read(b)
}

func (c *streamConn) initReader() error {
	salt := make([]byte, SaltSize)
	if _, err := io.ReadFull(c.Conn, salt); err != nil {
		return fmt.Errorf("failed to read salt: %v", err)
	}

	subkey := make([]byte, len(c.cipher.psk))
	hkdfSHA1(c.cipher.psk, salt, []byte(SubKeyInfo), subkey)

	aead, err := c.cipher.makeAEAD(subkey)
	if err != nil {
		return fmt.Errorf("failed to create AEAD: %v", err)
	}

	c.reader.aead = aead
	c.reader.nonce = make([]byte, aead.NonceSize())
	return nil
}

func (c *streamConn) Write(b []byte) (n int, err error) {
	if c.writer.aead == nil {
		// Generate and write salt
		salt := make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, salt); err != nil {
			return 0, err
		}
		if _, err := c.Conn.Write(salt); err != nil {
			return 0, err
		}

		// Derive subkey
		subkey := make([]byte, len(c.cipher.psk))
		hkdfSHA1(c.cipher.psk, salt, []byte("ss-subkey"), subkey)

		aead, err := c.cipher.makeAEAD(subkey)
		if err != nil {
			return 0, err
		}

		c.writer.aead = aead
		c.writer.nonce = make([]byte, aead.NonceSize())
	}
	return c.writer.Write(b)
}

func (r *reader) Read(b []byte) (n int, err error) {
	// Use cached data
	if n = r.readBuf(b); n > 0 {
		return
	}

	// Read and decrypt size
	size, err := r.readSize()
	if err != nil {
		return 0, err
	}

	// Read and decrypt payload
	payload, err := r.readPayload(size)
	if err != nil {
		return 0, err
	}

	// Copy data to output buffer
	return r.copyPayload(b, payload), nil
}

// Add helper methods
func (r *reader) readBuf(b []byte) int {
	if r.buf != nil && r.offset < len(r.buf) {
		n := copy(b, r.buf[r.offset:])
		r.offset += n
		if r.offset >= len(r.buf) {
			r.buf = nil
			r.offset = 0
		}
		return n
	}
	return 0
}

func (r *reader) readSize() (int, error) {
	sizeBuf := make([]byte, 2+r.aead.Overhead())
	if _, err := io.ReadFull(r.conn, sizeBuf); err != nil {
		return 0, err
	}

	size, err := r.aead.Open(nil, r.nonce, sizeBuf, nil)
	if err != nil {
		return 0, fmt.Errorf("failed to decrypt size: %v", err)
	}
	incrementNonce(r.nonce)

	length := int(size[0])<<8 | int(size[1])
	if length <= 0 || length > MaxPayloadSize {
		return 0, fmt.Errorf("invalid payload size: %d", length)
	}
	return length, nil
}

func (r *reader) readPayload(size int) ([]byte, error) {
	payload := make([]byte, size+r.aead.Overhead())
	if _, err := io.ReadFull(r.conn, payload); err != nil {
		return nil, err
	}

	payload, err := r.aead.Open(nil, r.nonce, payload, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt payload: %v", err)
	}
	incrementNonce(r.nonce)

	return payload, nil
}

func (r *reader) copyPayload(dst []byte, payload []byte) int {
	n := copy(dst, payload)
	if n < len(payload) {
		r.buf = payload
		r.offset = n
	}
	return n
}

func (w *writer) Write(b []byte) (n int, err error) {
	if w.aead == nil {
		return 0, fmt.Errorf("cipher not initialized")
	}

	if len(b) > 16384 {
		for i := 0; i < len(b); i += 16384 {
			end := i + 16384
			if end > len(b) {
				end = len(b)
			}
			_, err := w.Write(b[i:end])
			if err != nil {
				return 0, err
			}
		}
		return len(b), nil
	}

	// Encrypt size
	size := make([]byte, 2)
	size[0] = byte(len(b) >> 8)
	size[1] = byte(len(b))

	// Write size and payload together
	sealedSize := w.aead.Seal(nil, w.nonce, size, nil)
	incrementNonce(w.nonce)

	sealed := w.aead.Seal(nil, w.nonce, b, nil)
	incrementNonce(w.nonce)

	// Write all at once
	data := make([]byte, 0, len(sealedSize)+len(sealed))
	data = append(data, sealedSize...)
	data = append(data, sealed...)
	
	_, err = w.conn.Write(data)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

func hkdfSHA1(secret, salt, info, outkey []byte) {
	r := hkdf.New(sha1.New, secret, salt, info)
	if _, err := io.ReadFull(r, outkey); err != nil {
		panic(err)
	}
}

func kdf(password string, keyLen int) []byte {
	var b, prev []byte
	h := md5.New()
	for len(b) < keyLen {
		h.Write(prev)
		h.Write([]byte(password))
		b = h.Sum(b)
		prev = b[len(b)-h.Size():]
		h.Reset()
	}
	return b[:keyLen]
}

func incrementNonce(b []byte) {
	for i := range b {
		b[i]++
		if b[i] != 0 {
			return
		}
	}
}
