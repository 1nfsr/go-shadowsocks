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
)

type Cipher interface {
	StreamConn(net.Conn) net.Conn
	GetMethod() string
}

type aeadCipher struct {
	psk      []byte
	makeAEAD func(key []byte) (cipher.AEAD, error)
	method   string
}

func (aead *aeadCipher) StreamConn(c net.Conn) net.Conn {
	return newStreamConn(c, aead)
}

func (aead *aeadCipher) GetMethod() string {
	return aead.method
}

func NewCipher(method, password string) (Cipher, error) {
	if method != "chacha20-ietf-poly1305" {
		return nil, fmt.Errorf("unsupported method: %s", method)
	}

	key := kdf(password, chacha20poly1305.KeySize)
	return &aeadCipher{
		psk:      key,
		makeAEAD: chacha20poly1305.New,
		method:   method,
	}, nil
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
		// Read salt
		salt := make([]byte, 32)
		if _, err := io.ReadFull(c.Conn, salt); err != nil {
			return 0, err
		}

		// Derive subkey
		subkey := make([]byte, len(c.cipher.psk))
		hkdfSHA1(c.cipher.psk, salt, []byte("ss-subkey"), subkey)

		aead, err := c.cipher.makeAEAD(subkey)
		if err != nil {
			return 0, err
		}

		c.reader.aead = aead
	}
	return c.reader.Read(b)
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
	if r.buf != nil && r.offset < len(r.buf) {
		n = copy(b, r.buf[r.offset:])
		r.offset += n
		if r.offset >= len(r.buf) {
			r.buf = nil
			r.offset = 0
		}
		return n, nil
	}

	// Read encrypted size
	sizeBuf := make([]byte, 2+r.aead.Overhead())
	if _, err := io.ReadFull(r.conn, sizeBuf); err != nil {
		return 0, err
	}

	// Decrypt size
	size, err := r.aead.Open(nil, r.nonce, sizeBuf, nil)
	if err != nil {
		return 0, fmt.Errorf("failed to decrypt size: %v", err)
	}
	incrementNonce(r.nonce)

	length := int(size[0])<<8 | int(size[1])
	if length <= 0 || length > 16384 {
		return 0, fmt.Errorf("invalid payload size: %d", length)
	}

	// Read encrypted payload
	payload := make([]byte, length+r.aead.Overhead())
	if _, err := io.ReadFull(r.conn, payload); err != nil {
		return 0, err
	}

	// Decrypt payload
	payload, err = r.aead.Open(nil, r.nonce, payload, nil)
	if err != nil {
		return 0, fmt.Errorf("failed to decrypt payload: %v", err)
	}
	incrementNonce(r.nonce)

	n = copy(b, payload)
	if n < len(payload) {
		r.buf = payload
		r.offset = n
	}
	return n, nil
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
