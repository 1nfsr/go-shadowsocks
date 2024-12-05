package cipher

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
)

type streamConn struct {
	net.Conn
	cipher *aeadCipher
	reader *reader
	writer *writer
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

func newStreamConn(c net.Conn, cipher *aeadCipher) net.Conn {
	return &streamConn{
		Conn:   c,
		cipher: cipher,
		reader: &reader{
			conn:   c,
			cipher: cipher,
		},
		writer: &writer{
			conn:   c,
			cipher: cipher,
		},
	}
}

func (c *streamConn) Read(b []byte) (n int, err error) {
	if c.reader.aead == nil {
		salt := make([]byte, SaltSize)
		if _, err := io.ReadFull(c.Conn, salt); err != nil {
			return 0, err
		}

		subkey := make([]byte, len(c.cipher.psk))
		hkdfSHA1(c.cipher.psk, salt, []byte(SubKeyInfo), subkey)

		aead, err := c.cipher.makeAEAD(subkey)
		if err != nil {
			return 0, err
		}

		c.reader.aead = aead
		c.reader.nonce = make([]byte, aead.NonceSize())
	}
	return c.reader.Read(b)
}

func (c *streamConn) Write(b []byte) (n int, err error) {
	if c.writer.aead == nil {
		salt := make([]byte, SaltSize)
		if _, err := io.ReadFull(rand.Reader, salt); err != nil {
			return 0, err
		}
		if _, err := c.Conn.Write(salt); err != nil {
			return 0, err
		}

		subkey := make([]byte, len(c.cipher.psk))
		hkdfSHA1(c.cipher.psk, salt, []byte(SubKeyInfo), subkey)

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
	if len(r.buf) > r.offset {
		n = copy(b, r.buf[r.offset:])
		r.offset += n
		if r.offset >= len(r.buf) {
			r.buf = nil
			r.offset = 0
		}
		return
	}

	sizeBuf := make([]byte, 2+r.aead.Overhead())
	_, err = io.ReadFull(r.conn, sizeBuf)
	if err != nil {
		return 0, err
	}

	_, err = r.aead.Open(sizeBuf[:0], r.nonce, sizeBuf, nil)
	if err != nil {
		return 0, err
	}
	incrementNonce(r.nonce)

	size := int(binary.BigEndian.Uint16(sizeBuf[:2]))
	if size > MaxPayloadSize {
		return 0, io.ErrShortBuffer
	}

	buf := make([]byte, size+r.aead.Overhead())
	_, err = io.ReadFull(r.conn, buf)
	if err != nil {
		return 0, err
	}

	_, err = r.aead.Open(buf[:0], r.nonce, buf, nil)
	if err != nil {
		return 0, err
	}
	incrementNonce(r.nonce)

	n = copy(b, buf[:size])
	if n < size {
		r.buf = buf[:size]
		r.offset = n
	}
	return n, nil
}

func (w *writer) Write(b []byte) (n int, err error) {
	for len(b) > 0 {
		size := len(b)
		if size > MaxPayloadSize {
			size = MaxPayloadSize
		}

		sizeBuf := make([]byte, 2+w.aead.Overhead())
		binary.BigEndian.PutUint16(sizeBuf[:2], uint16(size))

		sizeBuf = w.aead.Seal(sizeBuf[:0], w.nonce, sizeBuf[:2], nil)
		incrementNonce(w.nonce)

		if _, err = w.conn.Write(sizeBuf); err != nil {
			return
		}

		buf := make([]byte, size+w.aead.Overhead())
		buf = w.aead.Seal(buf[:0], w.nonce, b[:size], nil)
		incrementNonce(w.nonce)

		if _, err = w.conn.Write(buf); err != nil {
			return
		}

		n += size
		b = b[size:]
	}
	return
}

// Reference existing methods for streamConn, reader, writer