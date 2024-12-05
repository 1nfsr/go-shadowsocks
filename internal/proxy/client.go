package proxy

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	
	"github.com/1nfsr/go-shadowsocks/internal/cipher"
	"github.com/1nfsr/go-shadowsocks/internal/config"
	"github.com/1nfsr/go-shadowsocks/pkg/logger"
)

type Client struct {
	config   *config.Config
	cipher   cipher.Cipher
	listener net.Listener
	logger   *logger.Logger
	
	connPool sync.Pool
	done     chan struct{}
}

func NewClient(config *config.Config) (*Client, error) {
	ciph, err := cipher.NewCipher(config.Method, config.Password)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %v", err)
	}
	
	return &Client{
		config: config,
		cipher: ciph,
		connPool: sync.Pool{
			New: func() interface{} {
				return make([]byte, 32*1024)
			},
		},
		done: make(chan struct{}),
		logger: logger.New(config.LogLevel != ""),
	}, nil
}

func (c *Client) Start() error {
	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", c.config.LocalPort))
	if err != nil {
		return err
	}
	c.listener = listener
	
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept: %v", err)
			continue
		}
		
		go c.handleConnection(conn)
	}
}

func (c *Client) handleConnection(conn net.Conn) {
	defer conn.Close()
	
	// Connect to remote server
	remote, err := net.Dial("tcp", fmt.Sprintf("%s:%d", c.config.Server, c.config.ServerPort))
	if err != nil {
		log.Printf("Failed to connect to server: %v", err)
		return
	}
	defer remote.Close()

	// Create encrypted connection
	sconn := c.cipher.StreamConn(remote)
	defer sconn.Close()

	// Handle SOCKS5 handshake
	targetAddr, err := c.handshake(conn)
	if err != nil {
		log.Printf("Socks5 handshake failed: %v", err)
		return
	}

	// Forward target address to server
	if err := c.writeTargetAddress(sconn, targetAddr); err != nil {
		log.Printf("Failed to write target address: %v", err)
		return
	}

	// Start proxying
	done := make(chan error, 2)
	go func() { _, err := io.Copy(sconn, conn); done <- err }()
	go func() { _, err := io.Copy(conn, sconn); done <- err }()
	
	err = <-done
	if err != nil {
		log.Printf("Connection error: %v", err)
	}
}

func (c *Client) handshake(conn net.Conn) (addr string, err error) {
	// Read version and auth methods
	buf := make([]byte, 258)
	if _, err = io.ReadFull(conn, buf[:2]); err != nil {
		return "", err
	}

	ver, nmethods := buf[0], buf[1]
	if ver != 5 {
		return "", fmt.Errorf("invalid version: %d", ver)
	}

	// Read auth methods
	if _, err = io.ReadFull(conn, buf[2:2+nmethods]); err != nil {
		return "", err
	}

	// Send auth method (no auth)
	if _, err = conn.Write([]byte{5, 0}); err != nil {
		return "", err
	}

	// Read request
	if _, err = io.ReadFull(conn, buf[:4]); err != nil {
		return "", err
	}

	ver, cmd, _, atyp := buf[0], buf[1], buf[2], buf[3]
	if ver != 5 || cmd != 1 {
		return "", fmt.Errorf("invalid ver/cmd: %d/%d", ver, cmd)
	}

	var host string
	var port uint16

	switch atyp {
	case 1: // IPv4
		if _, err = io.ReadFull(conn, buf[:4]); err != nil {
			return "", err
		}
		host = fmt.Sprintf("%d.%d.%d.%d", buf[0], buf[1], buf[2], buf[3])
	case 3: // Domain
		if _, err = io.ReadFull(conn, buf[:1]); err != nil {
			return "", err
		}
		domainLen := int(buf[0])
		if _, err = io.ReadFull(conn, buf[1:1+domainLen]); err != nil {
			return "", err
		}
		host = string(buf[1 : 1+domainLen])
	case 4: // IPv6
		if _, err = io.ReadFull(conn, buf[:16]); err != nil {
			return "", err
		}
		host = net.IP(buf[:16]).String()
	default:
		return "", fmt.Errorf("unsupported address type: %#x", atyp)
	}

	// Read port
	if _, err = io.ReadFull(conn, buf[:2]); err != nil {
		return "", err
	}
	port = binary.BigEndian.Uint16(buf[:2])

	// Send response
	_, err = conn.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%s:%d", host, port), nil
}

func (c *Client) writeTargetAddress(conn net.Conn, addr string) error {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}

	port, err := net.LookupPort("tcp", portStr)
	if err != nil {
		return err
	}

	ip := net.ParseIP(host)
	if ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			// IPv4
			buf := make([]byte, 7)
			buf[0] = 1
			copy(buf[1:5], ip4)
			binary.BigEndian.PutUint16(buf[5:], uint16(port))
			_, err = conn.Write(buf)
			return err
		}
		// IPv6
		buf := make([]byte, 19)
		buf[0] = 4
		copy(buf[1:17], ip)
		binary.BigEndian.PutUint16(buf[17:], uint16(port))
		_, err = conn.Write(buf)
		return err
	}

	// Domain
	if len(host) > 255 {
		return fmt.Errorf("domain name too long")
	}
	buf := make([]byte, 4+len(host))
	buf[0] = 3
	buf[1] = byte(len(host))
	copy(buf[2:], host)
	binary.BigEndian.PutUint16(buf[2+len(host):], uint16(port))
	_, err = conn.Write(buf)
	return err
} 