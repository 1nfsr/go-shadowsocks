package proxy

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	
	"github.com/1nfsr/go-shadowsocks/internal/cipher"
	"github.com/1nfsr/go-shadowsocks/internal/config"
	"github.com/1nfsr/go-shadowsocks/pkg/logger"
)

// Server defines the proxy server
type Server struct {
	config   *config.Config  // Server configuration
	cipher   cipher.Cipher   // Encryption handler
	listener net.Listener    // Network listener
	logger   *logger.Logger  // Logger instance
	
	connPool sync.Pool       // Connection pool
	done     chan struct{}   // Graceful shutdown signal
}

func NewServer(config *config.Config) (*Server, error) {
	ciph, err := cipher.NewCipher(config.Method, config.Password)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %v", err)
	}
	
	return &Server{
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

func (s *Server) Start() error {
	listener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", s.config.Server, s.config.ServerPort))
	if err != nil {
		return err
	}
	s.listener = listener
	
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept: %v", err)
			continue
		}
		
		go s.handleConnection(conn)
	}
}

func (s *Server) handleConnection(conn net.Conn) {
	defer conn.Close()
	
	remoteAddr := conn.RemoteAddr().String()
	log.Printf("New connection from: %s", remoteAddr)
	
	// Create encrypted connection
	sconn := s.cipher.StreamConn(conn)
	defer sconn.Close()
	
	// Read target address
	buf := make([]byte, 259) // Max length: 1(atyp) + 1(len) + 255(domain) + 2(port)
	
	// Read address type
	if _, err := io.ReadFull(sconn, buf[:1]); err != nil {
		log.Printf("Failed to read address type: %v", err)
		return
	}
	
	atyp := buf[0]
	var targetAddr string
	var domain string
	
	switch atyp {
	case 0x01: // IPv4
		if _, err := io.ReadFull(sconn, buf[1:7]); err != nil {
			log.Printf("Failed to read IPv4 address: %v", err)
			return
		}
		domain = fmt.Sprintf("%d.%d.%d.%d", buf[1], buf[2], buf[3], buf[4])
		port := binary.BigEndian.Uint16(buf[5:7])
		targetAddr = fmt.Sprintf("%s:%d", domain, port)
		
	case 0x03: // Domain name
		if _, err := io.ReadFull(sconn, buf[1:2]); err != nil {
			log.Printf("Failed to read domain length: %v", err)
			return
		}
		
		domainLen := int(buf[1])
		log.Printf("Debug: Domain length received: %d", domainLen)
		if domainLen == 0 || domainLen > 255 {
			log.Printf("Invalid domain length: %d", domainLen)
			return
		}
		
		if _, err := io.ReadFull(sconn, buf[2:2+domainLen+2]); err != nil {
			log.Printf("Failed to read domain and port: %v", err)
			return
		}
		
		domain = string(buf[2 : 2+domainLen])
		port := binary.BigEndian.Uint16(buf[2+domainLen : 2+domainLen+2])
		targetAddr = fmt.Sprintf("%s:%d", domain, port)
		
	default:
		log.Printf("Unsupported address type: %#x", atyp)
		return
	}
	
	if domain == "" || targetAddr == "" {
		log.Printf("Invalid target address")
		return
	}
	
	log.Printf("Client %s is visiting: %s", remoteAddr, domain)
	
	// Connect to target
	target, err := net.Dial("tcp", targetAddr)
	if err != nil {
		log.Printf("Failed to connect to target %s: %v", targetAddr, err)
		return
	}
	defer target.Close()
	
	// Start proxying
	done := make(chan error, 2)
	
	// Client to target
	go func() {
		_, err := io.Copy(target, sconn)
		done <- err
	}()
	
	// Target to client
	go func() {
		_, err := io.Copy(sconn, target)
		done <- err
	}()
	
	// Wait for either direction to finish
	err = <-done
	if err != nil && !isClosedConnError(err) {
		log.Printf("Connection error: %v", err)
	}
}

func isClosedConnError(err error) bool {
	if err == io.EOF {
		return true
	}
	if err == io.ErrClosedPipe {
		return true
	}
	if strings.Contains(err.Error(), "use of closed network connection") {
		return true
	}
	return false
}
