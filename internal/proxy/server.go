package proxy

import (
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

type Server struct {
	config   *config.Config
	cipher   cipher.Cipher
	listener net.Listener
	logger   *logger.Logger
	
	// 连接池
	connPool sync.Pool
	// 优雅关闭
	done     chan struct{}
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
	
	log.Printf("Debug: Cipher method=%s", s.cipher.GetMethod())
	
	// Try to get StreamConn interface
	sconn := s.cipher.StreamConn(conn)
	defer sconn.Close()
	
	// Read target address
	buf := make([]byte, 259)
	_, err := io.ReadFull(sconn, buf[:1]) // read atyp
	if err != nil {
		log.Printf("Failed to read address type: %v", err)
		return
	}
	
	atyp := buf[0]
	var targetAddr string
	var domain string
	
	switch atyp {
	case 0x01: // IPv4
		_, err = io.ReadFull(sconn, buf[1:7])
		if err != nil {
			log.Printf("Failed to read IPv4 address: %v", err)
			return
		}
		targetAddr = fmt.Sprintf("%d.%d.%d.%d:%d",
			buf[1], buf[2], buf[3], buf[4],
			uint16(buf[5])<<8|uint16(buf[6]))
		domain = fmt.Sprintf("%d.%d.%d.%d", buf[1], buf[2], buf[3], buf[4])
		
	case 0x03: // Domain name
		_, err = io.ReadFull(sconn, buf[1:2]) // read domain length
		if err != nil {
			log.Printf("Failed to read domain length: %v", err)
			return
		}
		domainLen := int(buf[1])
		_, err = io.ReadFull(sconn, buf[2:2+domainLen+2])
		if err != nil {
			log.Printf("Failed to read domain and port: %v", err)
			return
		}
		domain = string(buf[2 : 2+domainLen])
		targetAddr = fmt.Sprintf("%s:%d",
			domain,
			uint16(buf[2+domainLen])<<8|uint16(buf[2+domainLen+1]))
	}
	
	log.Printf("Client %s is visiting: %s", remoteAddr, domain)
	
	// Connect to target
	target, err := net.Dial("tcp", targetAddr)
	if err != nil {
		log.Printf("Failed to connect to target %s: %v", targetAddr, err)
		return
	}
	defer target.Close()
	
	// Start proxying with traffic monitoring
	done := make(chan error, 2)
	
	// Client to target
	go func() {
		written, err := io.Copy(target, sconn)
		if err != nil && !isClosedConnError(err) {
			log.Printf("Error copying to target %s: %v", domain, err)
		}
		log.Printf("Client %s uploaded %d bytes to %s", remoteAddr, written, domain)
		done <- err
	}()
	
	// Target to client
	go func() {
		written, err := io.Copy(sconn, target)
		if err != nil && !isClosedConnError(err) {
			log.Printf("Error copying from target %s: %v", domain, err)
		}
		log.Printf("Client %s downloaded %d bytes from %s", remoteAddr, written, domain)
		done <- err
	}()
	
	// Wait for either direction to finish
	<-done
	return
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
