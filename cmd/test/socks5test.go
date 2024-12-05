package main

import (
    "flag"
    "fmt"
    "io"
    "log"
    "net"
    "time"
)

func main() {
    proxyAddr := flag.String("proxy", "127.0.0.1:1080", "SOCKS5 proxy address")
    testURL := flag.String("url", "example.com:80", "Test URL to connect")
    flag.Parse()

    // Connect to SOCKS5 proxy
    conn, err := net.Dial("tcp", *proxyAddr)
    if err != nil {
        log.Fatalf("Failed to connect to proxy: %v", err)
    }
    defer conn.Close()

    log.Printf("Connected to proxy %s", *proxyAddr)

    // SOCKS5 handshake
    if err := socks5Handshake(conn, *testURL); err != nil {
        log.Fatalf("SOCKS5 handshake failed: %v", err)
    }

    log.Printf("SOCKS5 handshake successful")

    // Send HTTP request
    httpReq := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", *testURL)
    if _, err := conn.Write([]byte(httpReq)); err != nil {
        log.Fatalf("Failed to send HTTP request: %v", err)
    }

    // Set read deadline
    conn.SetReadDeadline(time.Now().Add(5 * time.Second))

    // Read response
    buf := make([]byte, 4096)
    n, err := conn.Read(buf)
    if err != nil && err != io.EOF {
        log.Fatalf("Failed to read response: %v", err)
    }

    log.Printf("Received response (%d bytes):\n%s", n, buf[:n])
}

func socks5Handshake(conn net.Conn, target string) error {
    // Send version and auth method
    if _, err := conn.Write([]byte{5, 1, 0}); err != nil {
        return fmt.Errorf("write version failed: %v", err)
    }

    // Read auth response
    buf := make([]byte, 2)
    if _, err := io.ReadFull(conn, buf); err != nil {
        return fmt.Errorf("read auth response failed: %v", err)
    }
    if buf[0] != 5 || buf[1] != 0 {
        return fmt.Errorf("unexpected auth response: %v", buf)
    }

    // Parse target address
    host, portStr, err := net.SplitHostPort(target)
    if err != nil {
        return fmt.Errorf("invalid target address: %v", err)
    }

    port, err := net.LookupPort("tcp", portStr)
    if err != nil {
        return fmt.Errorf("invalid port: %v", err)
    }

    // Build connect request
    req := make([]byte, 0, 7+len(host))
    req = append(req, 5, 1, 0, 3)
    req = append(req, byte(len(host)))
    req = append(req, host...)
    req = append(req, byte(port>>8), byte(port))

    // Send connect request
    if _, err := conn.Write(req); err != nil {
        return fmt.Errorf("write connect request failed: %v", err)
    }

    // Read response
    resp := make([]byte, 10)
    if _, err := io.ReadFull(conn, resp); err != nil {
        return fmt.Errorf("read connect response failed: %v", err)
    }
    if resp[0] != 5 || resp[1] != 0 {
        return fmt.Errorf("connect failed: %v", resp)
    }

    return nil
} 