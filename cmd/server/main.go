package main

import (
    "flag"
    "log"
    
    "github.com/1nfsr/go-shadowsocks/internal/config"
    "github.com/1nfsr/go-shadowsocks/internal/proxy"
)

func main() {
    configFile := flag.String("c", "config.json", "config file path")
    flag.Parse()

    cfg, err := config.Load(*configFile)
    if err != nil {
        log.Fatalf("Failed to load config: %v", err)
    }

    server, err := proxy.NewServer(cfg)
    if err != nil {
        log.Fatalf("Failed to create server: %v", err)
    }

    if err := server.Start(); err != nil {
        log.Fatalf("Server failed: %v", err)
    }
}