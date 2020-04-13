package main

import (
	"os/signal"
	"syscall"

	proxy "github.com/alexthemonk/DoH_Proxy"
)

var client proxy.Client = proxy.Client{}

func main() {
	client.Init("127.0.0.1", 53)
	// For testing purposes, the port is set to a higher number to avoid sudo
	// client.Init("127.0.0.1", 53533)
	signal.Notify(client.ShutDownChan, syscall.SIGINT, syscall.SIGTERM)
	client.AddUpstream("Google", "8.8.8.8/resolve", 443) // dns.google.com
	// client.AddUpstream("Cloudflare", "1.1.1.1/dns-query", 443) // cloudflare-dns.com
	// client.AddUpstream("Quad9", "9.9.9.9:5053/dns-query", 443) // dns.quad9.net
	// client.AddUpstream("Google", "8.8.8.8", 53)

	client.StartProxy()
}
