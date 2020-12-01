package proxy

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"

	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
)

// Server serves server side traffics
type Server struct {
	// name of the resolver
	Name string

	// upstream resolver
	// IP for DNS, url for DoH
	Upstream string

	// header
	Header map[string]string

	// port number of the upstream server
	// 53 for DNS, 443 for DoH
	Port int

	// signal channel for shutting down the server
	// ShutDown chan os.Signal

	// https client set header of get request
	httpClient http.Client
}

// Init initialize server
func (server *Server) Init(upstream string, port int) {

	server.Upstream = upstream
	server.Header = make(map[string]string)
	server.Port = port
	// server.ShutDown = make(chan os.Signal)

	// Initialize Header
	if server.Name == "Google" {
		server.Header["accept"] = "application/dns-message"
	} else {
		server.Header["accept"] = "application/dns-json"
	}

	log.SetFormatter(&log.TextFormatter{ForceColors: true})
	// Only log the Debug level or above.
	log.SetLevel(log.InfoLevel)

	log.Info("Server initialized")
}

// DoH makes an https request and resolves the question using miekg/dns
func DoH(server *Server, question dns.Question) (map[string]interface{}, error) {
	if server.Port != 443 {
		log.Fatal("Unable to make https request from a server for other purpose")
		return nil, errors.New("Invalid Port Number")
	}
	query := question.Name
	queryType := strconv.Itoa(int(question.Qtype))
	queryURL := fmt.Sprintf("https://%s?name=%s&type=%s", server.Upstream, query, queryType)
	log.WithFields(log.Fields{"Url": queryURL}).Info("Constructed Url")

	// contruct http.client for get request with header set for json
	req, err := http.NewRequest("GET", queryURL, nil)
	if err != nil {
		log.WithFields(log.Fields{"Error": err}).Error("Error creating request")
		return nil, err
	}

	// Add header fields
	for key, value := range server.Header {
		req.Header.Add(key, value)
	}

	// Special to Google
	// May need to consider to move to different place
	if server.Name == "Google" {
		req.Host = "dns.google"
	}

	resp, err := server.httpClient.Do(req)
	if err != nil {
		log.WithFields(log.Fields{"Error": err}).Error("Error during DoH get request")
		return nil, err
	}

	responseBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.WithFields(log.Fields{"Error": err}).Error("Error parsing HTTPS response body")
		return nil, err
	}

	responseMap := make(map[string]interface{})
	err = json.Unmarshal(responseBytes, &responseMap)
	if err != nil {
		log.WithFields(log.Fields{"Error": err}).Error("Error marshaling HTTPS response body")
		return nil, err
	}

	return responseMap, nil
}

// DNS forwards the DNS query and resolve the message
func DNS(server *Server, queryM *dns.Msg) (*dns.Msg, error) {
	if server.Port != 53 {
		log.Fatal("Unable to make https request from a server for other purpose")
		return nil, errors.New("Invalid Port Number")
	}
	resolver := fmt.Sprintf("%s:%d", server.Upstream, server.Port)

	dnsClient := &dns.Client{
		Net: "udp",
	}

	responseM, _, err := dnsClient.Exchange(queryM, resolver)

	if err != nil {
		log.WithFields(log.Fields{
			"error":       err.Error(),
			"name server": resolver}).Error("DNS Client Exchange Socket error")
		return nil, err
	}

	if responseM != nil && responseM.Rcode != dns.RcodeSuccess {
		// failure
		log.WithFields(log.Fields{
			"name server": resolver}).Info("Failed to get a valid answer for query from nameserver")
		if responseM.Rcode == dns.RcodeServerFailure {
			// SERVFAIL: don't provide response because other DNS servers may have better luck
			log.WithFields(log.Fields{"Rcode": responseM.Rcode}).Error("ServFail")
			return nil, err
		} else {
			log.WithFields(log.Fields{"Rcode": responseM.Rcode}).Error("NXDOMAIN ERROR")
		}
	}

	return responseM, nil
}

// Debugging

// PrintInfo prints server ip and port
func (server *Server) PrintInfo() {
	fmt.Printf("IP: %s; Port: %d\n", server.Upstream, server.Port)
}
