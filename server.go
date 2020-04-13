package proxy

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"

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

	// port number of the upstream server
	// 53 for DNS, 443 for DoH
	Port int

	// signal channel for shutting down the server
	ShutDown chan os.Signal

	// https client set header of get request
	httpClient http.Client

	count int
}

// Init initialize server
func (server *Server) Init(upstream string, port int) {

	server.Upstream = upstream
	server.Port = port
	server.ShutDown = make(chan os.Signal)

	log.SetFormatter(&log.TextFormatter{ForceColors: true})
	// Only log the Debug level or above.
	log.SetLevel(log.InfoLevel)

	log.Info("Server initialized")

	server.count = 0
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
	log.WithFields(log.Fields{"Url": queryURL}).Debug("Constructed Url")

	// contruct http.client for get request with header set for json
	req, err := http.NewRequest("GET", queryURL, nil)
	if err != nil {
		log.WithFields(log.Fields{"Error": err}).Error("Error creating request")
		return nil, err
	}

	req.Header.Add("accept", "application/dns-json")

	if server.count%2 == 0 {
		fmt.Println(server.count)
		time.Sleep(time.Second * 5)
	}
	server.count++

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
func DNS(server *Server, queryM *dns.Msg) (dns.Msg, error) {
	if server.Port != 53 {
		log.Fatal("Unable to make https request from a server for other purpose")
		return dns.Msg{}, errors.New("Invalid Port Number")
	}
	resolver := fmt.Sprintf("%s:%d", server.Upstream, server.Port)

	// TODO: add timeout and resend
	conn, err := net.Dial("udp", resolver)

	if err != nil {
		log.WithFields(log.Fields{"Error": err}).Error("Error dialing UDP resolver")
	}

	queryBytes, err := queryM.Pack()
	if err != nil {
		log.WithFields(log.Fields{"Error": err}).Error("Error packing query")
	}
	conn.Write(queryBytes)

	buffer := make([]byte, 1024)
	conn.Read(buffer)

	var responseM dns.Msg

	responseM.Unpack(buffer)

	fmt.Println(responseM)

	return responseM, nil
}

// Debugging

// PrintInfo prints server ip and port
func (server *Server) PrintInfo() {
	fmt.Printf("IP: %s; Port: %d\n", server.Upstream, server.Port)
}
