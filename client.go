package proxy

import (
	"errors"
	"fmt"
	"math/rand"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
)

// Resolution job
type job struct {
	// ip address associated to client
	Addr net.Addr

	// data in bytes
	Data []byte
}

// Client serves client side traffics
type Client struct {
	// map resolver name to upstream server
	// each maintains a persistent HTTPS connection with the upstream
	Resolvers []Server

	// ip on the client side
	// 127.0.0.1 by default
	IP string

	// port number on the client side
	// 53 for DNS, 443 for DoH
	Port int

	// signal channel for shutting down the client
	ShutDownChan chan os.Signal

	// child exit chan send signal to exit workers
	ChildExitChan chan bool

	// finish shut down
	ExitChan chan bool

	// lookup channel and result channel
	// passing data for multi processing
	LookUpChan chan job
	ResultChan chan job

	// number of workers
	Num int

	// PacketConn for listening udp packets
	PC net.PacketConn

	// latest error message
	Err error
}

// Init initialize client
func (client *Client) Init(ip string, port int) {

	client.IP = ip
	client.Port = port

	client.Num = runtime.NumCPU()

	client.ShutDownChan = make(chan os.Signal, 1)
	client.ChildExitChan = make(chan bool, client.Num)
	client.ExitChan = make(chan bool, client.Num)
	client.LookUpChan = make(chan job, client.Num)
	client.ResultChan = make(chan job, client.Num)

	log.SetFormatter(&log.TextFormatter{ForceColors: true})
	// Only log the Debug level or above.
	log.SetLevel(log.InfoLevel)

	rand.Seed(time.Now().Unix())

	log.Info("Client initialized")
}

// AddUpstream adds upstream server to client resolvers
func (client *Client) AddUpstream(name string, ip string, port int) {
	var server Server
	server.Name = name
	server.Init(ip, port)
	client.Resolvers = append(client.Resolvers, server)
}

// StartProxy starts client side network service and waiting for packet
func (client *Client) StartProxy() {
	host := client.IP + ":" + strconv.Itoa(client.Port)

	client.PC, client.Err = net.ListenPacket("udp", host)
	if client.Err != nil {
		log.WithFields(log.Fields{"Error": client.Err}).Fatal("Client failed to listen UDP")
	}

	for i := 0; i < client.Num; i++ {
		go client.runReader(i)
	}
	go client.runWriter()

	client.Stop()
}

// Stop closes all channels and shuts down the client
func (client *Client) Stop() {
	// Wait until shutdown
	<-client.ShutDownChan
	log.Info("Client exiting")

	close(client.ShutDownChan)
	close(client.LookUpChan)
	close(client.ResultChan)

	log.Info("Client shut down")
}

// run keeps running, acting as proxy that listen and send and receive and send
func (client *Client) runReader(id int) {
	log.WithFields(log.Fields{"ID": id}).Info("Client reader running")
	for {
		buffer := make([]byte, 1024)
		size, addr, err := client.PC.ReadFrom(buffer)
		if err != nil {
			log.WithFields(log.Fields{"Error": err}).Error("Client failed to read packet")
			continue
		}
		newJob := job{
			Addr: addr,
			Data: buffer,
		}
		client.LookUpChan <- newJob
		log.WithFields(log.Fields{"Size": size, "ID": id}).Info("Message received")

		client.Resolve()
	}
}

func (client *Client) runWriter() {
	log.Info("Client writer running")
	for {
		newResult := <-client.ResultChan
		addr := newResult.Addr
		responseBytes := newResult.Data

		// Reply back to the client
		client.PC.WriteTo(responseBytes, addr)
	}
}

// Resolve takes byte array of query packet and return byte array of resonse packet using miekg/dns package
func (client *Client) Resolve(resolvers ...Server) {
	if len(resolvers) > 1 {
		log.Error("Should only be provided zero or one resolver")
		return
	}

	var resolver Server

	newJob := <-client.LookUpChan
	addr := newJob.Addr
	buffer := newJob.Data

	// Parse the message
	var queryM *dns.Msg = new(dns.Msg)
	err := queryM.Unpack(buffer)
	if err != nil {
		log.WithFields(log.Fields{"Error": err}).Error("Parsing error")
		return
	}

	questions := queryM.Question
	header := queryM.MsgHdr
	id := header.Id
	opcode := header.Opcode

	log.WithFields(log.Fields{
		"ID":     id,
		"OpCode": opcode,
	}).Info("Query Parsed")

	responseBytes := make([]byte, 1024)

	for _, question := range questions {
		log.WithFields(log.Fields{"Question": question}).Info("Question received")

		questionString := question.String()

		if len(resolvers) == 0 {
			// No resolver provided
			resolver = client.shard(questionString)
		} else {
			resolver = resolvers[0]
		}

		log.WithFields(log.Fields{"Resolver selected": resolver.Name}).Info("Selected Resolver")

		if resolver.Port == 443 {
			responseMap, err := DoH(&resolver, question)
			if err != nil {
				log.WithFields(log.Fields{"Error": err}).Error("Failed performing DoH")
				return
			}

			log.WithFields(log.Fields(responseMap)).Info("Response from DoH")

			// Construct response message
			var responseM *dns.Msg = new(dns.Msg)
			responseM.Compress = true
			responseM.SetReply(queryM)
			err = constructResponseMessage(responseM, responseMap)
			if err != nil {
				log.WithFields(log.Fields{"Error": err}).Error("Failed construct response message")
				return
			}

			// Pack response message in bytes
			responseBytes, err = responseM.Pack()
			if err != nil {
				log.WithFields(log.Fields{"Error": err}).Error("Failed packing DNS response message")
				return
			}
		} else if resolver.Port == 53 {
			responseM, err := DNS(&resolver, queryM)
			if err != nil {
				log.WithFields(log.Fields{"Error": err}).Error("Failed performing DNS")
				return
			}

			responseBytes, err = responseM.Pack()
			if err != nil {
				log.WithFields(log.Fields{"Error": err}).Error("Failed packing DNS response message")
				return
			}
		}
	}
	newResult := job{
		Addr: addr,
		Data: responseBytes,
	}
	client.ResultChan <- newResult
}

// shard takes applies an algorithm to select one of the resolver for resolution
func (client *Client) shard(questionString string) (resolver Server) {
	return client.Resolvers[rand.Intn(len(client.Resolvers))]
}

// Utils

// construct takes a response map and construct a dns response message using miekg/dns package
// the constructed dns message will be stored in responseM, as a argument passed by reference
func constructResponseMessage(responseM *dns.Msg, responseMap map[string]interface{}) error {
	// Construct response packet using responseMap
	var responseAnswers []dns.RR
	var responseAuthorities []dns.RR
	var responseAdditionals []dns.RR

	// Answers
	answerMap, ok := responseMap["Answer"]
	if ok {
		for _, answerInterface := range answerMap.([]interface{}) {
			answer := answerInterface.(map[string]interface{})

			resourceBody, err := constructResource(answer)
			if err != nil {
				log.WithFields(log.Fields{"Error": err}).Error("Failed constructing DNS response")
				return err
			}

			responseAnswers = append(responseAnswers, resourceBody)
		}
	}

	// Authorities
	authorityMap, ok := responseMap["Authority"]
	if ok {
		for _, authorityInterface := range authorityMap.([]interface{}) {
			authority := authorityInterface.(map[string]interface{})

			resourceBody, err := constructResource(authority)
			if err != nil {
				log.WithFields(log.Fields{"Error": err}).Error("Failed constructing DNS response")
				return err
			}

			responseAuthorities = append(responseAuthorities, resourceBody)
		}
	}

	// Additionals
	additionalMap, ok := responseMap["Additional"]
	if ok {
		for _, additionalInterface := range additionalMap.([]interface{}) {
			additional := additionalInterface.(map[string]interface{})

			resourceBody, err := constructResource(additional)
			if err != nil {
				log.WithFields(log.Fields{"Error": err}).Error("Failed constructing DNS response")
				return err
			}

			responseAdditionals = append(responseAdditionals, resourceBody)
		}
	}

	truncated, ok := responseMap["TC"]
	if ok {
		responseM.MsgHdr.Truncated = truncated.(bool)
	} else {
		// default false
		responseM.MsgHdr.Truncated = false
	}

	recursionDesired, ok := responseMap["RD"]
	if ok {
		responseM.MsgHdr.RecursionDesired = recursionDesired.(bool)
	} else {
		// default true
		responseM.MsgHdr.RecursionDesired = true
	}

	recursionAvailable, ok := responseMap["RA"]
	if ok {
		responseM.MsgHdr.RecursionAvailable = recursionAvailable.(bool)
	} else {
		// default true
		responseM.MsgHdr.RecursionAvailable = true
	}

	responseM.Answer = responseAnswers
	responseM.Ns = responseAuthorities
	responseM.Extra = responseAdditionals

	return nil
}

func constructResource(answer map[string]interface{}) (dns.RR, error) {
	var resourceHeader dns.RR_Header = dns.RR_Header{
		Name:   dns.Fqdn(answer["name"].(string)),
		Rrtype: uint16(answer["type"].(float64)),
		Class:  dns.ClassINET,
		Ttl:    uint32(answer["TTL"].(float64)),
	}

	var resourceBody dns.RR
	switch answer["type"].(float64) {
	case 1:
		// Type A
		resourceIP := net.ParseIP(answer["data"].(string))
		resourceBody = &dns.A{
			Hdr: resourceHeader,
			A:   resourceIP,
		}
		break
	case 2:
		// Type NS
		resourceBody = &dns.NS{
			Hdr: resourceHeader,
			Ns:  answer["data"].(string),
		}
		break
	case 5:
		// Type CNAME
		resourceBody = &dns.CNAME{
			Hdr:    resourceHeader,
			Target: answer["data"].(string),
		}
		break
	case 6:
		// Type SOA
		resourceData := strings.Split(answer["data"].(string), " ")

		resourceSerial, err := strconv.Atoi(resourceData[2])
		resourceRefresh, err := strconv.Atoi(resourceData[3])
		resourceRetry, err := strconv.Atoi(resourceData[4])
		resourceExpire, err := strconv.Atoi(resourceData[5])
		resourceMinttl, err := strconv.Atoi(resourceData[6])
		if err != nil {
			log.WithFields(log.Fields{"Error": err}).Error("Failed to parse SOA data")
			return nil, err
		}

		resourceBody = &dns.SOA{
			Hdr:     resourceHeader,
			Ns:      resourceData[0],
			Mbox:    resourceData[1],
			Serial:  uint32(resourceSerial),
			Refresh: uint32(resourceRefresh),
			Retry:   uint32(resourceRetry),
			Expire:  uint32(resourceExpire),
			Minttl:  uint32(resourceMinttl),
		}
		break
	case 12:
		// Type PTR
		resourceBody = &dns.PTR{
			Hdr: resourceHeader,
			Ptr: answer["data"].(string),
		}
		break
	case 15:
		// Type MX
		resourceData := strings.Split(answer["data"].(string), " ")

		resourcePreference, err := strconv.Atoi(resourceData[0])
		if err != nil {
			log.WithFields(log.Fields{"Error": err}).Error("Failed to parse MX data")
			return nil, err
		}

		resourceBody = &dns.MX{
			Hdr:        resourceHeader,
			Preference: uint16(resourcePreference),
			Mx:         resourceData[1],
		}
		break
	case 28:
		// Type AAAA
		resourceIP := net.ParseIP(answer["data"].(string))
		resourceBody = &dns.AAAA{
			Hdr:  resourceHeader,
			AAAA: resourceIP,
		}
		break
	default:
		log.WithFields(log.Fields{"data": answer["data"].(string)}).Error("Constructing DNS response. Type not supported")
		return nil, errors.New("Type not supported")
	}

	return resourceBody, nil
}

// Debugging

// PrintInfo prints all resolvers ip and ports
func (client *Client) PrintInfo() {
	for k, v := range client.Resolvers {
		fmt.Printf("%d: \n", k)
		v.PrintInfo()
	}
}
