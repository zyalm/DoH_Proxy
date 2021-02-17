package proxy

import (
	"errors"
	"net"
	"strconv"
	"strings"

	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
)

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

		serial, err := strconv.Atoi(resourceData[2])
		refresh, err := strconv.Atoi(resourceData[3])
		retry, err := strconv.Atoi(resourceData[4])
		expire, err := strconv.Atoi(resourceData[5])
		minTTL, err := strconv.Atoi(resourceData[6])
		if err != nil {
			log.WithFields(log.Fields{"Error": err}).Error("Failed to parse SOA data")
			return nil, err
		}

		resourceBody = &dns.SOA{
			Hdr:     resourceHeader,
			Ns:      resourceData[0],
			Mbox:    resourceData[1],
			Serial:  uint32(serial),
			Refresh: uint32(refresh),
			Retry:   uint32(retry),
			Expire:  uint32(expire),
			Minttl:  uint32(minTTL),
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
	case 16:
		// Type TXT
		data, err := strconv.Unquote(answer["data"].(string))
		if err != nil {
			log.WithFields(log.Fields{"Error": err}).Error("Failed to parse TXT data")
			return nil, err
		}
		resourceData := []string{data}

		resourceBody = &dns.TXT{
			Hdr: resourceHeader,
			Txt: resourceData,
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
	case 33:
		// Type SRV
		resourceData := strings.Split(answer["data"].(string), " ")
		priority, err := strconv.Atoi(resourceData[0])
		weight, err := strconv.Atoi(resourceData[1])
		port, err := strconv.Atoi(resourceData[2])
		if err != nil {
			log.WithFields(log.Fields{"Error": err}).Error("Failed to parse SRV data")
			return nil, err
		}

		resourceBody = &dns.SRV{
			Hdr:      resourceHeader,
			Priority: uint16(priority),
			Weight:   uint16(weight),
			Port:     uint16(port),
			Target:   resourceData[3],
		}
		break
	case 46:
		// Type RRSIG
		resourceData := strings.Split(answer["data"].(string), " ")

		algorithm, err := strconv.Atoi(resourceData[1])
		labels, err := strconv.Atoi(resourceData[2])
		origTTL, err := strconv.Atoi(resourceData[3])
		expiration, err := strconv.Atoi(resourceData[4])
		inception, err := strconv.Atoi(resourceData[5])
		keyTag, err := strconv.Atoi(resourceData[6])
		if err != nil {
			log.WithFields(log.Fields{"Error": err}).Error("Failed to parse SOA data")
			return nil, err
		}

		resourceBody = &dns.RRSIG{
			Hdr:         resourceHeader,
			TypeCovered: dns.StringToType[resourceData[0]],
			Algorithm:   uint8(algorithm),
			Labels:      uint8(labels),
			OrigTtl:     uint32(origTTL),
			Expiration:  uint32(expiration),
			Inception:   uint32(inception),
			KeyTag:      uint16(keyTag),
			SignerName:  resourceData[7],
			Signature:   resourceData[8],
		}
		break
	case 47:
		// Type NSEC
		resourceData := strings.Split(answer["data"].(string), " ")
		nextDomain := resourceData[0]

		var typeBitMap []uint16
		for _, t := range resourceData[1:] {
			typeBitMap = append(typeBitMap, dns.StringToType[t])
		}

		resourceBody = &dns.NSEC{
			Hdr:        resourceHeader,
			NextDomain: nextDomain,
			TypeBitMap: typeBitMap,
		}
		break
	default:
		log.WithFields(log.Fields{"data": answer["data"].(string),
			"type": answer["type"].(float64)}).Error("Constructing DNS response. Type not supported")
		return nil, errors.New("Type not supported")
	}

	return resourceBody, nil
}
