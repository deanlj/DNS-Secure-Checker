package DNSQuery

import (
	"strconv"
	// "fmt"
	"net"
	"github.com/miekg/dns"
	"time"
)

func GetDNSKEY(domain string, authenticationServer string, port int) ([]*dns.DNSKEY, []*dns.RRSIG, error) {
	queryServer := authenticationServer + ":" + strconv.Itoa(port)
	conn, err := net.DialTimeout("tcp", queryServer, time.Duration(5)*time.Second)
	if err != nil {
		return nil, nil,err
	}
	m := new(dns.Msg)
	m.SetEdns0(4096, true)
	m.Id = dns.Id()
	m.RecursionDesired = false
	m.Question = make([]dns.Question, 1)
	m.Question[0] = dns.Question{dns.Fqdn(domain), dns.TypeDNSKEY, dns.ClassINET}
	// c := new(dns.Client)
	// c := new(dns.Client)
	in, err := dns.ExchangeConn(conn, m)
	if err != nil {
		return  nil, nil, err
	}
	keyList := []*dns.DNSKEY{}
	rrsigList := []*dns.RRSIG{}
	for _, answer := range in.Answer {
		switch t := answer.(type) {
		case *dns.DNSKEY:
			keyList = append(keyList, t)
		case *dns.RRSIG:
			rrsigList = append(rrsigList, t)
		default:

		}
	}

	return keyList, rrsigList, nil

}

func GetDS(domain string, authenticationServer string, port int) ([]*dns.DS, []*dns.RRSIG, error) {
	queryServer := authenticationServer + ":" + strconv.Itoa(port)
	conn, err := net.DialTimeout("tcp", queryServer, time.Duration(5)*time.Second)
	if err != nil {
		return nil, nil,err
	}
	defer conn.Close()
	m := new(dns.Msg)
	m.SetEdns0(4096, true)
	m.Id = dns.Id()
	m.RecursionDesired = false
	m.Question = make([]dns.Question, 1)
	m.Question[0] = dns.Question{dns.Fqdn(domain), dns.TypeDS, dns.ClassINET}
	// c := new(dns.Client)
	in, err := dns.ExchangeConn(conn, m)
	if err != nil {
		return  nil, nil, err
	}
	DSList := []*dns.DS{}
	rrsigList := []*dns.RRSIG{}
	for _, answer := range in.Answer {
		switch t := answer.(type) {
		case *dns.DS:
			DSList = append(DSList, t)
		case *dns.RRSIG:
			rrsigList = append(rrsigList, t)
		default:

		}
	}

	return DSList, rrsigList, nil

}



func DNSSecDomainRRSig(domain string, authenticationServer string, port int) ([]*dns.RR,[]*dns.RRSIG, error){
	queryServer := authenticationServer + ":" + strconv.Itoa(port)
	conn, err := net.DialTimeout("tcp", queryServer, time.Duration(5)*time.Second)
	if err != nil {
		return nil, nil,err
	}
	defer conn.Close()

	m := new(dns.Msg)
	m.SetEdns0(4096, true)
	m.Id = dns.Id()
	m.Question = make([]dns.Question, 1)
	m.Question[0] = dns.Question{dns.Fqdn(domain), dns.TypeA, dns.ClassINET}
	// c := new(dns.Client)
	in, err := dns.ExchangeConn(conn, m)
	if err != nil {
		return  nil, nil, err
	}
	rr_list:= []*dns.RR{}
	rrsigList := []*dns.RRSIG{}
	for _, answer := range in.Answer {
		switch t := answer.(type) {
		case *dns.RRSIG:
			rrsigList = append(rrsigList, t)
		default :
			rr_list = append(rr_list,&t)
		}
	}
	return rr_list,rrsigList, nil
}
