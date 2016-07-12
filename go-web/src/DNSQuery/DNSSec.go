package DNSQuery

import (
	"strconv"
	// "fmt"
	"github.com/miekg/dns"
)

func GetDNSKEY(domain string, authenticationServer string, port int) ([]*dns.DNSKEY, []*dns.RRSIG, error) {
	queryServer := authenticationServer + ":" + strconv.Itoa(port)
	m := new(dns.Msg)
	m.SetEdns0(4096, true)
	m.Id = dns.Id()
	m.RecursionDesired = false
	m.Question = make([]dns.Question, 1)
	m.Question[0] = dns.Question{domain, dns.TypeDNSKEY, dns.ClassINET}
	c := new(dns.Client)
	in, _, err := c.Exchange(m, queryServer)
	if err != nil {
		return []*dns.DNSKEY{}, []*dns.RRSIG{}, err
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


func DNSSecDomainRRSig(domain string, authenticationServer string, port int) ([]*dns.RR,[]*dns.RRSIG, error){
	queryServer := authenticationServer + ":" + strconv.Itoa(port)
	m := new(dns.Msg)
	m.SetEdns0(4096, true)
	m.Id = dns.Id()
	m.Question = make([]dns.Question, 1)
	m.Question[0] = dns.Question{dns.Fqdn(domain), dns.TypeA, dns.ClassINET}
	c := new(dns.Client)
	in, _, err := c.Exchange(m, queryServer)
	if err != nil {
		return  []*dns.RR{},[]*dns.RRSIG{}, err
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
