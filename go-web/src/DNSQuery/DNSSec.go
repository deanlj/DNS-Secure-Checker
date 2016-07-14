package DNSQuery

import (
	"strconv"
	"time"

	"github.com/miekg/dns"
)

func _SendDNSSecRequest(domain string, authenticationServer string, port int, query_type uint16) ([]dns.RR, error) {
	queryServer := authenticationServer + ":" + strconv.Itoa(port)
	m := new(dns.Msg)
	m.SetEdns0(4096, true)
	m.Id = dns.Id()
	m.RecursionDesired = false
	m.Question = make([]dns.Question, 1)
	m.Question[0] = dns.Question{dns.Fqdn(domain), query_type, dns.ClassINET}
	c := new(dns.Client)
	c.DialTimeout = time.Second * 5
	var retry int = 0
LABEL_RETRY:
	in, _, err := c.Exchange(m, queryServer)
	if err != nil || len(in.Answer) == 0 {
		if retry == 2 {
			return nil, err
		} else {
			retry++
			goto LABEL_RETRY
		}
	}
	return in.Answer, nil
}
func GetDNSKEY(domain string, authenticationServer string, port int) ([]*dns.DNSKEY, []*dns.RRSIG, error) {
	answers, err := _SendDNSSecRequest(domain, authenticationServer, port, dns.TypeDNSKEY)
	if err != nil {
		return nil, nil, err
	}
	keyList := []*dns.DNSKEY{}
	rrsigList := []*dns.RRSIG{}
	for _, answer := range answers {
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
	answers, err := _SendDNSSecRequest(domain, authenticationServer, port, dns.TypeDS)
	if err != nil {
		return nil, nil, err
	}
	DSList := []*dns.DS{}
	rrsigList := []*dns.RRSIG{}
	for _, answer := range answers {
		switch t := answer.(type) {
		case *dns.DS:
			DSList = append(DSList, t)
		case *dns.RRSIG:
			rrsigList = append(rrsigList, t)
		default:
			break
		}
	}

	return DSList, rrsigList, nil

}

func GetDomainRRSig(domain string, authenticationServer string, port int) ([]*dns.RR, []*dns.RRSIG, error) {
	answers, err := _SendDNSSecRequest(domain, authenticationServer, port, dns.TypeA)
	if err != nil {
		return nil, nil, err
	}
	rr_list := []*dns.RR{}
	rrsigList := []*dns.RRSIG{}
	for _, answer := range answers {
		switch t := answer.(type) {
		case *dns.RRSIG:
			rrsigList = append(rrsigList, t)
		default:
			rr_list = append(rr_list, &t)
		}
	}
	return rr_list, rrsigList, nil
}
