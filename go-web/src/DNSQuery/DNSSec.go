package DNSQuery

import (
	"strconv"

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
			// fmt.Printf("%#v\n", t)
		default:

		}
	}

	return keyList, rrsigList, nil

}
