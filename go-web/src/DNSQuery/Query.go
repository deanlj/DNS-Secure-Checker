package DNSQuery

import (
	"net"
	"strconv"
	"strings"
	"time"
	"util"
	"github.com/miekg/dns"
)

// QueryFormat 展示格式化的数据输出
func QueryFormat(domain string, typeQuery uint16, typeString string, server string, port int) ([]string, time.Duration, error) {

	// 查询域名的A记录
	answerA, rtt, err := Query(domain, typeQuery, RecursiveServer, Port)
	if err != nil {
		return nil, time.Duration(0), err
	}
	if typeQuery != dns.TypeTXT {
		list := util.ExtractLastRow(answerA)
		return list, rtt, nil
	} else {
		return answerA, rtt, nil
	}

}
// Query 查询域名状态，参数分别为 查询类型 服务器IP 与 端口
func Query(domain string, typeQuery uint16, server string, port int) ([]string, time.Duration, error) {
	m1 := new(dns.Msg)
	m1.Id = dns.Id()
	m1.RecursionDesired = true
	m1.Question = make([]dns.Question, 1)
	m1.Question[0] = dns.Question{dns.Fqdn(domain), typeQuery, dns.ClassINET}
	c := new(dns.Client)
	queryServer := server + ":" + strconv.Itoa(port)
	in, rtt, err := c.Exchange(m1, queryServer)
	if err != nil {
		return nil, time.Duration(0), err
	}
	nsArray := []string{}
	for _, answer := range in.Answer {
		nsArray = append(nsArray, answer.String())
	}

	return nsArray, rtt, nil
}

// QueryTCP 使用tcp查询域名状态，参数分别为 查询类型 服务器IP 与 端口
func QueryTCP(domain string, typeQuery uint16, server string, port int) ([]string, error) {
	queryServer := server + ":" + strconv.Itoa(port)
	conn, err := net.DialTimeout("tcp", queryServer, time.Duration(5)*time.Second)
	if err != nil {
		return nil, err
	}
	m1 := new(dns.Msg)
	m1.Id = dns.Id()
	m1.RecursionDesired = true
	m1.Question = make([]dns.Question, 1)
	m1.Question[0] = dns.Question{dns.Fqdn(domain), typeQuery, dns.ClassINET}
	// c := new(dns.Client)
	in, err := dns.ExchangeConn(conn, m1)
	// fmt.Printf("%v", in)
	if err != nil {
		conn.Close()
		return nil, err
	}
	nsArray := []string{}
	for _, answer := range in.Answer {
		nsArray = append(nsArray, answer.String())
	}
	conn.Close()
	return nsArray, nil
}

func QueryHostName(ns string, port int) (string, string, error) {
	queryServer := ns + ":" + strconv.Itoa(port)
	m := new(dns.Msg)
	m.Id = dns.Id()
	m.RecursionDesired = false
	m.Question = make([]dns.Question, 1)
	m.Question[0] = dns.Question{"hostname.bind.", dns.TypeTXT, dns.ClassCHAOS}
	c := new(dns.Client)
	in, _, err := c.Exchange(m, queryServer)

	if err != nil {
		return "", "", err
	}
	hostname := ""
	if len(in.Answer) > 0 {
		hostname = util.ExtractLastItemWithQuotes(in.Answer[0].String())
	} else {
		hostname = ""
	}
	m.Question[0] = dns.Question{"version.bind.", dns.TypeTXT, dns.ClassCHAOS}
	in, _, err = c.Exchange(m, queryServer)
	if err != nil {
		return "", "", err
	} else {
		if len(in.Answer) > 0 {
			return hostname, util.ExtractLastItemWithQuotes(in.Answer[0].String()), nil
		} else {
			return hostname, "", nil
		}
	}
}

func QueryAxfr(domain string, nslist []string, port int) (bool, []string, error) {
	// queryServer := ns + ":" + strconv.Itoa(port)
	returnList := []string{}
	for _, nameserver := range nslist {
		data, _, err := Query(domain, dns.TypeAXFR, nameserver, port)
		// fmt.Printf("%v", data)
		if err != nil {
			return false, returnList, err
		}
		if data != nil && len(data) > 0 {
			returnList = append(returnList, nameserver)
		}
	}

	if len(returnList) == 0 {
		return false, returnList, nil
	} else {
		return true, returnList, nil
	}
}

// QueryPTR：查询IP对应的PTR记录如果有的话则返回数据否则返回空字符串

func QueryPTR(ip string, server string, port int) (string, error) {
	ptrString, err := dns.ReverseAddr(ip)
	if err != nil {
		return "", err
	} else {
		if len(ptrString) > 0 {
			return ptrString, nil
		} else {
			return "", nil
		}
	}
}

func QuerySOA(domain string, typeQuery uint16, typeString string, server string, port int) ([]string, time.Duration, error) {
	answers, rtt, err := Query(domain, typeQuery, server, Port)
	if err != nil {
		return []string{}, time.Duration(0), err
	}
	if len(answers) > 0 {
		soastring := strings.Fields(answers[0])
		return soastring, rtt, nil
	}
	return []string{}, rtt, nil
}

// 返回ip地址对应的as号

func QueryASN(ip string) (string, error) {

	reversedip := util.ReversIP(ip)
	answers, _, err := Query(reversedip+"."+ASNServer, dns.TypeTXT, RecursiveServer, Port)
	if err != nil {
		return "", err
	}
	if len(answers) > 0 {
		fields := strings.Fields(answers[0])
		// fmt.Print(fields)
		if len(fields) > 4 {
			return strings.TrimLeft(strings.Split(strings.Join(fields[4:], " "), " | ")[0], "\""), nil
		}
		return "", nil
	}
	return "", nil
}
