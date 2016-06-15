package main

import (
	"fmt"
	"log"
	"strconv"
	"time"
	"util"

	"github.com/miekg/dns"
)

// 设置递归服务器的地址
const (
	RecursiveServer = "8.8.8.8"
	Port            = 53
)

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

// CheckNSResponse 查看NS是否都有响应
func CheckNSResponse(domain string, nslist []string) (string, error) {
	nsReturnArrays := map[string][]string{}
	oneKey := ""
	for _, ns := range nslist {
		answers, rtt, err := Query(domain, dns.TypeA, ns, Port)
		if err != nil {
			log.Panicf("%v", err)
		}
		if nsReturnArrays[ns] == nil {
			nsReturnArrays[ns] = util.ExtractLastRow(answers)
		}
		fmt.Printf("查询%s的返回时间：%v\n", ns, rtt)
		fmt.Printf("%v\n", answers)
		oneKey = ns
	}
	for key := range nsReturnArrays {
		if util.CompareReturnArray(nsReturnArrays[key], nsReturnArrays[oneKey]) != true {
			fmt.Printf("查询%s和%s返回数据不一致\n", key, oneKey)
		} else {
			fmt.Printf("查询%s和%s返回数据一致\n", key, oneKey)
		}
	}
	return fmt.Sprint(""), nil
}
func main() {
	domain := "google.com"
	answers, rtt, err := Query(domain, dns.TypeNS, RecursiveServer, Port)
	if err != nil {
		log.Panicf("%v", err)
	}
	// 查看查询的返回时间
	fmt.Printf("查询ns的返回时间：%v\n", rtt)
	nslist := util.ExtractLastRow(answers)
	CheckNSResponse(domain, nslist)

}
