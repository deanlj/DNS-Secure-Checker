// 这是核心的DNS检查流程代码
package DNSQuery

import (
	"errors"
	"fmt"
	"log"
	"util"

	"github.com/miekg/dns"
)

// 获取域名a地址的函数
func ProcessGetIpv4List(domain string) ([]string, error) {
	AList, _, err := QueryFormat(domain, dns.TypeA, " A ", RecursiveServer, Port)
	if err != nil {
		log.Panicf("%v", err)
		return []string{}, err
	}
	return AList, nil
}

// 获取域名IPV6地址的函数
func ProcessGetIpv6List(domain string) ([]string, error) {
	AAAAList, _, err := QueryFormat(domain, dns.TypeAAAA, " AAAA ", RecursiveServer, Port)
	if err != nil {
		return []string{}, err
	}
	return AAAAList, nil
}

// 获取域名NS地址的函数
func ProcessGetNSList(domain string) ([]string, error) {
	NsList, _, err := QueryFormat(domain, dns.TypeNS, " NS ", RecursiveServer, Port)
	if err != nil {
		return []string{}, err
	}
	return NsList, nil
}

func ProcessGetHostName(ns string) (string, string, error) {

	hostname, versionName, err := QueryHostName(ns, Port)
	if err != nil {
		fmt.Printf("Host name searching went wrong %v", err)
		return "", "", err
	} else if versionName != "" || hostname != "" {
		return hostname, versionName, nil
	} else {
		return "", "", errors.New("No HostName and VersionName")
	}
}

// CheckNSResponse 查看NS是否都有响应
func ProcessCheckNSResponse(domain string, nslist []string) (bool, []string, error) {
	nsReturnArrays := map[string][]string{}
	oneKey := ""
	for _, ns := range nslist {
		answers, _, err := Query(domain, dns.TypeA, ns, Port)
		if err != nil {
			log.Panicf("%v", err)
		}
		if nsReturnArrays[ns] == nil {
			nsReturnArrays[ns] = util.ExtractLastRow(answers)
		}
		oneKey = ns
	}
	okStatus := true
	alarmString := []string{}
	for key := range nsReturnArrays {
		if util.CompareReturnArray(nsReturnArrays[key], nsReturnArrays[oneKey]) != true {
			alarmString = append(alarmString, fmt.Sprintf("查询%s和%s返回数据不一致\n", key, oneKey))
			okStatus = false
		}
	}
	return okStatus, alarmString, nil
}

//
//　查询是否获得权限去区域传输
func ProcessCheckAxfrZoneTransfer(domain string, nsList []string) (bool, string, error) {
	okStatus := true
	ableAxfr, ableAxfrList, err := QueryAxfr(domain, nsList, Port)
	if err != nil {
		// fmt.Printf("%v", err)
		return false, "", err
	} else {
		if ableAxfr {
			okStatus = false
			return okStatus, fmt.Sprintf("\n存在可区域传输的NS服务器：\n%v\n", ableAxfrList), nil
		} else {
			return okStatus, "", err
		}
	}
}
