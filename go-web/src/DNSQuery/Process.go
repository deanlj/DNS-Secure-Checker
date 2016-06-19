// 这是核心的DNS检查流程代码
package DNSQuery

import (
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"
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

// 获取域名NS地址的函数
func ProcessGetMXList(domain string) ([]string, error) {
	MXList, _, err := QueryFormat(domain, dns.TypeMX, " MX ", RecursiveServer, Port)
	if err != nil {
		return []string{}, err
	}
	return MXList, nil
}

// 获取域名txt记录的函数
func ProcessGetTXTList(domain string) ([]string, error) {
	TXTList, _, err := QueryFormat(domain, dns.TypeTXT, " TXT ", RecursiveServer, Port)
	if err != nil {
		return []string{}, err
	}
	return TXTList, nil
}

func ProcessGetHostName(ns string) (string, string, error) {

	hostname, versionName, err := QueryHostName(ns, Port)
	if err != nil {
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
	ableAxfr, ableAxfrList, err := QueryAxfr(domain, nsList, Port)
	if err != nil {
		return false, "", err
	} else {
		if ableAxfr {
			return false, fmt.Sprintf("\n存在可区域传输的NS服务器：\n%v\n", ableAxfrList), nil
		} else {
			return true, "", nil
		}
	}
}

func ProcessCheckPTR(ip string) (string, error) {
	answer, err := QueryPTR(ip, RecursiveServer, Port)
	if err != nil {
		return "", err
	} else if answer != "" {
		return answer, nil
	} else {
		return "", nil
	}
}

// 查询是否支持tcp查询
func ProcessCheckTCPSupport(domain string, nslist []string) (bool, []string, error) {
	isSupportTcp, supportTCPList, err := CheckTCPSupport(domain, nslist, Port)
	if err != nil {
		return false, []string{}, err
	} else {
		if isSupportTcp {
			return true, nslist, nil
		} else if len(supportTCPList) > 0 {
			return false, supportTCPList, nil
		} else {
			return false, []string{}, nil
		}
	}
}

func ProcessCheckSOA(domain string, nslist []string) ([]string, []string, error) {
	SOANumberList := []string{}
	SOAParams := map[string]int{}
	isSameResult := []string{}
	for i, ns := range nslist {
		SOAList, _, err := QuerySOA(domain, dns.TypeSOA, " SOA ", ns, Port)
		if err != nil {
			return []string{}, []string{}, err
		}
		if len(SOAList) > 10 {
			SOANumberList = append(SOANumberList, SOAList[6])
			if i == len(nslist)-1 {
				SOAParams["TTL"], _ = strconv.Atoi(SOAList[1])
				SOAParams["Refresh"], _ = strconv.Atoi(SOAList[7])
				SOAParams["Retry"], _ = strconv.Atoi(SOAList[8])
				SOAParams["Expire"], _ = strconv.Atoi(SOAList[9])
				SOAParams["minimum"], _ = strconv.Atoi(SOAList[10])
			}
		}
	}
	for i, numberString := range SOANumberList {
		if SOANumberList[0] == numberString {
			continue
		} else {
			isSameResult = append(isSameResult, fmt.Sprintf("SOA Number for %s is not same %s-%s: %s-%s\n", domain, nslist[0], SOANumberList[0], nslist[i], numberString))
		}
	}
	if len(SOAParams) == 5 {
		alarmStrings := CheckSOAParam(SOAParams)
		if len(alarmStrings) == 0 {
			return isSameResult, []string{}, nil
		} else {
			return isSameResult, alarmStrings, nil
		}
	}
	return isSameResult, []string{}, nil
}

func ProcessGetASN(nslist []string) ([]string, error) {
	NsListArray := []string{}
	for _, ns := range nslist {
		NsAList, _, err := QueryFormat(ns, dns.TypeA, " A ", RecursiveServer, Port)
		if err != nil {
			// log.Panicf("%v", err)
			return []string{}, err
		}
		NsListArray = append(NsListArray, NsAList...)
	}
	asnList := []string{}
	for _, ip := range NsListArray {
		asn, err := QueryASN(ip)
		if err != nil {
			return []string{}, err
		} else {
			if len(asn) != 0 {
				asnList = append(asnList, strings.Fields(asn)...)
			}
		}
	}
	if len(asnList) > 0 {
		return util.ArrayWithoutSameItem(asnList), nil
	} else {
		return []string{}, errors.New("No asn found!")
	}

}

//
//
// //获取所有ns的A地址
// NsListArray := []string{}
// for _, ns := range NsList {
// 	NsAList, _, err := DNSQuery.QueryFormat(ns, dns.TypeA, " A ", RecursiveServer, Port)
// 	if err != nil {
// 		log.Panicf("%v", err)
// 	}
// 	NsListArray = append(NsListArray, NsAList...)
// 	// fmt.Printf("\n%v\n",NsAList)
// }
//
// fmt.Printf("%v", NsListArray)
