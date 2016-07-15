// 这是核心的DNS检查流程代码
package DNSQuery

import (
	"errors"
	"fmt"
	"log"
	// "strconv"
	// "strconv"
	// "strings"
	"util"

	"github.com/miekg/dns"
)

// 获取域名A地址的函数
func GetIPv4List(domain string, server string, port int) ([]string, error) {
	answers, _, err := Query(domain, dns.TypeA, server, port)
	addressList := []string{}
	if err != nil {
		log.Panicf("%v", err)
		return []string{}, err
	} else {
		for _, answer := range answers {

			if t, ok := answer.(*dns.A); ok == true {
				addressList = append(addressList, t.A.String())
			} else {
				continue
			}
		}
	}
	return addressList, nil
}

func GetIPv6List(domain string, server string, port int) ([]string, error) {
	answers, _, err := Query(domain, dns.TypeAAAA, server, port)
	addressList := []string{}
	if err != nil {
		log.Panicf("%v", err)
		return []string{}, err
	} else {
		for _, answer := range answers {

			if t, ok := answer.(*dns.AAAA); ok == true {
				addressList = append(addressList, t.AAAA.String())
			} else {
				continue
			}
		}
	}
	return addressList, nil
}

// 获取域名NS地址的函数
func GetNSList(domain string, server string, port int) ([]string, error) {
	answers, _, err := Query(domain, dns.TypeNS, server, port)
	nsList := []string{}
	if err != nil {
		log.Panicf("%v", err)
		return []string{}, err
	} else {
		for _, answer := range answers {
			if t, ok := answer.(*dns.NS); ok == true {
				nsList = append(nsList, t.Ns)
			} else {
				continue
			}
		}
	}
	return nsList, nil
}

// // 获取域名NS地址的函数
// 获取域名NS地址的函数
func GetMXList(domain string, server string, port int) ([]string, error) {
	answers, _, err := Query(domain, dns.TypeMX, server, port)
	mxList := []string{}
	if err != nil {
		log.Panicf("%v", err)
		return []string{}, err
	} else {
		for _, answer := range answers {
			if t, ok := answer.(*dns.MX); ok == true {
				mxList = append(mxList, t.Mx)
			} else {
				continue
			}
		}
	}
	return mxList, nil
}

func GetSOA(domain string, server string, port int) (string, error) {
	answers, _, err := Query(domain, dns.TypeSOA, server, port)
	if err != nil {
		return "", err
	} else {
		if t, ok := answers[0].(*dns.SOA); ok == true {
			return t.String(), nil
		} else {
			return "", nil
		}
	}
}

// // 获取域名txt记录的函数
func GetTXTList(domain string, server string, port int) ([]string, error) {
	answers, _, err := Query(domain, dns.TypeTXT, server, port)
	txtList := []string{}
	if err != nil {
		log.Panicf("%v", err)
		return []string{}, err
	} else {
		for _, answer := range answers {
			if t, ok := answer.(*dns.TXT); ok == true {
				txtList = append(txtList, t.Txt...)
			} else {
				continue
			}
		}
	}
	return txtList, nil
}

func GetHostName(ns string, server string, port int) ([]string, error) {
	answers, _, err := QueryHostName(ns, port)
	hostnameList := []string{}
	if err != nil {
		return nil, err
	} else {
		for _, answer := range answers {
			if t, ok := answer.(*dns.TXT); ok == true {
				hostnameList = append(hostnameList, t.Txt...)
			} else {
				continue
			}
		}
	}
	return hostnameList, nil
}
func GetVersionName(ns string, server string, port int) ([]string, error) {
	answers, _, err := QueryVersionName(ns, port)
	versionList := []string{}
	if err != nil {
		return nil, err
	} else {
		for _, answer := range answers {
			if t, ok := answer.(*dns.TXT); ok == true {
				versionList = append(versionList, t.Txt...)
			} else {
				continue
			}
		}
	}
	return versionList, nil
}

// NSConsistencyCheck 查看NS是否都有响应
func NSConsistencyCheck(domain string, nslist []string, port int) (bool, []string, error) {
	nsReturnArrays := map[string][]string{}
	one_ns_name := ""
	for _, ns := range nslist {
		answers, err := GetIPv4List(domain, ns, port)
		if err != nil {
			return false, nil, err
		} else {
			nsReturnArrays[ns] = append(nsReturnArrays[ns], answers...)
		}
		one_ns_name = ns
	}
	okStatus := true
	alarmString := []string{}
	for key := range nsReturnArrays {
		if util.CompareReturnArray(nsReturnArrays[key], nsReturnArrays[one_ns_name]) != true {
			alarmString = append(alarmString, fmt.Sprintf("查询%s和%s返回数据不一致\n", key, one_ns_name))
			okStatus = false
		}
	}
	return okStatus, alarmString, nil
}

func AxfrCheck(domain string, nslist []string, port int) (bool, []dns.RR, error) {
	return_data := []dns.RR{}
	for _, ns := range nslist {
		data, err := QueryAxfr(domain, ns, port)
		if err != nil {
			return false, nil, err
		} else {
			return_data = append(return_data, data...)
		}
	}

	if len(return_data) == 0 {
		return true, return_data, nil
	} else {
		return false, return_data, nil
	}
}

// CheckTCPSupport
// 返回所有不支持tcp连接的服务器
func CheckTCPSupport(domain string, nslist []string, port int) ([]string, error) {
	return_data := []string{}
	for _, ns := range nslist {
		answers, _, err := QueryByTcp(domain, dns.TypeNS, ns, port)
		if err != nil {
			return []string{}, err
		}
		if len(answers) == 0 {
			return_data = append(return_data, ns)
		} else {
			continue
		}
	}
	return return_data, nil
}

func CheckSOAConsistency(domain string, nslist []string) (map[string]string ,[]string, []string, error) {
	SOANumberList := []int{}
	SOAParams := map[string]int{}
	SOAParamsList:=map[string]string{}
	Result := []string{}
	for i, ns := range nslist {
		answer, _, err := Query(domain, dns.TypeSOA, ns, Port)
		if err != nil {
			return nil,nil,nil, err
		}
		SOA,ok:=answer[0].(*dns.SOA)
		if ok==false{
			return nil,nil,nil, errors.New("无法获得SOA记录")
		}
		SOANumberList = append(SOANumberList, int(SOA.Serial))
		if i == len(nslist)-1 {
			SOAParams["Refresh"]=int(SOA.Refresh)
			SOAParams["Retry"]=int(SOA.Retry)
			SOAParams["Expire"]=int(SOA.Expire)
			SOAParams["minimum"]=int(SOA.Minttl)
		}
		SOAParamsList[ns]=SOA.String();
	}
	for i, numberString := range SOANumberList {
		if SOANumberList[0] == numberString {
			continue
		} else {
			Result = append(Result, fmt.Sprintf("域名 %s SOA号 %s 比对 %s-%s: %s-%s\n", domain, nslist[0], SOANumberList[0], nslist[i], numberString))
		}
	}
	if len(SOAParams) == 4 {
		alarmStrings := CheckSOAParam(SOAParams)
		if len(alarmStrings) == 0 {
			return SOAParamsList, Result, []string{}, nil
		} else {
			return SOAParamsList, Result, alarmStrings, nil
		}
	}
	return SOAParamsList,Result, []string{}, nil
}
func GetASN(ip string) ([]string, error) {
	asnList := []string{}
	reversedip := util.ReversIP(ip)
	answers, _, err := Query(reversedip+"."+ASNServer, dns.TypeTXT, RecursiveServer, Port)
	if err != nil {
		return []string{}, err
	} else {
		for _, answer := range answers {
			if t, ok := answer.(*dns.TXT); ok == true {
				asnList = append(asnList, t.Txt...)
			} else {
				continue
			}
		}
	}
	return asnList, nil
}
func GetNSASN(nslist []string, server string, port int) ([]string, error) {
	ns_ip_list := []string{}
	for _, ns := range nslist {
		address_list, err := GetIPv4List(ns, server, Port)
		if err != nil {
			return []string{}, err
		}
		ns_ip_list = append(ns_ip_list, address_list...)
	}
	asnList := []string{}

	for _, ip := range ns_ip_list {
		asn, err := GetASN(ip)
		if err != nil {
			return []string{}, err
		} else {
			if len(asn) != 0 {
				asnList = append(asnList, asn...)
			}
		}
	}
	if len(asnList) > 0 {
		return util.ArrayWithoutSameItem(asnList), nil
	} else {
		return []string{}, nil
	}

}
