package main

import (
	"fmt"

	"DNSQuery"
)

const (
	RecursiveServer = DNSQuery.RecursiveServer
	Port            = DNSQuery.Port
)

func main() {
	domain := "baidu.com"
	// 1-获取IPV4地址
	AList, err := DNSQuery.ProcessGetIpv4List(domain)
	if err != nil {
		fmt.Printf("[x]1-ProcessGetIpv4List fail: %v\n", err)
	} else {
		fmt.Printf("[*]1-ProcessGetIpv4List success: %v\n", AList)
	}

	// 2-获取IPV6地址
	AAAAList, err := DNSQuery.ProcessGetIpv4List(domain)
	if err != nil {
		fmt.Printf("[x]2-ProcessGetIpv6List fail: %v\n", err)
	} else {
		fmt.Printf("[*]2-ProcessGetIpv6List success: %v\n", AAAAList)
	}

	// 3-获取NS记录
	NsList, err := DNSQuery.ProcessGetNSList(domain)
	if err != nil {
		fmt.Printf("[x]3-Get hostName and version list for %s fail: %v\n", domain, err)
	} else {
		fmt.Printf("[*]3-Get hostName and version list for %s success: %v\n", domain, NsList)
	}

	//  4 -获取所有NS的 hostname 或者version name

	for _, ns := range NsList {
		if host, version, err := DNSQuery.ProcessGetHostName(ns); err == nil {
			fmt.Printf("[*]4-Get hostName and version list for %s success: %s - %s\n", ns, host, version)
		} else {
			fmt.Printf("[x]4-Get hostName and version list for %s fail: %v\n", ns, err)
		}
	}

	if ok, alarmStrings, err := DNSQuery.ProcessCheckNSResponse(domain, NsList); err != nil {
		fmt.Printf("[x]5-Check all ns responses for %s fail: %v\n", domain, err)
	} else if ok == true && len(alarmStrings) == 0 {
		fmt.Printf("[*]5-Check all ns responses for %s success\n", domain)
	} else if ok == false && len(alarmStrings) > 0 {
		fmt.Printf("[*]5-Check all ns responses for %s fail: %v\n", domain, alarmStrings)
	}
	//
	//　查询是否获得权限去区域传输

	if ok, alarm, err := DNSQuery.ProcessCheckAxfrZoneTransfer(domain, NsList); err != nil {
		fmt.Printf("[x]6-Check zone transfer responses for %s fail: %v\n", domain, err)
	} else if ok == true {
		fmt.Printf("[*]6-Check zone transfer responses for %s success: all ns close zone transfer\n", domain)
	} else if ok == false && len(alarm) > 0 {
		fmt.Printf("[x]6-Check zone transfer responses for %s failed with error: %v\n", domain, alarm)
	}

	// 查询是否支持TCP链接
	if ok, supportList, err := DNSQuery.ProcessCheckTCPSupport(domain, NsList); err != nil {
		fmt.Printf("[x]7-Check TCP responses for %s fail: %v\n", domain, err)
	} else if ok == true {
		fmt.Printf("[*]7-Check TCP responses for %s  all nameservers response success\n", domain)
	} else if ok == false && len(supportList) > 0 {
		fmt.Printf("[x]7-Check TCP responses for %s  part of nameservers response success:%v\n", domain, supportList)
	} else {
		fmt.Printf("[x]7-Check TCP responses for %s  no nameservers response success\n", domain)
	}

	// 获取mx记录
	MXList, err := DNSQuery.ProcessGetMXList(domain)
	if err != nil {
		fmt.Printf("[x]8-Get MX list for %s fail: %v\n", domain, err)
	} else {
		fmt.Printf("[*]8-Get Mx  for %s success: %v\n", domain, MXList)
	}

	// 获取txt记录
	TXTList, err := DNSQuery.ProcessGetTXTList(domain)
	if err != nil {
		fmt.Printf("[x]8-Get TXT list for %s fail: %v\n", domain, err)
	} else {
		fmt.Printf("[*]8-Get TXT for %s success: %v\n", domain, TXTList)
	}

	// 获取a记录的ptr记录
	for _, ip := range AList {
		ptr, err := DNSQuery.ProcessCheckPTR(ip)
		if err != nil {
			fmt.Printf("[x]9-Get PTR for %s fail: %v\n", ip, err)
		} else if ptr == "" {
			fmt.Printf("[x]9-Get PTR for %s failed with no ptr records\n", ip)
		} else {
			fmt.Printf("[*]9-Get PTR for %s success : %s\n", ip, ptr)
		}
	}

	isSameDesc, isScopeRigthDesc, err := DNSQuery.ProcessCheckSOA(domain, NsList)
	if err != nil {
		fmt.Printf("[x]10-Peocessing SOA Check for %s fail: %v\n", domain, err)
	}
	if len(isSameDesc) > 0 || len(isScopeRigthDesc) > 0 {
		if len(isSameDesc) > 0 {
			fmt.Printf("[x]10-Peocessing SOA Check for %s fail: %v\n", domain, isSameDesc)
		}
		if len(isScopeRigthDesc) > 0 {
			fmt.Printf("[x]10-Peocessing SOA Check for %s fail: %v\n", domain, isScopeRigthDesc)
		}
	} else {
		fmt.Printf("[*]10-Peocessing SOA Check for %s success", domain)
	}

	if asnlist, err := DNSQuery.ProcessGetASN(NsList); err == nil {
		fmt.Printf("[*]11-Processing Get ASN for name servers success: %v\n", asnlist)
	} else {
		fmt.Printf("[x]11-Processing Get ASN for name servers failed with error: %v\n", err)
	}

}
