package Process

import (
	"DNSQuery"
	"fmt"
	"github.com/miekg/dns"
)

const (
	RecursiveServer = DNSQuery.RecursiveServer
	Port            = DNSQuery.Port
)

func ProcessDNSMain(domain string) {
	// 1-获取IPV4地址
	AList, err := DNSQuery.GetIPv4List(domain,RecursiveServer,Port)
	if err != nil {
		fmt.Printf("[x]Step-1 获取域名 %s A记录失败:%v\n",domain,err)
	} else {
		fmt.Printf("[*]Step-1 获取域名 %s A记录成功: %v\n",domain,AList)
		// // 获取a记录的ptr记录
		for i, ip := range AList {
			ptr, err := dns.ReverseAddr(ip)
			if err != nil {
				fmt.Printf("\t[x]Step-1-%d 获取域名 %s 的IP: %s 对应PTR记录失败:%v\n",i,domain,ip,err)
			} else if len(ptr)==0 {
				fmt.Printf("\t[x]Step-1-%d 获取域名 %s 的IP: %s 对应PTR记录为空\n",i,domain,ip)
			} else {
				fmt.Printf("\t[*]Step-1-%d 获取域名 %s 的IP: %s 对应PTR: %v\n",i,domain,ip,ptr)
			}
		}
	}

	// 2-获取IPV6地址
	AAAAList, err := DNSQuery.GetIPv6List(domain,RecursiveServer,Port)
	if err != nil {
		fmt.Printf("[x]Step-2 获取域名 %s AAAA记录失败:%v\n",domain,err)
	} else {
		fmt.Printf("[*]Step-2 获取域名 %s AAAA记录成功: %v\n",domain,AAAAList)
	}

	// 3-获取NS记录
	NsList, err := DNSQuery.GetNSList(domain,RecursiveServer,Port)
	if err != nil {
		fmt.Printf("[x]Step-3 获取域名 %s NS记录失败:%v\n",domain,err)
	} else {
		fmt.Printf("[*]Step-3 获取域名 %s NS记录成功: %v\n",domain,NsList)
		// 获取所有NS的 hostname
		for i, ns := range NsList {
			if host, err := DNSQuery.GetHostName(ns,RecursiveServer,Port); err == nil {
				fmt.Printf("\t[*]Step-3-%d 获取域名 %s 的NS记录: %s 对应的hostname 成功: %v\n",i, domain,ns, host)
			} else {
				fmt.Printf("\t[x]Step-3-%d 获取域名 %s 的NS记录: %s 对应的hostname失败\n",i, domain,ns)
			}
		}
		// 获取所有NS的 version
		for i, ns := range NsList {
			if version, err := DNSQuery.GetVersionName(ns,RecursiveServer,Port); err == nil {
				fmt.Printf("\t[*]Step-3-%d 获取域名 %s 的NS记录: %s 对应的version 成功: %v\n",i, domain,ns, version)
			} else {
				fmt.Printf("\t[x]Step-3-%d 获取域名 %s 的NS记录: %s 对应的version失败\n",i, domain,ns)
			}
		}
	}

	// 获取mx记录
	MXList, err := DNSQuery.GetMXList(domain,RecursiveServer,Port)
	if err != nil {
		fmt.Printf("[x]Step-4 获取域名 %s MX记录失败:%v\n",domain,err)
	} else {
		fmt.Printf("[*]Step-4 获取域名 %s MX记录成功: %v\n",domain,MXList)
	}


	// 获取txt记录
	TXTList, err := DNSQuery.GetTXTList(domain,RecursiveServer,Port)
	if err != nil {
		fmt.Printf("[x]Step-5 获取域名 %s TXT记录失败:%v\n",domain,err)
	} else {
		fmt.Printf("[*]Step-5 获取域名 %s TXT记录成功: %v\n",domain,TXTList)
	}


	if ok, alarmStrings, err := DNSQuery.NSConsistencyCheck(domain, NsList,Port); err != nil {
		fmt.Printf("[x]Step-6 域名　%s　的权威NS服务器一致性检查失败：%s: %v\n", domain, err)
	} else if ok == true && len(alarmStrings) == 0 {
		fmt.Printf("[*]Step-6 域名　%s　的权威NS服务器一致性检查成功，所有权威服务器数据返回一致\n", domain)
	} else if ok == false && len(alarmStrings) > 0 {
		fmt.Printf("[x]Step-6 域名　%s　的权威NS服务器一致性检查失败：%s: %v\n", domain, alarmStrings)
	}
	//　查询是否获得权限去区域传输

	if ok, return_data, err := DNSQuery.AxfrCheck(domain, NsList,Port); err != nil {
		fmt.Printf("[x]Step-7 域名　%s　的权威NS服务器去传送检查失败: %v\n", domain, err)
	} else if ok == true {
		fmt.Printf("[*]Step-7 域名　%s　的权威NS服务器区传送检查成功: 所有权威服务器均已关闭区传送\n", domain)
	} else if ok == false && len(return_data) > 0 {
		fmt.Printf("[x]Step-7 域名　%s　的权威NS服务器去传送检查失败,返回信息如下: \n\t%v\n", domain, return_data)
	}

	// CheckTCPSupport查询是否支持TCP链接
	if unsupport_list, err := DNSQuery.CheckTCPSupport(domain, NsList,Port); err != nil {
		fmt.Printf("[x]Step-8 域名　%s　的权威NS服务器TCP检查失败: %v\n", domain, err)
	} else if len(unsupport_list) == 0 {
		fmt.Printf("[*]Step-8 域名　%s　的权威NS服务器TCP检查成功: 所有权威服务器均支持tcp连接\n", domain)
	} else if len(unsupport_list) > 0 {
		fmt.Printf("[x]Step-8 域名　%s　的权威NS服务器TCP检查失败,不支持的服务器列表如下: \n\t%v\n", domain, unsupport_list)
	}


	// isSameDesc, isScopeRigthDesc, err := DNSQuery.ProcessCheckSOA(domain, NsList)
	// if err != nil {
	// 	fmt.Printf("[x]10-Peocessing SOA Check for %s fail: %v\n", domain, err)
	// }
	// if len(isSameDesc) > 0 || len(isScopeRigthDesc) > 0 {
	// 	if len(isSameDesc) > 0 {
	// 		fmt.Printf("[x]10-Peocessing SOA Check for %s fail: %v\n", domain, isSameDesc)
	// 	}
	// 	if len(isScopeRigthDesc) > 0 {
	// 		fmt.Printf("[x]10-Peocessing SOA Check for %s fail: %v\n", domain, isScopeRigthDesc)
	// 	}
	// } else {
	// 	fmt.Printf("[*]10-Peocessing SOA Check for %s success", domain)
	// }

	if asnlist, err := DNSQuery.GetNSASN(NsList,RecursiveServer,Port); err == nil {
		fmt.Printf("[*]Step-10 域名　%s　的权威NS服务器对应的ASN查询成功: %v\n", asnlist)
	} else {
		fmt.Printf("[x]Step-10 域名　%s　的权威NS服务器对应的ASN查询失败: %v\n", domain, err)
	}
}