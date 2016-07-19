package Process

import (
	"DNSQuery"
	"fmt"
	"github.com/miekg/dns"
	"util"
)

func SendToChannel(f ,e ,t string, c chan util.ResonseMessage){
	r:=util.ResonseMessage{f,e,t}
	c<-r
}
func WebProcessDNSMain(domain string,result chan util.ResonseMessage) {
	// 1-获取IPV4地址
	AList, err := DNSQuery.GetIPv4List(domain, RecursiveServer, Port)
	if err != nil {
		f:=fmt.Sprintf("获取域名 %s A记录失败:%v\n", domain, err)
		SendToChannel(f,"query_error","dns",result)
	} else {
		f:=fmt.Sprintf("获取域名 %s A记录成功: %v\n", domain, AList)
		SendToChannel(f,"","dns",result)
		// // 获取a记录的ptr记录
		for _, ip := range AList {
			ptr, _err := dns.ReverseAddr(ip)
			if _err != nil {
				f:=fmt.Sprintf("获取域名 %s 的IP: %s 对应PTR记录失败:%v\n", domain, ip, _err)
				SendToChannel(f,"query_error","dns",result)
			} else if len(ptr) == 0 {
				f:=fmt.Sprintf("获取域名 %s 的IP: %s 对应PTR记录为空\n", domain, ip)
				SendToChannel(f,"query_error","dns",result)
			} else {

				f:=fmt.Sprintf("获取域名 %s 的IP: %s 对应PTR: %v\n", domain, ip, ptr)
				SendToChannel(f,"","dns",result)
			}
		}
	}

	// 2-获取IPV6地址
	AAAAList, err := DNSQuery.GetIPv6List(domain, RecursiveServer, Port)
	if err != nil {
		f:=fmt.Sprintf("获取域名 %s AAAA记录失败:%v\n", domain, err)
		SendToChannel(f,"query_error","dns",result)
	} else {
		f:=fmt.Sprintf("获取域名 %s AAAA记录成功: %v\n", domain, AAAAList)
		SendToChannel(f,"","dns",result)
	}

	// 3-获取NS记录
	NsList, err := DNSQuery.GetNSList(domain, RecursiveServer, Port)
	if err != nil {
		f:=fmt.Sprintf("获取域名 %s NS记录失败:%v\n", domain, err)
		SendToChannel(f,"query_error","dns",result)
	} else {
		f:=fmt.Sprintf("获取域名 %s NS记录成功: %v\n", domain, NsList)
		SendToChannel(f,"","dns",result)
		// 获取所有NS的 hostname
		for _, ns := range NsList {
			if host, _err := DNSQuery.GetHostName(ns, RecursiveServer, Port); _err == nil {
				f:=fmt.Sprintf("获取域名 %s 的NS记录: %s 对应的hostname 成功: %v\n", domain, ns, host)
				SendToChannel(f,"","dns",result)
			} else {
				f:=fmt.Sprintf("获取域名 %s 的NS记录: %s 对应的hostname失败\n", domain, ns)
				SendToChannel(f,"query_error","dns",result)
			}
		}
		// 获取所有NS的 version
		for _, ns := range NsList {
			if version, _err := DNSQuery.GetVersionName(ns, RecursiveServer, Port); _err == nil {
				f:=fmt.Sprintf("获取域名 %s 的NS记录: %s 对应的version 成功: %v\n",  domain, ns, version)

				SendToChannel(f,"","dns",result)
			} else {
				f:=fmt.Sprintf("获取域名 %s 的NS记录: %s 对应的version失败\n", domain, ns)
				SendToChannel(f,"query_error","dns",result)
			}
		}
	}

	// 获取mx记录
	MXList, err := DNSQuery.GetMXList(domain, RecursiveServer, Port)
	if err != nil {
		f:=fmt.Sprintf("获取域名 %s MX记录失败:%v\n", domain, err)
		SendToChannel(f,"query_error","dns",result)
	} else {
		f:=fmt.Sprintf("获取域名 %s MX记录成功: %v\n", domain, MXList)
		SendToChannel(f,"","dns",result)
	}

	// 获取txt记录
	TXTList, err := DNSQuery.GetTXTList(domain, RecursiveServer, Port)
	if err != nil {
		f:=fmt.Sprintf("获取域名 %s TXT记录失败:%v\n", domain, err)
		SendToChannel(f,"query_error","dns",result)
	} else {
		f:=fmt.Sprintf("获取域名 %s TXT记录成功: %v\n", domain, TXTList)
		SendToChannel(f,"","dns",result)
	}

	if ok, alarmStrings, _err := DNSQuery.NSConsistencyCheck(domain, NsList, Port); _err != nil {
		f:=fmt.Sprintf("域名　%s　的权威NS服务器一致性检查失败: %v\n", domain, _err)
		SendToChannel(f,"query_error","dns",result)
	} else if ok == true && len(alarmStrings) == 0 {
		f:=fmt.Sprintf("域名　%s　的权威NS服务器一致性检查成功，所有权威服务器数据返回一致\n", domain)
		SendToChannel(f,"","dns",result)
	} else if ok == false && len(alarmStrings) > 0 {
		f:=fmt.Sprintf("域名　%s　的权威NS服务器一致性检查失败: %v\n", domain, alarmStrings)
		SendToChannel(f,"query_error","dns",result)
	}
	//　查询是否获得权限去区域传输

	if ok, return_data, _err := DNSQuery.AxfrCheck(domain, NsList, Port); _err != nil {
		f:=fmt.Sprintf("域名　%s　的权威NS服务器去传送检查失败: %v\n", domain, _err)
		SendToChannel(f,"query_error","dns",result)
	} else if ok == true {
		f:=fmt.Sprintf("域名　%s　的权威NS服务器区传送检查成功: 所有权威服务器均已关闭区传送\n", domain)
		SendToChannel(f,"","dns",result)
	} else if ok == false && len(return_data) > 0 {
		f:=fmt.Sprintf("域名　%s　的权威NS服务器去传送检查失败,返回信息如下: \n\t%v\n", domain, return_data)
		SendToChannel(f,"query_error","dns",result)
	}

	// CheckTCPSupport查询是否支持TCP链接
	if unsupport_list, _err := DNSQuery.CheckTCPSupport(domain, NsList, Port); _err != nil {
		f:=fmt.Sprintf("域名　%s　的权威NS服务器TCP检查失败: %v\n", domain, _err)
		SendToChannel(f,"query_error","dns",result)
	} else if len(unsupport_list) == 0 {
		f:=fmt.Sprintf("域名　%s　的权威NS服务器TCP检查成功: 所有权威服务器均支持tcp连接\n", domain)
		SendToChannel(f,"","dns",result)
	} else if len(unsupport_list) > 0 {
		f:=fmt.Sprintf("域名　%s　的权威NS服务器TCP检查失败,不支持的服务器列表如下: \n\t%v\n", domain, unsupport_list)
		SendToChannel(f,"query_error","dns",result)
	}

	soa_list, result_list,alarm_list,err := DNSQuery.CheckSOAConsistency(domain, NsList)
	if err != nil {
		f:=fmt.Sprintf("域名　%s　的 SOA 检查失败 %v\n", domain, err)
		SendToChannel(f,"query_error","dns",result)
	}
	f:=fmt.Sprintf("域名　%s　的 SOA 获取成功：\n\t%+v\n", domain,soa_list)
	SendToChannel(f,"","dns",result)
	if len(result_list) > 0 || len(alarm_list) > 0 {
		if len(result_list) > 0 {
			f:=fmt.Sprintf(" 域名　%s　的 SOA 检查失败 %v\n", domain, result_list)
			SendToChannel(f,"query_error","dns",result)
		}
		if len(alarm_list) > 0 {
			f:=fmt.Sprintf("域名　%s　的 SOA 检查失败 %v\n", domain, alarm_list)
			SendToChannel(f,"query_error","dns",result)
		}
	} else {
		f:=fmt.Sprintf("域名　%s　的 SOA 检查成功，符合基本规范", domain)
		SendToChannel(f,"","dns",result)
	}

	if asnlist, err := DNSQuery.GetNSASN(NsList, RecursiveServer, Port); err == nil {
		f:=fmt.Sprintf("域名　%s　的权威NS服务器对应的ASN查询成功:信息如下：AS|IP范围|所属地区|运营单位|日期\n\t%v", domain, asnlist)
		SendToChannel(f,"","dns",result)
	} else {
		f:=fmt.Sprintf("域名　%s　的权威NS服务器对应的ASN查询失败: %v\n", domain, err)
		SendToChannel(f,"query_error","dns",result)
	}
}
