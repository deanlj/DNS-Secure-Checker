package Process

import (
	"DNSQuery"
	"fmt"
	"errors"
	"github.com/miekg/dns"
	"util"
)

func SendToChannel(f ,e ,t string, c chan util.ResonseMessage){
	r:=util.ResonseMessage{f,e,t}
	c<-r
}
func SendErrorsIfNull(e error)error{
	if e==nil{
		return errors.New("返回数据为空")
	}else{
		return e
	}
}
func WebProcessDNSMain(domain string,result chan util.ResonseMessage) {
	// 1-获取IPV4地址
	AList, err := DNSQuery.GetIPv4List(domain, RecursiveServer, Port)
	if err != nil || len(AList)==0 {
		f:=fmt.Sprintf("获取域名 %s A记录失败:%v", domain,SendErrorsIfNull(err))
		SendToChannel(f,"query_error","dns_IPv4_10%",result)
	} else {
		f:=fmt.Sprintf("获取域名 %s A记录成功: %v", domain, AList)
		SendToChannel(f,"","dns_IPv4_10%",result)
		// // 获取a记录的ptr记录
		for _, ip := range AList {
			ptr, _err := dns.ReverseAddr(ip)
			if _err != nil {
				f:=fmt.Sprintf("获取域名 %s 的IP: %s 对应PTR记录失败:%v", domain, ip, _err)
				SendToChannel(f,"query_error","dns_PTR_15%",result)
			} else if len(ptr) == 0 {
				f:=fmt.Sprintf("获取域名 %s 的IP: %s 对应PTR记录为空", domain, ip)
				SendToChannel(f,"query_error","dns_PTR_15%",result)
			} else {

				f:=fmt.Sprintf("获取域名 %s 的IP: %s 对应PTR: %v", domain, ip, ptr)
				SendToChannel(f,"","dns_PTR_15%",result)
			}
		}
	}

	// 2-获取IPV6地址
	AAAAList, err := DNSQuery.GetIPv6List(domain, RecursiveServer, Port)
	if err != nil ||len(AAAAList)==0{
		f:=fmt.Sprintf("获取域名 %s AAAA记录失败:%v", domain, SendErrorsIfNull(err))
		SendToChannel(f,"query_error","dns_IPv6_20%",result)
	} else {
		f:=fmt.Sprintf("获取域名 %s AAAA记录成功: %v", domain, AAAAList)
		SendToChannel(f,"","dns_IPv6_20%",result)
	}

	// 3-获取NS记录
	NsList, err := DNSQuery.GetNSList(domain, RecursiveServer, Port)
	if err != nil ||len(NsList)==0 {
		f:=fmt.Sprintf("获取域名 %s NS记录失败:%v", domain, SendErrorsIfNull(err))
		SendToChannel(f,"query_error","dns_NS_30%",result)
	} else {
		f:=fmt.Sprintf("获取域名 %s NS记录成功: %v", domain, NsList)
		SendToChannel(f,"","dns_NS_30%",result)
		// 获取所有NS的 hostname
		for _, ns := range NsList {
			if host, _err := DNSQuery.GetHostName(ns, RecursiveServer, Port); _err == nil && len(host)!=0 {
				f:=fmt.Sprintf("获取域名 %s 的NS记录: %s 对应的hostname 成功: %v", domain, ns, host)
				SendToChannel(f,"","dns_HostName_35%",result)
			} else {
				f:=fmt.Sprintf("获取域名 %s 的NS记录: %s 对应的hostname失败", domain, ns)
				SendToChannel(f,"query_error","dns_HostName_35%",result)
			}
		}
		// 获取所有NS的 version
		for _, ns := range NsList {
			if version, _err := DNSQuery.GetVersionName(ns, RecursiveServer, Port); _err == nil && len(version)!=0{
				f:=fmt.Sprintf("获取域名 %s 的NS记录: %s 对应的version 成功: %v",  domain, ns, version)
				SendToChannel(f,"","dns_VersionName_40%",result)
			} else {
				f:=fmt.Sprintf("获取域名 %s 的NS记录: %s 对应的version失败", domain, ns)
				SendToChannel(f,"query_error","dns_VersionName_40%",result)
			}
		}
	}

	// 获取mx记录
	MXList, err := DNSQuery.GetMXList(domain, RecursiveServer, Port)
	if err != nil || len(MXList)==0{
		f:=fmt.Sprintf("获取域名 %s MX记录失败:%v", domain, SendErrorsIfNull(err))
		SendToChannel(f,"query_error","dns_MX_50%",result)
	} else {
		f:=fmt.Sprintf("获取域名 %s MX记录成功: %v", domain, MXList)
		SendToChannel(f,"","dns_MX_50%",result)
	}

	// 获取txt记录
	TXTList, err := DNSQuery.GetTXTList(domain, RecursiveServer, Port)
	if err != nil ||len(TXTList)==0{
		f:=fmt.Sprintf("获取域名 %s TXT记录失败:%v", domain, SendErrorsIfNull(err))
		SendToChannel(f,"query_error","dns_TXT_60%",result)
	} else {
		f:=fmt.Sprintf("获取域名 %s TXT记录成功: %v", domain, TXTList)
		SendToChannel(f,"","dns_TXT_60%",result)
	}
	soa_list, result_list,alarm_list,err := DNSQuery.CheckSOAConsistency(domain, NsList)
	if err != nil {
		f:=fmt.Sprintf("获取域名　%s　的 SOA 失败 %v", domain, err)
		SendToChannel(f,"query_error","dns_SOA_65%",result)
	}
	f:=fmt.Sprintf("获取域名　%s　的 SOA 成功：%v", domain,soa_list)
	SendToChannel(f,"","dns_SOA_65%",result)
	if len(result_list) > 0 || len(alarm_list) > 0 {
		if len(result_list) > 0 {
			f:=fmt.Sprintf(" 域名　%s　的 SOA 检查失败 %v", domain, result_list)
			SendToChannel(f,"query_error","dns_SOA_70%",result)
		}
		if len(alarm_list) > 0 {
			f:=fmt.Sprintf("域名　%s　的 SOA 检查失败 %v", domain, alarm_list)
			SendToChannel(f,"query_error","dns_SOA_70%",result)
		}
	} else {
		f:=fmt.Sprintf("域名　%s　的 SOA 检查成功，符合基本规范", domain)
		SendToChannel(f,"","dns_SOA_70%",result)
	}

	if asnlist, err := DNSQuery.GetNSASN(NsList, RecursiveServer, Port); err == nil {
		f:=fmt.Sprintf("获取域名　%s　的权威NS服务器对应的ASN成功:%v", domain, asnlist)
		SendToChannel(f,"","dns_AS_75%",result)
	} else {
		f:=fmt.Sprintf("获取域名　%s　的权威NS服务器对应的ASN失败: %v", domain, err)
		SendToChannel(f,"query_error","dns_AS_75%",result)
	}

	if ok, alarmStrings, _err := DNSQuery.NSConsistencyCheck(domain, NsList, Port); _err != nil {
		f:=fmt.Sprintf("域名　%s　的权威NS服务器一致性检查失败: %v", domain, _err)
		SendToChannel(f,"query_error","dns_Consistency_80%",result)
	} else if ok == true && len(alarmStrings) == 0 {
		f:=fmt.Sprintf("域名　%s　的权威NS服务器一致性检查成功，所有权威服务器数据返回一致\n", domain)
		SendToChannel(f,"","dns_Consistency_80%",result)
	} else if ok == false && len(alarmStrings) > 0 {
		f:=fmt.Sprintf("域名　%s　的权威NS服务器一致性检查失败: %v", domain, alarmStrings)
		SendToChannel(f,"query_error","dns_Consistency_80%",result)
	}
	//　查询是否获得权限去区域传输

	if ok, return_data, _err := DNSQuery.AxfrCheck(domain, NsList, Port); _err != nil {
		f:=fmt.Sprintf("域名　%s　的权威NS服务器去传送检查失败: %v", domain, _err)
		SendToChannel(f,"query_error","dns_ZoneTransfer_90%",result)
	} else if ok == true {
		f:=fmt.Sprintf("域名　%s　的权威NS服务器区传送检查成功: 所有权威服务器均已关闭区传送", domain)
		SendToChannel(f,"","ZoneTransfer_90%",result)
	} else if ok == false && len(return_data) > 0 {
		f:=fmt.Sprintf("域名　%s　的权威NS服务器去传送检查失败,返回信息如下: %v", domain, return_data)
		SendToChannel(f,"query_error","ZoneTransfer_90%",result)
	}

	// CheckTCPSupport查询是否支持TCP链接
	if unsupport_list, _err := DNSQuery.CheckTCPSupport(domain, NsList, Port); _err != nil {
		f:=fmt.Sprintf("域名　%s　的权威NS服务器TCP检查失败: %v", domain, _err)
		SendToChannel(f,"query_error","dns_TCP_97%",result)
	} else if len(unsupport_list) == 0 {
		f:=fmt.Sprintf("域名　%s　的权威NS服务器TCP检查成功: 所有权威服务器均支持tcp连接", domain)
		SendToChannel(f,"","dns_TCP_97%",result)
	} else if len(unsupport_list) > 0 {
		f:=fmt.Sprintf("域名　%s　的权威NS服务器TCP检查失败,不支持的服务器列表如下:%v", domain, unsupport_list)
		SendToChannel(f,"query_error","dns_TCP_97%",result)
	}

  	SendToChannel(f, "", "dns_结束_100%", result)
}
