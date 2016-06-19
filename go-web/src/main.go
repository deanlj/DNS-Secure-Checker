package main

import (
	"fmt"
	"log"
	"strconv"

	"DNSQuery"

	"github.com/miekg/dns"
)

const (
	RecursiveServer = DNSQuery.RecursiveServer
	Port            = DNSQuery.Port
)

func main() {
	domain := "cnnic.cn"
	AList, _, err := DNSQuery.QueryFormat(domain, dns.TypeA, " A ", RecursiveServer, Port)
	if err != nil {
		log.Panicf("%v", err)
	}
	fmt.Printf("\n%v\n", AList)

	AAAAList, _, err := DNSQuery.QueryFormat(domain, dns.TypeAAAA, " AAAA ", RecursiveServer, Port)
	if err != nil {
		log.Panicf("%v", err)
	}
	fmt.Printf("\n%v\n", AAAAList)

	NsList, _, err := DNSQuery.QueryFormat(domain, dns.TypeNS, " NS ", RecursiveServer, Port)
	if err != nil {
		log.Panicf("%v", err)
	}
	fmt.Printf("\n%v\n", NsList)

	// fmt.Printf("\nHost name searching....\n")
	// for _,ns:=range(NsList){
	// 	hostname,versionName,err:=QueryHostName(ns,Port)
	// 	if err!=nil{
	// 		fmt.Printf("Host name searching went wrong %v",err)
	// 	}else if versionName!="" || hostname !=""{
	// 		fmt.Printf("Host name for %s is\n %s \n %s\n",ns,hostname,versionName)
	// 	}else{
	// 		fmt.Printf("Host name for %s not found:%s\n",ns,err)
	// 	}
	// }
	//
	//
	//
	// // 检查记录是否相同
	// CheckNSResponse(domain, NsList)
	//
	// //　查询是否获得权限去区域传输
	// ableAxfr,ableAxfrList,err:=QueryAxfr(domain,NsList,Port)
	// if err!=nil{
	// 	fmt.Printf("%v",err)
	// }else{
	// 	if ableAxfr{
	// 		fmt.Printf("\n存在可区域传输的NS服务器：\n%v\n",ableAxfrList)
	// 	}else{
	// 		fmt.Printf("\n不存在可区域传输的NS服务器\n")
	// 	}
	// }
	//
	//
	// // 查询是否支持tcp查询
	// isSupportTcp,supportTCPList,err:=CheckTCPSupport(domain,NsList,Port)
	// if err!=nil{
	// 	fmt.Printf("\n查询TCP支持出错:%v\n",err)
	// }else{
	// 	if isSupportTcp{
	// 		fmt.Printf("\nNS服务器全部支持TCP传输\n")
	// 	}else if len(supportTCPList)>0{
	// 		fmt.Printf("\nNS服务器部分支持TCP传输：%v\n",supportTCPList)
	// 	}else{
	// 		fmt.Printf("\nNS服务器不支持TCP传输\n")
	// 	}
	// }
	// MXList,_,err:=QueryFormat(domain, dns.TypeMX," MX ",RecursiveServer, Port)
	// if err!=nil{
	// 	log.Panicf("%v",err);
	// }
	// fmt.Printf("\n%v\n",MXList)
	//
	// TXTList,_,err:=QueryFormat(domain, dns.TypeTXT," TXT ",RecursiveServer, Port)
	// if err!=nil{
	// 	log.Panicf("%v",err);
	// }
	// fmt.Printf("\n%v\n",TXTList)
	//
	// for _,ip:= range(AList){
	// 	answer,err:=QueryPTR(ip,RecursiveServer, Port)
	// 	if err!=nil{
	// 		fmt.Println("Error found in PTR Quering");
	// 	}else if answer!=""{
	// 		fmt.Printf("\n%v have Ptr: %v\n",ip,answer)
	// 	}
	// }
	SOANumberList := []string{}
	SOAParams := map[string]int{}
	for i, ns := range NsList {
		SOAList, _, err := DNSQuery.QuerySOA(domain, dns.TypeSOA, " SOA ", ns, Port)
		if err != nil {
			log.Panicf("%v", err)
		}

		if len(SOAList) > 10 {
			fmt.Printf("\n%v\n", SOAList[6])
			SOANumberList = append(SOANumberList, SOAList[6])
			if i == len(NsList)-1 {
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
			fmt.Printf("SOA Number is same %s-%s: %s-%s\n", NsList[0], SOANumberList[0], NsList[i], numberString)
			continue
		} else {
			fmt.Printf("SOA Number is not same %s-%s: %s-%s\n", NsList[0], SOANumberList[0], NsList[i], numberString)
		}
	}
	// fmt.Printf("%v", SOAParams)
	if len(SOAParams) == 5 {
		alarmStrings := DNSQuery.CheckSOAParam(SOAParams)
		if len(alarmStrings) == 0 {
			fmt.Printf("All soa params is right\n")
		} else {
			fmt.Printf("Checking SOA with default value: %d warnings founded\n", len(alarmStrings))
			fmt.Printf("SOA alarms showing: %v\n", alarmStrings)
		}
	}

	//获取所有ns的A地址
	NsListArray := []string{}
	for _, ns := range NsList {
		NsAList, _, err := DNSQuery.QueryFormat(ns, dns.TypeA, " A ", RecursiveServer, Port)
		if err != nil {
			log.Panicf("%v", err)
		}
		NsListArray = append(NsListArray, NsAList...)
		// fmt.Printf("\n%v\n",NsAList)
	}

	fmt.Printf("%v", NsListArray)

	// 获取所有ns a 地址的as 号

	// 203.119.28.5----24151
	// [5.26.119.203.origin.asn.cymru.com. 14399 IN TXT "24406 24409 | 203.119.26.0/24 | CN | apnic | 2004-04-21"]
	// 203.119.26.5----24406 24409
	// [5.29.119.203.origin.asn.cymru.com. 14399 IN TXT "24151 24406 24409 | 203.119.29.0/24 | CN | apnic | 2004-04-21"]
	// 203.119.29.5----24151 24406 24409
	// [5.25.119.203.origin.asn.cymru.com. 13925 IN TXT "24151 | 203.119.25.0/24 | CN | apnic | 2004-04-21"]
	// 203.119.25.5----24151
	// [5.27.119.203.origin.asn.cymru.com

	for _, ip := range NsListArray {
		asn, err := DNSQuery.QueryASN(ip)
		if err != nil {
			fmt.Printf("%v\n", err)
		} else {
			if len(asn) != 0 {
				fmt.Printf("%v\n", asn)
			}
		}
	}

}
