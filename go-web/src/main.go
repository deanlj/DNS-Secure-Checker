package main
import (
	"fmt"
	"log"
	"strconv"
	"time"
	"util"
	"net"
	"strings"
	// "errors"
	"github.com/miekg/dns"
)

// 设置递归服务器的地址
const (
	RecursiveServer = "8.8.8.8"
	Port            = 53
	ASNServer="origin.asn.cymru.com"
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


// QueryTCP 使用tcp查询域名状态，参数分别为 查询类型 服务器IP 与 端口
func QueryTCP(domain string, typeQuery uint16, server string, port int) ([]string, error) {
	queryServer := server + ":" + strconv.Itoa(port)
  conn,err:=net.DialTimeout("tcp",queryServer,time.Duration(5)*time.Second);
	if err!=nil{
		return nil, err
	}
	m1 := new(dns.Msg)
	m1.Id = dns.Id()
	m1.RecursionDesired = true
	m1.Question = make([]dns.Question, 1)
	m1.Question[0] = dns.Question{dns.Fqdn(domain), typeQuery, dns.ClassINET}
	// c := new(dns.Client)
	in,err := dns.ExchangeConn(conn,m1)
	fmt.Printf("%v",in)
	if err != nil{
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
		// fmt.Printf("%v\n", answers)
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


// QueryFormat 展示格式化的数据输出
func QueryFormat(domain string, typeQuery uint16, typeString string,server string, port int)([]string, time.Duration,error){

		fmt.Printf("---------------------%s----------------\n",typeString)
		// 查询域名的A记录
		answerA, rtt, err := Query(domain, typeQuery, RecursiveServer, Port)
		if err != nil {
			return nil, time.Duration(0), err
		}
		// 查看查询A的返回时间
		fmt.Printf("查询%s记录的返回时间：\n%v\n", typeString,rtt)
		if typeQuery!=dns.TypeTXT{
			list := util.ExtractLastRow(answerA)
			return list,rtt,nil
		}else{
			return answerA,rtt,nil
		}

}

func QueryHostName(ns string,port int)(string,string,error){
	queryServer := ns + ":" + strconv.Itoa(port)
	m := new(dns.Msg)
	m.Id = dns.Id()
	m.RecursionDesired = true
	m.Question = make([]dns.Question, 1)
	m.Question[0] = dns.Question{"hostname.bind.", dns.TypeTXT, dns.ClassCHAOS}
	c := new(dns.Client)
	in, _, err := c.Exchange(m, queryServer)

	if err != nil {
		return "","", err
	}
	hostname:=""
	if len(in.Answer)>0{
		hostname=in.Answer[0].String()

	}else{
		hostname=""
	}
	m.Question[0] = dns.Question{"version.bind.", dns.TypeTXT, dns.ClassCHAOS}
	in, _ , err = c.Exchange(m, queryServer)
	if err != nil {
		return "","", err
	}else{
		if len(in.Answer)>0{
			return hostname,in.Answer[0].String(),nil
		}else{
			return hostname,"",nil
		}
	}
}

func QueryAxfr(domain string, nslist []string,port int)(bool,[]string,error){
	// queryServer := ns + ":" + strconv.Itoa(port)
	returnList:=[]string{}
	for _,nameserver :=range(nslist){
			data,_,err:=Query(domain,dns.TypeAXFR, nameserver, port)
			fmt.Printf("%v",data)
			if err!=nil{
				return false,returnList,err;
			}
			if data!=nil && len(data)>0{
				returnList=append(returnList,nameserver)
			}
	}

	if(len(returnList)==0){
		return false,returnList,nil
	}else{
		return true,returnList,nil
	}
}

func CheckTCPSupport(domain string, nslist []string,port int)(bool,[]string,error){
	// queryServer := ns + ":" + strconv.Itoa(port)
	returnList:=[]string{}
	for _,nameserver :=range(nslist){
			data,err:=QueryTCP(domain,dns.TypeA, nameserver, port)
			// fmt.Printf("%v",data)
			if err!=nil{
				continue
			}
			if data!=nil && len(data)>0{
				returnList=append(returnList,nameserver)
			}
	}

	if(len(returnList)==0){
		return false,returnList,nil
	}else{
		return true,returnList,nil
	}
}



// QueryPTR：查询IP对应的PTR记录如果有的话则返回数据否则返回空字符串

func QueryPTR(ip string,server string,port int)(string,error){
	ptrString,err:=dns.ReverseAddr(ip)
	if err!=nil{
		return "",err
	}else{
		if len(ptrString)>0{
			return ptrString,nil
		}else{
			return "",nil
		}
	}
}

func QuerySOA(domain string, typeQuery uint16, typeString string,server string, port int)([]string, time.Duration,error){

		fmt.Printf("---------------------%s----------------\n",typeString)
		// 查询域名的A记录
		answers, rtt, err := Query(domain, typeQuery, server, Port)
		if err != nil {
			return []string{}, time.Duration(0), err
		}
		if len(answers)>0{
			soastring:= strings.Fields(answers[0])
			return soastring,rtt,nil
		}
		return []string{},rtt,nil
}

func CheckSOAParam(SOAParams map[string]int)([]string){
	alarmString:=[]string{}
	if ttl,ok:=SOAParams["TTL"];ok==true{
		if ttl<=3600{
			alarmString=append(alarmString,fmt.Sprintf("The value of ttl is %d less than 3600",ttl))
		}
	}

	if refresh,ok:=SOAParams["Refresh"];ok==true{
		if refresh<14400{
			alarmString=append(alarmString,fmt.Sprintf("The value of refresh is %d less than 14400",refresh))
		}
	}

	if retry,ok:=SOAParams["Retry"];ok==true{
		if retry<3600{
			alarmString=append(alarmString,fmt.Sprintf("The value of ttl retry %d less than 3600",retry))
		}
	}

	if expire,ok:=SOAParams["Expire"];ok==true{
		if expire<604800{
			alarmString=append(alarmString,fmt.Sprintf("The value of expire is %d less than 604800",expire))
		}
	}
	if minimum,ok:=SOAParams["minimum"];ok==true{
		if minimum<300 || minimum >86400.{
			alarmString=append(alarmString,fmt.Sprintf("The value of minimum is %d not in the scope of [300,86400]",minimum))
		}
	}
	return alarmString
}

func ReversIP(ip string)(string){
	s:=strings.Split(ip,".")
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
			s[i], s[j] = s[j], s[i]
	}
	reversed:=strings.Join(s, ".")
	return reversed
}


// 返回ip地址对应的as号

func QueryASN(ip string)(string,error){

	reversedip:=ReversIP(ip)
	answers, _, err := Query(reversedip+"."+ASNServer, dns.TypeTXT, RecursiveServer, Port)
	if err != nil {
		return "", err
	}
	if len(answers)>0{
		fields:=strings.Fields(answers[0])
		// fmt.Print(fields)
		if len(fields)>4{
			return strings.TrimLeft(strings.Split(strings.Join(fields[4:]," ")," | ")[0],"\""),nil
		}
		return "",nil
	}
	return "",nil
}


func main() {
	domain := "cnnic.cn"
	AList,_,err:=QueryFormat(domain, dns.TypeA," A ",RecursiveServer, Port)
	if err!=nil{
		log.Panicf("%v",err);
	}
	fmt.Printf("\n%v\n",AList)


	AAAAList,_,err:=QueryFormat(domain, dns.TypeAAAA," AAAA ",RecursiveServer, Port)
	if err!=nil{
		log.Panicf("%v",err);
	}
	fmt.Printf("\n%v\n",AAAAList)

	NsList,_,err:=QueryFormat(domain, dns.TypeNS," NS ",RecursiveServer, Port)
	if err!=nil{
		log.Panicf("%v",err);
	}
	fmt.Printf("\n%v\n",NsList)

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
	SOANumberList:=[]string{}
	SOAParams:=map[string]int{}
	for i,ns:=range(NsList){
		SOAList,_,err:=QuerySOA(domain, dns.TypeSOA," SOA ",ns, Port)
		if err!=nil{
			log.Panicf("%v",err);
		}

		if len(SOAList)>10{
			fmt.Printf("\n%v\n",SOAList[6])
			SOANumberList=append(SOANumberList,SOAList[6])
			if i==len(NsList)-1{
				SOAParams["TTL"],_=strconv.Atoi(SOAList[1])
				SOAParams["Refresh"],_=strconv.Atoi(SOAList[7])
				SOAParams["Retry"],_=strconv.Atoi(SOAList[8])
				SOAParams["Expire"],_=strconv.Atoi(SOAList[9])
				SOAParams["minimum"],_=strconv.Atoi(SOAList[10])
			}
		}
	}
	for i,numberString:=range(SOANumberList){
		if SOANumberList[0]==numberString{
			fmt.Printf("SOA Number is same %s-%s: %s-%s\n",NsList[0],SOANumberList[0],NsList[i],numberString)
			continue
		}else{
			fmt.Printf("SOA Number is not same %s-%s: %s-%s\n",NsList[0],SOANumberList[0],NsList[i],numberString)
		}
	}
	// fmt.Printf("%v", SOAParams)
	if len(SOAParams)==5{
	  alarmStrings:=CheckSOAParam(SOAParams)
		if len(alarmStrings)==0{
			fmt.Printf("All soa params is right\n")
		}else{
			fmt.Printf("Checking SOA with default value: %d warnings founded\n", len(alarmStrings))
			fmt.Printf("SOA alarms showing: %v\n",alarmStrings)
		}
	}

  //获取所有ns的A地址
	NsListArray:=[]string{}
	for _,ns := range(NsList){
		NsAList,_,err:=QueryFormat(ns, dns.TypeA," A ",RecursiveServer, Port)
		if err!=nil{
			log.Panicf("%v",err);
		}
		NsListArray=append(NsListArray,NsAList...)
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


	for _,ip:=range(NsListArray){
		asn,err:=QueryASN(ip)
		if err!=nil{
			fmt.Printf("%v\n", err)
		}else{
			if len(asn)!=0{
				fmt.Printf("%v\n", asn)
			}
		}
	}
}
