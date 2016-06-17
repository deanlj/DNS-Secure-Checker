package main
import (
	"fmt"
	"log"
	"strconv"
	"time"
	"util"
	"net"
	// "errors"
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

	fmt.Printf("\nHost name searching....\n")
	for _,ns:=range(NsList){
		hostname,versionName,err:=QueryHostName(ns,Port)
		if err!=nil{
			fmt.Printf("Host name searching went wrong %v",err)
		}else if versionName!="" || hostname !=""{
			fmt.Printf("Host name for %s is\n %s \n %s\n",ns,hostname,versionName)
		}else{
			fmt.Printf("Host name for %s not found:%s\n",ns,err)
		}
	}



	// 检查ns记录是否相同
	CheckNSResponse(domain, NsList)

	//　查询是否获得权限去区域传输
	ableAxfr,ableAxfrList,err:=QueryAxfr(domain,NsList,Port)
	if err!=nil{
		fmt.Printf("%v",err)
	}else{
		if ableAxfr{
			fmt.Printf("\n存在可区域传输的NS服务器：\n%v\n",ableAxfrList)
		}else{
			fmt.Printf("\n不存在可区域传输的NS服务器\n")
		}
	}


	// 查询是否支持tcp查询

	isSupportTcp,supportTCPList,err:=CheckTCPSupport(domain,NsList,Port)
	if err!=nil{
		fmt.Printf("\n查询TCP支持出错:%v\n",err)
	}else{
		if isSupportTcp{
			fmt.Printf("\nNS服务器全部支持TCP传输\n")
		}else if len(supportTCPList)>0{
			fmt.Printf("\nNS服务器部分支持TCP传输：%v\n",supportTCPList)
		}else{
			fmt.Printf("\nNS服务器不支持TCP传输\n")
		}
	}





	MXList,_,err:=QueryFormat(domain, dns.TypeMX," MX ",RecursiveServer, Port)
	if err!=nil{
		log.Panicf("%v",err);
	}
	fmt.Printf("\n%v\n",MXList)

	TXTList,_,err:=QueryFormat(domain, dns.TypeTXT," TXT ",RecursiveServer, Port)
	if err!=nil{
		log.Panicf("%v",err);
	}
	fmt.Printf("\n%v\n",TXTList)




}
