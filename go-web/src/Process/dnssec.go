package Process

import (
	"DNSQuery"
	"fmt"
	"github.com/miekg/dns"
)
var root_key = make(map[string]string,2)

func GetRootKey(){
	// 获取根服务器的公钥证书(存储在数组指针中)
	rootDNSKeyList, rootRRSIGList, err := DNSQuery.GetDNSKEY(".", DNSQuery.RootServer, DNSQuery.Port)
	if err != nil {
		fmt.Printf("[x]暂时无法获取根证书:%v", err)
		return
	}
	root_key["KSK"]=(*rootDNSKeyList[0]).PublicKey
    root_key["ZSK"]=(*rootDNSKeyList[1]).PublicKey
	fmt.Printf("[*]已获取根证书 %d 份及签名文件 %d 份", len(rootDNSKeyList), len(rootRRSIGList))

}

// func GetDNSKey(domain string) (map[string]string,error){
// 	// 获取根服务器的公钥证书(存储在数组指针中)
// 	domain_key := make(map[string]string,2)
// 	DNSKeyList, RRSIGList, err := DNSQuery.GetDNSKEY(domain, DNSQuery.RecursiveServer, DNSQuery.Port)
// 	if err != nil {
// 		fmt.Printf("[x]暂时无法获取%v的签名秘钥:%v",domain,err)
// 		return domain_key,err
// 	}
// 	fmt.Printf("%v",DNSKeyList)

// 	// domain_key["KSK"]=(*DNSKeyList[0]).PublicKey
//  //    domain_key["ZSK"]=(*DNSKeyList[1]).PublicKey
// 	fmt.Printf("[*]已获取根证书 %d 份及签名文件 %d 份", len(DNSKeyList),len(RRSIGList))
// 	return domain_key,nil
// }


func GetDomainRRSig(domain string){
	// // 获取域名的公钥证书和rrsig(存储在数组指针中)
	rr_list,rrsig_list,err:=DNSQuery.DNSSecDomainRRSig(domain,DNSQuery.RecursiveServer, DNSQuery.Port)
	if err != nil {
		fmt.Printf("[x]暂时无法获取证书和签名:%v\n", err)
		return
	}
	// fmt.Printf("%+v\n",*rrsig_list[0])
	// fmt.Printf("%+v\n",*rr_list[0])
	fmt.Printf("[*]获取域名对应的签名文件 %d 份\n", len(rrsig_list))

	// 获得key_tag和signer的字符串
	domain_rrsig_key_tag:=(*rrsig_list[0]).KeyTag
	domain_rrsig_key_signer:=(*rrsig_list[0]).SignerName

    fmt.Printf("[*]域名%v的签名key_tag = %v 和　签名机构　key_signer = %s\n",domain,domain_rrsig_key_tag,domain_rrsig_key_signer)
    // 获得对应的key
    // 获得ns服务器地址，带入上述的函数中获得key和rrsig
    // var signed_key string
    domain_key_list,domain_rrsig_list,err:=DNSQuery.GetDNSKEY(domain_rrsig_key_signer,"b.iana-servers.net.", DNSQuery.Port)
    for _,key:=range(domain_key_list){
    	if key.KeyTag()==domain_rrsig_key_tag{
    		fmt.Printf("[*]找到签名的秘钥%v:%v\n",domain_rrsig_key_tag,key)
    		if err:=(rrsig_list[0]).Verify(key,[]dns.RR{*rr_list[0]});err!=nil{
    			fmt.Println("验证失败")
    		}else{
    			fmt.Println("验证成功")
    		}

    	}
    }



    if err!=nil{
    	fmt.Printf("[x]暂时无法获取证书和签名:%v\n", err)
		return
    }
    fmt.Printf("[*]获取域名对应的签名:%v\n%v\n",domain_key_list,domain_rrsig_list)
}



func ProcessDNSSecMain(domain string) {
	GetRootKey()
	// fmt.Printf("%+v\n",root_key)
	GetDomainRRSig("www.icann.org")
}


