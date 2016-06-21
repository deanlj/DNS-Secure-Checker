package Process

import (
	"DNSQuery"
	"fmt"
)

func ProcessDNSSecMain(domain string) {
	// 获取根服务器的公钥证书(存储在数组指针中)

	// []*dns.DNSKEY{(*dns.DNSKEY)(0xc82006a340), (*dns.DNSKEY)(0xc82006a380), (*dns.DNSKEY)(0xc82006a3c0)}
	// []*dns.RRSIG{(*dns.RRSIG)(0xc820086540)}

	rootDNSKeyList, rootRRSIGList, err := DNSQuery.GetDNSKEY(".", DNSQuery.RootServer, DNSQuery.Port)
	if err != nil {
		fmt.Printf("[x]暂时无法获取根证书:%v", err)
		return
	}
	fmt.Printf("[*]已获取根证书 %d 份及签名文件 %d 份", len(rootDNSKeyList), len(rootRRSIGList))

}
