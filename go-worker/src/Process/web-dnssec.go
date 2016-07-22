package Process

import (
	"DNSQuery"
	"fmt"
	"github.com/miekg/dns"
	"strings"
	"util"
)

//CheckRootKey:检查根的DNSKEY的签名是否合法
func WebCheckRootKey(result chan util.ResonseMessage) {

	f := fmt.Sprintf("\n-------------根区信任检查:.-----------\n\n")
	SendToChannel(f, "", "dnssec_Root", result)
	rootDNSKeyList, rootRRSIGList, err := DNSQuery.GetDNSKEY(".", DNSQuery.RootServer, DNSQuery.Port)
	if err != nil {
		f := fmt.Sprintf("暂时无法获取根证书:%v", err)
		SendToChannel(f, "query_error", "dnssec_Root", result)
		return
	}
	f = fmt.Sprintf("已获取根证书 %d 份及签名文件 %d 份", len(rootDNSKeyList), len(rootRRSIGList))
	SendToChannel(f, "", "dnssec_Root", result)
	for _, root_key := range rootDNSKeyList {
		// 找到ksk的公钥验证dnskey记录
		if root_key.Flags == 257 {
			for _, root_rrsig := range rootRRSIGList {
				tempRRList := []dns.RR{}
				for _, item := range rootDNSKeyList {
					tempRRList = append(tempRRList, item)
				}

				if err := root_rrsig.Verify(root_key, tempRRList); err == nil {
					f := fmt.Sprintf("Root　key验证成功")
					SendToChannel(f, "", "dnssec_VerifyRoot", result)

				} else {
					f := fmt.Sprintf("Root　key验证失败")
					SendToChannel(f, "query_error", "dnssec_VerifyRoot", result)
				}
			}
		}
	}

}

// CheckDomainTrustChain:检查域名的DNSSec记录是否合法
func WebCheckDomainTrustChain(domain string, result chan util.ResonseMessage) {
	// // 获取域名的公钥证书和rrsig(存储在数组指针中)
	f := fmt.Sprintf("-------------域名RRSIGCheck:.-----------")
	rr_list, rrsig_list, err := DNSQuery.GetDomainRRSig(domain, DNSQuery.RecursiveServer, DNSQuery.Port)
	if err != nil {
		f := fmt.Sprintf("暂时无法获取证书和签名:%v", err)
		SendToChannel(f, "query_error", "dnssec_RRSIG", result)
		return
	}
	f = fmt.Sprintf("获取域名%s对应的 RR %d份和 RRSIG %d份", domain, len(rr_list), len(rrsig_list))
	SendToChannel(f, "", "dnssec_RRSIG", result)
	lenOfRRSig := len(rrsig_list)
	if lenOfRRSig == 0 {
		f := fmt.Sprintf("域名%s不包含RRSIG记录无法验证DNSSEC", domain)
		SendToChannel(f, "query_error", "dnssec_RRSIG", result)
		return
	}
	for i, rrsig_item := range rrsig_list {
		// 获得key_tag和signer的字符串
		domain_rrsig_key_tag := (*rrsig_item).KeyTag
		domain_rrsig_key_signer := (*rrsig_item).SignerName

		f := fmt.Sprintf("域名%v的rrset:%+v:key_tag = %v 和　签名机构　key_signer = %s", domain, *rr_list[i], domain_rrsig_key_tag, domain_rrsig_key_signer)
		// 获得对应的key
		SendToChannel(f, "", "dnssec_RRSET", result)
		// 获得ns服务器地址，带入上述的函数中获得key和rrsig
		domain_rrsig_key_signer_ns, err := DNSQuery.GetNSList(domain_rrsig_key_signer, DNSQuery.RecursiveServer, DNSQuery.Port)
		if err != nil || len(domain_rrsig_key_signer_ns) == 0 {
			f := fmt.Sprintf("暂时无法获得签名者%v的ns记录:%v\n", domain_rrsig_key_signer, err)
			SendToChannel(f, "query_error", "dnssec_NS", result)
			return
		}
		f = fmt.Sprintf("获得签名者%v的ns记录:%v", domain_rrsig_key_signer, domain_rrsig_key_signer_ns)
		domain_key_list, _, err := DNSQuery.GetDNSKEY(domain_rrsig_key_signer, domain_rrsig_key_signer_ns[0], DNSQuery.Port)
		if err != nil {
			f := fmt.Sprintf("验证失败,发现错误:%v", err)
			SendToChannel(f, "query_error", "dnssec_DNSKEY", result)
		}
		for _, key := range domain_key_list {
			if key.KeyTag() == domain_rrsig_key_tag {
				f := fmt.Sprintf("从域名服务器%s获得签名的密钥:key_tag = %v:%v", domain_rrsig_key_signer_ns[0], domain_rrsig_key_tag, key)
				SendToChannel(f, "", "dnssec_DNSKEY", result)
				if err := (rrsig_list[i]).Verify(key, []dns.RR{*rr_list[i]}); err != nil {
					f := fmt.Sprintf("验证失败")
					SendToChannel(f, "query_error", "dnssec_VerifyRRSet", result)
					return
				} else {

					f := fmt.Sprintf("验证%s的RRSet签名成功", domain)
					SendToChannel(f, "", "dnssec_VerifyRRSet", result)
					break
				}
			}
		}
	}
	for {

		if len(domain) > 1 {
			f := fmt.Sprintf("\n-------------信任链检查:%s-----------\n\n", domain)
			SendToChannel(f, "", "dnssec_TrustChainVerify", result)
			WebCheckTrustChain(domain, result)
			domain = strings.Join(strings.Split(domain, ".")[1:], ".")
		} else {
			break
		}
	}
}
func WebCheckTrustChain(domain string, result chan util.ResonseMessage) {
	f := fmt.Sprintf("域名%s的信任连验证\n", domain)
	SendToChannel(f, "", "dnssec_TrustChainVerify", result)
	// 获得ns服务器地址,直接向服务器请求dnskey记录
	domain_ns_list, err := DNSQuery.GetNSList(domain, DNSQuery.RecursiveServer, DNSQuery.Port)
	if err != nil {
		f := fmt.Sprintf("暂时无法获得签名者%v的ns记录:%v", domain_ns_list, err)
		SendToChannel(f, "query_error", "dnssec_NS", result)
		return
	} else if len(domain_ns_list) == 0 {
		f := fmt.Sprintf("暂时无法获得签名者%v的ns记录:可能由于该域名存在cname记录，直接进入下一级别的验证", domain_ns_list)
		SendToChannel(f, "query_error", "dnssec_NS", result)
		return
	}
	f = fmt.Sprintf("获得签名者%s的ns记录:%v\n", domain, domain_ns_list)
	SendToChannel(f, "", "dnssec_NS", result)
	domain_key_list, domain_key_rrsig_list, err := DNSQuery.GetDNSKEY(domain, domain_ns_list[0], DNSQuery.Port)

	// 查询返回的key 包含zsk和ksk记录
	f = fmt.Sprintf("验证DNSKEY的合法性:获得域名%s的DNSKEY RRSet:%d,RRSIG:%d", domain, len(domain_key_list), len(domain_key_rrsig_list))
	for _, rrsig_item := range domain_key_rrsig_list {
		// 获得rrsig的key_tag
		key_tag := rrsig_item.KeyTag
		for _, key_item := range domain_key_list {
			if (*key_item).KeyTag() == key_tag {
				f := fmt.Sprintf("已找到签名DNSKEY的密钥记录%d", key_tag)
				SendToChannel(f, "", "dnssec_DNSKEY", result)
				tempRRList := []dns.RR{}
				for _, item := range domain_key_list {
					tempRRList = append(tempRRList, item)
				}
				if err := rrsig_item.Verify(key_item, (tempRRList)); err != nil {
					fmt.Println("验证dnskey失败")
					SendToChannel(f, "query_error", "dnssec_VerifyRRSet", result)
					return
				} else {
					fmt.Println("验证dnskey成功")
					SendToChannel(f, "", "dnssec_VerifyRRSet", result)
					goto LABEL_KSK_CHECK_FINISH
				}
			}
		}
	}

LABEL_KSK_CHECK_FINISH:

	// 获取域名的DS记录

	up_level_domain := strings.Join(strings.Split(domain, ".")[1:], ".")
	f = fmt.Sprintf("从父区%s获取域名%s的DS记录", up_level_domain, domain)
	SendToChannel(f, "", "dnssec_DS", result)

	domain_ns, err := DNSQuery.GetNSList(domain, DNSQuery.RecursiveServer, DNSQuery.Port)
	if err != nil || len(domain_ns) == 0 {
		f := fmt.Sprintf("暂时无法获得%v的ns记录:%v", domain, err)
		SendToChannel(f, "query_error", "dnssec_NS", result)
		return
	}
	f = fmt.Sprintf("已获得%v的ns记录%v", domain, domain_ns)
	SendToChannel(f, "", "dnssec_NS", result)

	// 获取上层域名的ns服务器
	up_level_domain_ns, err := DNSQuery.GetNSList(up_level_domain, DNSQuery.RecursiveServer, DNSQuery.Port)
	if err != nil || len(up_level_domain_ns) == 0 {
		f := fmt.Sprintf("暂时无法获得%v的ns记录:%v", up_level_domain, err)
		SendToChannel(f, "query_error", "dnssec_NS", result)
		return
	}
	f = fmt.Sprintf("已获得父区域%s的ns记录%v", up_level_domain, up_level_domain_ns)
	domain_ds_list, domain_ds_rrsig_list, err := DNSQuery.GetDS(domain, up_level_domain_ns[0], DNSQuery.Port)
	if err != nil {
		f := fmt.Sprintf("暂时无法获得%s的DS记录:%v", domain, err)
		SendToChannel(f, "query_error", "dnssec_DS", result)
		return
	}
	f = fmt.Sprintf("从父区域获得%s的DS记录:%d条,rrsig记录%v条", domain, len(domain_ds_list), len(domain_ds_rrsig_list))
	SendToChannel(f, "", "dnssec_DS", result)
	// 验证ds是否一致
	check_ds_with_ksk := 0
	for _, key := range domain_key_list {
		if key.Flags == 257 {
			for _, ds := range domain_ds_list {
				for (key.ToDS(ds.DigestType)).Digest == ds.Digest {
					f := fmt.Sprintf("%s ID=%d 的KSK哈希值与父区域保存的DS%d记录比对成功", domain, key.KeyTag(), ds.KeyTag)
					SendToChannel(f, "", "dnssec_DS", result)
					check_ds_with_ksk++
					goto LABEL_DS_CHECK_CONSISTENT
				}
			}
		}
	}
LABEL_DS_CHECK_CONSISTENT:
	if check_ds_with_ksk == 0 {
		f := fmt.Sprintf("%s的KSK的Hash与DS记录比对失败", domain)
		SendToChannel(f, "query_error", "dnssec_DS", result)
		return
	}

	// 验证ds的rrsig是否已被父区域签名
	// 获取父区域的dnskey
	up_level_key_list, _, err := DNSQuery.GetDNSKEY(up_level_domain, up_level_domain_ns[0], DNSQuery.Port)
	if err != nil {
		f := fmt.Sprintf("验证失败,发现错误:%v", err)
		SendToChannel(f, "query_error", "dnssec_DNSKEY", result)
	}
	for _, ds_rrsig_item := range domain_ds_rrsig_list {
		for _, dnskey_item := range up_level_key_list {
			if dnskey_item.KeyTag() == ds_rrsig_item.KeyTag {
				tempRRList := []dns.RR{}
				for _, item := range domain_ds_list {
					tempRRList = append(tempRRList, item)
				}

				if err := ds_rrsig_item.Verify(dnskey_item, tempRRList); err != nil {
					f := fmt.Sprintf("%sDS已被父区域签名，但验证失败", domain)
					SendToChannel(f, "query_error", "dnssec_VerifyDS", result)
					return
				} else {
					f := fmt.Sprintf("%s的DS已被父区域签名，验证成功", domain)
					SendToChannel(f, "", "dnssec_VerifyDS", result)
					goto LABEL_DS_CHECK_FINISH
				}
			}
		}
	}
LABEL_DS_CHECK_FINISH:
}

func WebProcessDNSSecMain(domain string, result chan util.ResonseMessage) {
	if _, ok := dns.IsDomainName(domain); ok != true {
		f := fmt.Sprintf("%s：不合法请输入正确的域名", domain)
		SendToChannel(f, "query_error", "dnssec_Domain", result)
		return
	}
	WebCheckDomainTrustChain(domain, result)
	WebCheckRootKey(result)
}
