package main

import "Process"

func main() {
	domain := "icann.org"
	// 完成常规DNS检查
	Process.ProcessDNSMain(domain)
	//完成DNSSec验证流程
	Process.ProcessDNSSecMain(domain)
}
