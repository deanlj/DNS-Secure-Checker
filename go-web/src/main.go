package main

import "Process"

func main() {
	domain := "baidu.com"
	// get dns information and find something wrong with it
	// Process.ProcessMain(domain)

	// get dnssec validation
	Process.ProcessDNSSecMain(domain)
}
