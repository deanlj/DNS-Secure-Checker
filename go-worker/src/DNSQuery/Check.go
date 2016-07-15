package DNSQuery

import (
	"fmt"

	// "util"

	// "github.com/miekg/dns"
)

func CheckSOAParam(SOAParams map[string]int) []string {
	alarmString := []string{}
	if refresh, ok := SOAParams["Refresh"]; ok == true {
		if refresh < 14400 {
			alarmString = append(alarmString, fmt.Sprintf("Refresh:%d 比推荐的值14400小", refresh))
		}
	}

	if retry, ok := SOAParams["Retry"]; ok == true {
		if retry < 3600 {
			alarmString = append(alarmString, fmt.Sprintf("Retry:%d 比推荐的值3600小", retry))
		}
	}

	if expire, ok := SOAParams["Expire"]; ok == true {
		if expire < 604800 {
			alarmString = append(alarmString, fmt.Sprintf("Refresh:%d 比推荐的值604800小", expire))
		}
	}
	if minimum, ok := SOAParams["minimum"]; ok == true {
		if minimum < 300 || minimum > 86400. {
			alarmString = append(alarmString, fmt.Sprintf("Minimum:%d 推荐范围[300,86400]", minimum))
		}
	}
	return alarmString
}
