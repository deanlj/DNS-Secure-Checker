package DNSQuery

import (
	"fmt"

	// "util"

	"github.com/miekg/dns"
)

func CheckSOAParam(SOAParams map[string]int) []string {
	alarmString := []string{}
	if ttl, ok := SOAParams["TTL"]; ok == true {
		if ttl <= 3600 {
			alarmString = append(alarmString, fmt.Sprintf("The value of ttl is %d less than 3600", ttl))
		}
	}

	if refresh, ok := SOAParams["Refresh"]; ok == true {
		if refresh < 14400 {
			alarmString = append(alarmString, fmt.Sprintf("The value of refresh is %d less than 14400", refresh))
		}
	}

	if retry, ok := SOAParams["Retry"]; ok == true {
		if retry < 3600 {
			alarmString = append(alarmString, fmt.Sprintf("The value of ttl retry %d less than 3600", retry))
		}
	}

	if expire, ok := SOAParams["Expire"]; ok == true {
		if expire < 604800 {
			alarmString = append(alarmString, fmt.Sprintf("The value of expire is %d less than 604800", expire))
		}
	}
	if minimum, ok := SOAParams["minimum"]; ok == true {
		if minimum < 300 || minimum > 86400. {
			alarmString = append(alarmString, fmt.Sprintf("The value of minimum is %d not in the scope of [300,86400]", minimum))
		}
	}
	return alarmString
}

func CheckTCPSupport(domain string, nslist []string, port int) (bool, []string, error) {
	// queryServer := ns + ":" + strconv.Itoa(port)
	returnList := []string{}
	for _, nameserver := range nslist {
		data, err := QueryTCP(domain, dns.TypeA, nameserver, port)
		// fmt.Printf("%v",data)
		if err != nil {
			continue
		}
		if data != nil && len(data) > 0 {
			returnList = append(returnList, nameserver)
		}
	}

	if len(returnList) == 0 {
		return false, returnList, nil
	} else {
		return true, returnList, nil
	}
}
