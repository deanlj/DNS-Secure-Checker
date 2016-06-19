package util

import (
	"sort"
	"strings"
)

// ExtractLastRow 提取字符串数组中最后的一列数据
func ExtractLastRow(dataRow []string) []string {
	retlist := []string{}
	for _, line := range dataRow {
		data := strings.Fields(line)
		retlist = append(retlist, data[len(data)-1])
	}
	return retlist
}

func ArrayWithoutSameItem(arr []string) []string {
	setArray := []string{}
	if len(arr) == 0 {
		return arr
	} else {
		for _, s := range arr {
			setFlag := true
			for _, t := range setArray {
				if s == t {
					setFlag = false
					break
				}
			}
			if setFlag == true {
				setArray = append(setArray, s)
			}
		}
	}
	return setArray
}

func ReversIP(ip string) string {
	s := strings.Split(ip, ".")
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
	reversed := strings.Join(s, ".")
	return reversed
}

// CompareReturnArray 比较两个数组对象是否相等（排序以后的数组对象元素）
func CompareReturnArray(a []string, b []string) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	sort.Strings(a)
	sort.Strings(b)
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
