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
