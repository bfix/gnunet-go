package util

import (
	"strings"
)

type CounterMap map[interface{}]int

func (cm CounterMap) Add(i interface{}) int {
	count, ok := cm[i]
	if !ok {
		count = 1
	} else {
		count++
	}
	cm[i] = count
	return count
}

func (cm CounterMap) Num(i interface{}) int {
	count, ok := cm[i]
	if !ok {
		count = 0
	}
	return count
}

func StripPathRight(s string) string {
	if idx := strings.LastIndex(s, "."); idx != -1 {
		return s[:idx]
	}
	return s
}
