package main

import (
	"time"
	"fmt"
)

func getCSTTime(utcTime time.Time) time.Time {
	beijing, err := time.LoadLocation("Asia/Chongqing")
	if err != nil {
		fmt.Println(err)
	}
	utcTime = utcTime.Add(8 * time.Hour)
	CSTTime := time.Date(utcTime.Year(), utcTime.Month(), utcTime.Day(),
		utcTime.Hour(),
		utcTime.Minute(),
		utcTime.Second(),
		utcTime.Nanosecond(),
		beijing)
	return CSTTime
}

func main() {

	ticker := time.NewTicker(1 * time.Second)

	for {
		select {
		case t := <-ticker.C:
			fmt.Println(getCSTTime(t.UTC()))
		}

	}
}
