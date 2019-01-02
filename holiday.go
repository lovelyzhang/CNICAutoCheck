package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"time"
)

type HolidayInfoSt struct {
	IsHoliday bool `json:"holiday"`
}
type HolidayAPIResp struct {
	Code        int           `json:"code"`
	HolidayInfo HolidayInfoSt `json:"holiday"`
}

var holidayAPIUrl = "http://timor.tech/api/holiday/info/"

type RequestClient struct {
	client *http.Client
}

func NewRequestClient() *RequestClient {
	rc := new(RequestClient)
	client := http.Client{
		Timeout: time.Duration(5 * time.Second),
	}
	rc.client = &client
	return rc
}

func (rc *RequestClient) SendRequest(year, month, day int) *HolidayAPIResp {
	dataStr := fmt.Sprintf("%d-%d-%d", year, month, day)
	reqUrl := holidayAPIUrl + dataStr
	resp, err := rc.client.Get(reqUrl)
	if err != nil {
		log.Println(err)
		return nil
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Println(err)
		return nil
	}
	var holidayAPIResp HolidayAPIResp
	err = json.Unmarshal(body, &holidayAPIResp)
	if err != nil {
		log.Println(err)
		return nil
	}
	return &holidayAPIResp
}
