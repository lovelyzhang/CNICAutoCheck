package main

import "testing"

func TestRequestClient_SendRequest(t *testing.T) {
	reqClient := NewRequestClient()
	resp := reqClient.SendRequest(2019, 1, 1)
	if resp == nil {
		t.Fail()
	}
	if resp.HolidayInfo.IsHoliday != true {
		t.Fail()
	}

	resp = reqClient.SendRequest(2019, 1, 2)
	if resp == nil {
		t.Fail()
	}
	if resp.HolidayInfo.IsHoliday == true {
		t.Fail()
	}
}
