package main

import (
	"net/http"
	"log"
	"time"
	"net"
	"net/url"
	"strings"
	"encoding/json"
	"io/ioutil"
	"fmt"
	"errors"
	"strconv"
	"github.com/sendgrid/sendgrid-go"
	"github.com/sendgrid/sendgrid-go/helpers/mail"

	"runtime"
	"syscall"
	"os"
	"math/rand"
)

type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
}
type AutoCheckConfig struct {
	Users   []User `json:"Users"`
	ApiKey  string `json:"api_key"`
	ForTime int    `json:"for_time"`
}

type UserInfo struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

var (
	checkInAuthUrl = "http://159.226.29.10/CnicCheck/authorization"

	//passportAuthUrl = "https://passport.escience.cn/oauth2/authorize"

	checkInInfoUrl = "http://159.226.29.10/CnicCheck/CheckInfoServlet"

	checkInUrl = "http://159.226.29.10/CnicCheck/CheckServlet"

	cookies []*http.Cookie

	netTransport = &http.Transport{
		Dial: (&net.Dialer{
			Timeout: 10 * time.Second,
		}).Dial,
		TLSHandshakeTimeout: 10 * time.Second,
	}

	client = &http.Client{
		Timeout:   time.Second * 10,
		Transport: netTransport,
		// 不跟随跳转
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	config AutoCheckConfig

	newDayCheckIn  = true
	newDayCheckout = true

	randSrc = rand.NewSource(time.Now().Unix())
	myRand  = rand.New(randSrc)
)

func getAuthUrl() string {
	resp, err := client.Get(checkInAuthUrl)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("Login clinet...")
	toURL, err := resp.Location()
	if err != nil {
		log.Fatal(err)
	}
	log.Println("Get redirect authentication url success ...")
	return toURL.String()
}

func getSessions(url string) {
	resp, err := client.Get(url)
	if err != nil {
		log.Fatal(err)
	}
	for _, cookie := range resp.Cookies() {
		cookies = append(cookies, cookie)
	}
	log.Println("Get JSESSION cookie success ...")
}

func getToken(toUrl string, username string, password string) (string, error) {
	formData := url.Values{}
	formData.Set("userName", username)
	formData.Set("password", password)
	formData.Set("pageinfo", "userinfo")

	req, err := http.NewRequest("POST", toUrl,
		strings.NewReader(formData.Encode()))
	if err != nil {
		log.Fatal(err)
	}

	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8")
	req.Header.Set("X-Requested-With", "com.cnic.signin")
	req.Header.Set("Upgrade-Insecure-Requests", "1")

	resp, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}

	toURL, err := resp.Location()
	if err != nil {
		log.Fatal()
	}
	resp, err = client.Get(toURL.String())
	body, err := ioutil.ReadAll(resp.Body)
	results := map[string]string{}
	json.Unmarshal(body, &results)

	if _, ok := results["token"]; ok {
		log.Println("Get token success ...")
		return results["token"], nil
	}
	log.Println("Get token failed ...")
	return "", errors.New("get token failed")
}

func getCheckinInfo(token string) {
	param := url.Values{}
	param.Set("token", token)
	urlString := checkInInfoUrl + "?" + param.Encode()
	resp, err := client.Get(urlString)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	fmt.Println(string(body))
}

func checkInAndOut(token string, checkType string) bool {

	latitude := 39.97968469863066
	longitude := 116.32915613026009

	//latitude := 39.98
	//longitude := 116.32

	//randSrc := rand.NewSource(time.Now().Unix())
	//myRand := rand.New(randSrc)
	//disturb := myRand.Float64() / 100
	//latitude += disturb
	//disturb = myRand.Float64() / 100
	//longitude += disturb

	param := url.Values{}
	param.Set("weidu", strconv.FormatFloat(latitude, 'f', -1, 64))
	param.Set("jingdu", strconv.FormatFloat(longitude, 'f', -1, 64))
	param.Set("type", checkType)
	param.Set("token", token)

	toUrl := checkInUrl + "?" + param.Encode()
	resp, err := client.Get(toUrl)
	if err != nil {
		log.Fatal(err)
	}

	resultsJson := map[string]string{}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	err = json.Unmarshal(body, &resultsJson)
	if err != nil {
		log.Fatal(err)
	}
	if resultsJson["success"] == "true" {
		log.Println(checkType + " " + "success.")
		return true
	}
	return false
}

func sendMail(checkType string, username string, result bool) {
	from := mail.NewEmail("onecat", "onecat@onecat.win")
	subject := "Check Results"
	to := mail.NewEmail(username, username)
	plainText := fmt.Sprintf("%s:%t!", checkType, result)
	htmlContent := fmt.Sprintf("<strong>%s:%t!</strong>", checkType, result)
	message := mail.NewSingleEmail(from, subject, to, plainText, htmlContent)
	api_key := config.ApiKey
	mailClient := sendgrid.NewSendClient(api_key)
	_, err := mailClient.Send(message)
	if err != nil {
		log.Println(err)
	} else {
		log.Println("Send mail success ...")
	}
}

func doFunc(username string, password string, checkType string) {

	authUrl := getAuthUrl()
	getSessions(authUrl)
	token, err := getToken(authUrl, username, password)
	if err != nil {
		log.Fatal(err)
	}
	result := checkInAndOut(token, checkType)
	sendMail(checkType, username, result)
	log.Println("do func.")
}

//func doFunc(username string, password string, checkType string) {
//	fmt.Println(username, password, checkType)
//}

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

func BeDaemonProcess(umask int, workDir string) {
	darwin := runtime.GOOS == "darwin"
	ret1, ret2, err := syscall.RawSyscall(syscall.SYS_FORK, 0, 0, 0)
	if err != 0 {
		log.Printf("Error:syscall.RawSyscall(syscall.SYS_FORK),errno:%d.", err)
		os.Exit(-1)
	}

	// fork failed.
	if ret2 < 0 {
		log.Printf("Error:fork failed.")
		os.Exit(-1)
	}

	// darwin ret1 is pid ret2 == 0 meas parent ret2 == 1 means child.
	if darwin && ret2 == 1 {
		ret1 = 0
	}

	// parent exit.
	if ret1 > 0 {
		os.Exit(0)
	}

	syscall.Umask(umask)

	sRet, sErrno := syscall.Setsid()
	if sErrno != nil {
		log.Printf("Error:syscall.Setsid,errno: %d.", sErrno)
		os.Exit(-1)
	}

	if sRet < 0 {
		log.Printf("Error:setsid failed.")
		os.Exit(-1)
	}

	os.Chdir(workDir)

	syscall.Close(int(os.Stdin.Fd()))
	syscall.Close(int(os.Stdout.Fd()))
	syscall.Close(int(os.Stderr.Fd()))
}

func main() {
	// 读取配置文件和用户
	configFile, err := ioutil.ReadFile("users.json")
	if err != nil {
		log.Fatal("read config file failed:", err)
	}
	json.Unmarshal(configFile, &config)

	// 标志时间
	userIndex := 0
	ticker := time.NewTicker(1 * time.Second)
	var flagTime time.Time
	flag := false
	defer ticker.Stop()

	for {
		select {
		case t := <-ticker.C:
			CSTTime := getCSTTime(t.UTC())
			// 每天晚上11点,重置
			if CSTTime.Hour() >= 23 {
				newDayCheckIn = true
				newDayCheckout = true
				flag = false
				log.Println("Rest check ...")
			}
			if CSTTime.Weekday() >= 1 && CSTTime.Weekday() <= 5 {
				log.Println("Work day ...")
				if CSTTime.Hour() >= 8 && CSTTime.Hour() < 9 {
					if CSTTime.Minute() == 15 && flag == false {
						flagTime = CSTTime
						flag = true
					}
					if newDayCheckIn && flag {
						checkTime := flagTime.Add(time.Duration(myRand.Int()%30+1) * time.Minute)
						log.Println(checkTime)
						if CSTTime.After(checkTime) {
							username := config.Users[userIndex].Username
							password := config.Users[userIndex].Password
							doFunc(username, password, "checkin")
							log.Println("username: ", username)
							userIndex++
							if userIndex == len(config.Users) {
								userIndex = 0
								newDayCheckIn = false
								flag = false
							}
						}
					}

				}
				if CSTTime.Hour() >= 18 && CSTTime.Hour() < 19 {
					if CSTTime.Minute() == 0 && flag == false {
						flagTime = CSTTime
						flag = true
					}
					if newDayCheckout && flag {
						checkTime := flagTime.Add(time.Duration(myRand.Int()%30+1) * time.Minute)
						if CSTTime.After(checkTime) {
							username := config.Users[userIndex].Username
							password := config.Users[userIndex].Password
							doFunc(username, password, "checkout")
							log.Printf("%s checkout.\n", username)
							userIndex++
							if userIndex == len(config.Users) {
								userIndex = 0
								newDayCheckout = false
								flag = false
							}
						}
					}

				}
			} else {
				log.Println("Do fun ...")
			}
		}
	}

}
