package main

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
	"net"
	"math/rand"
	"sync"
	"github.com/miekg/dns"
)

// Config 结构用于存储应用程序配置信息
type Config struct {
	NodeCode string `json:"node_code"`
	APIKey   string `json:"api_key"`
	APIURL   string `json:"api_url"`
	DNS_SERVERS string `json:"dns_server"`
	SAFE_DNS_SERVERS string `json:"safe_dns_server"`
	CN_DNS_SERVERS string `json:"CN_DNS_SERVERS"`
	CACHE string `json:"cache"`
}

// APIResponse 结构表示从 API 返回的 JSON 响应
type APIResponse struct {
	Code int `json:"code"`
	Data struct {
		DomainList []string `json:"domain_list"`
	} `json:"data"`
	Msg string `json:"msg"`
}

// DNSCache 结构用于管理 DNS 查询的缓存
type DNSCache struct {
	cache map[string]*dns.Msg
	mutex sync.RWMutex
}


var dnsCache DNSCache

// 全局变量，存储配置信息
var config Config

// 白名单
var whitelist []string
var whitelistMutex sync.RWMutex

// init 函数用于初始化配置信息
func init() {
	// 示例：从环境变量加载配置信息
	err := loadConfigFromEnv()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}
}

// loadConfigFromEnv 函数用于从环境变量加载配置信息
func loadConfigFromEnv() error {
	config = Config{
		NodeCode: os.Getenv("NODE_CODE"),
		APIKey:   os.Getenv("API_KEY"),
		APIURL:   os.Getenv("API_URL"),
		DNS_SERVERS: os.Getenv("DNS_SERVERS"),
		SAFE_DNS_SERVERS: os.Getenv("SAFE_DNS_SERVERS"),
		CN_DNS_SERVERS: os.Getenv("CN_DNS_SERVERS"),
		CACHE: os.Getenv("CACHE"),
	}

	if config.NodeCode == "" || config.APIKey == "" || config.APIURL == "" || config.DNS_SERVERS == "" || config.SAFE_DNS_SERVERS == "" || config.CN_DNS_SERVERS == "" {
		return fmt.Errorf("missing required configuration")
	}

	if config.CACHE == "" {
		config.CACHE = "0"
	}

	return nil
}

// GenerateSign 函数生成请求签名
func GenerateSign(params map[string]string, apiKey string) string {
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var signString strings.Builder
	for _, k := range keys {
		signString.WriteString(fmt.Sprintf("%s=%s&", k, params[k]))
	}
	signString.WriteString(fmt.Sprintf("key=%s", apiKey))

	hash := md5.Sum([]byte(signString.String()))
	return hex.EncodeToString(hash[:])
}

// GetWhitelist 函数从 API 获取白名单
func GetWhitelist() ([]string, error) {
	timestamp := fmt.Sprintf("%d", time.Now().Unix())
	params := map[string]string{
		"node_code": config.NodeCode,
		"time":      timestamp,
	}

	sign := GenerateSign(params, config.APIKey)

	requestBody, err := json.Marshal(params)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request body: %v", err)
	}

	client := &http.Client{}
	req, err := http.NewRequest("POST", config.APIURL, strings.NewReader(string(requestBody)))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %v", err)
	}

	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("sign", sign)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make API request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API returned non-200 status code: %d", resp.StatusCode)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read API response body: %v", err)
	}

	var apiResponse APIResponse
	err = json.Unmarshal(body, &apiResponse)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal API response: %v", err)
	}

	if apiResponse.Code != 1 {
		return nil, fmt.Errorf("API error: %s", apiResponse.Msg)
	}

	return apiResponse.Data.DomainList, nil
}

func main() {
	dnsCache = DNSCache{
		cache: make(map[string]*dns.Msg),
	}
	go cleanupCache()
	go updateWhitelistPeriodically()

	// 读取白名单文件
	whitelist, err := GetWhitelist()
	if err != nil {
		log.Fatalf("Failed to get whitelist: %v", err)
	}

	server := dns.Server{Addr: ":53", Net: "udp"}
	dns.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		for _, q := range r.Question {
			// Check cache first
			if config.CACHE == "1" {
				if cachedResponse, found := getCachedResponse(q.Name); found {
					cachedResponse.Id = r.Id
					cachedResponse.Question[0] = q
					// Send the cached response back to the client
					err := w.WriteMsg(cachedResponse)
					if err != nil {
						log.Printf("Error writing cached DNS response: %s", err.Error())
						return
					}
					// log.Printf("Cache hit: %s\n", q.Name)
					continue
				}
			}

			// 检查域名是否在白名单中
			if isInWhiteList(q.Name, whitelist) {
				// log.Printf("In WhiteList: Received DNS request for %s from client %s type %s\n", q.Name, w.RemoteAddr().String(), dns.TypeToString[q.Qtype])
				
				DNS_SERVERS := parseResolvers(config.DNS_SERVERS)
				rand.Seed(time.Now().UnixNano())
				DNS_SERVER := DNS_SERVERS[rand.Intn(len(DNS_SERVERS))]
				if !strings.Contains(DNS_SERVER, ":") {
					DNS_SERVER = DNS_SERVER + ":53"
				}
				realIP := queryDNS(q.Name, DNS_SERVER)
				if realIP == "" {
					// Return an error message to the client
					m := new(dns.Msg)
					m.SetReply(r)
					m.SetRcode(r, dns.RcodeRefused)
					if err := w.WriteMsg(m); err != nil {
						log.Println("Error writing DNS response for NXDOMAIN:", err)
					}
					return
				}
				// Create a new response
				response := new(dns.Msg)
				response.SetReply(r)
				// Add the answer
				response.Answer = append(response.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
					A:   net.ParseIP(realIP),
				})
				// Cache the response
				cacheResponse(q.Name, response)
				
				// Send the response back to the client
				err := w.WriteMsg(response)
				if err != nil {
					log.Printf("Error writing DNS response: %s", err.Error())
					return
				}
			} else {
				// log.Printf("Not in WhiteList: Received DNS request for %s from client %s type %s\n", q.Name, w.RemoteAddr().String(), dns.TypeToString[q.Qtype])
				// 从安全 DNS 服务器列表中随机选择一个 DNS 服务器
				SAFE_DNS_SERVERS := parseResolvers(config.SAFE_DNS_SERVERS)
				rand.Seed(time.Now().UnixNano())
				SAFE_DNS_SERVER := SAFE_DNS_SERVERS[rand.Intn(len(SAFE_DNS_SERVERS))]
				if !strings.Contains(SAFE_DNS_SERVER, ":") {
					SAFE_DNS_SERVER = SAFE_DNS_SERVER + ":53"
				}

				realIP := queryDNS(q.Name, SAFE_DNS_SERVER)
				if realIP == "94.140.14.35" || realIP == "156.154.112.17" || realIP == "156.154.113.17" || realIP == "0.0.0.0" || realIP == "127.0.0.1" {
					// Return a blocked response
					blockResponse := new(dns.Msg)
					blockResponse.SetReply(r)
					blockResponse.Answer = []dns.RR{
						&dns.A{
							Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 86400},
							A:   net.ParseIP(realIP),
						},
					}
					cacheResponse(q.Name, blockResponse)

					err := w.WriteMsg(blockResponse)
					if err != nil {
						log.Printf("Error writing blocked DNS response: %s", err.Error())
						return
					}
					return
				}

				CN_DNS_SERVERS := parseResolvers(config.CN_DNS_SERVERS)

				// Seed the random number generator
				rand.Seed(time.Now().UnixNano())

				// Choose a random resolver from the list
				CN_DNS_SERVER := CN_DNS_SERVERS[rand.Intn(len(CN_DNS_SERVERS))]
				// 如果 CN_DNS_SERVER 末尾含有端口号。则直接使用，否则添加默认端口号 53
				if !strings.Contains(CN_DNS_SERVER, ":") {
					CN_DNS_SERVER = CN_DNS_SERVER + ":53"
				}


				// Create a new DNS client
				client := new(dns.Client)

				// Set a timeout for the DNS query
				client.Timeout = 2 * time.Second
				// Send the request to the resolver
				response, _, err := client.Exchange(r, CN_DNS_SERVER)
				if err != nil {
					log.Printf("Error resolving DNS: %s", err.Error())
					return
				}
				// Cache the response
				cacheResponse(q.Name, response)
				// Send the response back to the client
				err = w.WriteMsg(response)
				if err != nil {
					log.Printf("Error writing DNS response: %s", err.Error())
					return
				}
			}
		}
		defer w.Close()
	})

	log.Println("Starting DNS server on port 53")
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("Failed to start DNS server: %s\n", err.Error())
	}
}

func parseResolvers(env string) []string {
    return strings.Split(env, ",")
}

// isInWhiteList 检查域名是否在白名单中
func isInWhiteList(domain string, whitelist []string) bool {
	// 去除 domain 末尾的点
	domain = strings.TrimSuffix(domain, ".")
	for _, allowedDomain := range whitelist {
		// 转义 pattern 中的 '.' 和 '*' 字符
		pattern := strings.ReplaceAll(regexp.QuoteMeta(allowedDomain), "\\*", ".*")
		// 将 pattern 编译成正则表达式
		matched, _ := regexp.MatchString("^"+pattern+"$", domain)
		if matched {
			return true
		}
	}
	return false
}

// queryDNS 函数查询指定 DNS 服务器解析域名的真实 IP 地址
func queryDNS(domain, server string) string {
	c := dns.Client{}
	m := dns.Msg{}
	m.SetQuestion(dns.Fqdn(domain), dns.TypeA)
	r, _, err := c.Exchange(&m, server)
	if err != nil {
		log.Println("Error querying DNS:", err)
		return ""
	}
	for _, ans := range r.Answer {
		if a, ok := ans.(*dns.A); ok {
			return a.A.String()
		}
	}
	return ""
}


// cacheResponse 函数更新为支持缓存 DNS 解析结果
func cacheResponse(name string, response *dns.Msg) {
	dnsCache.mutex.Lock()
	defer dnsCache.mutex.Unlock()

	dnsCache.cache[name] = response.Copy() // 缓存复制的 dns.Msg 对象
}

// getCachedResponse 函数更新为支持从缓存中读取 DNS 解析结果
func getCachedResponse(name string) (*dns.Msg, bool) {
    dnsCache.mutex.RLock()
    defer dnsCache.mutex.RUnlock()

    if entry, found := dnsCache.cache[name]; found {
        return entry.Copy(), true // 返回复制的 dns.Msg 对象
    }
    return nil, false
}


// cleanupCache 函数更新为支持定期清理过期的缓存条目
func cleanupCache() {
	for {
		<-time.After(3 * time.Minute) // Check every 5 minutes
		// <-time.After(30 * time.Second) // 每30秒检查一次
		dnsCache.mutex.Lock()
		dnsCache.cache = make(map[string]*dns.Msg) // Clear cache
		dnsCache.mutex.Unlock()
		log.Println("Cache cleared")
	}
}

func updateWhitelistPeriodically() {
	for {
		<-time.After(1 * time.Minute) // 每5分钟更新一次白名单
		// <-time.After(30 * time.Second) // 每30秒检查一次
		newWhitelist, err := GetWhitelist()
		if err != nil {
			log.Printf("Failed to update whitelist: %v", err)
			continue
		}
		whitelistMutex.Lock()
		whitelist = newWhitelist
		whitelistMutex.Unlock()
		log.Println("Whitelist updated")
	}
}
