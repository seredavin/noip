package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"gopkg.in/yaml.v2"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
)

var config Config
var cache map[string]string

type Config struct {
	Clients  []Client `yaml:"clients"`
	Settings Settings `yaml:"settings"`
}

type Client struct {
	Name      string `yaml:"name"`
	Token     string `yaml:"token"`
	Domain    string `yaml:"domain"`
	Subdomain string `yaml:"subdomain"`
}

type Settings struct {
	Port     int    `yaml:"port"`
	APIAddr  string `yaml:"apiAddr"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
	Key      string `yaml:"key"`
	Crt      string `yaml:"crt"`
}

type Request struct {
	Domain    string `json:"domain"`
	Subdomain string `json:"subdomain"`
	Token     string `json:"token"`
}

func readConfig() (Config, error) {
	path := os.Getenv("CONFIG_PATH")
	file, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}

	var cfg Config
	err = yaml.Unmarshal(file, &cfg)
	if err != nil {
		return Config{}, err
	}

	err = checkConfig(cfg)
	if err != nil {
		return Config{}, err
	}

	return cfg, nil
}

// check config for unique tokens
func checkConfig(cfg Config) error {
	tokens := make(map[string]bool)
	for _, client := range cfg.Clients {
		if tokens[client.Token] {
			return fmt.Errorf("token %v is not unique", client.Token)
		}
		tokens[client.Token] = true
	}
	return nil
}

// print Client ip from Request
func handleRequest(w http.ResponseWriter, req *http.Request) {
	log.Printf("request from %v", req.RemoteAddr)
	//parse body to Request struct
	var r Request
	err := json.NewDecoder(req.Body).Decode(&r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	//check if token is valid
	client := findClientByToken(config, r.Token)
	if client == nil {
		http.Error(w, "invalid token", http.StatusBadRequest)
		return
	}

	//check if domain is valid
	if client.Domain != r.Domain {
		http.Error(w, "invalid domain", http.StatusBadRequest)
		return
	}

	//check if subdomain is valid
	if client.Subdomain != r.Subdomain {
		http.Error(w, "invalid subdomain", http.StatusBadRequest)
		return
	}

	//get client ip
	ip := req.Header.Get("X-Real-Ip")
	if ip == "" {
		ip = req.Header.Get("X-Forwarded-For")
	}

	if ip == "" {
		//get ip from request without colon and right part
		ip = strings.Split(req.RemoteAddr, ":")[0]
	}

	inCache := findInCache(client.Domain, client.Subdomain)

	if inCache == ip {
		log.Printf("client %v ip %v already in cache", client.Name, ip)
		fmt.Fprintf(w, "ip: %v\n", ip)
		return
	}

	err = deleteAlias(config.Settings, *client)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	err = addAlias(config.Settings, *client, ip)

	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	addToCache(client.Domain, client.Subdomain, ip)

	log.Printf("client %v ip %v added to cache", client.Name, ip)

	fmt.Fprintf(w, "ip: %v\n", ip)

}

func findInCache(domain string, subdomain string) string {
	key := subdomain + "." + domain
	return cache[key]
}

func addToCache(domain string, subdomain string, ip string) {
	key := subdomain + "." + domain
	cache[key] = ip
}

func findClientByToken(config Config, token string) *Client {
	for _, client := range config.Clients {
		if client.Token == token {
			return &client
		}
	}
	return nil
}

func addAlias(settings Settings, client Client, ip string) error {
	log.Printf("client %v witn fqdn %v adding to dns", client.Name, client.Subdomain+"."+client.Domain)
	queryParams := url.Values{}
	queryParams.Set("username", settings.Username)
	queryParams.Set("password", settings.Password)
	queryParams.Set("domain_name", client.Domain)
	queryParams.Set("subdomain", client.Subdomain)
	queryParams.Set("ipaddr", ip)
	query := queryParams.Encode()

	err := sendPostRequest(settings, query, "/api/regru2/zone/add_alias")
	if err != nil {
		return err
	}

	log.Printf("client %v witn fqdn %v ip %v added to dns", client.Name, client.Subdomain+"."+client.Domain, ip)

	return nil
}

func deleteAlias(settings Settings, client Client) error {
	log.Printf("client %v witn fqdn %v deleting from dns", client.Name, client.Subdomain+"."+client.Domain)
	queryParams := url.Values{}
	queryParams.Set("username", settings.Username)
	queryParams.Set("password", settings.Password)
	queryParams.Set("domain_name", client.Domain)
	queryParams.Set("record_type", "A")
	queryParams.Set("subdomain", client.Subdomain)
	query := queryParams.Encode()

	err := sendPostRequest(settings, query, "/api/regru2/zone/remove_record")
	if err != nil {
		return err
	}

	log.Printf("client %v witn fqdn %v deleted from dns", client.Name, client.Subdomain+"."+client.Domain)
	return nil
}

// send post request to api from config.Settings.APIAddr with path /zone/add_alias with query params username, password,
// domain_name, subdomain, ipaddr with client cert and key from config.Settings.Crt and config.Settings.Key
func sendPostRequest(settings Settings, rewQuery string, path string) error {
	// Создание URL-адреса API с путем /zone/add_alias и параметрами запроса
	apiURL, err := url.Parse(settings.APIAddr)
	if err != nil {
		return err
	}
	apiURL.Path = path
	apiURL.RawQuery = rewQuery

	// Загрузка сертификата и ключа клиента
	clientCert, err := tls.LoadX509KeyPair(settings.Crt, settings.Key)
	if err != nil {
		return err
	}

	// Создание клиента HTTP с TLS-конфигурацией
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
	}
	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}
	client := &http.Client{
		Transport: transport,
	}

	// Отправка POST-запроса к API
	resp, err := client.Post(apiURL.String(), "application/x-www-form-urlencoded", strings.NewReader(""))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Проверка статусного кода ответа
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("неправильный статусный код: %d", resp.StatusCode)
	}

	return nil
}

func main() {
	log.Printf("starting noip server")
	cache = make(map[string]string)
	var err error
	config, err = readConfig()
	if err != nil {
		fmt.Println(err)
		return
	}

	http.HandleFunc("/update", handleRequest)

	err = http.ListenAndServe(fmt.Sprintf(":%v", config.Settings.Port), nil)
	if err != nil {
		return
	}
}
