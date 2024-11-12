package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	osUrl "net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"gopkg.in/twindagger/httpsig.v1"
)

const DefaultOrgID = "00000000-0000-0000-0000-000000000002"

var logger *logrus.Logger

func init() {
	logger = logrus.New()
	logger.SetOutput(os.Stdout)
	logger.SetFormatter(&logrus.TextFormatter{
		FullTimestamp: true, TimestampFormat: "2006-01-02 15:04:05",
	})
	logger.SetLevel(logrus.DebugLevel)
}

type CmdOptions struct {
	JmsServerURL    string
	AccessKeyID     string
	AccessKeySecret string
	ExcludeOrgIDs   string
	PageLimit       int
}

type JMSConfig struct {
	Endpoint string
	KeyID    string
	SecretID string
	Other    Other
}

type Resource struct {
	ID       string `json:"id"`
	Name     string `json:"name,omitempty"`
	Internal bool   `json:"internal,omitempty"`
}

type NodeMetaData struct {
	ID string `json:"id"`
}

type NodeMeta struct {
	Data NodeMetaData `json:"data"`
}

type Node struct {
	ID   string   `json:"id"`
	Meta NodeMeta `json:"meta"`
}

type ApiResponse struct {
	Count    int    `json:"count"`
	Next     string `json:"next"`
	Previous string `json:"previous"`
	Results  []any  `json:"results"`
}

type SpmResult struct {
	Spm string `json:"spm"`
}

type SigAuth struct {
	KeyID    string
	SecretID string
}

func (auth *SigAuth) Sign(r *http.Request) error {
	headers := []string{"(request-target)", "date"}
	signer, err := httpsig.NewRequestSigner(auth.KeyID, auth.SecretID, "hmac-sha256")
	if err != nil {
		return err
	}
	return signer.SignRequest(r, headers, nil)
}

func NewJMSClient(config *JMSConfig) *JMSClient {
	auth := SigAuth{KeyID: config.KeyID, SecretID: config.SecretID}
	return &JMSClient{
		endpoint: config.Endpoint, auth: auth,
		client: &http.Client{}, other: config.Other,
	}
}

type Other struct {
	PageLimit int
}

type JMSClient struct {
	endpoint string
	org      Resource
	auth     SigAuth
	other    Other

	client *http.Client
}

func (c *JMSClient) sign(r *http.Request) error {
	headers := []string{"(request-target)", "date"}
	signer, err := httpsig.NewRequestSigner(c.auth.KeyID, c.auth.SecretID, "hmac-sha256")
	if err != nil {
		return err
	}
	return signer.SignRequest(r, headers, nil)
}

func (c *JMSClient) NewRequest(method, url string, body io.Reader) (*http.Request, error) {
	request, err := http.NewRequest(method, c.endpoint+url, body)
	if err != nil {
		return nil, err
	}

	gmtFmt := "Mon, 02 Jan 2006 15:04:05 GMT"
	request.Header.Add("Date", time.Now().Format(gmtFmt))
	request.Header.Add("Accept", "application/json")
	request.Header.Add("X-JMS-ORG", c.org.ID)
	request.Header.Add("Content-Type", "application/json")
	if err = c.auth.Sign(request); err != nil {
		return nil, err
	}
	return request, nil
}

func (c *JMSClient) GetWithPage(url string) ([]byte, error) {
	offset, limit, total := 0, c.other.PageLimit, 0
	u, _ := osUrl.Parse(url)
	query := u.Query()
	query.Set("limit", strconv.Itoa(limit))
	var results []any
	for {
		query.Set("offset", strconv.Itoa(offset))
		u.RawQuery = query.Encode()
		resp, err := c.Get(u.String(), nil)
		if err != nil {
			return nil, err
		}
		var apiResponse ApiResponse
		if err = json.Unmarshal(resp, &apiResponse); err != nil {
			return nil, err
		} else {
			results = append(results, apiResponse.Results...)
			offset += limit
			total = apiResponse.Count
			if offset > total {
				break
			}
		}
	}
	ret, err := json.Marshal(results)
	if err != nil {
		return nil, err
	}
	return ret, nil
}

func (c *JMSClient) GetBody(request *http.Request) ([]byte, error) {
	resp, err := c.client.Do(request)
	if err != nil {
		return nil, err
	}
	body, _ := io.ReadAll(resp.Body)
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf(resp.Status + string(body))
	}
	return body, nil
}

func (c *JMSClient) Get(url string, cookies []*http.Cookie) ([]byte, error) {
	request, err := c.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	return c.GetBody(request)
}

func (c *JMSClient) Post(url string, data any) ([]byte, error) {
	byteData, _ := json.Marshal(data)
	request, err := c.NewRequest("POST", url, bytes.NewBuffer(byteData))
	if err != nil {
		return nil, err
	}
	return c.GetBody(request)
}

func (c *JMSClient) Delete(url string) error {
	request, err := c.NewRequest("DELETE", url, nil)
	if err != nil {
		return err
	}
	_, err = c.GetBody(request)
	return err
}

func (c *JMSClient) BulkDelete(url, method string, ids []string) {
	data := make(map[string][]string)
	data["resources"] = ids
	result, err := c.Post("/api/v1/common/resources/cache/", data)
	if err != nil {
		logger.Warnf("批量删除部分数据失败，请页面手动删除，错误: %v\n", err)
	}
	var spmResult SpmResult
	if err = json.Unmarshal(result, &spmResult); err != nil {
		logger.Warnf("批量删除部分数据失败，请页面手动删除，错误: %v\n", err)
	}
	u, _ := osUrl.Parse(url)
	query := u.Query()
	query.Set("spm", spmResult.Spm)
	u.RawQuery = query.Encode()
	if method == "POST" {
		_, err = c.Post(u.String(), nil)
	} else {
		err = c.Delete(u.String())
	}
	if err != nil {
		logger.Warnf("批量删除部分数据失败，请页面手动删除，错误: %v\n", err)
	}
}

func (c *JMSClient) DeleteOrg(org Resource) error {
	url := fmt.Sprintf("/api/v1/orgs/orgs/%s/", org.ID)
	err := c.Delete(url)
	if err != nil {
		return fmt.Errorf("删除组织失败: %v", err)
	}
	return nil
}

func (c *JMSClient) GetOrganizations() []Resource {
	url := "/api/v1/orgs/orgs/"
	var organizations []Resource
	result, err := c.GetWithPage(url)
	if err != nil {
		logger.Errorln(err)
		os.Exit(1)
	}
	err = json.Unmarshal(result, &organizations)
	if err != nil {
		logger.Errorf("获取组织失败: %v", err)
		os.Exit(1)
	}
	return organizations
}

func (c *JMSClient) GetUsers() []Resource {
	url := "/api/v1/users/users/"
	result, _ := c.GetWithPage(url)
	var users []Resource
	err := json.Unmarshal(result, &users)
	if err != nil {
		logger.Errorf("获取用户失败: %v", err)
		os.Exit(1)
	}
	return users
}

func (c *JMSClient) GetResource(r ResourceItem) []Resource {
	result, _ := c.GetWithPage(r.GetUrl())
	var resources []Resource
	err := json.Unmarshal(result, &resources)
	if err != nil {
		logger.Errorf("获取 %s 失败: %v", r.GetType(), err)
		os.Exit(1)
	}
	return resources
}

func (c *JMSClient) GetNodes() []Node {
	url := "/api/v1/assets/nodes/children/tree/?assets=0"
	result, _ := c.Get(url, nil)
	var nodes []Node
	err := json.Unmarshal(result, &nodes)
	if err != nil {
		logger.Errorf("获取节点失败: %v", err)
		os.Exit(1)
	}
	return nodes
}

type Worker struct {
	jmsClient *JMSClient
	options   *CmdOptions

	allOrgs        []Resource
	needDeleteOrgs []Resource
	otherOrg       Resource
}

func (w *Worker) ParseOption() {
	opts := CmdOptions{}
	flag.StringVar(&opts.JmsServerURL, "jms-url", opts.JmsServerURL, "JumpServer 服务地址")
	flag.StringVar(&opts.AccessKeyID, "ak", opts.AccessKeyID, "用户API Key ID")
	flag.StringVar(&opts.AccessKeySecret, "sk", opts.AccessKeySecret, "用户API Key Secret")
	flag.StringVar(&opts.ExcludeOrgIDs, "exclude-org-ids", opts.ExcludeOrgIDs, "保留的组织 ID，多个用逗号隔开")
	flag.IntVar(&opts.PageLimit, "page-limit", 100, "获取资源时的分页数据量")
	flag.Parse()
	if opts.JmsServerURL == "" {
		logger.Errorf("JumpServer 服务地址不能为空")
		os.Exit(1)
	}
	if opts.AccessKeyID == "" || opts.AccessKeySecret == "" {
		logger.Errorf("用户认证凭证不能为空")
		os.Exit(1)
	}
	w.options = &opts
}

func (w *Worker) GetOrgs() {
	logger.Infoln("正在获取组织数据中")
	orgs := w.jmsClient.GetOrganizations()
	for _, org := range orgs {
		if !org.Internal {
			w.allOrgs = append(w.allOrgs, org)
		}
	}
	if w.options.ExcludeOrgIDs != "" {
		excludeOrgIDs := strings.Split(w.options.ExcludeOrgIDs, ",")
		excludeOrgMap := make(map[string]string)
		for _, orgID := range excludeOrgIDs {
			excludeOrgMap[orgID] = orgID
		}
		for _, org := range w.allOrgs {
			if _, found := excludeOrgMap[org.ID]; !found {
				w.needDeleteOrgs = append(w.needDeleteOrgs, org)
			}
		}
	} else {
		for {
			fmt.Println("请需要删除的组织序号，多个组织之间用逗号隔开：")
			for i, item := range w.allOrgs {
				fmt.Printf("%d. %s\n", i+1, item.Name)
			}
			fmt.Print("0. 退出\n请输入: ")
			var choices string
			_, err := fmt.Scan(&choices)
			if err != nil {
				fmt.Println("输入无效，请重新选择。")
				continue
			}
			if choices == "0" {
				logger.Infoln("退出程序")
				os.Exit(0)
			}
			needDeleteNum := strings.Split(choices, ",")
			for _, num := range needDeleteNum {
				if index, err := strconv.Atoi(num); err == nil && index <= len(w.allOrgs) {
					w.needDeleteOrgs = append(w.needDeleteOrgs, w.allOrgs[index-1])
				}
			}
			break
		}
	}
	if len(w.needDeleteOrgs) == 0 {
		logger.Errorln("未选择有效的组织，请重新执行脚本")
		os.Exit(1)
	}
	var names []string
	for _, item := range w.needDeleteOrgs {
		names = append(names, item.Name)
	}
	fmt.Printf("需要删除的组织有: %s, ", strings.Join(names, ", "))
	fmt.Print("回复 Y/y 继续\n请输入: ")
	var answer string
	_, err := fmt.Scan(&answer)
	if err != nil {
		fmt.Println("输入无效，请重新选择。")
	}
	if !(answer == "y" || answer == "Y") {
		logger.Infoln("退出程序")
		os.Exit(0)
	}
}

func (w *Worker) Prepare() {
	logger.Infoln("程序预检中")
	config := JMSConfig{
		Endpoint: w.options.JmsServerURL,
		KeyID:    w.options.AccessKeyID,
		SecretID: w.options.AccessKeySecret,
		Other:    Other{PageLimit: w.options.PageLimit},
	}
	w.jmsClient = NewJMSClient(&config)
	w.GetOrgs()
}

func (w *Worker) RemoveUsers() {
	users := w.jmsClient.GetUsers()
	logger.Infof("[清理组织 %s 下用户，共 %v 个]------ 开始 ------\n", w.jmsClient.org.Name, len(users))
	var deleteIDs []string
	url := "/api/v1/users/users/remove/"
	for _, user := range users {
		deleteIDs = append(deleteIDs, user.ID)
		if len(deleteIDs) == w.options.PageLimit {
			w.jmsClient.BulkDelete(url, "POST", deleteIDs)
			deleteIDs = []string{}
		}
	}
	if len(deleteIDs) > 0 {
		w.jmsClient.BulkDelete(url, "POST", deleteIDs)
	}
	logger.Infof("[清理组织 %s 用户]------ 结束 ------\n\n", w.jmsClient.org.Name)
}

type ResourceItem interface {
	GetUrl() string
	GetType() string
}

type UserGroup struct {
}

func (ug *UserGroup) GetUrl() string {
	return "/api/v1/users/groups/"
}

func (ug *UserGroup) GetType() string {
	return "用户组"
}

type Asset struct {
}

func (a *Asset) GetUrl() string {
	return "/api/v1/assets/assets/"
}

func (a *Asset) GetType() string {
	return "资产"
}

type Domain struct {
}

func (d *Domain) GetUrl() string {
	return "/api/v1/assets/domains/"
}

func (d *Domain) GetType() string {
	return "网域"
}

type Perm struct {
}

func (p *Perm) GetUrl() string {
	return "/api/v1/perms/asset-permissions/"
}

func (p *Perm) GetType() string {
	return "资产授权"
}

type Label struct {
}

func (l *Label) GetUrl() string {
	return "/api/v1/labels/labels/"
}

func (l *Label) GetType() string {
	return "标签"
}

func (w *Worker) DeleteNodes() {
	var needDeleteNodes []Node
	for _, node := range w.jmsClient.GetNodes() {
		if strings.Contains(node.ID, ":") {
			needDeleteNodes = append(needDeleteNodes, node)
		}
	}
	logger.Infof("[清理组织 %s 下的节点，共 %v 个]------ 开始 ------\n", w.jmsClient.org.Name, len(needDeleteNodes))
	for _, node := range needDeleteNodes {
		_ = w.jmsClient.Delete(fmt.Sprintf("/api/v1/assets/nodes/%s/", node.Meta.Data.ID))
	}
	logger.Infof("[清理组织 %s 下的节点]------ 结束 ------\n\n", w.jmsClient.org.Name)
}

func (w *Worker) DeleteOrg(org Resource) {
	logger.Infof("[删除组织 %s]------ 开始 ------\n", org.Name)
	err := w.jmsClient.DeleteOrg(org)
	if err != nil {
		logger.Errorln(err)
		os.Exit(1)
	}
	logger.Infof("[删除组织 %s]------ 结束 ------\n\n", org.Name)
}

func (w *Worker) Do() {
	w.ParseOption()
	w.Prepare()
	for _, org := range w.needDeleteOrgs {
		w.jmsClient.org = org
		w.RemoveUsers()

		resourceItems := []ResourceItem{
			&UserGroup{}, &Asset{}, &Domain{}, &Perm{}, &Label{},
		}
		for _, r := range resourceItems {
			resources := w.jmsClient.GetResource(r)
			logger.Infof("[清理组织 %s 下的%s，共 %v 个]------ 开始 ------\n", w.jmsClient.org.Name, r.GetType(), len(resources))
			var deleteIDs []string
			for _, resource := range resources {
				deleteIDs = append(deleteIDs, resource.ID)
				if len(deleteIDs) == w.options.PageLimit {
					w.jmsClient.BulkDelete(r.GetUrl(), "DELETE", deleteIDs)
					deleteIDs = []string{}
				}
			}
			if len(deleteIDs) > 0 {
				w.jmsClient.BulkDelete(r.GetUrl(), "DELETE", deleteIDs)
			}
			logger.Infof("[清理组织 %s 下的%s]------ 结束 ------\n\n", w.jmsClient.org.Name, r.GetType())
		}
		w.DeleteNodes()
		w.jmsClient.org = Resource{ID: DefaultOrgID, Name: "Default"}
		w.DeleteOrg(org)
	}
	logger.Infoln("脚本执行成功")
}

func main() {
	worker := Worker{}
	worker.Do()
}
