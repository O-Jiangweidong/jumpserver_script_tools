// Golang 示例
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"gopkg.in/twindagger/httpsig.v1"
)

const (
	DefaultOrgId = "00000000-0000-0000-0000-000000000002"
	LDAPTaskName = "settings.tasks.ldap.import_ldap_user"
)

type CmdOptions struct {
	JmsServerURL    string
	AccessKeyID     string
	AccessKeySecret string
	OrgID           string
}

type TaskInfo struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type TaskExecution struct {
	ID string `json:"id"`
}

type SigAuth struct {
	KeyID    string
	SecretID string
}

type JumpServerClient struct {
	endpoint string
	orgID    string
	auth     SigAuth

	client *http.Client
}

func (c *JumpServerClient) NewRequest(method, url string, body io.Reader) (*http.Request, error) {
	request, err := http.NewRequest(method, c.endpoint+url, body)
	if err != nil {
		return nil, err
	}

	gmtFmt := "Mon, 02 Jan 2006 15:04:05 GMT"
	request.Header.Add("Date", time.Now().Format(gmtFmt))
	request.Header.Add("Accept", "application/json")
	request.Header.Add("X-JMS-ORG", c.orgID)
	request.Header.Add("Content-Type", "application/json")
	if err = c.auth.Sign(request); err != nil {
		return nil, err
	}
	return request, nil
}

func (c *JumpServerClient) Get(url string) ([]byte, error) {
	request, err := c.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.client.Do(request)
	if err != nil {
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)

	body, _ := io.ReadAll(resp.Body)
	return body, nil
}

func (c *JumpServerClient) Post(url string, data map[string]interface{}) ([]byte, error) {
	byteData, _ := json.Marshal(data)
	request, err := c.NewRequest("POST", url, bytes.NewBuffer(byteData))
	if err != nil {
		return nil, err
	}
	resp, err := c.client.Do(request)
	if err != nil {
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return body, fmt.Errorf("请求错误")
	}
	return body, nil
}

func GetJumpServerClient(opts CmdOptions) *JumpServerClient {
	auth := SigAuth{
		KeyID: opts.AccessKeyID, SecretID: opts.AccessKeySecret,
	}
	return &JumpServerClient{
		auth: auth, endpoint: opts.JmsServerURL, orgID: opts.OrgID, client: &http.Client{},
	}
}

func (auth *SigAuth) Sign(r *http.Request) error {
	headers := []string{"(request-target)", "date"}
	signer, err := httpsig.NewRequestSigner(auth.KeyID, auth.SecretID, "hmac-sha256")
	if err != nil {
		return err
	}
	return signer.SignRequest(r, headers, nil)
}

func (c *JumpServerClient) GetTaskID() (string, error) {
	var ldapTaskID string
	respData, err := c.Get("/api/v1/ops/tasks/?search=settings.tasks.ldap.import_ldap_user")
	if err != nil {
		return ldapTaskID, fmt.Errorf("[错误] %v", err)
	}
	var taskInfo []TaskInfo
	err = json.Unmarshal(respData, &taskInfo)
	if err != nil {
		return ldapTaskID, fmt.Errorf("[错误] 获取 LDAP 任务信息失败 %v", string(respData))
	}
	for _, task := range taskInfo {
		if task.Name == LDAPTaskName {
			ldapTaskID = task.ID
			break
		}
	}
	if ldapTaskID == "" {
		return ldapTaskID, fmt.Errorf("[错误] 未找到 LDAP 任务 ID")
	}
	return ldapTaskID, nil
}

func (c *JumpServerClient) GetTaskHistory(taskID string) ([]TaskExecution, error) {
	respData, err := c.Get(fmt.Sprintf("/api/v1/ops/task-executions/?task_id=%s", taskID))
	if err != nil {
		return nil, fmt.Errorf("[错误] %v", err)
	}
	var taskExecutions []TaskExecution
	err = json.Unmarshal(respData, &taskExecutions)
	if err != nil {
		return nil, fmt.Errorf("[错误] 获取 LDAP 任务历史信息失败: %v", string(respData))
	}
	if len(taskExecutions) < 1 {
		return nil, fmt.Errorf("[错误] 未获取 LDAP 任务历史信息 %v", string(respData))
	}
	return taskExecutions, nil
}

func (c *JumpServerClient) DoTask(executionId string) (string, error) {
	url := fmt.Sprintf("/api/v1/ops/task-executions/?from=%s", executionId)
	respData, err := c.Post(url, nil)
	if err != nil {
		return "", fmt.Errorf("[错误] %s: %v", err, string(respData))
	}
	var task TaskExecution
	err = json.Unmarshal(respData, &task)
	if err != nil {
		return "", fmt.Errorf("[错误] 获取执行任务的 ID 失败: %v", string(respData))
	}
	return task.ID, nil
}

func (c *JumpServerClient) StartLDAPTask() {
	log.Printf("[信息] 开始执行 LDAP 用户导入任务")
	log.Printf("[信息] 开始获取 LDAP 任务信息")
	ldapTaskID, err := c.GetTaskID()
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("[信息] 找到 LDAP 任务 ID: %s", ldapTaskID)
	log.Printf("[信息] 开始获取 LDAP 任务历史列表")
	taskExecutions, err := c.GetTaskHistory(ldapTaskID)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("[信息] 获取 LDAP 任务历史列表成功")
	log.Printf("[信息] 开始执行 LDAP 任务")
	_, err = c.DoTask(taskExecutions[0].ID)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("[信息] 执行 LDAP 任务成功")
}

func main() {
	opts := CmdOptions{}
	flag.StringVar(&opts.JmsServerURL, "jms_url", opts.JmsServerURL, "JumpServer服务地址")
	flag.StringVar(&opts.OrgID, "jms_org_id", DefaultOrgId, "JumpServer组织ID")
	flag.StringVar(&opts.AccessKeyID, "ak", opts.AccessKeyID, "用户API Key ID")
	flag.StringVar(&opts.AccessKeySecret, "sk", opts.AccessKeySecret, "用户API Key Secret")
	// 解析命令行标志
	flag.Parse()

	if opts.JmsServerURL == "" || opts.AccessKeyID == "" || opts.AccessKeySecret == "" {
		fmt.Println("[错误] 参数不能为空")
		flag.Usage()
		os.Exit(1)
	}

	client := GetJumpServerClient(opts)
	client.StartLDAPTask()
}
