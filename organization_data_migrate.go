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
    
    "github.com/google/uuid"
    "github.com/pquerna/otp/totp"
    "github.com/sirupsen/logrus"
    "gopkg.in/twindagger/httpsig.v1"
)

const (
    DefaultOrgID = "00000000-0000-0000-0000-000000000002"
    OrgUserID    = "00000000-0000-0000-0000-000000000007"
)

var logger *logrus.Logger

func init() {
    logger = logrus.New()
    logger.SetOutput(os.Stdout)
    logger.SetFormatter(&logrus.TextFormatter{
        FullTimestamp: true, TimestampFormat: "2006-01-02 15:04:05",
    })
    logger.SetLevel(logrus.DebugLevel)
}

type ResourceSet struct {
    setPool map[string]string
}

func (r *ResourceSet) Add(name, id string) {
    if r.setPool == nil {
        r.setPool = make(map[string]string)
    }
    r.setPool[strings.ToLower(name)] = id
}

func (r *ResourceSet) Exist(name string) (string, bool) {
    item, exist := r.setPool[strings.ToLower(name)]
    return item, exist
}

type CmdOptions struct {
    JmsServerURL    string
    AccessKeyID     string
    AccessKeySecret string
    OtpSecret       string
    PageLimit       int
    SyncDelete      bool
    
    MigrateFromOrgID string
    MigrateToOrgID   string
}

type JMSConfig struct {
    Endpoint  string
    KeyID     string
    SecretID  string
    OtpSecret string
    Other     Other
}

type Organization struct {
    ID   string `json:"id"`
    Name string `json:"name"`
}

type User struct {
    ID         string      `json:"id"`
    Name       string      `json:"name"`
    Username   string      `json:"username"`
    UserGroups []UserGroup `json:"groups,omitempty"`
}

type UserGroup struct {
    ID      string `json:"id"`
    Name    string `json:"name"`
    Comment string `json:"comment,omitempty"`
}

type Node struct {
    ID        string `json:"id,omitempty"`
    Key       string `json:"key,omitempty"`
    Value     string `json:"value,omitempty"`
    FullValue string `json:"full_value,omitempty"`
    ParentID  string `json:"-"`
}

type Platform struct {
    ID      int    `json:"id"`
    Name    string `json:"name"`
    Comment string `json:"comment,omitempty"`
}

type Protocol struct {
    Name string `json:"name"`
    Port int    `json:"port"`
}

type Action struct {
    Label string `json:"label"`
    Value string `json:"value"`
}

type SimpleAsset struct {
    ID        string     `json:"id"`
    Name      string     `json:"name"`
    Address   string     `json:"address,omitempty"`
    Comment   string     `json:"comment,omitempty"`
    Domain    *Domain    `json:"domain,omitempty"`
    Nodes     []Node     `json:"nodes,omitempty"`
    Accounts  []Account  `json:"accounts,omitempty"`
    Platform  Platform   `json:"platform,omitempty"`
    Protocols []Protocol `json:"protocols,omitempty"`
}

func (sa *SimpleAsset) HandleCreate(category string, w *Worker) {
    sa.HandleNodes(w)
    sa.HandleDomain(w)
    suFromAccounts := sa.HandleAccounts(w)
    oldAssetID := sa.ID
    w.jmsClient.org = w.migrateToOrg
    sa.ID = uuid.New().String()
    // 这里函数参数定义一个函数，这里去调用吧
    newAsset, err := w.jmsClient.CreateAsset(category, sa.Platform.ID, *sa)
    if err != nil {
        fmt.Printf("%v\n", sa.Domain)
        logger.Errorf("[迁移资产]迁移失败: %v", err)
        os.Exit(1)
    }
    var accountMapping = make(map[string]string)
    accounts := w.jmsClient.GetAssetAccount(*newAsset)
    for _, account := range accounts {
        accountMapping[account.Username] = account.ID
    }
    for _, account := range suFromAccounts {
        account.SuFrom.ID = accountMapping[account.SuFrom.Username]
        account.Asset = SimpleAsset{ID: newAsset.ID}
        _, err = w.jmsClient.CreateAccount(account)
        if err != nil {
            logger.Infof("[迁移资产]资产(%s)下的账号(%s)失败", sa.Name, account.Name)
        }
    }
    w.migrateFromAssetMapping[oldAssetID] = newAsset.ID
}

func (sa *SimpleAsset) HandleNodes(w *Worker) {
    var newNodes []Node
    for _, node := range sa.Nodes {
        newNodes = append(newNodes, Node{ID: w.migrateFromNodeMapping[node.ID]})
    }
    sa.Nodes = newNodes
}

func (sa *SimpleAsset) HandleDomain(w *Worker) {
    if sa.Domain != nil && sa.Domain.ID != "" {
        sa.Domain = &Domain{ID: w.migrateFromDomainMapping[sa.Domain.ID]}
    }
}

func (sa *SimpleAsset) HandleAccounts(w *Worker) []Account {
    var newAccounts []Account
    var suFromAccounts []Account
    w.jmsClient.org = w.migrateFromOrg
    for _, account := range w.jmsClient.GetAssetAccount(*sa) {
        if account.SourceId == "" {
            accountWithSecret, err := w.jmsClient.GetAccountSecret(account)
            if err != nil {
                logger.Errorf("[迁移资产]获取账号密码失败: %v", err)
                os.Exit(1)
            }
            account.Secret = accountWithSecret.Secret
            if account.SuFrom == nil {
                account.ID = ""
                newAccounts = append(newAccounts, account)
            } else {
                suFromAccounts = append(suFromAccounts, account)
            }
        } else {
            account.ID = ""
            account.Template = w.migrateFromAccountTemplateMapping[account.SourceId]
            newAccounts = append(newAccounts, account)
        }
    }
    sa.Accounts = newAccounts
    return suFromAccounts
}

type Host struct {
    SimpleAsset
}

type Database struct {
    SimpleAsset
    DBName string `json:"db_name"`
}

func (d *Database) HandleCreate(category string, w *Worker) {
    d.HandleNodes(w)
    d.HandleDomain(w)
    suFromAccounts := d.HandleAccounts(w)
    oldAssetID := d.ID
    w.jmsClient.org = w.migrateToOrg
    d.ID = uuid.New().String()
    // 这里函数参数定义一个函数，这里去调用吧
    newAsset, err := w.jmsClient.CreateAsset(category, d.Platform.ID, *d)
    if err != nil {
        logger.Errorf("[迁移资产]迁移数据库失败: %v", err)
        os.Exit(1)
    }
    var accountMapping = make(map[string]string)
    accounts := w.jmsClient.GetAssetAccount(*newAsset)
    for _, account := range accounts {
        accountMapping[account.Username] = account.ID
    }
    for _, account := range suFromAccounts {
        account.SuFrom.ID = accountMapping[account.SuFrom.Username]
        account.Asset = SimpleAsset{ID: newAsset.ID}
        _, err = w.jmsClient.CreateAccount(account)
        if err != nil {
            logger.Infof("[迁移资产]数据库(%s)下的账号(%s)失败", d.Name, account.Name)
        }
    }
    w.migrateFromAssetMapping[oldAssetID] = newAsset.ID
}

type Device struct {
    SimpleAsset
}

type Cloud struct {
    SimpleAsset
}

type Web struct {
    SimpleAsset
}

type GPT struct {
    SimpleAsset
}

type Custom struct {
    SimpleAsset
}

type Gateway struct {
    Host
}

type Domain struct {
    ID       string    `json:"id"`
    Name     string    `json:"name"`
    Gateways []Gateway `json:"gateways,omitempty"`
    Comment  string    `json:"comment,omitempty"`
}

type SecretType struct {
    Value string `json:"value"`
}

type SecretStrategy struct {
    Value string `json:"value"`
}

type SuFrom struct {
    ID       string `json:"id"`
    Username string `json:"username,omitempty"`
}

type Account struct {
    ID         string      `json:"id,omitempty"`
    Privileged bool        `json:"privileged"`
    SecretType SecretType  `json:"secret_type"`
    IsActive   bool        `json:"is_active"`
    Name       string      `json:"name"`
    Username   string      `json:"username"`
    SuFrom     *SuFrom     `json:"su_from,omitempty"`
    Secret     string      `json:"secret"`
    Asset      SimpleAsset `json:"asset"`
    SourceId   string      `json:"source_id,omitempty"`
    Template   string      `json:"template,omitempty"`
    Comment    string      `json:"comment,omitempty"`
}

type AccountTemplate struct {
    ID             string         `json:"id,omitempty"`
    Name           string         `json:"name"`
    Username       string         `json:"username"`
    AutoPush       bool           `json:"auto_push"`
    Privileged     bool           `json:"privileged"`
    SecretStrategy SecretStrategy `json:"secret_strategy"`
    SecretType     SecretType     `json:"secret_type"`
    Comment        string         `json:"comment,omitempty"`
    Secret         string         `json:"secret"`
    SuFrom         *SuFrom        `json:"su_from,omitempty"`
}

type Perm struct {
    ID          string        `json:"id"`
    Name        string        `json:"name"`
    Users       []User        `json:"users,omitempty"`
    UserGroups  []UserGroup   `json:"user_groups,omitempty"`
    Assets      []SimpleAsset `json:"assets,omitempty"`
    Nodes       []Node        `json:"nodes,omitempty"`
    IsActive    bool          `json:"is_active"`
    DateStart   string        `json:"date_start"`
    DateExpired string        `json:"date_expired"`
    Accounts    []string      `json:"accounts,omitempty"`
    Protocols   []string      `json:"protocols,omitempty"`
    Actions     []Action      `json:"actions"`
    Comment     string        `json:"comment"`
}

func containsArray(strNums []string, item string) bool {
    for _, str := range strNums {
        if str == item {
            return true
        }
    }
    return false
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
        endpoint: config.Endpoint, auth: auth, otpSecret: config.OtpSecret,
        client: &http.Client{}, other: config.Other,
    }
}

type Other struct {
    PageLimit  int
    MFACookies []*http.Cookie
}

type JMSClient struct {
    endpoint  string
    org       Organization
    auth      SigAuth
    otpSecret string
    other     Other
    
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
        return nil, fmt.Errorf(string(body))
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

func (c *JMSClient) Patch(url string, data any) ([]byte, error) {
    byteData, _ := json.Marshal(data)
    request, err := c.NewRequest("PATCH", url, bytes.NewBuffer(byteData))
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

func (c *JMSClient) DeleteOrg(org Organization) error {
    url := fmt.Sprintf("/api/v1/orgs/orgs/%s/", org.ID)
    err := c.Delete(url)
    if err != nil {
        return fmt.Errorf("删除组织失败: %v", err)
    }
    return nil
}

func (c *JMSClient) GetOrganizations() []Organization {
    url := "/api/v1/orgs/orgs/"
    var organizations []Organization
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

func (c *JMSClient) GetUsers() []User {
    url := "/api/v1/users/users/"
    result, _ := c.GetWithPage(url)
    var users []User
    err := json.Unmarshal(result, &users)
    if err != nil {
        logger.Errorf("获取用户失败: %v", err)
        os.Exit(1)
    }
    return users
}

func (c *JMSClient) GetUserGroups() []UserGroup {
    url := "/api/v1/users/groups/"
    result, _ := c.GetWithPage(url)
    var userGroups []UserGroup
    err := json.Unmarshal(result, &userGroups)
    if err != nil {
        logger.Errorf("获取用户组失败: %v", err)
        os.Exit(1)
    }
    return userGroups
}

func (c *JMSClient) GetNodes() []Node {
    url := "/api/v1/assets/nodes/"
    result, _ := c.GetWithPage(url)
    var nodes []Node
    err := json.Unmarshal(result, &nodes)
    if err != nil {
        logger.Errorf("获取节点失败: %v", err)
        os.Exit(1)
    }
    return nodes
}

func (c *JMSClient) GetAssets(category string) []any {
    url := fmt.Sprintf("/api/v1/assets/%s/", category)
    result, err := c.GetWithPage(url)
    if err != nil {
        logger.Errorf("获取资产失败: %v", err)
        os.Exit(1)
    }
    
    var assets []any
    switch category {
    case "hosts":
        var hostAssets []Host
        if err = json.Unmarshal(result, &hostAssets); err == nil {
            for _, asset := range hostAssets {
                assets = append(assets, asset)
            }
        }
    case "devices":
        var deviceAssets []Device
        if err = json.Unmarshal(result, &deviceAssets); err == nil {
            for _, asset := range deviceAssets {
                assets = append(assets, asset)
            }
        }
    case "databases":
        var databaseAssets []Database
        if err = json.Unmarshal(result, &databaseAssets); err == nil {
            for _, asset := range databaseAssets {
                assets = append(assets, asset)
            }
        }
    case "clouds":
        var cloudAssets []Cloud
        if err = json.Unmarshal(result, &cloudAssets); err == nil {
            for _, asset := range cloudAssets {
                assets = append(assets, asset)
            }
        }
    case "webs":
        var webAssets []Web
        if err = json.Unmarshal(result, &webAssets); err == nil {
            for _, asset := range webAssets {
                assets = append(assets, asset)
            }
        }
    case "gpts":
        var gptAssets []GPT
        if err = json.Unmarshal(result, &gptAssets); err == nil {
            for _, asset := range gptAssets {
                assets = append(assets, asset)
            }
        }
    case "customs":
        var customAssets []Custom
        if err = json.Unmarshal(result, &customAssets); err == nil {
            for _, asset := range customAssets {
                assets = append(assets, asset)
            }
        }
    }
    return assets
}

func (c *JMSClient) GetAssetAccount(asset SimpleAsset) []Account {
    url := fmt.Sprintf("/api/v1/accounts/accounts/?asset=%s", asset.ID)
    result, _ := c.Get(url, nil)
    var accounts []Account
    err := json.Unmarshal(result, &accounts)
    if err != nil {
        logger.Errorf("获取资产(%s)账号失败: %v", asset.Name, err)
        os.Exit(1)
    }
    return accounts
}

func (c *JMSClient) GenOTP() (string, error) {
    otp, err := totp.GenerateCode(c.otpSecret, time.Now())
    if err != nil {
        return "", err
    }
    return otp, nil
}

func (c *JMSClient) GetMFACookies() ([]*http.Cookie, error) {
    if c.other.MFACookies != nil {
        return c.other.MFACookies, nil
    }
    url := "/api/v1/authentication/confirm/"
    otp, err := c.GenOTP()
    if err != nil {
        return nil, err
    }
    
    data := map[string]string{
        "confirm_type": "mfa",
        "mfa_type":     "otp",
        "secret_key":   otp,
    }
    byteData, _ := json.Marshal(data)
    request, err := c.NewRequest("POST", url, bytes.NewBuffer(byteData))
    if err != nil {
        return nil, err
    }
    resp, err := c.client.Do(request)
    if err != nil {
        return nil, err
    }
    if resp.StatusCode != http.StatusOK {
        return nil, fmt.Errorf("failed to get MFA cookies: %s", resp.Status)
    }
    c.other.MFACookies = resp.Cookies()
    return c.other.MFACookies, nil
}

func (c *JMSClient) GetAccountSecret(account Account) (*Account, error) {
    url := fmt.Sprintf("/api/v1/accounts/account-secrets/%s/", account.ID)
    var newAccount Account
    cookies, _ := c.GetMFACookies()
    result, err := c.Get(url, cookies)
    if err != nil {
        return nil, err
    }
    err = json.Unmarshal(result, &newAccount)
    if err != nil {
        return nil, err
    }
    return &newAccount, nil
}

func (c *JMSClient) GetPerms() []Perm {
    url := "/api/v1/perms/asset-permissions/?action=default"
    result, _ := c.GetWithPage(url)
    var perms []Perm
    err := json.Unmarshal(result, &perms)
    if err != nil {
        logger.Errorf("获取资产授权失败: %v", err)
        os.Exit(1)
    }
    return perms
}

func (c *JMSClient) GetDomains() []Domain {
    url := "/api/v1/assets/domains/"
    result, _ := c.GetWithPage(url)
    var domains []Domain
    err := json.Unmarshal(result, &domains)
    if err != nil {
        logger.Errorf("获取网域失败: %v", err)
        os.Exit(1)
    }
    return domains
}

func (c *JMSClient) GetAccountTemplates() []AccountTemplate {
    url := "/api/v1/accounts/account-templates/"
    result, _ := c.GetWithPage(url)
    var accountTemplates []AccountTemplate
    err := json.Unmarshal(result, &accountTemplates)
    if err != nil {
        logger.Errorf("获取账号模板失败: %v", err)
        os.Exit(1)
    }
    return accountTemplates
}

func (c *JMSClient) GetAccountTemplateSecret(at AccountTemplate) (*AccountTemplate, error) {
    url := fmt.Sprintf("/api/v1/accounts/account-template-secrets/%s/", at.ID)
    var newAccountTemplate AccountTemplate
    cookies, _ := c.GetMFACookies()
    result, err := c.Get(url, cookies)
    if err != nil {
        return nil, err
    }
    err = json.Unmarshal(result, &newAccountTemplate)
    if err != nil {
        return nil, err
    }
    return &newAccountTemplate, nil
}

func (c *JMSClient) CreateAccountTemplate(at AccountTemplate) (*AccountTemplate, error) {
    url := "/api/v1/accounts/account-templates/"
    var newAccountTemplate AccountTemplate
    at.ID = uuid.New().String()
    result, err := c.Post(url, at)
    if err != nil {
        return nil, err
    }
    err = json.Unmarshal(result, &newAccountTemplate)
    if err != nil {
        return nil, err
    }
    return &newAccountTemplate, nil
}

func (c *JMSClient) CreateUserGroup(userGroup UserGroup) (*UserGroup, error) {
    url := "/api/v1/users/groups/"
    var newUserGroup UserGroup
    userGroup.ID = uuid.New().String()
    result, err := c.Post(url, userGroup)
    if err != nil {
        return nil, err
    }
    err = json.Unmarshal(result, &newUserGroup)
    if err != nil {
        return nil, err
    }
    return &newUserGroup, nil
}

func (c *JMSClient) CreateDomain(domain Domain) (*Domain, error) {
    // 先迁移主体，网关等迁移完资产后再更新网域迁移
    url := "/api/v1/assets/domains/"
    var newDomain Domain
    domain.ID = uuid.New().String()
    domain.Gateways = nil
    result, err := c.Post(url, domain)
    if err != nil {
        return nil, err
    }
    err = json.Unmarshal(result, &newDomain)
    if err != nil {
        return nil, err
    }
    return &newDomain, nil
}

func (c *JMSClient) UpdateDomain(domain Domain) error {
    result, err := c.Patch(fmt.Sprintf("/api/v1/assets/domains/%s/", domain.ID), domain)
    if err != nil {
        return err
    }
    var newDomain Domain
    err = json.Unmarshal(result, &newDomain)
    if err != nil {
        return err
    }
    return nil
}

func (c *JMSClient) CreateAsset(category string, platformID int, asset interface{}) (*SimpleAsset, error) {
    url := "/api/v1/assets/%s/?platform=%v"
    var newAsset SimpleAsset
    result, err := c.Post(fmt.Sprintf(url, category, platformID), asset)
    if err != nil {
        return nil, err
    }
    err = json.Unmarshal(result, &newAsset)
    if err != nil {
        return nil, err
    }
    return &newAsset, nil
}

func (c *JMSClient) CreateAccount(account Account) (*Account, error) {
    url := "/api/v1/accounts/accounts/"
    var newAccount Account
    result, err := c.Post(url, account)
    if err != nil {
        logger.Errorf("迁移账号失败: %v", err)
        os.Exit(1)
    }
    err = json.Unmarshal(result, &newAccount)
    if err != nil {
        return nil, err
    }
    return &newAccount, nil
}

func (c *JMSClient) CreatePerm(perm Perm) {
    url := "/api/v1/perms/asset-permissions/"
    _, err := c.Post(url, perm)
    if err != nil {
        logger.Errorf("[迁移授权]创建授权失败: %v", err)
        os.Exit(1)
    }
}

func (c *JMSClient) UpdateUser(user User) error {
    url := "/api/v1/users/users/%s/"
    data := make(map[string]interface{})
    data["groups"] = user.UserGroups
    _, err := c.Patch(fmt.Sprintf(url, user.ID), user)
    if err != nil {
        return fmt.Errorf("更新用户失败: %v", err)
    }
    return nil
}

func (c *JMSClient) InviteUser(user User) error {
    url := "/api/v1/users/users/invite/"
    data := make(map[string]interface{})
    data["org_roles"] = []string{OrgUserID}
    data["users"] = []string{user.ID}
    _, err := c.Post(url, data)
    if err != nil {
        return fmt.Errorf("邀请用户失败: %v", err)
    }
    return nil
}

func (c *JMSClient) CreateNode(node Node) (*Node, error) {
    var newNode Node
    url := "/api/v1/assets/nodes/"
    data := make(map[string]interface{})
    data["id"] = node.ID
    data["full_value"] = node.FullValue
    result, err := c.Post(url, data)
    if err != nil {
        return nil, err
    }
    err = json.Unmarshal(result, &newNode)
    if err != nil {
        return nil, err
    }
    return &newNode, nil
}

type Worker struct {
    jmsClient      *JMSClient
    options        *CmdOptions
    migrateFromOrg Organization
    migrateToOrg   Organization
    
    migrateFromUserMapping            map[string]string
    migrateFromUserGroupMapping       map[string]string
    migrateFromAssetMapping           map[string]string
    migrateFromNodeMapping            map[string]string
    migrateFromPermMapping            map[string]string
    migrateFromDomainMapping          map[string]string
    migrateFromAccountTemplateMapping map[string]string
    migrateDomainList                 []Domain
}

func (w *Worker) ParseOption() {
    opts := CmdOptions{}
    flag.StringVar(&opts.JmsServerURL, "jms-url", opts.JmsServerURL, "JumpServer 服务地址")
    flag.StringVar(&opts.MigrateFromOrgID, "from-org", DefaultOrgID, "迁出组织 ID")
    flag.StringVar(&opts.MigrateToOrgID, "to-org", "", "迁入组织 ID")
    flag.StringVar(&opts.AccessKeyID, "ak", opts.AccessKeyID, "用户API Key ID")
    flag.StringVar(&opts.AccessKeySecret, "sk", opts.AccessKeySecret, "用户API Key Secret")
    flag.StringVar(&opts.OtpSecret, "otp-secret", opts.AccessKeySecret, "MFA 密钥（数据库表 users_user 的 opt_secret_key 字段）")
    flag.IntVar(&opts.PageLimit, "page-limit", 100, "获取资源时的分页数据量")
    flag.BoolVar(&opts.SyncDelete, "sync-delete", false, "是否同步删除迁出组织资源")
    flag.Parse()
    if opts.JmsServerURL == "" {
        logger.Errorf("JumpServer 服务地址不能为空, -h查看脚本使用方式")
        os.Exit(1)
    }
    if opts.AccessKeyID == "" || opts.AccessKeySecret == "" {
        logger.Errorf("用户认证凭证不能为空, -h查看脚本使用方式")
        os.Exit(1)
    }
    if opts.MigrateToOrgID == "" {
        logger.Errorf("迁入组织 ID 不能为空, -h查看脚本使用方式")
        os.Exit(1)
    }
    if opts.OtpSecret == "" {
        logger.Errorf("OTP 密钥不能为空，否则账号密码无法同步, -h查看脚本使用方式")
        os.Exit(1)
    }
    w.options = &opts
}

func (w *Worker) CheckOrg() {
    config := JMSConfig{
        Endpoint:  w.options.JmsServerURL,
        KeyID:     w.options.AccessKeyID,
        SecretID:  w.options.AccessKeySecret,
        OtpSecret: w.options.OtpSecret,
        Other:     Other{PageLimit: w.options.PageLimit},
    }
    w.jmsClient = NewJMSClient(&config)
    for _, org := range w.jmsClient.GetOrganizations() {
        if org.ID == w.options.MigrateFromOrgID {
            w.migrateFromOrg = org
        }
        if org.ID == w.options.MigrateToOrgID {
            w.migrateToOrg = org
        }
    }
    if w.migrateToOrg.ID == "" {
        logger.Errorf("迁出组织不在本系统中，请检查迁出组织 ID(%s) 后重试", w.options.MigrateToOrgID)
        os.Exit(1)
    }
    if w.migrateFromOrg.ID == "" {
        logger.Errorf("迁入组织不在本系统中，请检查迁出组织 ID(%s) 后重试", w.options.MigrateFromOrgID)
        os.Exit(1)
    }
}

func (w *Worker) Prepare() {
    logger.Infoln("[预检]程序正在检查组织是否合法")
    w.CheckOrg()
}

func (w *Worker) MigrateUserGroup() {
    logger.Infoln("[迁移用户组]------ 开始 ------")
    w.jmsClient.org = w.migrateToOrg
    var localResourceSet = ResourceSet{}
    for _, userGroup := range w.jmsClient.GetUserGroups() {
        localResourceSet.Add(userGroup.Name, userGroup.ID)
    }
    w.jmsClient.org = w.migrateFromOrg
    for _, userGroup := range w.jmsClient.GetUserGroups() {
        if ugId, exists := localResourceSet.Exist(userGroup.Name); exists {
            w.migrateFromUserGroupMapping[userGroup.ID] = ugId
            logger.Warnf("[迁移用户组]用户组(%s)已经存在，跳过\n", userGroup.Name)
            continue
        }
        w.jmsClient.org = w.migrateToOrg
        newUserGroup, err := w.jmsClient.CreateUserGroup(userGroup)
        if err != nil {
            logger.Errorf("迁移用户组失败: %v", err)
            os.Exit(1)
        }
        w.migrateFromUserGroupMapping[userGroup.ID] = newUserGroup.ID
        logger.Infof("[迁移用户组]迁移用户组(%s)到组织(%s)成功\n", userGroup.Name, w.migrateToOrg.Name)
    }
    logger.Infof("[迁移用户组]------ 结束 ------\n\n")
}

func (w *Worker) MigrateUser() {
    logger.Infoln("[迁移用户]------ 开始 ------")
    w.jmsClient.org = w.migrateToOrg
    toUserMapping := map[string]User{}
    for _, user := range w.jmsClient.GetUsers() {
        toUserMapping[user.ID] = user
    }
    w.jmsClient.org = w.migrateFromOrg
    for _, user := range w.jmsClient.GetUsers() {
        w.migrateFromUserMapping[user.ID] = user.ID
        if _, exists := toUserMapping[user.ID]; exists {
            logger.Warnf("[迁移用户]组织(%s)下存在用户(%s), 跳过", w.jmsClient.org.Name, user.Name)
            continue
        }
        w.jmsClient.org = w.migrateToOrg
        err := w.jmsClient.InviteUser(user)
        if err != nil {
            logger.Errorf("迁移用户(%s)时，邀请失败: %v", user.Name, err)
            os.Exit(1)
        }
        var newUserGroups []UserGroup
        for _, ug := range user.UserGroups {
            newUserGroups = append(newUserGroups, UserGroup{ID: w.migrateFromUserGroupMapping[ug.ID]})
        }
        user.UserGroups = newUserGroups
        err = w.jmsClient.UpdateUser(user)
        if err != nil {
            logger.Errorf("迁移用户时(%s)，更新失败: %v", user.Name, err)
            os.Exit(1)
        }
        logger.Infof("[迁移用户]成功邀请用户(%s)到组织(%s)", user.Name, w.jmsClient.org.Name)
    }
    logger.Infof("[迁移用户]------ 结束 ------\n\n")
}

func (w *Worker) MigrateAccountTemplate() {
    logger.Infoln("[迁移账号模板]------ 开始 ------")
    w.jmsClient.org = w.migrateToOrg
    var localResourceSet = ResourceSet{}
    for _, at := range w.jmsClient.GetAccountTemplates() {
        localResourceSet.Add(at.Name, at.ID)
    }
    w.jmsClient.org = w.migrateFromOrg
    var suATs []AccountTemplate
    for _, fromAT := range w.jmsClient.GetAccountTemplates() {
        if toATId, exists := localResourceSet.Exist(fromAT.Name); exists {
            w.migrateFromAccountTemplateMapping[fromAT.ID] = toATId
            logger.Warnf("[迁移账号模板]模板(%s)已经存在，跳过", fromAT.Name)
            continue
        }
        w.jmsClient.org = w.migrateFromOrg
        withSecretAT, err := w.jmsClient.GetAccountTemplateSecret(fromAT)
        if err != nil {
            logger.Errorf("[迁移账号模板]获取账号密码失败: %v", err)
            os.Exit(1)
        }
        fromAT.Secret = withSecretAT.Secret
        
        if fromAT.SuFrom != nil {
            suATs = append(suATs, fromAT)
            continue
        }
        w.jmsClient.org = w.migrateToOrg
        newAT, err := w.jmsClient.CreateAccountTemplate(fromAT)
        if err != nil {
            logger.Errorf("[迁移账号模板]迁移模板失败: %v", err)
            os.Exit(1)
        }
        logger.Infof("[迁移账号模板]迁移模板(%s)到组织(%s)成功\n", fromAT.Name, w.migrateToOrg.Name)
        w.migrateFromAccountTemplateMapping[fromAT.ID] = newAT.ID
    }
    
    w.jmsClient.org = w.migrateToOrg
    for _, at := range suATs {
        at.SuFrom.ID = w.migrateFromAccountTemplateMapping[at.SuFrom.ID]
        newAT, err := w.jmsClient.CreateAccountTemplate(at)
        if err != nil {
            logger.Errorf("[迁移账号模板]迁移模板失败: %v", err)
            os.Exit(1)
        }
        logger.Infof("[迁移账号模板]迁移模板(%s)到组织(%s)成功\n", at.Name, w.migrateToOrg.Name)
        w.migrateFromAccountTemplateMapping[at.ID] = newAT.ID
    }
    logger.Info("[迁移账号模板]------ 结束 ------\n\n")
}

func (w *Worker) MigrateNode() {
    logger.Infoln("[迁移节点] ------ 开始 ------")
    var alreadyExistNode = make(map[int][]string)
    var migrateToNode = make(map[string]Node)
    w.jmsClient.org = w.migrateToOrg
    for _, node := range w.jmsClient.GetNodes() {
        migrateToNode[node.FullValue] = node
        nodePart := strings.Split(node.Key, ":")
        for index, part := range nodePart {
            nodeSet := alreadyExistNode[index]
            if !containsArray(nodeSet, part) {
                alreadyExistNode[index] = append(nodeSet, part)
            }
        }
    }
    
    w.jmsClient.org = w.migrateFromOrg
    for _, node := range w.jmsClient.GetNodes() {
        nodePart := strings.Split(node.Key, ":")
        if len(nodePart) > 1 {
            node.FullValue = strings.Replace(node.FullValue, w.migrateFromOrg.Name, w.migrateToOrg.Name, 1)
        } else {
            node.FullValue = fmt.Sprintf("/%s", w.migrateToOrg.Name)
        }
        if n, exists := migrateToNode[node.FullValue]; exists {
            w.migrateFromNodeMapping[node.ID] = n.ID
            continue
        }
        w.jmsClient.org = w.migrateToOrg
        logger.Infof("[迁移节点]创建节点(%s)到组织(%s)\n", node.FullValue, w.migrateToOrg.Name)
        newNode, err := w.jmsClient.CreateNode(node)
        if err != nil {
            logger.Errorf("迁移节点失败: %v", err)
            os.Exit(1)
        }
        w.migrateFromNodeMapping[node.ID] = newNode.ID
    }
    logger.Infof("[迁移节点]------ 结束 ------\n\n")
}

func (w *Worker) MigrateAsset() {
    assetCategory := []string{
        "hosts", "devices", "databases", "clouds", "webs", "gpts", "customs",
    }
    for _, category := range assetCategory {
        w.MigrateAssetSub(category)
    }
}

func (w *Worker) MigrateAssetSub(category string) {
    logger.Infof("[迁移 %s 类型资产]------ 开始 ------\n", category)
    w.jmsClient.org = w.migrateToOrg
    var localResourceSet = ResourceSet{}
    for _, a := range w.jmsClient.GetAssets(category) {
        switch category {
        case "hosts":
            asset := a.(Host)
            localResourceSet.Add(asset.Name, asset.ID)
        case "devices":
            asset := a.(Device)
            localResourceSet.Add(asset.Name, asset.ID)
        case "databases":
            asset := a.(Database)
            localResourceSet.Add(asset.Name, asset.ID)
        case "clouds":
            asset := a.(Cloud)
            localResourceSet.Add(asset.Name, asset.ID)
        case "webs":
            asset := a.(Web)
            localResourceSet.Add(asset.Name, asset.ID)
        case "gtps":
            asset := a.(GPT)
            localResourceSet.Add(asset.Name, asset.ID)
        case "customs":
            asset := a.(Custom)
            localResourceSet.Add(asset.Name, asset.ID)
        }
    }
    w.jmsClient.org = w.migrateFromOrg
    for _, a := range w.jmsClient.GetAssets(category) {
        switch category {
        case "hosts":
            asset := a.(Host)
            if assetID, exists := localResourceSet.Exist(asset.Name); exists {
                w.migrateFromAssetMapping[asset.ID] = assetID
                logger.Warnf("[迁移资产]主机(%s)已经存在，跳过", asset.Name)
                continue
            }
            asset.HandleCreate(category, w)
            logger.Infof("[迁移资产]主机(%s)到组织(%s)成功\n", asset.Name, w.migrateToOrg.Name)
        case "devices":
            asset := a.(Device)
            if assetID, exists := localResourceSet.Exist(asset.Name); exists {
                w.migrateFromAssetMapping[asset.ID] = assetID
                logger.Warnf("[迁移资产]网络设备(%s)已经存在，跳过", asset.Name)
                continue
            }
            asset.HandleCreate(category, w)
            logger.Infof("[迁移资产]网络设备(%s)到组织(%s)成功\n", asset.Name, w.migrateToOrg.Name)
        case "databases":
            asset := a.(Database)
            if assetID, exists := localResourceSet.Exist(asset.Name); exists {
                w.migrateFromAssetMapping[asset.ID] = assetID
                logger.Warnf("[迁移资产]数据库(%s)已经存在，跳过", asset.Name)
                continue
            }
            asset.HandleCreate(category, w)
            logger.Infof("[迁移资产]数据库(%s)到组织(%s)成功\n", asset.Name, w.migrateToOrg.Name)
        case "clouds":
            asset := a.(Cloud)
            if assetID, exists := localResourceSet.Exist(asset.Name); exists {
                w.migrateFromAssetMapping[asset.ID] = assetID
                logger.Warnf("[迁移资产]云服务(%s)已经存在，跳过", asset.Name)
                continue
            }
            asset.HandleCreate(category, w)
            logger.Infof("[迁移资产]云服务(%s)到组织(%s)成功\n", asset.Name, w.migrateToOrg.Name)
        case "webs":
            asset := a.(Web)
            if assetID, exists := localResourceSet.Exist(asset.Name); exists {
                w.migrateFromAssetMapping[asset.ID] = assetID
                logger.Warnf("[迁移资产]Web(%s)已经存在，跳过", asset.Name)
                continue
            }
            asset.HandleCreate(category, w)
            logger.Infof("[迁移资产]Web(%s)到组织(%s)成功\n", asset.Name, w.migrateToOrg.Name)
        case "gpts":
            asset := a.(GPT)
            if assetID, exists := localResourceSet.Exist(asset.Name); exists {
                w.migrateFromAssetMapping[asset.ID] = assetID
                logger.Warnf("[迁移资产]GPT(%s)已经存在，跳过", asset.Name)
                continue
            }
            asset.HandleCreate(category, w)
            logger.Infof("[迁移资产]GPT(%s)到组织(%s)成功\n", asset.Name, w.migrateToOrg.Name)
        case "customs":
            asset := a.(Custom)
            if assetID, exists := localResourceSet.Exist(asset.Name); exists {
                w.migrateFromAssetMapping[asset.ID] = assetID
                logger.Warnf("[迁移资产]自定义(%s)已经存在，跳过", asset.Name)
                continue
            }
            asset.HandleCreate(category, w)
            logger.Infof("[迁移资产]自定义(%s)到组织(%s)成功\n", asset.Name, w.migrateToOrg.Name)
        }
    }
    logger.Infof("[迁移 %s 资产]------ 结束 ------\n\n", category)
}

func (w *Worker) MigratePerm() {
    logger.Infoln("[迁移授权]------ 开始 ------")
    w.jmsClient.org = w.migrateToOrg
    var localResourceSet = ResourceSet{}
    for _, perm := range w.jmsClient.GetPerms() {
        localResourceSet.Add(perm.Name, perm.ID)
    }
    w.jmsClient.org = w.migrateFromOrg
    for _, perm := range w.jmsClient.GetPerms() {
        w.migrateFromPermMapping[perm.ID] = perm.ID
        if _, exists := localResourceSet.Exist(perm.Name); exists {
            logger.Warnf("[迁移授权]授权(%s)已经存在，跳过", perm.Name)
            continue
        }
        var newNodes []Node
        for _, node := range perm.Nodes {
            newNodes = append(newNodes, Node{ID: w.migrateFromNodeMapping[node.ID]})
        }
        var newAssets []SimpleAsset
        for _, asset := range perm.Assets {
            newAssets = append(newAssets, SimpleAsset{ID: w.migrateFromAssetMapping[asset.ID]})
        }
        var newUserGroups []UserGroup
        for _, ug := range perm.UserGroups {
            newUserGroups = append(newUserGroups, UserGroup{ID: w.migrateFromUserGroupMapping[ug.ID]})
        }
        perm.ID = uuid.New().String()
        perm.Nodes = newNodes
        perm.Assets = newAssets
        perm.UserGroups = newUserGroups
        w.jmsClient.org = w.migrateToOrg
        w.jmsClient.CreatePerm(perm)
        logger.Infof("[迁移授权]迁移授权(%s)到组织(%s)成功\n", perm.Name, w.migrateToOrg.Name)
    }
    logger.Info("[迁移授权]------ 结束 ------\n\n")
}

func (w *Worker) MigrateDomain() {
    logger.Infoln("[迁移网域]------ 开始 ------")
    w.jmsClient.org = w.migrateToOrg
    var localResourceSet = ResourceSet{}
    for _, domain := range w.jmsClient.GetDomains() {
        localResourceSet.Add(domain.Name, domain.ID)
    }
    w.jmsClient.org = w.migrateFromOrg
    for _, fromDomain := range w.jmsClient.GetDomains() {
        if toDomainId, exists := localResourceSet.Exist(fromDomain.Name); exists {
            w.migrateFromDomainMapping[fromDomain.ID] = toDomainId
            logger.Warnf("[迁移授权]网域(%s)已经存在，跳过", fromDomain.Name)
            continue
        }
        
        w.jmsClient.org = w.migrateToOrg
        gateways := fromDomain.Gateways
        newDomain, err := w.jmsClient.CreateDomain(fromDomain)
        if err != nil {
            logger.Errorf("迁移网域失败: %v", err)
            os.Exit(1)
        }
        newDomain.Gateways = gateways
        w.migrateDomainList = append(w.migrateDomainList, *newDomain)
        w.migrateFromDomainMapping[fromDomain.ID] = newDomain.ID
        logger.Infof("[迁移网域]迁移网域(%s)到组织(%s)成功\n", fromDomain.Name, w.migrateToOrg.Name)
    }
    logger.Info("[迁移网域]------ 结束 ------\n\n")
}

func (w *Worker) MigrateDomainPost() {
    logger.Infoln("[迁移网域]------ 开始更新网关 ------")
    for _, domain := range w.migrateDomainList {
        err := w.jmsClient.UpdateDomain(domain)
        if err != nil {
            logger.Errorf("更新网域网关失败: %v", err)
            os.Exit(1)
        }
    }
    logger.Info("[迁移网域]------ 结束更新 ------\n\n")
}

func (w *Worker) RemoveUsers() {
    userCount := len(w.migrateFromUserMapping)
    logger.Infof("[清理原组织用户(%v个)]------ 开始 ------\n", userCount)
    var deleteIDs []string
    url := "/api/v1/users/users/remove/"
    for userID, _ := range w.migrateFromUserMapping {
        deleteIDs = append(deleteIDs, userID)
        if len(deleteIDs) == w.options.PageLimit {
            w.jmsClient.BulkDelete(url, "POST", deleteIDs)
            deleteIDs = []string{}
        }
    }
    if len(deleteIDs) > 0 {
        w.jmsClient.BulkDelete(url, "POST", deleteIDs)
    }
    logger.Info("[清理原组织用户]------ 结束 ------\n\n")
}

func (w *Worker) DeleteUserGroups() {
    userGroupCount := len(w.migrateFromUserGroupMapping)
    logger.Infof("[清理原组织用户组(%v个)]------ 开始 ------\n", userGroupCount)
    var deleteIDs []string
    url := "/api/v1/users/groups/"
    for userGroupID, _ := range w.migrateFromUserGroupMapping {
        deleteIDs = append(deleteIDs, userGroupID)
        if len(deleteIDs) == w.options.PageLimit {
            w.jmsClient.BulkDelete(url, "DELETE", deleteIDs)
            deleteIDs = []string{}
        }
    }
    if len(deleteIDs) > 0 {
        w.jmsClient.BulkDelete(url, "DELETE", deleteIDs)
    }
    logger.Info("[清理原组织用户组]------ 结束 ------\n\n")
}

func (w *Worker) DeleteAssets() {
    assetCount := len(w.migrateFromAssetMapping)
    logger.Infof("[清理原组织资产(%v个)]------ 开始 ------\n", assetCount)
    var deleteIDs []string
    url := "/api/v1/assets/assets/"
    for assetID, _ := range w.migrateFromAssetMapping {
        deleteIDs = append(deleteIDs, assetID)
        if len(deleteIDs) == w.options.PageLimit {
            w.jmsClient.BulkDelete(url, "DELETE", deleteIDs)
            deleteIDs = []string{}
        }
    }
    if len(deleteIDs) > 0 {
        w.jmsClient.BulkDelete(url, "DELETE", deleteIDs)
    }
    logger.Info("[清理原组织资产]------ 结束 ------\n\n")
}

func (w *Worker) DeleteNodes() {
    nodeCount := len(w.migrateFromNodeMapping)
    logger.Infof("[清理原组织资产节点(%v个)]------ 开始 ------\n", nodeCount)
    for nodeID, _ := range w.migrateFromNodeMapping {
        _ = w.jmsClient.Delete(fmt.Sprintf("/api/v1/assets/nodes/%s/", nodeID))
    }
    logger.Info("[清理原组织资产节点]------ 结束 ------\n\n")
}

func (w *Worker) DeleteDomains() {
    domainCount := len(w.migrateFromDomainMapping)
    logger.Infof("[清理原组织网域(%v个)]------ 开始 ------\n", domainCount)
    var deleteIDs []string
    url := "/api/v1/assets/domains/"
    for domainID, _ := range w.migrateFromDomainMapping {
        deleteIDs = append(deleteIDs, domainID)
        if len(deleteIDs) == w.options.PageLimit {
            w.jmsClient.BulkDelete(url, "DELETE", deleteIDs)
            deleteIDs = []string{}
        }
    }
    if len(deleteIDs) > 0 {
        w.jmsClient.BulkDelete(url, "DELETE", deleteIDs)
    }
    logger.Info("[清理原组织网域]------ 结束 ------\n\n")
}

func (w *Worker) DeleteAccountTemplates() {
    accountTemplateCount := len(w.migrateFromAccountTemplateMapping)
    logger.Infof("[清理原组织账号模板(%v个)]------ 开始 ------\n", accountTemplateCount)
    var deleteIDs []string
    url := "/api/v1/accounts/account-templates/"
    for accountTemplateID, _ := range w.migrateFromAccountTemplateMapping {
        deleteIDs = append(deleteIDs, accountTemplateID)
        if len(deleteIDs) == w.options.PageLimit {
            w.jmsClient.BulkDelete(url, "DELETE", deleteIDs)
            deleteIDs = []string{}
        }
    }
    if len(deleteIDs) > 0 {
        w.jmsClient.BulkDelete(url, "DELETE", deleteIDs)
    }
    logger.Info("[清理原组织账号模板]------ 结束 ------\n\n")
}

func (w *Worker) DeletePerms() {
    permCount := len(w.migrateFromPermMapping)
    logger.Infof("[清理原组织授权(%v个)]------ 开始 ------\n", permCount)
    var deleteIDs []string
    url := "/api/v1/perms/asset-permissions/"
    for permID, _ := range w.migrateFromPermMapping {
        deleteIDs = append(deleteIDs, permID)
        if len(deleteIDs) == w.options.PageLimit {
            w.jmsClient.BulkDelete(url, "DELETE", deleteIDs)
            deleteIDs = []string{}
        }
    }
    if len(deleteIDs) > 0 {
        w.jmsClient.BulkDelete(url, "DELETE", deleteIDs)
    }
    logger.Info("[清理原组织授权]------ 结束 ------\n\n")
}

func (w *Worker) DeleteOrg() {
    logger.Infof("[清理原组织(%s)]------ 开始 ------\n", w.migrateFromOrg.Name)
    w.jmsClient.org = w.migrateToOrg
    err := w.jmsClient.DeleteOrg(w.migrateFromOrg)
    if err != nil {
        logger.Errorln(err)
        os.Exit(1)
    }
    logger.Info("[清理原组织]------ 结束 ------\n\n")
}

func (w *Worker) ClearMigrateOrg() {
    if w.options.SyncDelete {
        w.jmsClient.org = w.migrateFromOrg
        logger.Info("[清理原组织资源]------ 开始 ------")
        w.RemoveUsers()
        w.DeleteUserGroups()
        w.DeleteAssets()
        w.DeleteAccountTemplates()
        w.DeleteDomains()
        w.DeleteNodes()
        w.DeletePerms()
        w.DeleteOrg()
        logger.Info("[清理原组织资源------ 结束 ------\n\n")
    }
}

func (w *Worker) Do() {
    w.ParseOption()
    w.Prepare()
    w.MigrateUserGroup()
    w.MigrateUser()
    w.MigrateAccountTemplate()
    w.MigrateNode()
    w.MigrateDomain()
    w.MigrateAsset()
    w.MigratePerm()
    w.MigrateDomainPost()
    w.ClearMigrateOrg()
}

func main() {
    worker := Worker{
        migrateFromNodeMapping:            make(map[string]string),
        migrateFromAssetMapping:           make(map[string]string),
        migrateFromUserMapping:            make(map[string]string),
        migrateFromUserGroupMapping:       make(map[string]string),
        migrateFromPermMapping:            make(map[string]string),
        migrateFromDomainMapping:          make(map[string]string),
        migrateFromAccountTemplateMapping: make(map[string]string),
    }
    worker.Do()
}
