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

type SimpleItem struct {
    ID      string `json:"id"`
    Name    string `json:"name"`
    Comment string `json:"comment,omitempty"`
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
    Comment  string    `json:"comment,omitempty"`
    Gateways []Gateway `json:"gateways,omitempty"`
}

type ValueType struct {
    Value string `json:"value"`
}

type SuFrom struct {
    ID       string `json:"id"`
    Username string `json:"username,omitempty"`
}

type Account struct {
    ID         string      `json:"id,omitempty"`
    Name       string      `json:"name"`
    Comment    string      `json:"comment,omitempty"`
    Privileged bool        `json:"privileged"`
    SecretType ValueType   `json:"secret_type"`
    IsActive   bool        `json:"is_active"`
    Username   string      `json:"username"`
    SuFrom     *SuFrom     `json:"su_from,omitempty"`
    Secret     string      `json:"secret"`
    Asset      SimpleAsset `json:"asset"`
    SourceId   string      `json:"source_id,omitempty"`
    Template   string      `json:"template,omitempty"`
}

type AccountTemplate struct {
    ID             string    `json:"id,omitempty"`
    Name           string    `json:"name"`
    Comment        string    `json:"comment,omitempty"`
    Username       string    `json:"username"`
    AutoPush       bool      `json:"auto_push"`
    Privileged     bool      `json:"privileged"`
    SecretStrategy ValueType `json:"secret_strategy"`
    SecretType     ValueType `json:"secret_type"`
    Secret         string    `json:"secret"`
    SuFrom         *SuFrom   `json:"su_from,omitempty"`
}

type CloudAccount struct {
    ID       string    `json:"id"`
    Name     string    `json:"name"`
    Comment  string    `json:"comment,omitempty"`
    Provider ValueType `json:"provider"`
}

type StrategyActionValue struct {
    ID interface{} `json:"id"`
}

func (v StrategyActionValue) MarshalJSON() ([]byte, error) {
    return json.Marshal(v.ID)
}

type StrategyAction struct {
    Attr      ValueType           `json:"attr"`
    Value     StrategyActionValue `json:"value"`
    Protocols []Protocol          `json:"protocols,omitempty"`
}

type StrategyRule struct {
    Attr  ValueType `json:"attr"`
    Match ValueType `json:"match"`
    Value string    `json:"value"`
}

type CloudStrategy struct {
    ID           string           `json:"id"`
    Name         string           `json:"name"`
    Comment      string           `json:"comment,omitempty"`
    Priority     int              `json:"priority"`
    RuleRelation ValueType        `json:"rule_relation"`
    Actions      []StrategyAction `json:"strategy_actions"`
    Rules        []StrategyRule   `json:"strategy_rules"`
}

type CloudTask struct {
    ID                    string          `json:"id"`
    Name                  string          `json:"name"`
    Comment               string          `json:"comment,omitempty"`
    Account               *CloudAccount   `json:"account,omitempty"`
    FullySynchronous      bool            `json:"fully_synchronous"`
    IsAlwaysUpdate        bool            `json:"is_always_update"`
    IsPeriodic            bool            `json:"is_periodic"`
    ReleaseAssets         bool            `json:"release_assets"`
    HostnameStrategy      ValueType       `json:"hostname_strategy"`
    Interval              int             `json:"interval"`
    SyncIpType            int             `json:"sync_ip_type"`
    Regions               []string        `json:"regions"`
    IpNetworkSegmentGroup []string        `json:"ip_network_segment_group"`
    Strategies            []CloudStrategy `json:"strategy"`
}

func (v CloudTask) MarshalJSON() ([]byte, error) {
    type Alias CloudTask
    var strategies []string
    for _, strategy := range v.Strategies {
        strategies = append(strategies, strategy.ID)
    }
    
    return json.Marshal(&struct {
        Strategies []string `json:"strategy"`
        *Alias
    }{
        Strategies: strategies,
        Alias:      (*Alias)(&v),
    })
}

type CommandGroup struct {
    ID         string    `json:"id"`
    Name       string    `json:"name"`
    Comment    string    `json:"comment,omitempty"`
    Content    string    `json:"content"`
    IgnoreCase bool      `json:"ignore_case"`
    Type       ValueType `json:"type"`
}

type ResourceSelectAttr struct {
    Match string `json:"match"`
    Name  string `json:"name"`
    Value string `json:"value"`
}

type ResourceSelect struct {
    Type  string               `json:"type"`
    Ids   []string             `json:"ids"`
    Attrs []ResourceSelectAttr `json:"attrs,omitempty"`
}

type CommandACL struct {
    ID            string         `json:"id"`
    Name          string         `json:"name"`
    Comment       string         `json:"comment,omitempty"`
    IsActive      bool           `json:"is_active"`
    Priority      int            `json:"priority"`
    Action        ValueType      `json:"action"`
    CommandGroups []CommandGroup `json:"command_groups"`
    Accounts      []string       `json:"accounts"`
    Reviewers     []User         `json:"reviewers"`
    Users         ResourceSelect `json:"users"`
    Assets        ResourceSelect `json:"assets"`
}

type Perm struct {
    ID          string        `json:"id"`
    Name        string        `json:"name"`
    Comment     string        `json:"comment,omitempty"`
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

func (c *JMSClient) GetCommandGroups() []CommandGroup {
    url := "/api/v1/acls/command-groups/"
    result, _ := c.GetWithPage(url)
    var cmdGroups []CommandGroup
    err := json.Unmarshal(result, &cmdGroups)
    if err != nil {
        logger.Errorf("获取命令组失败: %v", err)
        os.Exit(1)
    }
    return cmdGroups
}

func (c *JMSClient) GetCommandFilterACL() []CommandACL {
    url := "/api/v1/acls/command-filter-acls/"
    result, _ := c.GetWithPage(url)
    var cmdACLs []CommandACL
    err := json.Unmarshal(result, &cmdACLs)
    if err != nil {
        logger.Errorf("获取命令过滤失败: %v", err)
        os.Exit(1)
    }
    return cmdACLs
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

func (c *JMSClient) GetCloudAccounts() []CloudAccount {
    url := "/api/v1/xpack/cloud/accounts/"
    result, _ := c.GetWithPage(url)
    var accounts []CloudAccount
    err := json.Unmarshal(result, &accounts)
    if err != nil {
        logger.Errorf("获取云账号失败: %v", err)
        os.Exit(1)
    }
    return accounts
}

func (c *JMSClient) GetCloudStrategies() []CloudStrategy {
    url := "/api/v1/xpack/cloud/strategies/"
    result, _ := c.GetWithPage(url)
    var strategies []CloudStrategy
    err := json.Unmarshal(result, &strategies)
    if err != nil {
        logger.Errorf("获取云同步策略失败: %v", err)
        os.Exit(1)
    }
    return strategies
}

func (c *JMSClient) GetCloudTasks() []CloudTask {
    url := "/api/v1/xpack/cloud/sync-instance-tasks/"
    result, _ := c.GetWithPage(url)
    var tasks []CloudTask
    err := json.Unmarshal(result, &tasks)
    if err != nil {
        logger.Errorf("获取云同步任务失败: %v", err)
        os.Exit(1)
    }
    return tasks
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

func (c *JMSClient) CreateCloudAccount(account CloudAccount) (*CloudAccount, error) {
    url := "/api/v1/xpack/cloud/accounts/"
    var newAccount CloudAccount
    account.ID = uuid.New().String()
    result, err := c.Post(url, account)
    if err != nil {
        return nil, err
    }
    err = json.Unmarshal(result, &newAccount)
    if err != nil {
        return nil, err
    }
    return &newAccount, nil
}

func (c *JMSClient) CreateCloudStrategy(strategy CloudStrategy) (*CloudStrategy, error) {
    url := "/api/v1/xpack/cloud/strategies/"
    var newStrategy CloudStrategy
    strategy.ID = uuid.New().String()
    result, err := c.Post(url, strategy)
    if err != nil {
        return nil, err
    }
    err = json.Unmarshal(result, &newStrategy)
    if err != nil {
        return nil, err
    }
    return &newStrategy, nil
}

func (c *JMSClient) CreateCloudTask(task CloudTask) (*CloudTask, error) {
    url := "/api/v1/xpack/cloud/sync-instance-tasks/"
    var newTask CloudTask
    task.ID = uuid.New().String()
    result, err := c.Post(url, task)
    if err != nil {
        return nil, err
    }
    err = json.Unmarshal(result, &newTask)
    if err != nil {
        return nil, err
    }
    return &newTask, nil
}

func (c *JMSClient) CreateCommandGroup(cmdGroup CommandGroup) (*CommandGroup, error) {
    url := "/api/v1/acls/command-groups/"
    var newCmdGroup CommandGroup
    cmdGroup.ID = uuid.New().String()
    result, err := c.Post(url, cmdGroup)
    if err != nil {
        return nil, err
    }
    err = json.Unmarshal(result, &newCmdGroup)
    if err != nil {
        return nil, err
    }
    return &newCmdGroup, nil
}

func (c *JMSClient) CreateCommandFilterACL(cmdACL CommandACL) (*SimpleItem, error) {
    url := "/api/v1/acls/command-filter-acls/"
    var newCmdACL SimpleItem
    cmdACL.ID = uuid.New().String()
    result, err := c.Post(url, cmdACL)
    if err != nil {
        return nil, err
    }
    err = json.Unmarshal(result, &newCmdACL)
    if err != nil {
        return nil, err
    }
    return &newCmdACL, nil
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
    
    migrateFromUserMapping             map[string]string
    migrateFromUserGroupMapping        map[string]string
    migrateFromAssetMapping            map[string]string
    migrateFromNodeMapping             map[string]string
    migrateFromPermMapping             map[string]string
    migrateFromDomainMapping           map[string]string
    migrateFromAccountTemplateMapping  map[string]string
    migrateFromCloudAccountMapping     map[string]string
    migrateFromCloudStrategyMapping    map[string]string
    migrateFromCloudTaskMapping        map[string]string
    migrateFromCommandGroupMapping     map[string]string
    migrateFromCommandFilterACLMapping map[string]string
    migrateDomainList                  []Domain
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

func (w *Worker) MigrateCommandGroup() {
    logger.Infoln("[迁移命令组]------ 开始 ------")
    w.jmsClient.org = w.migrateToOrg
    var localResourceSet = ResourceSet{}
    for _, cmdGroup := range w.jmsClient.GetCommandGroups() {
        localResourceSet.Add(cmdGroup.Name, cmdGroup.ID)
    }
    w.jmsClient.org = w.migrateFromOrg
    for _, fromCmdGroup := range w.jmsClient.GetCommandGroups() {
        if toCmdGroupId, exists := localResourceSet.Exist(fromCmdGroup.Name); exists {
            w.migrateFromCommandGroupMapping[fromCmdGroup.ID] = toCmdGroupId
            logger.Warnf("[迁移命令组](%s)已经存在，跳过", fromCmdGroup.Name)
            continue
        }
        
        w.jmsClient.org = w.migrateToOrg
        newCmdGroup, err := w.jmsClient.CreateCommandGroup(fromCmdGroup)
        if err != nil {
            logger.Errorf("[迁移命令组]迁移失败: %v", err)
            os.Exit(1)
        }
        w.migrateFromCommandGroupMapping[fromCmdGroup.ID] = newCmdGroup.ID
        logger.Infof("[迁移命令组]迁移(%s)到组织(%s)成功\n", fromCmdGroup.Name, w.migrateToOrg.Name)
    }
    logger.Info("[迁移命令组]------ 结束 ------\n\n")
}

func (w *Worker) ConvertCmdFilterACLResource(cmdACL *CommandACL) {
    var newUserIds, newAssetIds []string
    var newGroups []CommandGroup
    var newReviewers []User
    for _, id := range cmdACL.Users.Ids {
        newUserIds = append(newUserIds, w.migrateFromUserMapping[id])
    }
    for _, id := range cmdACL.Assets.Ids {
        newAssetIds = append(newAssetIds, w.migrateFromAssetMapping[id])
    }
    for _, cmdGroup := range cmdACL.CommandGroups {
        newGroups = append(newGroups, CommandGroup{ID: w.migrateFromCommandGroupMapping[cmdGroup.ID]})
    }
    for _, user := range cmdACL.Reviewers {
        newReviewers = append(newReviewers, User{ID: w.migrateFromUserMapping[user.ID]})
    }
    cmdACL.Users.Ids = newUserIds
    cmdACL.Assets.Ids = newAssetIds
    cmdACL.CommandGroups = newGroups
    cmdACL.Reviewers = newReviewers
}

func (w *Worker) MigrateCommandFilterACL() {
    logger.Infoln("[迁移命令组过滤]------ 开始 ------")
    w.jmsClient.org = w.migrateToOrg
    var localResourceSet = ResourceSet{}
    for _, cmdACL := range w.jmsClient.GetCommandFilterACL() {
        localResourceSet.Add(cmdACL.Name, cmdACL.ID)
    }
    w.jmsClient.org = w.migrateFromOrg
    for _, fromCmdACL := range w.jmsClient.GetCommandFilterACL() {
        if toCmdACLId, exists := localResourceSet.Exist(fromCmdACL.Name); exists {
            w.migrateFromCommandFilterACLMapping[fromCmdACL.ID] = toCmdACLId
            logger.Warnf("[迁移命令组过滤](%s)已经存在，跳过", fromCmdACL.Name)
            continue
        }
        
        w.jmsClient.org = w.migrateToOrg
        w.ConvertCmdFilterACLResource(&fromCmdACL)
        newCmdACL, err := w.jmsClient.CreateCommandFilterACL(fromCmdACL)
        if err != nil {
            logger.Errorf("[迁移命令组过滤]迁移失败: %v", err)
            os.Exit(1)
        }
        w.migrateFromCommandFilterACLMapping[fromCmdACL.ID] = newCmdACL.ID
        logger.Infof("[迁移命令组过滤]迁移(%s)到组织(%s)成功\n", fromCmdACL.Name, w.migrateToOrg.Name)
    }
    logger.Info("[迁移命令组过滤]------ 结束 ------\n\n")
}

func (w *Worker) MigrateCommandFilter() {
    w.MigrateCommandGroup()
    w.MigrateCommandFilterACL()
}

func (w *Worker) MigrateCloudSync() {
    w.MigrateCloudAccount()
    w.MigrateCloudStrategy()
    w.MigrateCloudSyncTask()
}

func (w *Worker) MigrateCloudAccount() {
    logger.Infoln("[迁移云账号]------ 开始 ------")
    w.jmsClient.org = w.migrateToOrg
    var localResourceSet = ResourceSet{}
    for _, account := range w.jmsClient.GetCloudAccounts() {
        localResourceSet.Add(account.Name, account.ID)
    }
    w.jmsClient.org = w.migrateFromOrg
    for _, fromAccount := range w.jmsClient.GetCloudAccounts() {
        if toAccountId, exists := localResourceSet.Exist(fromAccount.Name); exists {
            w.migrateFromCloudAccountMapping[fromAccount.ID] = toAccountId
            logger.Warnf("[迁移云账号](%s)已经存在，跳过", fromAccount.Name)
            continue
        }
        
        w.jmsClient.org = w.migrateToOrg
        newAccount, err := w.jmsClient.CreateCloudAccount(fromAccount)
        if err != nil {
            logger.Errorf("[迁移云账号]迁移失败: %v", err)
            os.Exit(1)
        }
        w.migrateFromCloudAccountMapping[fromAccount.ID] = newAccount.ID
        logger.Infof("[迁移云账号]迁移(%s)到组织(%s)成功\n", fromAccount.Name, w.migrateToOrg.Name)
    }
    logger.Info("[迁移云账号]------ 结束 ------\n\n")
}

func (w *Worker) ConvertStrategyActions(strategy CloudStrategy) {
    var mapping map[string]string
    for i, action := range strategy.Actions {
        switch action.Attr.Value {
        case "account_template":
            mapping = w.migrateFromAccountTemplateMapping
        case "domain":
            mapping = w.migrateFromDomainMapping
        case "node":
            mapping = w.migrateFromNodeMapping
        case "platform":
            continue
        }
        strategy.Actions[i].Value.ID = mapping[action.Value.ID.(string)]
    }
}

func (w *Worker) MigrateCloudStrategy() {
    logger.Infoln("[迁移云同步策略]------ 开始 ------")
    w.jmsClient.org = w.migrateToOrg
    var localResourceSet = ResourceSet{}
    for _, strategy := range w.jmsClient.GetCloudStrategies() {
        localResourceSet.Add(strategy.Name, strategy.ID)
    }
    w.jmsClient.org = w.migrateFromOrg
    for _, fromStrategy := range w.jmsClient.GetCloudStrategies() {
        if toStrategyId, exists := localResourceSet.Exist(fromStrategy.Name); exists {
            w.migrateFromCloudStrategyMapping[fromStrategy.ID] = toStrategyId
            logger.Warnf("[迁移云同步策略](%s)已经存在，跳过", fromStrategy.Name)
            continue
        }
        
        w.jmsClient.org = w.migrateToOrg
        w.ConvertStrategyActions(fromStrategy)
        newStrategy, err := w.jmsClient.CreateCloudStrategy(fromStrategy)
        if err != nil {
            logger.Errorf("[迁移云同步策略]失败: %v", err)
            os.Exit(1)
        }
        w.migrateFromCloudStrategyMapping[fromStrategy.ID] = newStrategy.ID
        logger.Infof("[迁移云同步策略]迁移(%s)到组织(%s)成功\n", fromStrategy.Name, w.migrateToOrg.Name)
    }
    logger.Info("[迁移云同步策略]------ 结束 ------\n\n")
}

func (w *Worker) MigrateCloudSyncTask() {
    logger.Infoln("[迁移云同步任务]------ 开始 ------")
    w.jmsClient.org = w.migrateToOrg
    var localResourceSet = ResourceSet{}
    for _, task := range w.jmsClient.GetCloudTasks() {
        localResourceSet.Add(task.Name, task.ID)
    }
    w.jmsClient.org = w.migrateFromOrg
    for _, fromTask := range w.jmsClient.GetCloudTasks() {
        if toTaskId, exists := localResourceSet.Exist(fromTask.Name); exists {
            w.migrateFromCloudTaskMapping[fromTask.ID] = toTaskId
            logger.Warnf("[迁移云同步任务](%s)已经存在，跳过", fromTask.Name)
            continue
        }
        
        w.jmsClient.org = w.migrateToOrg
        if fromTask.Account != nil {
            if aId, exists := w.migrateFromCloudAccountMapping[fromTask.Account.ID]; exists {
                fromTask.Account.ID = aId
            }
        }
        var convertStrategies []CloudStrategy
        for _, strategy := range fromTask.Strategies {
            convertStrategies = append(convertStrategies, CloudStrategy{
                ID: w.migrateFromCloudStrategyMapping[strategy.ID],
            })
        }
        fromTask.Strategies = convertStrategies
        newTask, err := w.jmsClient.CreateCloudTask(fromTask)
        if err != nil {
            logger.Errorf("[迁移云同步任务]失败: %v", err)
            os.Exit(1)
        }
        w.migrateFromCloudTaskMapping[fromTask.ID] = newTask.ID
        logger.Infof("[迁移云同步任务]迁移(%s)到组织(%s)成功\n", fromTask.Name, w.migrateToOrg.Name)
    }
    logger.Info("[迁移云同步任务]------ 结束 ------\n\n")
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

func (w *Worker) BulkDelete(name, url string, mapping map[string]string) {
    logger.Infof("[清理原组织%s(%v个)]------ 开始 ------\n", name, len(mapping))
    var deleteIDs []string
    for id, _ := range mapping {
        deleteIDs = append(deleteIDs, id)
        if len(deleteIDs) == w.options.PageLimit {
            w.jmsClient.BulkDelete(url, "POST", deleteIDs)
            deleteIDs = []string{}
        }
    }
    if len(deleteIDs) > 0 {
        w.jmsClient.BulkDelete(url, "POST", deleteIDs)
    }
    logger.Infof("[清理原组织%s]------ 结束 ------\n\n", name)
}

func (w *Worker) RemoveUsers() {
    url := "/api/v1/users/users/remove/"
    w.BulkDelete("用户", url, w.migrateFromUserMapping)
}

func (w *Worker) DeleteUserGroups() {
    url := "/api/v1/users/groups/"
    w.BulkDelete("用户组", url, w.migrateFromUserGroupMapping)
}

func (w *Worker) DeleteAssets() {
    url := "/api/v1/assets/assets/"
    w.BulkDelete("资产", url, w.migrateFromAssetMapping)
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
    url := "/api/v1/assets/domains/"
    w.BulkDelete("网域", url, w.migrateFromDomainMapping)
}

func (w *Worker) DeleteCloudSync() {
    w.DeleteCloudAccounts()
    w.DeleteCloudStrategies()
    w.DeleteCloudTasks()
}

func (w *Worker) DeleteCloudAccounts() {
    url := "/api/v1/xpack/cloud/accounts/"
    w.BulkDelete("云账号", url, w.migrateFromCloudAccountMapping)
}

func (w *Worker) DeleteCloudStrategies() {
    url := "/api/v1/xpack/cloud/strategies/"
    w.BulkDelete("云同步策略", url, w.migrateFromCloudStrategyMapping)
}

func (w *Worker) DeleteCloudTasks() {
    url := "/api/v1/xpack/cloud/ync-instance-tasks/"
    w.BulkDelete("云同步任务", url, w.migrateFromCloudTaskMapping)
}

func (w *Worker) DeleteAccountTemplates() {
    url := "/api/v1/accounts/account-templates/"
    w.BulkDelete("账号模板", url, w.migrateFromAccountTemplateMapping)
}

func (w *Worker) DeletePerms() {
    url := "/api/v1/perms/asset-permissions/"
    w.BulkDelete("授权", url, w.migrateFromPermMapping)
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
        w.DeleteCloudSync()
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
    w.MigrateCommandFilter()
    w.MigrateCloudSync()
    w.MigrateDomainPost()
    w.ClearMigrateOrg()
}

func main() {
    worker := Worker{
        migrateFromNodeMapping:             make(map[string]string),
        migrateFromAssetMapping:            make(map[string]string),
        migrateFromUserMapping:             make(map[string]string),
        migrateFromUserGroupMapping:        make(map[string]string),
        migrateFromPermMapping:             make(map[string]string),
        migrateFromDomainMapping:           make(map[string]string),
        migrateFromAccountTemplateMapping:  make(map[string]string),
        migrateFromCloudAccountMapping:     make(map[string]string),
        migrateFromCloudStrategyMapping:    make(map[string]string),
        migrateFromCloudTaskMapping:        make(map[string]string),
        migrateFromCommandGroupMapping:     make(map[string]string),
        migrateFromCommandFilterACLMapping: make(map[string]string),
    }
    worker.Do()
}
