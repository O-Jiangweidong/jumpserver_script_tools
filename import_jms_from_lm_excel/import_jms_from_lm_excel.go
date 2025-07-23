package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	urlParse "net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/spf13/viper"
	"github.com/xuri/excelize/v2"
)

const (
	GlobalOrgID  = "00000000-0000-0000-0000-000000000000"
	DefaultOrgID = "00000000-0000-0000-0000-000000000002"
	SystemUser   = "00000000-0000-0000-0000-000000000003"
	OrgUser      = "00000000-0000-0000-0000-000000000007"
	AllDay       = "00:00~00:00"

	C_Asset     = "资产"
	C_Account   = "账号"
	C_User      = "用户"
	C_UserGroup = "用户组"
	C_Node      = "节点"
	C_Perm      = "授权"
)

func readExcelFile(filePath string, headerRowNum, sheetIndex int) ([][]string, error) {
	f, err := excelize.OpenFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("打开Excel失败：%w", err)
	}
	defer f.Close()

	sheetName := f.GetSheetName(sheetIndex)
	rows, err := f.GetRows(sheetName)
	if err != nil {
		return nil, fmt.Errorf("读取工作表失败：%w", err)
	}

	if len(rows) <= headerRowNum {
		return nil, fmt.Errorf("excel 文件[%s]无有效数据（至少需要表头+1行数据）", filePath)
	}
	return rows, nil
}

type JumpServer struct {
	endpoint     string
	privateToken string
	headers      map[string]string
	client       *http.Client
}

func (jms *JumpServer) getHeaders() map[string]string {
	jms.headers["Content-Type"] = "application/json"
	jms.headers["Authorization"] = "Token " + jms.privateToken
	return jms.headers
}

func (jms *JumpServer) doRequest(method, url string, body interface{}) (*http.Response, error) {
	parsedUrl, err := urlParse.Parse(url)
	if err != nil {
		return nil, err
	}
	url = jms.endpoint + parsedUrl.Path + "?" + parsedUrl.RawQuery

	var reqBody []byte
	if body != nil {
		reqBody, err = json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("序列化请求体失败：%w", err)
		}
	}

	req, err := http.NewRequest(method, url, bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, fmt.Errorf("创建请求失败：%w", err)
	}

	for key, value := range jms.getHeaders() {
		req.Header.Set(key, value)
	}

	jms.client = &http.Client{}
	return jms.client.Do(req)
}

func (jms *JumpServer) Get(url string, result interface{}) error {
	resp, err := jms.doRequest("GET", url, nil)
	if err != nil {
		return fmt.Errorf("发送 GET 请求失败：%w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("读取响应失败：%w", err)
	}

	if resp.StatusCode >= 300 {
		return fmt.Errorf("GET 请求失败，状态码：%d，响应：%s", resp.StatusCode, string(body))
	}

	if err = json.Unmarshal(body, result); err != nil {
		return fmt.Errorf("解析响应到结构体失败：%w，响应内容：%s", err, string(body))
	}
	return nil
}

func (jms *JumpServer) Post(url string, obj interface{}) error {
	resp, err := jms.doRequest("POST", url, obj)
	if err != nil {
		return fmt.Errorf("发送 POST 请求失败：%w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("读取响应失败：%w", err)
	}

	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("POST 请求失败，响应：%s", string(body))
	}
	return nil
}

func (jms *JumpServer) Put(url string, obj interface{}) error {
	resp, err := jms.doRequest("PUT", url, obj)
	if err != nil {
		return fmt.Errorf("发送 PUT 请求失败：%w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("读取响应失败：%w", err)
	}

	if resp.StatusCode >= 300 {
		return fmt.Errorf("PUT 请求失败，响应：%s", string(body))
	}
	return nil
}

func (jms *JumpServer) Patch(url string, obj interface{}) error {
	resp, err := jms.doRequest("PATCH", url, obj)
	if err != nil {
		return fmt.Errorf("发送 PATCH 请求失败：%w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("读取响应失败：%w", err)
	}

	if resp.StatusCode >= 300 {
		return fmt.Errorf("PATCH 请求失败，响应：%s", string(body))
	}
	return nil
}

type User struct {
	ID               string   `json:"id,omitempty"`
	Name             string   `json:"name"`
	Username         string   `json:"username"`
	Email            string   `json:"email"`
	Password         string   `json:"password,omitempty"`
	PasswordStrategy string   `json:"password_strategy"`
	Source           string   `json:"source"`
	Comment          string   `json:"comment"`
	Groups           []string `json:"groups"`
	OrgRoles         []string `json:"org_roles"`
	SystemRoles      []string `json:"system_roles"`
}

func (u *User) SetPassword(value string) {
	if u.Source == "local" {
		u.Password = value
		u.PasswordStrategy = "custom"
	}
}

type UserResponse struct {
	Next    *string `json:"next"`
	Results []User  `json:"results"`
}

type LabelValue struct {
	Label string `json:"label"`
	Value string `json:"value"`
}

func (jms *JumpServer) ListProtocols() ([]LabelValue, error) {
	url := "/api/v1/assets/protocols/"
	var resp []LabelValue
	if err := jms.Get(url, &resp); err != nil {
		return nil, err
	}
	return resp, nil
}

func (jms *JumpServer) ListUsers() ([]User, error) {
	var users []User
	url := "/api/v1/users/users/?limit=100&offset=0&fields_size=mini"
	for {
		var userResp UserResponse
		if err := jms.Get(url, &userResp); err != nil {
			return nil, err
		}
		users = append(users, userResp.Results...)
		if userResp.Next == nil || *userResp.Next == "" {
			break
		}
		url = *userResp.Next
	}
	return users, nil
}

func (jms *JumpServer) CreateUser(user User) error {
	url := "/api/v1/users/users/"
	if err := jms.Post(url, user); err != nil {
		return err
	}
	return nil
}

func (jms *JumpServer) UpdateUser(id string, user User) error {
	url := fmt.Sprintf("/api/v1/users/users/%s/", id)
	if err := jms.Put(url, user); err != nil {
		return err
	}
	return nil
}

func (jms *JumpServer) InviteUser(data interface{}) error {
	url := "/api/v1/users/users/invite/"
	if err := jms.Post(url, data); err != nil {
		return err
	}
	return nil
}

type IDValue struct {
	ID    int    `json:"id"`
	Value string `json:"value"`
}

type ACLRule struct {
	IpGroup []string  `json:"ip_group"`
	Period  []IDValue `json:"time_period"`
}

type ACLAttr struct {
	Match string `json:"match"`
	Name  string `json:"name"`
	Value string `json:"value"`
}

type ACLUser struct {
	Type  string    `json:"type"`
	Ids   []string  `json:"ids"`
	Attrs []ACLAttr `json:"attrs"`
}

type LoginACL struct {
	ID       string   `json:"id,omitempty"`
	Name     string   `json:"name"`
	Action   string   `json:"action"`
	Priority int      `json:"priority"`
	Rules    *ACLRule `json:"rules"`
	Users    ACLUser  `json:"users"`
}

type LoginACLResponse struct {
	Next    *string    `json:"next"`
	Results []LoginACL `json:"results"`
}

func (jms *JumpServer) ListLoginACLs() ([]LoginACL, error) {
	var loginAcls []LoginACL
	url := "/api/v1/acls/login-acls/?limit=100&offset=0&fields_size=mini"
	for {
		var loginAclResp LoginACLResponse
		if err := jms.Get(url, &loginAclResp); err != nil {
			return nil, err
		}
		loginAcls = append(loginAcls, loginAclResp.Results...)
		if loginAclResp.Next == nil || *loginAclResp.Next == "" {
			break
		}
		url = *loginAclResp.Next
	}
	return loginAcls, nil
}

func (jms *JumpServer) CreateLoginACL(acl LoginACL) error {
	url := "/api/v1/acls/login-acls/"
	if err := jms.Post(url, acl); err != nil {
		return err
	}
	return nil
}

func (jms *JumpServer) UpdateLoginACL(id string, acl LoginACL) error {
	url := fmt.Sprintf("/api/v1/acls/login-acls/%s/", id)
	if err := jms.Put(url, acl); err != nil {
		return err
	}
	return nil
}

type UserGroupResponse struct {
	Next    *string     `json:"next"`
	Results []UserGroup `json:"results"`
}

func (jms *JumpServer) ListUserGroups() ([]UserGroup, error) {
	var groups []UserGroup
	url := "/api/v1/users/groups/?limit=100&offset=0&fields_size=mini"
	for {
		var groupResp UserGroupResponse
		if err := jms.Get(url, &groupResp); err != nil {
			return nil, err
		}
		groups = append(groups, groupResp.Results...)
		if groupResp.Next == nil || *groupResp.Next == "" {
			break
		}
		url = *groupResp.Next
	}
	return groups, nil
}

func (jms *JumpServer) CreateUserGroup(group UserGroup) error {
	url := "/api/v1/users/groups/"
	if err := jms.Post(url, group); err != nil {
		return err
	}
	return nil
}

func (jms *JumpServer) UpdateUserGroup(id string, group UserGroup) error {
	url := fmt.Sprintf("/api/v1/users/groups/%s/", id)
	if err := jms.Put(url, group); err != nil {
		return err
	}
	return nil
}

type Platform struct {
	ID       int        `json:"id"`
	Name     string     `json:"name"`
	Category LabelValue `json:"category"`
	Type     LabelValue `json:"type"`
}

type PlatformResponse struct {
	Next    *string    `json:"next"`
	Results []Platform `json:"results"`
}

func (jms *JumpServer) ListPlatforms() ([]Platform, error) {
	var platforms []Platform
	url := "/api/v1/assets/platforms/?limit=100&offset=0&fields_size=mini"
	for {
		var platformResp PlatformResponse
		if err := jms.Get(url, &platformResp); err != nil {
			return nil, err
		}
		platforms = append(platforms, platformResp.Results...)
		if platformResp.Next == nil || *platformResp.Next == "" {
			break
		}
		url = *platformResp.Next
	}
	return platforms, nil
}

type Asset struct {
	ID           string       `json:"id,omitempty"`
	Name         string       `json:"name"`
	Address      string       `json:"address"`
	Platform     Platform     `json:"platform"`
	Protocols    []Protocol   `json:"protocols"`
	NodesDisplay []string     `json:"nodes_display"`
	Comment      string       `json:"comment"`
	Accounts     []JmsAccount `json:"accounts"`
	AutoFill     string       `json:"autofill,omitempty"`
}

type AssetResponse struct {
	Next    *string `json:"next"`
	Results []Asset `json:"results"`
}

func (jms *JumpServer) ListAssets() ([]Asset, error) {
	var assets []Asset
	url := "/api/v1/assets/assets/?limit=100&offset=0&fields_size=mini"
	for {
		var assetResp AssetResponse
		if err := jms.Get(url, &assetResp); err != nil {
			return nil, err
		}
		assets = append(assets, assetResp.Results...)
		if assetResp.Next == nil || *assetResp.Next == "" {
			break
		}
		url = *assetResp.Next
	}
	return assets, nil
}

func (jms *JumpServer) CreateAsset(category string, asset Asset) error {
	url := fmt.Sprintf("/api/v1/assets/%s/", category)
	if err := jms.Post(url, asset); err != nil {
		return err
	}
	return nil
}

func (jms *JumpServer) UpdateAsset(id, category string, asset Asset) error {
	url := fmt.Sprintf("/api/v1/assets/%s/%s/", category, id)
	if err := jms.Put(url, asset); err != nil {
		return err
	}
	return nil
}

type Account struct {
	ID         string     `json:"id,omitempty"`
	Name       string     `json:"name"`
	Username   string     `json:"username"`
	Asset      Asset      `json:"asset"`
	SecretType LabelValue `json:"secret_type"`
}

type AccountResponse struct {
	Next    *string   `json:"next"`
	Results []Account `json:"results"`
}

func (jms *JumpServer) ListAccounts() ([]Account, error) {
	var accounts []Account
	url := "/api/v1/accounts/accounts/?limit=100&offset=0"
	for {
		var accountResp AccountResponse
		if err := jms.Get(url, &accountResp); err != nil {
			return nil, err
		}
		accounts = append(accounts, accountResp.Results...)
		if accountResp.Next == nil || *accountResp.Next == "" {
			break
		}
		url = *accountResp.Next
	}
	return accounts, nil
}

func (jms *JumpServer) CreateAccount(account JmsAccount) error {
	url := "/api/v1/accounts/accounts/"
	if err := jms.Post(url, account); err != nil {
		return err
	}
	return nil
}

type Node struct {
	ID    string `json:"id"`
	Value string `json:"value"`
}

type NodeResponse struct {
	Next    *string `json:"next"`
	Results []Node  `json:"results"`
}

func (jms *JumpServer) ListNodes() ([]Node, error) {
	var nodes []Node
	url := "/api/v1/assets/nodes/?limit=100&offset=0&fields_size=mini"
	for {
		var nodeResp NodeResponse
		if err := jms.Get(url, &nodeResp); err != nil {
			return nil, err
		}
		nodes = append(nodes, nodeResp.Results...)
		if nodeResp.Next == nil || *nodeResp.Next == "" {
			break
		}
		url = *nodeResp.Next
	}
	return nodes, nil
}

func (jms *JumpServer) CreateNode(node Node) error {
	url := "/api/v1/assets/nodes/"
	if err := jms.Post(url, node); err != nil {
		return err
	}
	return nil
}

func (jms *JumpServer) NodeAddAssets(nodeId string, assetIds []string) error {
	url := fmt.Sprintf("/api/v1/assets/nodes/%s/assets/add/", nodeId)
	if err := jms.Put(url, map[string][]string{"assets": assetIds}); err != nil {
		return err
	}
	return nil
}

type Permission struct {
	ID        string   `json:"id,omitempty"`
	Name      string   `json:"name"`
	Accounts  []string `json:"accounts"`
	Actions   []string `json:"actions"`
	Assets    []string `json:"assets"`
	Protocols []string `json:"protocols"`
	Users     []User   `json:"users"`
}

func (p *Permission) mergeAccounts(accountName string) {
	for _, account := range p.Accounts {
		if accountName == account {
			return
		}
	}
	p.Accounts = append(p.Accounts, accountName)
}

func (p *Permission) mergeProtocols(value string, protocolsMap map[string]bool) {
	set := make(map[string]struct{})
	for _, p1 := range p.Protocols {
		set[strings.ToLower(p1)] = struct{}{}
	}

	for _, p2 := range strings.Split(value, ",") {
		set[strings.ToLower(p2)] = struct{}{}
	}
	result := make([]string, 0, len(set))
	for item := range set {
		if _, exists := protocolsMap[item]; !exists {
			continue
		}
		result = append(result, item)
	}
	p.Protocols = result
}

type PermResponse struct {
	Next    *string      `json:"next"`
	Results []Permission `json:"results"`
}

func (jms *JumpServer) ListPerms() ([]Permission, error) {
	var perms []Permission
	url := "/api/v1/perms/asset-permissions/?limit=100&offset=0&fields_size=mini"
	for {
		var permResp PermResponse
		if err := jms.Get(url, &permResp); err != nil {
			return nil, err
		}
		perms = append(perms, permResp.Results...)
		if permResp.Next == nil || *permResp.Next == "" {
			break
		}
		url = *permResp.Next
	}
	return perms, nil
}

func (jms *JumpServer) CreatePerm(perm Permission) error {
	url := "/api/v1/perms/asset-permissions/"
	if err := jms.Post(url, perm); err != nil {
		return err
	}
	return nil
}

func (jms *JumpServer) UpdatePerm(id string, perm Permission) error {
	url := fmt.Sprintf("/api/v1/perms/asset-permissions/%s/", id)
	if err := jms.Put(url, perm); err != nil {
		return err
	}
	return nil
}

func (jms *JumpServer) SetOrg(orgId string) {
	jms.headers["x-jms-org"] = orgId
}

func (jms *JumpServer) GetOrgId() string {
	return jms.headers["x-jms-org"]
}

func newJumpServer(c JmsConfig) *JumpServer {
	endpoint := strings.TrimSuffix(c.Endpoint, "/")
	jumpserver := &JumpServer{
		endpoint:     endpoint,
		privateToken: c.Token,
		headers:      make(map[string]string),
	}
	orgId := DefaultOrgID
	if c.OrgId != "" {
		orgId = c.OrgId
	}
	jumpserver.headers["x-jms-org"] = orgId
	return jumpserver
}

type Handler struct {
	config Config

	jmsClient    *JumpServer
	getGroups    bool
	getUsers     bool
	getAssets    bool
	getPlatforms bool
	getLoginAcls bool
	getAccounts  bool
	getNodes     bool
	getPerms     bool
	userMap      map[string]string
	usernameMap  map[string]string
	groupMap     map[string]string
	loginAclMap  map[string]string
	assetMap     map[string]string
	platformMap  map[string]map[string]string
	accountMap   map[string]string
	nodeMap      map[string]string
	permMap      map[string]string

	errorMsgBucket   map[string][]string
	errorMsgCache    map[string]bool
	supportProtocols map[string]bool
}

func (h *Handler) AddError(category, errMsg string) {
	if _, exists := h.errorMsgCache[errMsg]; exists {
		return
	}

	h.errorMsgCache[errMsg] = true
	errMsgBucket, exist := h.errorMsgBucket[category]
	if exist {
		errMsgBucket = append(errMsgBucket, errMsg)
		h.errorMsgBucket[category] = errMsgBucket
	} else {
		h.errorMsgBucket[category] = []string{errMsg}
	}
}

func (h *Handler) checkHeaders(headers, data []string) {
	if len(headers) > len(data) {
		log.Fatalf("请保证文件表头字段足够解析: %s", strings.Join(headers, ","))
	}
	if len(headers) != len(data) {
		reader := bufio.NewReader(os.Stdin)
		fmt.Printf("请确保文件表头字段下方有效值是以以下顺序开始的，否则可能解析失败，表头名称随意。\n需求：%s\n现在: %s\n回复 y 继续: ",
			strings.Join(headers, ","), strings.Join(data, ","))
		value, _ := reader.ReadString('\n')
		if strings.TrimSpace(strings.ToLower(value)) != "y" {
			os.Exit(0)
		}
	}
}

type EUser struct {
	Name     string   `json:"name" excel:"用户名"`
	Username string   `json:"username" excel:"登录名"`
	Email    string   `json:"email" excel:"邮箱"`
	Source   string   `json:"source" excel:"登录类型"`
	Comment  string   `json:"comment" excel:"备注"`
	Groups   []string `excel:"用户组"`
	AllowIPs []string `excel:"允许登录IP"`
}

func (h *Handler) getUserFromRemote() {
	if !h.getUsers {
		users, err := h.jmsClient.ListUsers()
		if err != nil {
			log.Fatalf("获取用户数据失败: %v", err)
		}
		for _, user := range users {
			h.userMap[fmt.Sprintf("%s(%s)", user.Username, user.Name)] = user.ID
			h.usernameMap[user.Username] = user.ID
		}
		h.getUsers = true
	}
}

func (h *Handler) getValidRow(row []string, length int) []string {
	if length <= len(row) {
		return row
	}

	need := length - len(row)
	result := make([]string, 0, length)
	result = append(result, row...)
	for i := 0; i < need; i++ {
		result = append(result, "")
	}
	return result
}

func (h *Handler) InitResources() {
	protocols, err := h.jmsClient.ListProtocols()
	if err != nil {
		log.Fatalf("获取资产协议数据失败: %v", err)
	}
	for _, protocol := range protocols {
		h.supportProtocols[protocol.Value] = true
	}
}

func (h *Handler) MigrateUser() {
	config := h.config.User
	if config.Path == "" {
		return
	}

	log.Println("开始迁移用户数据...")
	rows, err := readExcelFile(config.Path, config.HeaderRowNum, 0)
	if err != nil {
		log.Fatalf("读取用户 Excel 失败：%v", err)
	}

	headers := []string{"登录名", "登录类型", "用户名", "用户组", "邮箱", "允许登录IP", "备注"}
	h.checkHeaders(headers, rows[config.HeaderRowNum])

	h.getUserFromRemote()
	h.getUserGroupFromRemote()
	h.getLoginAclFromRemote()

	var globalUserMap = make(map[string]string)
	rawOrgId := h.jmsClient.GetOrgId()
	h.jmsClient.SetOrg(GlobalOrgID)

	var periods []IDValue
	for i := 0; i <= 6; i++ {
		periods = append(periods, IDValue{ID: i, Value: AllDay})
	}

	var aclUser ACLUser
	if !h.config.Jumpserver.ACLLoginDenyIncludeAdmin {
		attrs := []ACLAttr{
			{Match: "not", Value: "admin", Name: "username"},
		}
		aclUser = ACLUser{Type: "attrs", Attrs: attrs}
	} else {
		aclUser = ACLUser{Type: "all"}
	}
	gLoginAcl := LoginACL{
		Name: "DENY_ALL", Priority: 80, Action: "reject",
		Rules: &ACLRule{IpGroup: []string{"*"}, Period: periods},
		Users: aclUser,
	}
	_ = h.jmsClient.CreateLoginACL(gLoginAcl)

	globalUsers, err := h.jmsClient.ListUsers()
	if err != nil {
		log.Fatalf("[ERROR] 在全局视图下获取用户失败")
	}
	for _, row := range globalUsers {
		globalUserMap[row.Username] = row.ID
	}
	h.jmsClient.SetOrg(rawOrgId)

	for _, row := range rows[h.config.User.HeaderRowNum+1:] {
		row = h.getValidRow(row, len(headers))
		source := "local"
		if row[1] != "" {
			source = row[1]
		}
		user := EUser{
			Name: row[2], Username: row[0], Email: row[4], Groups: strings.Split(row[3], ","),
			Source: source, Comment: row[6], AllowIPs: strings.Split(row[5], ","),
		}
		var groupIds []string
		for _, groupName := range user.Groups {
			if groupName == "" {
				continue
			}
			groupName = strings.ReplaceAll(groupName, " ", "")
			groupId := h.groupMap[groupName]
			if groupId == "" {
				groupId = uuid.New().String()
				userGroup := UserGroup{
					ID: groupId, Name: groupName, Users: make([]string, 0),
				}
				if err = h.jmsClient.CreateUserGroup(userGroup); err != nil {
					h.AddError(C_UserGroup, fmt.Sprintf("'%s' 创建失败: %v", groupName, err))
					groupId = ""
				} else {
					h.groupMap[groupName] = groupId
				}
			}
			if groupId != "" {
				groupIds = append(groupIds, groupId)
			}
		}
		if len(groupIds) == 0 {
			groupIds = make([]string, 0)
		}

		userId := globalUserMap[user.Username]
		email := user.Email
		if email == "" {
			email = fmt.Sprintf("%s@%s", user.Username, "company.com")
		}
		jmsUser := User{
			Name: user.Name, Username: user.Username,
			Email: email, Source: user.Source,
			PasswordStrategy: "email",
			Comment:          user.Comment, Groups: groupIds,
			SystemRoles: []string{SystemUser},
			OrgRoles:    []string{OrgUser},
		}
		jmsUser.SetPassword(h.config.Jumpserver.DefaultPassword)
		if userId == "" {
			userId = uuid.New().String()
			jmsUser.ID = userId
			if err = h.jmsClient.CreateUser(jmsUser); err != nil {
				h.AddError(C_User, fmt.Sprintf("'%s(%s)' 创建失败: %v", user.Name, user.Username, err))
				continue
			} else {
				log.Printf("[INFO] [用户: %s(%s)] 创建成功\n", user.Name, user.Username)
				h.userMap[fmt.Sprintf("%s(%s)", user.Username, user.Name)] = userId
				h.usernameMap[user.Username] = userId
			}
		}
		orgUserId := h.userMap[fmt.Sprintf("%s(%s)", user.Username, user.Name)]
		if orgUserId == "" {
			if err = h.jmsClient.InviteUser(map[string][]string{
				"users": {userId}, "org_roles": {OrgUser},
			}); err != nil {
				h.AddError(C_User, fmt.Sprintf("'%s(%s)' 邀请失败: %v", user.Name, user.Username, err))
				continue
			} else {
				log.Printf("[INFO] [用户: %s(%s)] 邀请成功\n", user.Name, user.Username)
				h.userMap[fmt.Sprintf("%s(%s)", user.Username, user.Name)] = userId
				h.usernameMap[user.Username] = userId
			}
		} else {
			if err = h.jmsClient.UpdateUser(orgUserId, jmsUser); err != nil {
				h.AddError(C_User, fmt.Sprintf("'%s(%s)' 更新失败: %v", user.Name, user.Username, err))
				continue
			} else {
				log.Printf("[INFO] [用户: %s(%s)] 更新成功\n", user.Name, user.Username)
			}
		}

		aclId := h.loginAclMap[user.Username]
		loginAcl := LoginACL{
			Name: user.Username, Priority: 50, Action: "accept",
			Rules: &ACLRule{IpGroup: user.AllowIPs, Period: periods},
			Users: ACLUser{Type: "ids", Ids: []string{userId}},
		}
		if aclId == "" {
			if err = h.jmsClient.CreateLoginACL(loginAcl); err != nil {
				h.AddError(C_User, fmt.Sprintf("'%s' 的 ACL 创建失败: %v", user.Name, err))
			} else {
				h.loginAclMap[user.Username] = aclId
				log.Printf("[INFO] [ACL: %s] 创建成功\n", user.Name)
			}
		} else {
			if err = h.jmsClient.UpdateLoginACL(aclId, loginAcl); err != nil {
				h.AddError(C_User, fmt.Sprintf("'%s' 的 ACL 更新失败: %v", user.Name, err))
			} else {
				log.Printf("[INFO] [ACL: %s] 更新成功\n", user.Name)
			}
		}
	}
}

type UserGroup struct {
	ID      string   `json:"id,omitempty"`
	Name    string   `json:"name"`
	Comment string   `json:"comment"`
	Users   []string `json:"users"`
}

func (h *Handler) getUserGroupFromRemote() {
	if !h.getGroups {
		userGroups, err := h.jmsClient.ListUserGroups()
		if err != nil {
			log.Fatalf("获取用户组数据失败: %v", err)
		}
		for _, group := range userGroups {
			h.groupMap[group.Name] = group.ID
		}
		h.getGroups = true
	}
}

func (h *Handler) getLoginAclFromRemote() {
	if !h.getLoginAcls {
		loginAcls, err := h.jmsClient.ListLoginACLs()
		if err != nil {
			log.Fatalf("获取用户组数据失败: %v", err)
		}
		for _, acl := range loginAcls {
			h.loginAclMap[acl.Name] = acl.ID
		}
		h.getLoginAcls = true
	}
}

func (h *Handler) MigrateUserGroup() {
	config := h.config.UserGroup
	if config.Path == "" {
		return
	}
	log.Println("[INFO] 开始迁移用户组数据...")
	rows, err := readExcelFile(config.Path, config.HeaderRowNum, 0)
	if err != nil {
		log.Fatalf("[ERROR] 读取用户组 Excel 失败：%v", err)
	}

	h.getUserFromRemote()
	h.getUserGroupFromRemote()

	for i, name := range rows[config.HeaderRowNum] {
		var comment string
		if len(rows) >= config.HeaderRowNum+2 && len(rows[config.HeaderRowNum+2]) > i {
			comment = rows[config.HeaderRowNum+2][i]
		}
		group := UserGroup{
			Name:    name,
			Users:   make([]string, 0),
			Comment: comment,
		}
		users := strings.Split(rows[config.HeaderRowNum+1][i], "\n")
		for _, user := range users {
			user = strings.ReplaceAll(user, " ", "")
			userId := h.userMap[user]
			if userId == "" {
				h.AddError(C_UserGroup, fmt.Sprintf("用户 '%s' 在 JumpServer 不存在，跳过", user))
				continue
			}
			group.Users = append(group.Users, userId)
		}
		groupId := h.groupMap[group.Name]
		if groupId == "" {
			group.ID = uuid.New().String()
			if err = h.jmsClient.CreateUserGroup(group); err != nil {
				h.AddError(C_UserGroup, fmt.Sprintf("'%s' 创建失败: %v", group.Name, err))
			} else {
				h.groupMap[group.Name] = group.ID
				log.Printf("[INFO] [用户组: %s] 创建成功\n", group.Name)
			}
		} else {
			if err = h.jmsClient.UpdateUserGroup(groupId, group); err != nil {
				h.AddError(C_UserGroup, fmt.Sprintf("'%s' 更新失败: %v", group.Name, err))
			} else {
				log.Printf("[INFO] [用户组: %s] 更新成功\n", group.Name)
			}
		}
	}
}

type Protocol struct {
	Name string `json:"name"`
	Port int    `json:"port"`
}

type EAsset struct {
	Name      string     `json:"name"`
	Address   string     `json:"address"`
	Platform  string     `json:"platform"`
	Protocols []Protocol `json:"protocols"`
	Node      string     `json:"node"`
	Comment   string     `json:"comment"`
}

func (i *EAsset) FitProtocols(protocolStr string) {
	protocolStr = strings.TrimPrefix(protocolStr, "{")
	protocolStr = strings.TrimSuffix(protocolStr, "}")
	pairs := strings.Split(protocolStr, ",")
	if len(pairs) == 0 {
		return
	}
	var protocols []Protocol
	for _, pair := range pairs {
		parts := strings.Split(pair, ":")
		if len(parts) != 2 {
			continue
		}
		port, err := strconv.Atoi(parts[1])
		if err != nil {
			continue
		}
		protocolName := strings.ToLower(parts[0])
		if protocolName == "scp" || protocolName == "ftp" {
			continue
		}
		protocols = append(protocols, Protocol{Name: protocolName, Port: port})
	}
	i.Protocols = protocols
}

func (i *EAsset) FitPlatform(value string) {
	value = strings.ReplaceAll(value, "服务器", "")
	idx := strings.Index(value, "/")
	if idx != -1 {
		value = value[idx+1:]
	}
	i.Platform = strings.ToLower(value)
}

func (h *Handler) getAssetFromRemote() {
	if !h.getAssets {
		assets, err := h.jmsClient.ListAssets()
		if err != nil {
			log.Fatalf("[ERROR] 获取资产数据失败: %v", err)
		}
		for _, asset := range assets {
			h.assetMap[asset.Name] = asset.ID
		}
		h.getAssets = true
	}
}

func (h *Handler) getPlatformFromRemote() {
	if !h.getPlatforms {
		platforms, err := h.jmsClient.ListPlatforms()
		if err != nil {
			log.Fatalf("[ERROR] 获取平台数据失败: %v", err)
		}
		for _, platform := range platforms {
			h.platformMap[strings.ToLower(platform.Name)] = map[string]string{
				"id":       strconv.Itoa(platform.ID),
				"category": platform.Category.Value,
				"type":     platform.Type.Value,
			}
		}
		h.getPlatforms = true
	}
}

func (h *Handler) MigrateAsset() {
	config := h.config.Asset
	if config.Path == "" {
		return
	}
	log.Println("[INFO] 开始迁移资产数据...")

	rows, err := readExcelFile(config.Path, config.HeaderRowNum, 0)
	if err != nil {
		log.Fatalf("[ERROR] 读取资产 Excel 失败：%v", err)
	}
	headers := []string{"设备名称", "设备IP", "设备类型", "设备协议", "部门", "备注"}
	h.checkHeaders(headers, rows[config.HeaderRowNum])

	webRows, err := readExcelFile(config.Path, config.HeaderRowNum, 1)
	if err != nil {
		log.Fatalf("[ERROR] 读取 Web 资产 Excel 失败：%v", err)
	}
	webHeaders := []string{"设备名称", "首页/资产地址", "部门", "备注"}
	h.checkHeaders(webHeaders, webRows[config.HeaderRowNum])

	for _, row := range webRows[config.HeaderRowNum+1:] {
		row = h.getValidRow(row, len(webHeaders))
		tranRow := []string{row[0], row[1], "website", "{http:80}", row[2], row[3]}
		rows = append(rows, tranRow)
	}

	h.getAssetFromRemote()
	h.getPlatformFromRemote()

	for _, row := range rows[config.HeaderRowNum+1:] {
		row = h.getValidRow(row, len(headers))
		asset := EAsset{
			Name: row[0], Address: row[1], Node: row[4], Comment: row[5],
		}
		asset.FitProtocols(row[3])
		asset.FitPlatform(row[2])

		platformObj, exist := h.platformMap[asset.Platform]
		if !exist {
			h.AddError(C_Asset, fmt.Sprintf("资产平台 '%s' 不存在，'%s' 跳过创建", asset.Platform, asset.Name))
			continue
		}

		assetId := h.assetMap[asset.Name]
		platformId, _ := strconv.Atoi(platformObj["id"])
		category := platformObj["category"] + "s"
		jmsAsset := Asset{
			Name:         asset.Name,
			Address:      asset.Address,
			Protocols:    asset.Protocols,
			Platform:     Platform{ID: platformId},
			NodesDisplay: []string{asset.Node},
			Comment:      asset.Comment,
		}
		if category == "webs" {
			jmsAsset.Accounts = []JmsAccount{
				{Name: "null", Username: "null", SecretType: "password"},
			}
			jmsAsset.AutoFill = "no"
		}
		if assetId == "" {
			jmsAsset.ID = uuid.New().String()
			if err = h.jmsClient.CreateAsset(category, jmsAsset); err != nil {
				h.AddError(C_Asset, fmt.Sprintf("'%s' 创建失败: %v", asset.Name, err))
			} else {
				log.Printf("[INFO] [资产: %s] 创建成功\n", asset.Name)
				h.assetMap[asset.Name] = jmsAsset.ID
			}
		} else {
			if err = h.jmsClient.UpdateAsset(assetId, category, jmsAsset); err != nil {
				h.AddError(C_Asset, fmt.Sprintf("'%s' 更新失败: %v", asset.Name, err))
			} else {
				log.Printf("[INFO] [资产: %s] 更新成功\n", asset.Name)
			}
		}
	}
}

func (h *Handler) getAccountFromRemote() {
	if !h.getAccounts {
		accounts, err := h.jmsClient.ListAccounts()
		if err != nil {
			log.Fatalf("[ERROR] 获取账号数据失败: %v", err)
		}
		for _, account := range accounts {
			username := strings.ToLower(account.Username)
			key := fmt.Sprintf("%s-%s-%s", account.Asset.Name, account.Asset.Address, username)
			h.accountMap[key] = account.Asset.ID
		}
		h.getAccounts = true
	}
}

type JmsAccount struct {
	Name       string `json:"name"`
	Username   string `json:"username"`
	Asset      string `json:"asset"`
	SecretType string `json:"secret_type"`
	Secret     string `json:"secret"`
	Comment    string `json:"comment"`
}

func (h *Handler) MigrateAccount() {
	config := h.config.Account
	if config.Path == "" {
		return
	}
	log.Println("[INFO] 开始迁移资产账号数据...")
	rows, err := readExcelFile(config.Path, config.HeaderRowNum, 0)
	if err != nil {
		log.Fatalf("[ERROR] 读取账号 Excel 失败：%v", err)
	}

	headers := []string{"设备名称", "设备IP", "备注", "账号、特权命令", "密码"}
	h.checkHeaders(headers, rows[config.HeaderRowNum])

	h.getAssetFromRemote()
	h.getAccountFromRemote()

	for _, row := range rows[config.HeaderRowNum+1:] {
		// assetName, assetAddress, comment, Username, Secret
		if row[0] == "" || row[1] == "" {
			h.AddError(C_Account, fmt.Sprintf("数据不完整，跳过: %s", strings.Join(row, ", ")))
			continue
		}
		row = h.getValidRow(row, len(headers))
		username := strings.ToLower(row[3])
		username = strings.TrimPrefix(row[3], ".\\")
		username = strings.ReplaceAll(username, "\\", "@")
		if username == "" {
			username = "null"
		}

		assetId := h.accountMap[fmt.Sprintf("%s-%s-%s", row[0], row[1], username)]
		if assetId != "" {
			continue
		}
		assetId = h.assetMap[row[0]]
		if assetId == "" {
			h.AddError(C_Account, fmt.Sprintf("资产 '%s' 未找到，'%s' 跳过创建", row[0], row[3]))
			continue
		}
		secret := ""
		if len(row) >= 5 {
			secret = row[4]
		}
		jmsAccount := JmsAccount{
			Name: username, Username: username, Comment: row[2],
			Asset: assetId, SecretType: "password", Secret: secret,
		}
		if err = h.jmsClient.CreateAccount(jmsAccount); err != nil {
			h.AddError(C_Account, fmt.Sprintf("'%s' 创建失败: %v", jmsAccount.Name, err))
		} else {
			log.Printf("[INFO] [账号: %s] 创建成功", jmsAccount.Name)
			h.accountMap[fmt.Sprintf("%s-%s-%s", row[0], row[1], username)] = assetId
		}
	}

}

func (h *Handler) getNodeFromRemote() {
	if !h.getNodes {
		nodes, err := h.jmsClient.ListNodes()
		if err != nil {
			log.Fatalf("[ERROR] 获取节点数据失败: %v", err)
		}
		for _, node := range nodes {
			h.nodeMap[node.Value] = node.ID
		}
		h.getNodes = true
	}
}

func (h *Handler) MigrateNode() {
	config := h.config.Node
	if config.Path == "" {
		return
	}
	log.Println("[INFO] 开始迁移节点数据...")
	rows, err := readExcelFile(config.Path, config.HeaderRowNum, 0)
	if err != nil {
		log.Fatalf("[ERROR] 读取节点 Excel 失败：%v", err)
	}

	h.getAssetFromRemote()
	h.getNodeFromRemote()

	for i, name := range rows[config.HeaderRowNum] {
		name = strings.TrimSpace(name)
		nodeId := h.nodeMap[name]
		jmsNode := Node{
			Value: name,
		}
		if nodeId == "" {
			nodeId = uuid.New().String()
			jmsNode.ID = nodeId
			if err = h.jmsClient.CreateNode(jmsNode); err != nil {
				h.AddError(C_Node, fmt.Sprintf("'%s' 创建失败: %v", name, err))
				continue
			} else {
				h.nodeMap[name] = nodeId
			}
		}

		var assetIds []string
		assets := strings.Split(rows[config.HeaderRowNum+1][i], "\n")
		for _, asset := range assets {
			assetId := h.assetMap[asset]
			if assetId == "" {
				h.AddError(C_Node, fmt.Sprintf("资产 '%s' 不存在 JumpServer 中，无法绑定节点 '%s'，请创建后重试", asset, name))
				continue
			}
			assetIds = append(assetIds, assetId)
		}
		if len(assetIds) == 0 {
			continue
		}

		if err = h.jmsClient.NodeAddAssets(nodeId, assetIds); err != nil {
			h.AddError(C_Node, fmt.Sprintf("节点资产关联失败: %v", err))
		} else {
			log.Printf("[INFO] 共 %v 个资产和节点 %s 关联", len(assetIds), name)
		}
	}
}

func (h *Handler) getPermFromRemote() {
	if !h.getPerms {
		perms, err := h.jmsClient.ListPerms()
		if err != nil {
			log.Fatalf("[ERROR] 获取授权数据失败: %v", err)
		}
		for _, perm := range perms {
			h.permMap[perm.Name] = perm.ID
		}
		h.getPerms = true
	}
}

func (h *Handler) MigratePermission() {
	config := h.config.Permission
	if config.Path == "" {
		return
	}
	log.Println("[INFO] 开始迁移授权数据...")
	rows, err := readExcelFile(config.Path, config.HeaderRowNum, 0)
	if err != nil {
		log.Fatalf("[ERROR] 读取授权 Excel 失败：%v", err)
	}

	headers := []string{"用户", "资产", "资产IP", "资产支持的协议", "账号", "账号协议", "数据库服务名"}
	h.checkHeaders(headers, rows[config.HeaderRowNum])

	h.getUserFromRemote()
	h.getAssetFromRemote()
	h.getPermFromRemote()

	var permissionsMap = make(map[string]Permission)
	// username, asset_name, asset_category, asset_ip, support_protocols, account, account_protocols, db_name
	for _, row := range rows[config.HeaderRowNum+1:] {
		row = h.getValidRow(row, len(headers))
		name := fmt.Sprintf("%s-%s", row[1], row[0])
		userId := h.usernameMap[row[0]]
		if userId == "" {
			h.AddError(C_Perm, fmt.Sprintf("用户 '%s' 在 JumpServer 不存在，跳过授权", row[0]))
			continue
		}
		assetId := h.assetMap[row[1]]
		if assetId == "" {
			h.AddError(C_Perm, fmt.Sprintf("资产 '%s' 在 JumpServer 不存在，跳过授权", row[1]))
			continue
		}
		perm, exists := permissionsMap[name]
		if exists {
			perm.mergeAccounts(row[5])
			perm.mergeProtocols(row[6], h.supportProtocols)
			permissionsMap[name] = perm
		} else {
			jmsPerm := Permission{
				ID:        uuid.New().String(),
				Name:      name,
				Users:     []User{{ID: userId}},
				Assets:    []string{assetId},
				Accounts:  []string{"@SPEC", row[5]},
				Protocols: []string{},
				Actions: []string{
					"connect", "upload", "download", "copy", "paste", "delete", "share",
				},
			}
			for _, p := range strings.Split(row[6], ",") {
				p = strings.ToLower(p)
				if _, exists = h.supportProtocols[p]; !exists {
					continue
				}
				jmsPerm.Protocols = append(jmsPerm.Protocols, p)
			}
			permissionsMap[name] = jmsPerm
		}

	}
	for _, perm := range permissionsMap {
		permId := h.permMap[perm.Name]
		if permId != "" {
			perm.ID = ""
			if err = h.jmsClient.UpdatePerm(permId, perm); err != nil {
				h.AddError(C_Perm, fmt.Sprintf("'%s' 更新失败: %v", perm.Name, err))
			} else {
				log.Printf("[INFO] [资产授权: %s] 更新成功", perm.Name)
			}
		} else {
			if err = h.jmsClient.CreatePerm(perm); err != nil {
				h.AddError(C_Perm, fmt.Sprintf("'%s' 创建失败: %v", perm.Name, err))
			} else {
				log.Printf("[INFO] [资产授权: %s] 创建成功", perm.Name)
			}
		}
	}
}

func (h *Handler) PrintErrorSummary() {
	if len(h.errorMsgBucket) == 0 {
		fmt.Println("✅ 没有错误信息")
		return
	}
	summaryLines := []string{
		"❌ 错误摘要",
		"----------------------------------------",
	}
	for category, errors := range h.errorMsgBucket {
		summaryLines = append(summaryLines, fmt.Sprintf("\n【%s】(%d个错误)", category, len(errors)))
		for i, errMsg := range errors {
			summaryLines = append(summaryLines, fmt.Sprintf("  %d. %s", i+1, errMsg))
		}
	}

	summaryLines = append(summaryLines, "\n----------------------------------------")
	totalErrors := 0
	for _, errors := range h.errorMsgBucket {
		totalErrors += len(errors)
	}
	summaryLines = append(summaryLines, fmt.Sprintf("总计: %d 个错误", totalErrors))
	for _, line := range summaryLines {
		fmt.Println(line)
	}

	errorFilePath := filepath.Join(".", "error_summary.txt")
	file, err := os.OpenFile(errorFilePath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer file.Close()
	_, err = file.WriteString(strings.Join(summaryLines, "\n"))
	if err != nil {
		return
	}
	fmt.Printf("错误摘要信息已同步保存到文件 %s 中\n", errorFilePath)
}

func (h *Handler) Do() {
	h.InitResources()
	h.MigrateUser()
	h.MigrateUserGroup()
	h.MigrateAsset()
	h.MigrateAccount()
	h.MigrateNode()
	h.MigratePermission()
	h.PrintErrorSummary()
}

type PathConfig struct {
	Path         string `mapstructure:"Path"`
	HeaderRowNum int    `mapstructure:"HeaderRowNum"`
}

type JmsConfig struct {
	Endpoint                 string `mapstructure:"Endpoint"`
	Token                    string `mapstructure:"Token"`
	OrgId                    string `mapstructure:"OrgId"`
	DefaultPassword          string `mapstructure:"DefaultPassword"`
	ACLLoginDenyIncludeAdmin bool   `mapstructure:"ACLLoginDenyIncludeAdmin"`
}

type Config struct {
	User       PathConfig `mapstructure:"User"`
	UserGroup  PathConfig `mapstructure:"UserGroup"`
	Asset      PathConfig `mapstructure:"Asset"`
	Account    PathConfig `mapstructure:"Account"`
	Node       PathConfig `mapstructure:"Node"`
	Permission PathConfig `mapstructure:"Permission"`

	Jumpserver JmsConfig `mapstructure:"JumpServer"`
}

func main() {
	configPath := flag.String("f", "config.yml", "Config 文件路径")
	flag.Parse()

	if _, err := os.Stat(*configPath); err != nil {
		log.Fatalf("Config 文件读取失败: %v", err)
	}

	var conf Config
	fileViper := viper.New()
	fileViper.SetConfigFile(*configPath)
	if err := fileViper.ReadInConfig(); err == nil {
		if err = fileViper.Unmarshal(&conf); err == nil {
			log.Printf("Load config from %s success\n", *configPath)
		} else {
			log.Fatalf("读取配置文件失败: %v", err)
		}
	} else {
		log.Fatalf("读取配置文件失败: %v", err)
	}

	if conf.Jumpserver.Endpoint == "" || conf.Jumpserver.Token == "" {
		log.Fatal("JumpServer 地址和 PrivateToken 不能为空！")
	}

	conf.User.HeaderRowNum--
	conf.UserGroup.HeaderRowNum--
	conf.Asset.HeaderRowNum--
	conf.Account.HeaderRowNum--
	conf.Node.HeaderRowNum--
	conf.Permission.HeaderRowNum--
	handler := &Handler{
		config:      conf,
		jmsClient:   newJumpServer(conf.Jumpserver),
		userMap:     make(map[string]string),
		usernameMap: make(map[string]string),
		groupMap:    make(map[string]string),
		loginAclMap: make(map[string]string),
		assetMap:    make(map[string]string),
		accountMap:  make(map[string]string),
		nodeMap:     make(map[string]string),
		permMap:     make(map[string]string),
		platformMap: make(map[string]map[string]string),

		errorMsgBucket:   make(map[string][]string),
		errorMsgCache:    make(map[string]bool),
		supportProtocols: make(map[string]bool),
	}
	handler.Do()
	log.Println("所有迁移任务执行完毕")
}
