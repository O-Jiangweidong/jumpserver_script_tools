package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

const (
	Reset        = "\033[0m"
	Green        = "\033[1;32m"
	BrightCyan   = "\033[1;36m"
	BrightYellow = "\033[1;33m"

	DefaultNTPServer = "asia.pool.ntp.org"
	TitleColor       = BrightCyan
)

func main() {
	menuInput := flag.String("s", "", "输入菜单序号，多个用逗号隔开")
	showHelp := flag.Bool("m", false, "显示菜单信息")
	allDo := flag.Bool("a", false, "是否执行全部任务")
	initNetwork := flag.Bool("i", false, "初始化私网信息")
	test := flag.Bool("t", false, "Test")
	flag.Parse()

	if *test {
		outputSystemInfo()
		return
	}

	if *initNetwork {
		initSelfNetwork()
		return
	}

	if *showHelp {
		showMenu()
		return
	}

	if *allDo {
		disableSELinux()
		configTimeServer()
		optimizeSysParams()
		configureNetwork()
		disableRootLogin()
	} else {
		if *menuInput != "" {
			menus := strings.Split(*menuInput, ",")
			for _, menu := range menus {
				menu = strings.TrimSpace(menu)
				switch menu {
				case "1":
					disableSELinux()
				case "2":
					configTimeServer()
				case "3":
					optimizeSysParams()
				case "4":
					configureNetwork()
				case "5":
					disableRootLogin()
				default:
					log.Printf("无效的菜单序号: %s", menu)
				}
			}
		} else {
			configureNetwork()
		}
	}
	outputSystemInfo()
	rebootMachine()
}

func disableSELinux() {
	if _, err := exec.LookPath("sestatus"); err != nil {
		log.Println("SELinux 检查工具未找到，跳过 SELinux 处理。")
		return
	}

	output, err := execCommand("sestatus")
	if err != nil || !strings.Contains(output, "enabled") {
		log.Println("SELinux 未启用，跳过 SELinux 处理。")
		return
	}

	output, err = execCommand("setenforce 0")
	if err != nil {
		log.Fatalf("关闭 SELinux 失败: %s", output)
	}
	output, err = execCommand("sed -i 's/^SELINUX=.*/SELINUX=disabled/' /etc/selinux/config")
	if err != nil {
		log.Fatalf("关闭 SELinux 失败: %s", output)
	}
	log.Printf("%s\n%s%s\n", Green, "SELinux 已关闭", Reset)
}

func checkAndInstallNTP() error {
	if _, err := exec.LookPath("ntpd"); err == nil {
		fmt.Println("NTP 已安装，跳过安装步骤。")
		return nil
	}

	var cmd *exec.Cmd
	if _, err := exec.LookPath("apt"); err == nil {
		cmd = exec.Command("apt", "install", "-y", "ntp")
	} else if _, err := exec.LookPath("yum"); err == nil {
		cmd = exec.Command("yum", "install", "-y", "ntp")
	} else {
		log.Fatalf("不支持的包管理工具")
	}
	return cmd.Run()
}

func updateNTPServers(ntpServers string) error {
	configFile := "/etc/ntp.conf"
	data, err := os.ReadFile(configFile)
	if err != nil {
		return err
	}

	lines := strings.Split(string(data), "\n")
	var updatedLines []string

	for _, line := range lines {
		if strings.HasPrefix(line, "pool ") || strings.HasPrefix(line, "server ") {
			updatedLines = append(updatedLines, "# "+line)
		} else {
			updatedLines = append(updatedLines, line)
		}
	}
	servers := strings.Split(ntpServers, " ")
	for _, server := range servers {
		updatedLines = append(updatedLines, fmt.Sprintf("server %s iburst", server))
	}

	return os.WriteFile(configFile, []byte(strings.Join(updatedLines, "\n")), 0644)
}

func startNTP() error {
	cmd := exec.Command("systemctl", "start", "ntp")
	if err := cmd.Run(); err != nil {
		return err
	}

	cmd = exec.Command("systemctl", "enable", "ntp")
	return cmd.Run()
}

func configTimeServer() {
	if err := checkAndInstallNTP(); err != nil {
		log.Fatalf("安装 NTP 服务失败: %s", err)
	}

	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("请输入 NTP 服务器地址（多个地址用空格分隔）, 默认 %s: ", DefaultNTPServer)
	ntpServers, _ := reader.ReadString('\n')
	if ntpServers == "" {
		ntpServers = DefaultNTPServer
	}
	ntpServers = strings.TrimSpace(ntpServers)

	if err := updateNTPServers(ntpServers); err != nil {
		log.Fatalf("更新 NTP 服务器失败: %s", err)
	}

	if err := startNTP(); err != nil {
		log.Fatalf("启动 NTP 服务失败: %s", err)
	}
	log.Printf("%s\n%s%s\n", Green, "时间服务器已配置", Reset)
}

func updateConfigFile(filePath string, newConfigs map[string]string) error {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}

	lines := strings.Split(string(data), "\n")
	var updatedLines []string

	for _, line := range lines {
		for prefix, _ := range newConfigs {
			if strings.HasPrefix(line, prefix) {
				line = ""
				break
			}
		}
		if line != "" {
			updatedLines = append(updatedLines, line)
		}
	}

	for _, newConfig := range newConfigs {
		updatedLines = append(updatedLines, newConfig)
	}

	return os.WriteFile(filePath, []byte(strings.Join(updatedLines, "\n")), 0644)
}

func optimizeSysParams() {
	newLimit := "204800"
	limitsConfigs := map[string]string{
		"* soft nofile": fmt.Sprintf("* soft nofile %s", newLimit),
		"* hard nofile": fmt.Sprintf("* hard nofile %s", newLimit),
		"* soft nproc":  fmt.Sprintf("* soft nproc %s", newLimit),
		"* hard nproc":  fmt.Sprintf("* hard nproc %s", newLimit),
	}

	if err := updateConfigFile("/etc/security/limits.conf", limitsConfigs); err != nil {
		log.Fatalf("更新 limits.conf 失败: %s", err)
	}

	sysctlConfigs := map[string]string{
		"fs.file-max":         "fs.file-max = " + newLimit,
		"net.ipv4.ip_forward": "net.ipv4.ip_forward = 1",
	}

	if err := updateConfigFile("/etc/sysctl.conf", sysctlConfigs); err != nil {
		log.Fatalf("持久化文件描述符限制失败: %s", err)
	}

	if output, err := execCommand("sysctl -p"); err != nil {
		log.Fatalf("重载 sysctl 配置失败: %s", output)
	}

	log.Printf("%s\n%s%s%s\n", Green, "系统参数已优化，文件数量限制设置为 ", newLimit, Reset)
}

func rebootMachine() {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("您确定要重启机器吗？(y/n): ")
	confirm, _ := reader.ReadString('\n')
	confirm = strings.TrimSpace(confirm)

	if confirm != "y" && confirm != "Y" {
		log.Println("重启操作已取消")
		return
	}

	output, err := execCommand("reboot")
	if err != nil {
		log.Fatalf("重启失败: %s", output)
	}
}

func showMenu() {
	fmt.Println("1. 关闭 SELinux")
	fmt.Println("2. 配置时间服务器")
	fmt.Println("3. 系统参数优化")
	fmt.Println("4. 基础网络配置")
	fmt.Println("5. 禁止 root 直接登录")
}

func execCommand(cmd string) (string, error) {
	command := exec.Command("bash", "-c", cmd)
	output, err := command.CombinedOutput()
	if err != nil {
		return string(output), err
	}
	return string(output), nil
}

func subnetMaskToCIDR(netmask string) int {
	parts := strings.Split(netmask, ".")
	var cidr int
	for _, part := range parts {
		val := 0
		_, _ = fmt.Sscanf(part, "%d", &val)
		for i := 7; i >= 0; i-- {
			if (val>>i)&1 == 1 {
				cidr++
			}
		}
	}
	return cidr
}

func getInterfaceNames() (interfaces []string) {
	output, err := execCommand("ip link show | awk -F': ' '/^[0-9]+: /{print $2}'")
	if err != nil {
		log.Fatalf("获取网卡名称失败: %s", output)
	}

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		iFaceName := strings.TrimSpace(line)
		if iFaceName != "lo" && iFaceName != "docker0" && iFaceName != "" {
			interfaces = append(interfaces, iFaceName)
		}
	}
	return interfaces
}

func initSelfNetwork() {
	configContent := `network:
  version: 2
  renderer: networkd
  ethernets:
    ens5f1:
      dhcp4: no
      addresses:
        - 192.168.1.100/24
      routes:
        - to: 192.168.1.0/24
`
	configFile := fmt.Sprintf("/etc/netplan/%s.yaml", "ens5f1")
	_ = os.WriteFile(configFile, []byte(configContent), 0644)
}

func configureNetwork() {
	reader := bufio.NewReader(os.Stdin)
	var ip, netmask, gateway, selectedInterface string
	ipRegex := regexp.MustCompile(`^([0-9]{1,3}\.){3}[0-9]{1,3}$`)

	interfaces := getInterfaceNames()
	for {
		for num, name := range interfaces {
			fmt.Printf("%d. %s\n", num, name)
		}
		fmt.Printf("请选择一个网卡名称，用来配置网络，输入序号: ")
		serial, _ := reader.ReadString('\n')
		serial = strings.TrimSpace(serial)
		index, err := strconv.Atoi(serial)
		if err != nil || index < 0 || index >= len(interfaces) {
			fmt.Println("无效的序号，请重新输入.")
			continue
		}
		selectedInterface = interfaces[index]
		break
	}

	for {
		fmt.Print("请输入IP地址 (例如 192.168.1.100): ")
		ip, _ = reader.ReadString('\n')
		ip = strings.TrimSpace(ip)
		if !ipRegex.MatchString(ip) {
			fmt.Println("IP 地址不合法!")
		} else {
			break
		}
	}

	for {
		fmt.Print("请输入子网掩码 (例如 255.255.255.0): ")
		netmask, _ = reader.ReadString('\n')
		netmask = strings.TrimSpace(netmask)
		if !ipRegex.MatchString(netmask) {
			fmt.Println("子网掩码地址不合法!")
		} else {
			break
		}
	}

	for {
		fmt.Print("请输入网关 (例如 192.168.1.1): ")
		gateway, _ = reader.ReadString('\n')
		gateway = strings.TrimSpace(gateway)
		if gateway == "" {
			break
		}
		if !ipRegex.MatchString(gateway) {
			fmt.Println("网关地址不合法!")
		} else {
			if _, err := checkGatewayConnectivity(gateway); err != nil {
				continue
			}
			break
		}
	}

	fmt.Print("请输入 DNS (例如 8.8.8.8)，多个用逗号隔开: ")
	dns, _ := reader.ReadString('\n')
	dns = strings.TrimSpace(dns)
	dnsAddresses := strings.Split(dns, ",")

	cidrBits := subnetMaskToCIDR(netmask)

	configFile := fmt.Sprintf("/etc/netplan/%s.yaml", selectedInterface)
	configContent := fmt.Sprintf(`network:
  version: 2
  renderer: networkd
  ethernets:
    %s:
      dhcp4: no
      addresses:
        - %s/%d
      routes:
        - to: 0.0.0.0/0
          via: %s
      nameservers:
        addresses:
`, selectedInterface, ip, cidrBits, gateway)

	for _, dns = range dnsAddresses {
		configContent += fmt.Sprintf("          - %s\n", strings.TrimSpace(dns))
	}
	_ = os.WriteFile(configFile, []byte(configContent), 0644)

	if output, err := execCommand("netplan apply"); err != nil {
		log.Fatalf("网络配置错误: %s", output)
	}
	if output, err := checkLocalLoopBack(); err != nil {
		log.Fatalf(output)
	}
	log.Printf("%s\n%s%s\n", Green, "基础网络配置已完成", Reset)
}

func checkLocalLoopBack() (string, error) {
	if _, err := execCommand("ping -c 4 127.0.0.1"); err != nil {
		return "本地回环地址 127.0.0.1 不可达，请检查本地网络配置", err
	}
	return "", nil
}

func checkGatewayConnectivity(gateway string) (string, error) {
	fmt.Println("检查网关地址的可连接性")
	if _, err := execCommand(fmt.Sprintf("ping -c 4 %s", gateway)); err != nil {
		return "网关配置无效，请检查", err
	}
	return "", nil
}

func disableRootLogin() {
	output, err := execCommand("sed -i '/^#*PermitRootLogin/s/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config")
	if err != nil {
		log.Fatalf("配置禁止 root 登陆失败: %s", output)
	}
	output, err = execCommand("systemctl restart sshd")
	if err != nil {
		log.Fatalf("重启 SSHD 服务失败: %s", output)
	}
	log.Printf("%s\n%s%s\n", Green, "已禁止 root 直接登录", Reset)
}

func outputSystemInfo() {
	var output, suffix string
	commands := map[string]map[string]string{
		"主机名和状态": {
			"cmd":       "hostnamectl",
			"linebreak": "1",
		},
		"CPU 信息": {
			"cmd":       "echo \"核心数: $(nproc)\"; grep \"model name\" /proc/cpuinfo | head -n 1 | awk -F: '{print \"型号: \"$2}'",
			"linebreak": "1",
		},
		"内存大小": {
			"cmd":       "fgrep MemTotal /proc/meminfo | awk '{printf \"%.2f GB\\n\", $2/1024/1024}'",
			"linebreak": "1",
		},
		"磁盘状态": {
			"cmd":       "df -h / /data 2>/dev/null",
			"linebreak": "1",
		},
		"防火墙状态": {
			"cmd":       "ufw status",
			"linebreak": "0",
		},
		"OpenSSL 版本": {
			"cmd":       "openssl version -v | awk '{print $2}'",
			"linebreak": "0",
		},
		"OpenSSH 版本": {
			"cmd":       "ssh -V 2>&1 | awk '{print $4}'",
			"linebreak": "0",
		},
		"网络接口信息": {
			"cmd":       "ip -o -f inet addr show | awk '{print $2, $4, $5}'",
			"linebreak": "1",
		},
		"DNS 配置": {
			"cmd":       "grep nameserver /etc/resolv.conf",
			"linebreak": "1",
		},
		"文件描述符限制": {
			"cmd":       "sysctl -a | grep fs.file-max",
			"linebreak": "0",
		},
		"是否允许 root 登录": {
			"cmd":       "grep -E '^PermitRootLogin' /etc/ssh/sshd_config | awk '{print $2}' | { read result; [[ \"$result\" = \"no\" || \"$result\" = \"prohibit-password\" ]] && echo \"是\" || echo \"否\"; }",
			"linebreak": "0",
		},
	}
	fmt.Println(BrightYellow + "=================== 系统信息 ===================" + Reset)
	for desc, item := range commands {
		fmt.Println(strings.Repeat("-", 60))
		if item["linebreak"] == "1" {
			suffix = "\n"
		} else {
			suffix = " "
		}
		fmt.Printf("%s%s%s:%s", TitleColor, desc, Reset, suffix)
		output, _ = execCommand(item["cmd"])
		if desc == "网络接口信息" {
			output = getNetworkInfo(output)
		}
		fmt.Print(output)
	}
	fmt.Println(BrightYellow + "============================================" + Reset)
}

func getNetworkInfo(output string) string {
	var result string
	lines := strings.Split(strings.TrimSpace(output), "\n")
	result += fmt.Sprintf("%-20s %-20s %-20s\n", "接口", "IP 地址", "状态")
	for _, line := range lines {
		parts := strings.Fields(line)
		if len(parts) >= 3 && parts[0] != "lo" {
			result += fmt.Sprintf(
				"%-20s %-20s %-20s\n", parts[0], parts[1], parts[2],
			)
		}
	}
	return result
}
