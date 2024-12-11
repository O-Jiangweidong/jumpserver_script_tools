package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
)

const (
	Reset  = "\033[0m"
	Red    = "\033[31m"
	Green  = "\033[32m"
	Yellow = "\033[33m"
	Cyan   = "\033[36m"
)

func main() {
	menuInput := flag.String("m", "", "输入菜单序号，多个用逗号隔开")
	flag.Parse()

	if *menuInput != "" {
		// 处理多个菜单序号
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
			case "6":
				outputSystemInfo()
			default:
				log.Printf("无效的菜单序号: %s", menu)
			}
		}
		rebootMachine()
	} else {
		interactiveMenu()
	}
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
	fmt.Print("请输入 NTP 服务器地址（多个地址用空格分隔）: ")
	ntpServers, _ := reader.ReadString('\n')
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
		"fs.file-max": "fs.file-max = " + newLimit,
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
	fmt.Println("选择要执行的功能:")
	fmt.Println("1. 关闭 SELinux")
	fmt.Println("2. 配置时间服务器")
	fmt.Println("3. 系统参数优化")
	fmt.Println("4. 基础网络配置")
	fmt.Println("5. 禁止 root 直接登录")
	fmt.Println("6. 输出机器各种配置信息")
	fmt.Println("7. 退出")
}

func interactiveMenu() {
	reader := bufio.NewReader(os.Stdin)

	for {
		showMenu()
		fmt.Print("请输入选项: ")
		option, _ := reader.ReadString('\n')
		option = strings.TrimSpace(option)

		switch option {
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
		case "6":
			outputSystemInfo()
		case "7":
			log.Println("退出程序")
		default:
			log.Println("无效的选项，请重试")
			continue
		}
		if option == "1" || option == "3" || option == "4" {
			rebootMachine()
		}
		return
	}
}

func execCommand(cmd string) (string, error) {
	command := exec.Command("bash", "-c", cmd)
	output, err := command.CombinedOutput()
	if err != nil {
		return "", err
	}
	return string(output), nil
}

func configureNetwork() {
	reader := bufio.NewReader(os.Stdin)

	log.Print("请输入IP地址 (例如 192.168.1.100): ")
	ip, _ := reader.ReadString('\n')
	ip = strings.TrimSpace(ip)

	log.Print("请输入子网掩码 (例如 255.255.255.0): ")
	netmask, _ := reader.ReadString('\n')
	netmask = strings.TrimSpace(netmask)

	log.Print("请输入网关 (例如 192.168.1.1): ")
	gateway, _ := reader.ReadString('\n')
	gateway = strings.TrimSpace(gateway)

	log.Print("请输入DNS (例如 8.8.8.8): ")
	dns, _ := reader.ReadString('\n')
	dns = strings.TrimSpace(dns)

	output, err := execCommand(
		fmt.Sprintf("nmcli con mod 'System eth0' ipv4.addresses %s/%s", ip, netmaskToCIDR(netmask)),
	)
	if err != nil {
		log.Fatalf("配置 IP 失败: %s", output)
	}
	output, err = execCommand(fmt.Sprintf("nmcli con mod 'System eth0' ipv4.gateway %s", gateway))
	if err != nil {
		log.Fatalf("配置网关失败: %s", output)
	}
	output, err = execCommand(fmt.Sprintf("nmcli con mod 'System eth0' ipv4.dns %s", dns))
	if err != nil {
		log.Fatalf("配置 DNS 失败: %s", output)
	}
	output, err = execCommand("nmcli con up 'System eth0'")
	if err != nil {
		log.Fatalf("启动网卡失败: %s", output)
	}
	log.Printf("%s\n%s%s\n", Green, "基础网络配置已完成", Reset)
}

func netmaskToCIDR(netmask string) string {
	mask := strings.Split(netmask, ".")
	bits := 0
	for _, m := range mask {
		v := toBinaryString(m)
		bits += strings.Count(v, "1")
	}
	return fmt.Sprintf("%d", bits)
}

func toBinaryString(n string) string {
	num, _ := exec.Command("bash", "-c", fmt.Sprintf("echo %s | awk '{ printf \"%%08d\", strtonum(\"%s\") }'", n, n)).Output()
	return strings.TrimSpace(string(num))
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
	var output string
	commands := map[string]string{
		"主机名和状态":       "hostnamectl",
		"网络接口信息":       "ip -o -f inet addr show | awk '{print $2, $4, $5}'",
		"DNS 配置":       "grep -v '^#' /etc/resolv.conf",
		"文件描述符限制":      "sysctl -a | grep fs.file-max",
		"是否允许 root 登录": "grep -i '^PermitRootLogin' /etc/ssh/sshd_config | awk '{print $2}' | grep -q 'yes' && echo \"是\" || (grep -q '^#PermitRootLogin' /etc/ssh/sshd_config && echo \"是\" || echo \"否\")",
	}
	fmt.Println(Green + "========== 系统信息 ==========" + Reset)
	for desc, cmd := range commands {
		output, _ = execCommand(cmd)
		fmt.Println(strings.Repeat("-", 60))
		if desc == "网络接口信息" {
			printNetworkInfo(output)
		} else {
			fmt.Printf("%s%s:\n%s%s\n", Cyan, desc, output, Reset)
		}
	}
	fmt.Println(Green + "=============================" + Reset)
}

func printNetworkInfo(output string) {
	lines := strings.Split(strings.TrimSpace(output), "\n")
	fmt.Printf("%s网络接口信息:\n", Cyan)
	fmt.Printf("%s%-20s %-20s %-20s%s\n", Cyan, "接口", "IP 地址", "状态", Reset)
	for _, line := range lines {
		parts := strings.Fields(line)
		if len(parts) >= 3 {
			fmt.Printf("%s%-20s %-20s %-20s%s\n",
				Cyan, parts[0],
				parts[1],
				parts[2],
				Reset)
		}
	}
}
