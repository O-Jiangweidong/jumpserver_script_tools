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

	DefaultNTPServer  = "asia.pool.ntp.org"
	DefaultSubnetMask = "255.255.255.0"
	TitleColor        = BrightCyan
)

func main() {
	menuInput := flag.String("s", "", "Enter the menu numbers, separated by commas")
	showHelp := flag.Bool("m", false, "Display menu information")
	allDo := flag.Bool("a", false, "Whether execute all tasks")
	initNetwork := flag.Bool("i", false, "Initialize private network information")
	//test := flag.Bool("t", false, "Test")
	flag.Parse()

	//if *test {
	//	outputSystemInfo()
	//	return
	//}

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
					log.Printf("Invalid menu number: %s", menu)
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
		log.Println("SELinux check tool not found, skipping SELinux processing.")
		return
	}

	output, err := execCommand("sestatus")
	if err != nil || !strings.Contains(output, "enabled") {
		log.Println("SELinux is not enabled, skipping SELinux processing.")
		return
	}

	output, err = execCommand("setenforce 0")
	if err != nil {
		log.Fatalf("Failed to disable SELinux: %s", output)
	}
	output, err = execCommand("sed -i 's/^SELINUX=.*/SELINUX=disabled/' /etc/selinux/config")
	if err != nil {
		log.Fatalf("Failed to disable SELinux: %s", output)
	}
	log.Printf("%s\n%s%s\n", Green, "SELinux is disabled", Reset)
}

func checkAndInstallNTP() error {
	if _, err := exec.LookPath("ntpd"); err == nil {
		fmt.Println("NTP is already installed, skipping installation step.")
		return nil
	}

	var cmd *exec.Cmd
	if _, err := exec.LookPath("apt"); err == nil {
		cmd = exec.Command("apt", "install", "-y", "ntp")
	} else if _, err := exec.LookPath("yum"); err == nil {
		cmd = exec.Command("yum", "install", "-y", "ntp")
	} else {
		log.Fatalf("Unsupported package management tool(apt/yum)")
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
		log.Fatalf("Failed to install NTP service: %s", err)
	}

	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("Please enter the NTP server address (separate multiple addresses with spaces), default: %s: ", DefaultNTPServer)
	ntpServers, _ := reader.ReadString('\n')
	if ntpServers == "" {
		ntpServers = DefaultNTPServer
	}
	ntpServers = strings.TrimSpace(ntpServers)

	if err := updateNTPServers(ntpServers); err != nil {
		log.Fatalf("Failed to update NTP server: %s", err)
	}

	if err := startNTP(); err != nil {
		log.Fatalf("Failed to start NTP service: %s", err)
	}
	log.Printf("%s\n%s%s\n", Green, "NTP server is configured.", Reset)
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
		log.Fatalf("Failed to update limits.conf: %s", err)
	}

	sysctlConfigs := map[string]string{
		"fs.file-max":         "fs.file-max = " + newLimit,
		"net.ipv4.ip_forward": "net.ipv4.ip_forward = 1",
	}

	if err := updateConfigFile("/etc/sysctl.conf", sysctlConfigs); err != nil {
		log.Fatalf("Failed to persist file descriptor limit: %s", err)
	}

	if output, err := execCommand("sysctl -p"); err != nil {
		log.Fatalf("Failed to reload sysctl configuration: %s", output)
	}

	log.Printf("%s\n%s%s%s\n", Green, "System parameters have been optimized, file limit set to: ", newLimit, Reset)
}

func rebootMachine() {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Are you sure you want to restart the machine? (y/n): ")
	confirm, _ := reader.ReadString('\n')
	confirm = strings.TrimSpace(confirm)

	if confirm != "y" && confirm != "Y" {
		log.Println("Restart operation has been canceled")
		return
	}

	output, err := execCommand("reboot")
	if err != nil {
		log.Fatalf("Restart failed: %s", output)
	}
}

func showMenu() {
	fmt.Println("1. Disable SELinux")
	fmt.Println("2. Configure time server(NTP)")
	fmt.Println("3. System parameter optimization")
	fmt.Println("4. Basic network configuration")
	fmt.Println("5. Disable direct root login")
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
		log.Fatalf("Failed to retrieve network interface name: %s", output)
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
		fmt.Printf("Please select a network interface name to configure the network, enter the number: ")
		serial, _ := reader.ReadString('\n')
		serial = strings.TrimSpace(serial)
		index, err := strconv.Atoi(serial)
		if err != nil || index < 0 || index >= len(interfaces) {
			fmt.Println("Invalid number, please enter again.")
			continue
		}
		selectedInterface = interfaces[index]
		break
	}

	for {
		fmt.Print("Please enter the IP address (e.g., 192.168.1.100): ")
		ip, _ = reader.ReadString('\n')
		ip = strings.TrimSpace(ip)
		if !ipRegex.MatchString(ip) {
			fmt.Println("Invalid IP address!")
		} else {
			break
		}
	}

	for {
		fmt.Printf("Please enter the subnet mask, default: %s: ", DefaultSubnetMask)
		netmask, _ = reader.ReadString('\n')
		netmask = strings.TrimSpace(netmask)
		if netmask == "" {
			netmask = DefaultSubnetMask
		}
		if !ipRegex.MatchString(netmask) {
			fmt.Println("Invalid subnet mask!")
		} else {
			break
		}
	}

	for {
		fmt.Print("Please enter the gateway (e.g., 192.168.1.1): ")
		gateway, _ = reader.ReadString('\n')
		gateway = strings.TrimSpace(gateway)
		if gateway == "" {
			break
		}
		if !ipRegex.MatchString(gateway) {
			fmt.Println("Invalid gateway address!")
		} else {
			if _, err := checkGatewayConnectivity(gateway); err != nil {
				continue
			}
			break
		}
	}

	fmt.Print("Please enter the DNS (e.g., 8.8.8.8), separated by commas for multiple entries: ")
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
		log.Fatalf("Network configuration error: %s", output)
	}
	if output, err := checkLocalLoopBack(); err != nil {
		log.Fatalf(output)
	}
	log.Printf("%s\n%s%s\n", Green, "Basic network configuration has been completed", Reset)
}

func checkLocalLoopBack() (string, error) {
	if _, err := execCommand("ping -c 4 127.0.0.1"); err != nil {
		return "The local loop address 127.0.0.1 is unreachable. Please check the local network configuration.", err
	}
	return "", nil
}

func checkGatewayConnectivity(gateway string) (string, error) {
	fmt.Println("Check the connectivity of the gateway address")
	if _, err := execCommand(fmt.Sprintf("ping -c 4 %s", gateway)); err != nil {
		return "Invalid gateway configuration, please check", err
	}
	return "", nil
}

func disableRootLogin() {
	output, err := execCommand("sed -i '/^#*PermitRootLogin/s/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config")
	if err != nil {
		log.Fatalf("Failed to configure disabling root login: %s", output)
	}
	output, err = execCommand("systemctl restart sshd")
	if err != nil {
		log.Fatalf("Failed to restart the sshd service: %s", output)
	}
	log.Printf("%s\n%s%s\n", Green, "Direct root login has been disabled", Reset)
}

func outputSystemInfo() {
	var output, suffix string
	commands := map[string]map[string]string{
		"Hostname and status": {
			"cmd":       "hostnamectl",
			"linebreak": "1",
		},
		"CPU information": {
			"cmd":       "echo \"Number of cores: $(nproc)\"; grep \"model name\" /proc/cpuinfo | head -n 1 | awk -F: '{print \"Model: \"$2}'",
			"linebreak": "1",
		},
		"Memory size": {
			"cmd":       "fgrep MemTotal /proc/meminfo | awk '{printf \"%.2f GB\\n\", $2/1024/1024}'",
			"linebreak": "1",
		},
		"Disk status": {
			"cmd":       "df -h / /data 2>/dev/null",
			"linebreak": "1",
		},
		"Firewall status": {
			"cmd":       "ufw status",
			"linebreak": "0",
		},
		"OpenSSL version": {
			"cmd":       "openssl version -v | awk '{print $2}'",
			"linebreak": "0",
		},
		"OpenSSH version": {
			"cmd":       "ssh -V 2>&1 | awk '{print $4}'",
			"linebreak": "0",
		},
		"Network interface information": {
			"cmd":       "ip -o -f inet addr show | awk '{print $2, $4, $5}'",
			"linebreak": "1",
		},
		"DNS configuration": {
			"cmd":       "grep nameserver /etc/resolv.conf",
			"linebreak": "1",
		},
		"File descriptor limit": {
			"cmd":       "sysctl -a | grep fs.file-max",
			"linebreak": "0",
		},
		"Is root login allowed": {
			"cmd":       "grep -E '^PermitRootLogin' /etc/ssh/sshd_config | awk '{print $2}' | { read result; [[ \"$result\" = \"no\" || \"$result\" = \"prohibit-password\" ]] && echo \"Yes\" || echo \"No\"; }",
			"linebreak": "0",
		},
	}
	fmt.Println(BrightYellow + "=================== System information ===================" + Reset)
	for desc, item := range commands {
		fmt.Println(strings.Repeat("-", 60))
		if item["linebreak"] == "1" {
			suffix = "\n"
		} else {
			suffix = " "
		}
		fmt.Printf("%s%s%s:%s", TitleColor, desc, Reset, suffix)
		output, _ = execCommand(item["cmd"])
		if desc == "Network interface information" {
			output = getNetworkInfo(output)
		}
		fmt.Print(output)
	}
	fmt.Println(BrightYellow + "============================================" + Reset)
}

func getNetworkInfo(output string) string {
	var result string
	lines := strings.Split(strings.TrimSpace(output), "\n")
	result += fmt.Sprintf("%-20s %-20s %-20s\n", "Interface", "IP address", "status")
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
