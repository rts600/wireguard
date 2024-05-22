#!/bin/bash

exiterr()  { echo "Error: $1" >&2; exit 1; }
exiterr2() { exiterr "'apt-get install' failed."; }
exiterr3() { exiterr "'yum install' failed."; }
exiterr4() { exiterr "'zypper install' failed."; }

check_ip() {
	IP_REGEX='^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$'
	printf '%s' "$1" | tr -d '\n' | grep -Eq "$IP_REGEX"
}

check_os() {
	if grep -qs "ubuntu" /etc/os-release; then
		os="ubuntu"
		os_version=$(grep 'VERSION_ID' /etc/os-release | cut -d '"' -f 2 | tr -d '.')
	elif [[ -e /etc/debian_version ]]; then
		os="debian"
		os_version=$(grep -oE '[0-9]+' /etc/debian_version | head -1)
	elif [[ -e /etc/almalinux-release || -e /etc/rocky-release || -e /etc/centos-release ]]; then
		os="centos"
		os_version=$(grep -shoE '[0-9]+' /etc/almalinux-release /etc/rocky-release /etc/centos-release | head -1)
	elif [[ -e /etc/fedora-release ]]; then
		os="fedora"
		os_version=$(grep -oE '[0-9]+' /etc/fedora-release | head -1)
	elif [[ -e /etc/SUSE-brand && "$(head -1 /etc/SUSE-brand)" == "openSUSE" ]]; then
		os="openSUSE"
		os_version=$(tail -1 /etc/SUSE-brand | grep -oE '[0-9\\.]+')
	else
		exiterr "This installer seems to be running on an unsupported distribution.
Supported distros are Ubuntu, Debian, AlmaLinux, Rocky Linux, CentOS, Fedora and openSUSE."
	fi
}

check_os_ver() {
	if [[ "$os" == "ubuntu" && "$os_version" -lt 1804 ]]; then
		exiterr "Ubuntu 18.04 or higher is required."
	fi

	if [[ "$os" == "debian" && "$os_version" -lt 10 ]]; then
		exiterr "Debian 10 or higher is required."
	fi
}

check_dns_name() {
	FQDN_REGEX='^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
	printf '%s' "$1" | tr -d '\n' | grep -Eq "$FQDN_REGEX"
}

install_wget() {
	# Detect some Debian minimal setups where neither wget nor curl are installed
	if ! hash wget 2>/dev/null && ! hash curl 2>/dev/null; then
		if [ "$auto" = 0 ]; then
			echo "Wget is required."
			read -n1 -r -p "Press any key to install Wget and continue..."
		fi
		export DEBIAN_FRONTEND=noninteractive
		(
			set -x
			apt-get -yqq update || apt-get -yqq update
			apt-get -yqq install wget >/dev/null
		) || exiterr2
	fi
}

install_iproute() {
	if ! hash ip 2>/dev/null; then
		if [ "$auto" = 0 ]; then
			echo "iproute is required."
			read -n1 -r -p "Press any key to install iproute and continue..."
		fi
		if [ "$os" = "debian" ] || [ "$os" = "ubuntu" ]; then
			export DEBIAN_FRONTEND=noninteractive
			(
				set -x
				apt-get -yqq update || apt-get -yqq update
				apt-get -yqq install iproute2 >/dev/null
			) || exiterr2
		fi
	fi
}

show_start_setup() {
	if [ "$auto" = 0 ]; then
		echo
		echo '��ʼ��װWireGuard'
		echo
		echo '���ʹ��Ĭ��ѡ����س�������'
	else
		echo
		echo 'ʹ��Ĭ��ѡ�װWireGuard'
	fi
}

enter_server_address() {
	echo
	printf "����ʹ������������̨WireGuard�������� [y/N] "
	read -r response
	case $response in
		[yY][eE][sS]|[yY])
			use_dns_name=1
			echo
			;;
		*)
			use_dns_name=0
			;;
	esac
	if [ "$use_dns_name" = 1 ]; then
		read -rp "��������̨WireGuard������������: " server_addr
		until check_dns_name "$server_addr"; do
			echo "������Ч��������ϸ������."
			read -rp "��������̨WireGuard������������: " server_addr
		done
		ip="$server_addr"
		echo
		echo "Note: ��ȷ�������ѽ�������̨WireGuard��������IPv4��ַ"
	else
		detect_ip
		check_nat_ip
	fi
}

find_public_ip() {
	ip_url1="http://ipv4.icanhazip.com"
	ip_url2="http://ip1.dynupdate.no-ip.com"
	# Get public IP and sanitize with grep
	get_public_ip=$(grep -m 1 -oE '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' <<< "$(wget -T 10 -t 1 -4qO- "$ip_url1" || curl -m 10 -4Ls "$ip_url1")")
	if ! check_ip "$get_public_ip"; then
		get_public_ip=$(grep -m 1 -oE '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' <<< "$(wget -T 10 -t 1 -4qO- "$ip_url2" || curl -m 10 -4Ls "$ip_url2")")
	fi
}

detect_ip() {
	# If system has a single IPv4, it is selected automatically.
	if [[ $(ip -4 addr | grep inet | grep -vEc '127(\.[0-9]{1,3}){3}') -eq 1 ]]; then
		ip=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}')
	else
		# Use the IP address on the default route
		ip=$(ip -4 route get 1 | sed 's/ uid .*//' | awk '{print $NF;exit}' 2>/dev/null)
		if ! check_ip "$ip"; then
			find_public_ip
			ip_match=0
			if [ -n "$get_public_ip" ]; then
				ip_list=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}')
				while IFS= read -r line; do
					if [ "$line" = "$get_public_ip" ]; then
						ip_match=1
						ip="$line"
					fi
				done <<< "$ip_list"
			fi
			if [ "$ip_match" = 0 ]; then
				if [ "$auto" = 0 ]; then
					echo
					echo "��ѡ��Ҫʹ�õ�IP"
					num_of_ip=$(ip -4 addr | grep inet | grep -vEc '127(\.[0-9]{1,3}){3}')
					ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | nl -s ') '
					read -rp "IPv4 address [1]: " ip_num
					until [[ -z "$ip_num" || "$ip_num" =~ ^[0-9]+$ && "$ip_num" -le "$num_of_ip" ]]; do
						echo "$ip_num: invalid selection."
						read -rp "IPv4 address [1]: " ip_num
					done
					[[ -z "$ip_num" ]] && ip_num=1
				else
					ip_num=1
				fi
				ip=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | sed -n "$ip_num"p)
			fi
		fi
	fi
	if ! check_ip "$ip"; then
		echo "����: �޷���ȡ����������IP��ַ���˳�" >&2
		exit 1
	fi
}

check_nat_ip() {
	# If $ip is a private IP address, the server must be behind NAT
	if printf '%s' "$ip" | grep -qE '^(10|127|172\.(1[6-9]|2[0-9]|3[0-1])|192\.168|169\.254)\.'; then
		find_public_ip
		if ! check_ip "$get_public_ip"; then
			if [ "$auto" = 0 ]; then
				echo
				echo "����ʹ�ù���IPv4��ַ"
				read -rp "Public IPv4 address: " public_ip
				until check_ip "$public_ip"; do
					echo "Invalid input."
					read -rp "Public IPv4 address: " public_ip
				done
			else
				echo "����: �޷���ȡ���������Ĺ���IP��ַ���˳�" >&2
				exit 1
			fi
		else
			public_ip="$get_public_ip"
		fi
	fi
}

show_config() {
	if [ "$auto" != 0 ]; then
		echo
		printf '%s' "Server IP: "
		[ -n "$public_ip" ] && printf '%s\n' "$public_ip" || printf '%s\n' "$ip"
		echo "Port: UDP/51820"
		echo "Client name: client"
		echo "Client DNS: Google Public DNS"
	fi
}

detect_ipv6() {
	ip6=""
	if [[ $(ip -6 addr | grep -c 'inet6 [23]') -ne 0 ]]; then
		ip6=$(ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}' | sed -n 1p)
	fi
}

select_port() {
	if [ "$auto" = 0 ]; then
		echo
		echo "Which port should WireGuard listen to?"
		read -rp "Port [51820]: " port
		until [[ -z "$port" || "$port" =~ ^[0-9]+$ && "$port" -le 65535 ]]; do
			echo "$port: invalid port."
			read -rp "Port [51820]: " port
		done
		[[ -z "$port" ]] && port=51820
	else
		port=51820
	fi
}

enter_custom_dns() {
	read -rp "��������DNS������: " dns1
	until check_ip "$dns1"; do
		echo "DNS��������Ч."
		read -rp "��������DNS������: " dns1
	done
	read -rp "�������DNS������(�س�������): " dns2
	until [ -z "$dns2" ] || check_ip "$dns2"; do
		echo "DNS��������Ч."
		read -rp "�������DNS������(�س�������): " dns2
	done
}

set_client_name() {
	# Allow a limited set of characters to avoid conflicts
	# Limit to 15 characters for compatibility with Linux clients
	client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_client" | cut -c-15)
}

enter_client_name() {
	if [ "$auto" = 0 ]; then
		echo
		echo "�������һ���ͻ��˵�����:"
		read -rp "Name [client]: " unsanitized_client
		set_client_name
		[[ -z "$client" ]] && client=client
	else
		client=client
	fi
}

check_firewall() {
	# Install a firewall if firewalld or iptables are not already available
	if ! systemctl is-active --quiet firewalld.service && ! hash iptables 2>/dev/null; then
		if [[ "$os" == "debian" || "$os" == "ubuntu" ]]; then
			firewall="iptables"
		fi
	fi
}

abort_and_exit() {
	echo "�˳�" >&2
	exit 1
}

confirm_setup() {
	if [ "$auto" = 0 ]; then
		printf "�Ƿ����? [Y/n] "
		read -r response
		case $response in
			[yY][eE][sS]|[yY]|'')
				:
				;;
			*)
				abort_and_exit
				;;
		esac
	fi
}

new_client_dns() {
	if [ "$auto" = 0 ]; then
		echo
		echo "��ѡ��DNS������:"
		echo "   1) ��ǰ��DNS������"
		echo "   2) Google����DNS"
		echo "   3) Cloudflare DNS"
		echo "   4) OpenDNS"
		echo "   5) Quad9"
		echo "   6) AdGuard DNS"
		echo "   7) Custom"
		read -rp "DNS server [2]: " dns
		until [[ -z "$dns" || "$dns" =~ ^[1-7]$ ]]; do
			echo "$dns: ѡ����Ч"
			read -rp "DNS server [2]: " dns
		done
	else
		dns=2
	fi
		# DNS
	case "$dns" in
		1)
			# Locate the proper resolv.conf
			# Needed for systems running systemd-resolved
			if grep '^nameserver' "/etc/resolv.conf" | grep -qv '127.0.0.53' ; then
				resolv_conf="/etc/resolv.conf"
			else
				resolv_conf="/run/systemd/resolve/resolv.conf"
			fi
			# Extract nameservers and provide them in the required format
			dns=$(grep -v '^#\|^;' "$resolv_conf" | grep '^nameserver' | grep -v '127.0.0.53' | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | xargs | sed -e 's/ /, /g')
		;;
		2|"")
			dns="8.8.8.8, 8.8.4.4"
		;;
		3)
			dns="1.1.1.1, 1.0.0.1"
		;;
		4)
			dns="208.67.222.222, 208.67.220.220"
		;;
		5)
			dns="9.9.9.9, 149.112.112.112"
		;;
		6)
			dns="94.140.14.14, 94.140.15.15"
		;;
		7)
			enter_custom_dns
			if [ -n "$dns2" ]; then
				dns="$dns1, $dns2"
			else
				dns="$dns1"
			fi
		;;
	esac
}

get_export_dir() {
	export_to_home_dir=0
	export_dir=~/
	if [ -n "$SUDO_USER" ] && getent group "$SUDO_USER" >/dev/null 2>&1; then
		user_home_dir=$(getent passwd "$SUDO_USER" 2>/dev/null | cut -d: -f6)
		if [ -d "$user_home_dir" ] && [ "$user_home_dir" != "/" ]; then
			export_dir="$user_home_dir/"
			export_to_home_dir=1
		fi
	fi
}

select_client_ip() {
	# Given a list of the assigned internal IPv4 addresses, obtain the lowest still
	# available octet. Important to start looking at 2, because 1 is our gateway.
	octet=2
	while grep AllowedIPs /etc/wireguard/wg0.conf | cut -d "." -f 4 | cut -d "/" -f 1 | grep -q "$octet"; do
		(( octet++ ))
	done
	# Don't break the WireGuard configuration in case the address space is full
	if [[ "$octet" -eq 255 ]]; then
		exiterr "������253���ͻ��ˣ�WireGuard�޷���Ӹ���ͻ���"
	fi
}

new_client_setup() {
	select_client_ip
	specify_ip=n
	if [ "$1" = "add_client" ]; then
		echo
		read -rp "���µĿͻ���ָ������IP��ַ��[y/N]: " specify_ip
		until [[ "$specify_ip" =~ ^[yYnN]*$ ]]; do
			echo "$specify_ip: ѡ����Ч"
			read -rp "���µĿͻ���ָ������IP��ַ��[y/N]: " specify_ip
		done
		if [[ ! "$specify_ip" =~ ^[yY]$ ]]; then
			echo "Using auto assigned IP address 10.7.0.$octet."
		fi
	fi
	if [[ "$specify_ip" =~ ^[yY]$ ]]; then
		echo
		read -rp "������ÿͻ��˵�����IP��ַ(���磺10.7.0.X): " client_ip
		octet=$(printf '%s' "$client_ip" | cut -d "." -f 4)
		until [[ $client_ip =~ ^10\.7\.0\.([2-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-4])$ ]] \
			&& ! grep AllowedIPs /etc/wireguard/wg0.conf | cut -d "." -f 4 | cut -d "/" -f 1 | grep -q "$octet"; do
			if [[ ! $client_ip =~ ^10\.7\.0\.([2-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-4])$ ]]; then
				echo "��Ч��IP��ַ��Χ��10.7.0.2 - 10.7.0.254."
			else
				echo "IP��ַ�ѱ�ʹ��"
			fi
			read -rp "������ÿͻ��˵�����IP��ַ(���磺10.7.0.X): " client_ip
			octet=$(printf '%s' "$client_ip" | cut -d "." -f 4)
		done
	fi
	key=$(wg genkey)
	psk=$(wg genpsk)
	# Configure client in the server
	cat << EOF >> /etc/wireguard/wg0.conf
# BEGIN_PEER $client
[Peer]
PublicKey = $(wg pubkey <<< "$key")
PresharedKey = $psk
AllowedIPs = 10.7.0.$octet/32$(grep -q 'fddd:2c4:2c4:2c4::1' /etc/wireguard/wg0.conf && echo ", fddd:2c4:2c4:2c4::$octet/128")
# END_PEER $client
EOF
	# Create client configuration
	get_export_dir
	cat << EOF > "$export_dir$client".conf
[Interface]
Address = 10.7.0.$octet/24$(grep -q 'fddd:2c4:2c4:2c4::1' /etc/wireguard/wg0.conf && echo ", fddd:2c4:2c4:2c4::$octet/64")
DNS = $dns
PrivateKey = $key

[Peer]
PublicKey = $(grep PrivateKey /etc/wireguard/wg0.conf | cut -d " " -f 3 | wg pubkey)
PresharedKey = $psk
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = $(grep '^# ENDPOINT' /etc/wireguard/wg0.conf | cut -d " " -f 3):$(grep ListenPort /etc/wireguard/wg0.conf | cut -d " " -f 3)
PersistentKeepalive = 25
EOF
	if [ "$export_to_home_dir" = 1 ]; then
		chown "$SUDO_USER:$SUDO_USER" "$export_dir$client".conf
	fi
	chmod 600 "$export_dir$client".conf
}

update_sysctl() {
	mkdir -p /etc/sysctl.d
	conf_fwd="/etc/sysctl.d/99-wireguard-forward.conf"
	conf_opt="/etc/sysctl.d/99-wireguard-optimize.conf"
	# Enable net.ipv4.ip_forward for the system
	echo 'net.ipv4.ip_forward=1' > "$conf_fwd"
	if [[ -n "$ip6" ]]; then
		# Enable net.ipv6.conf.all.forwarding for the system
		echo "net.ipv6.conf.all.forwarding=1" >> "$conf_fwd"
	fi
	# Apply sysctl settings
	sysctl -e -q -p "$conf_fwd"
	sysctl -e -q -p "$conf_opt"
}

update_rclocal() {
	ipt_cmd="systemctl restart wg-iptables.service"
	if ! grep -qs "$ipt_cmd" /etc/rc.local; then
		if [ ! -f /etc/rc.local ]; then
			echo '#!/bin/sh' > /etc/rc.local
		else
			if [ "$os" = "ubuntu" ] || [ "$os" = "debian" ]; then
				sed --follow-symlinks -i '/^exit 0/d' /etc/rc.local
			fi
		fi
cat >> /etc/rc.local <<EOF

$ipt_cmd
EOF
		if [ "$os" = "ubuntu" ] || [ "$os" = "debian" ]; then
			echo "exit 0" >> /etc/rc.local
		fi
		chmod +x /etc/rc.local
	fi
}

show_usage() {
	if [ -n "$1" ]; then
		echo "Error: $1" >&2
	fi
cat 1>&2 <<EOF

Usage: bash $0 [options]

Options:
  --auto      auto install WireGuard using default options
  -h, --help  show this help message and exit

EOF
	exit 1
}

wgsetup() {

export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

if [ "$(id -u)" != 0 ]; then
	exiterr "��ʹ��root�û���װ'"
fi

# Detect Debian users running the script with "sh" instead of bash
if readlink /proc/$$/exe | grep -q "dash"; then
	exiterr 'This installer needs to be run with "bash", not "sh".'
fi

# Detect OpenVZ 6
if [[ $(uname -r | cut -d "." -f 1) -eq 2 ]]; then
	exiterr "The system is running an old kernel, please update"
fi

check_os
check_os_ver

if systemd-detect-virt -cq 2>/dev/null; then
	exiterr "This system is running inside a container, which is not supported."
fi

auto=0
if [[ ! -e /etc/wireguard/wg0.conf ]]; then
	check_nftables
	while [ "$#" -gt 0 ]; do
		case $1 in
			--auto)
				auto=1
				shift
				;;
			-h|--help)
				show_usage
				;;
			*)
				show_usage "Unknown parameter: $1"
				;;
		esac
	done
	install_wget
	install_iproute
	show_start_setup
	public_ip=""
	if [ "$auto" = 0 ]; then
		enter_server_address
	else
		detect_ip
		check_nat_ip
	fi
	show_config
	detect_ipv6
	select_port
	enter_client_name
	new_client_dns
	if [ "$auto" = 0 ]; then
		echo
		echo "��ʼ��װWireGuard"
	fi
	check_firewall
	confirm_setup
	echo
	echo "���ڰ�װWireGuard, ���Ժ�..."
	if [[ "$os" == "ubuntu" ]]; then
		export DEBIAN_FRONTEND=noninteractive
		(
			set -x
			apt-get -yqq update || apt-get -yqq update
			apt-get -yqq install wireguard qrencode $firewall >/dev/null
		) || exiterr2
	elif [[ "$os" == "debian" && "$os_version" -ge 11 ]]; then
		export DEBIAN_FRONTEND=noninteractive
		(
			set -x
			apt-get -yqq update || apt-get -yqq update
			apt-get -yqq install wireguard qrencode $firewall >/dev/null
		) || exiterr2
	elif [[ "$os" == "debian" && "$os_version" -eq 10 ]]; then
		if ! grep -qs '^deb .* buster-backports main' /etc/apt/sources.list /etc/apt/sources.list.d/*.list; then
			echo "deb http://deb.debian.org/debian buster-backports main" >> /etc/apt/sources.list
		fi
		export DEBIAN_FRONTEND=noninteractive
		(
			set -x
			apt-get -yqq update || apt-get -yqq update
			# Try to install kernel headers for the running kernel and avoid a reboot. This
			# can fail, so it's important to run separately from the other apt-get command.
			apt-get -yqq install linux-headers-"$(uname -r)" >/dev/null
		)
		# There are cleaner ways to find out the $architecture, but we require an
		# specific format for the package name and this approach provides what we need.
		architecture=$(dpkg --get-selections 'linux-image-*-*' | cut -f 1 | grep -oE '[^-]*$' -m 1)
		# linux-headers-$architecture points to the latest headers. We install it
		# because if the system has an outdated kernel, there is no guarantee that old
		# headers were still downloadable and to provide suitable headers for future
		# kernel updates.
		(
			set -x
			apt-get -yqq install linux-headers-"$architecture" >/dev/null
			apt-get -yqq install wireguard qrencode $firewall >/dev/null
		) || exiterr2
	fi
	[ ! -d /etc/wireguard ] && exiterr2
	# Generate wg0.conf
	cat << EOF > /etc/wireguard/wg0.conf
# Do not alter the commented lines
# They are used by wireguard-install
# ENDPOINT $([[ -n "$public_ip" ]] && echo "$public_ip" || echo "$ip")

[Interface]
Address = 10.7.0.1/24$([[ -n "$ip6" ]] && echo ", fddd:2c4:2c4:2c4::1/64")
PrivateKey = $(wg genkey)
ListenPort = $port

EOF
	chmod 600 /etc/wireguard/wg0.conf
	update_sysctl
	if systemctl is-active --quiet firewalld.service; then
		# Using both permanent and not permanent rules to avoid a firewalld reload
		firewall-cmd -q --add-port="$port"/udp
		firewall-cmd -q --zone=trusted --add-source=10.7.0.0/24
		firewall-cmd -q --permanent --add-port="$port"/udp
		firewall-cmd -q --permanent --zone=trusted --add-source=10.7.0.0/24
		# Set NAT for the VPN subnet
		firewall-cmd -q --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.7.0.0/24 ! -d 10.7.0.0/24 -j MASQUERADE
		firewall-cmd -q --permanent --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.7.0.0/24 ! -d 10.7.0.0/24 -j MASQUERADE
		if [[ -n "$ip6" ]]; then
			firewall-cmd -q --zone=trusted --add-source=fddd:2c4:2c4:2c4::/64
			firewall-cmd -q --permanent --zone=trusted --add-source=fddd:2c4:2c4:2c4::/64
			firewall-cmd -q --direct --add-rule ipv6 nat POSTROUTING 0 -s fddd:2c4:2c4:2c4::/64 ! -d fddd:2c4:2c4:2c4::/64 -j MASQUERADE
			firewall-cmd -q --permanent --direct --add-rule ipv6 nat POSTROUTING 0 -s fddd:2c4:2c4:2c4::/64 ! -d fddd:2c4:2c4:2c4::/64 -j MASQUERADE
		fi
	else
		# Create a service to set up persistent iptables rules
		iptables_path=$(command -v iptables)
		ip6tables_path=$(command -v ip6tables)
		# nf_tables is not available as standard in OVZ kernels. So use iptables-legacy
		# if we are in OVZ, with a nf_tables backend and iptables-legacy is available.
		if [[ $(systemd-detect-virt) == "openvz" ]] && readlink -f "$(command -v iptables)" | grep -q "nft" && hash iptables-legacy 2>/dev/null; then
			iptables_path=$(command -v iptables-legacy)
			ip6tables_path=$(command -v ip6tables-legacy)
		fi
		echo "[Unit]
Before=network.target
[Service]
Type=oneshot
ExecStart=$iptables_path -t nat -A POSTROUTING -s 10.7.0.0/24 ! -d 10.7.0.0/24 -j MASQUERADE
ExecStart=$iptables_path -I INPUT -p udp --dport $port -j ACCEPT
ExecStart=$iptables_path -I FORWARD -s 10.7.0.0/24 -j ACCEPT
ExecStart=$iptables_path -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
ExecStop=$iptables_path -t nat -D POSTROUTING -s 10.7.0.0/24 ! -d 10.7.0.0/24 -j MASQUERADE
ExecStop=$iptables_path -D INPUT -p udp --dport $port -j ACCEPT
ExecStop=$iptables_path -D FORWARD -s 10.7.0.0/24 -j ACCEPT
ExecStop=$iptables_path -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT" > /etc/systemd/system/wg-iptables.service
		if [[ -n "$ip6" ]]; then
			echo "ExecStart=$ip6tables_path -t nat -A POSTROUTING -s fddd:2c4:2c4:2c4::/64 ! -d fddd:2c4:2c4:2c4::/64 -j MASQUERADE
ExecStart=$ip6tables_path -I FORWARD -s fddd:2c4:2c4:2c4::/64 -j ACCEPT
ExecStart=$ip6tables_path -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
ExecStop=$ip6tables_path -t nat -D POSTROUTING -s fddd:2c4:2c4:2c4::/64 ! -d fddd:2c4:2c4:2c4::/64 -j MASQUERADE
ExecStop=$ip6tables_path -D FORWARD -s fddd:2c4:2c4:2c4::/64 -j ACCEPT
ExecStop=$ip6tables_path -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT" >> /etc/systemd/system/wg-iptables.service
		fi
		echo "RemainAfterExit=yes
[Install]
WantedBy=multi-user.target" >> /etc/systemd/system/wg-iptables.service
		(
			set -x
			systemctl enable --now wg-iptables.service >/dev/null 2>&1
		)
	fi
	# Generates the custom client.conf
	new_client_setup
	# Enable and start the wg-quick service
	(
		set -x
		systemctl enable --now wg-quick@wg0.service >/dev/null 2>&1
	)
	echo
	qrencode -t UTF8 < "$export_dir$client".conf
	echo -e '\xE2\x86\x91 That is a QR code containing the client configuration.'
	echo
	# If the kernel module didn't load, system probably had an outdated kernel
	# We'll try to help, but will not force a kernel upgrade upon the user
	if ! modprobe -nq wireguard; then
		echo "Warning!"
		echo "Installation was finished, but the WireGuard kernel module could not load."
		if [[ "$os" == "ubuntu" && "$os_version" -eq 1804 ]]; then
			echo 'Upgrade the kernel and headers with "apt-get install linux-generic" and restart.'
		elif [[ "$os" == "debian" && "$os_version" -eq 10 ]]; then
			echo "Upgrade the kernel with \"apt-get install linux-image-$architecture\" and restart."
		fi
	else
		echo "���!"
	fi
	echo
	echo "�ͻ��������ļ�: $export_dir$client.conf"
	echo "���������нű�����µĿͻ���."
else
	show_header
	echo
	echo "WireGuard�Ѱ�װ���"
	echo
	echo "��ѡ��:"
	echo "   1) ����µĿͻ���"
	echo "   2) �г����пͻ���"
	echo "   3) ɾ�����пͻ���"
	echo "   4) ��ʾ�ͻ���QR code"
	echo "   5) ж��WireGuard"
	echo "   6) �˳�"
	read -rp "Option: " option
	until [[ "$option" =~ ^[1-6]$ ]]; do
		echo "$option: ѡ����Ч"
		read -rp "Option: " option
	done
	case "$option" in
		1)
			echo
			echo "������ͻ�������:"
			read -rp "Name: " unsanitized_client
			[ -z "$unsanitized_client" ] && abort_and_exit
			set_client_name
			while [[ -z "$client" ]] || grep -q "^# BEGIN_PEER $client$" /etc/wireguard/wg0.conf; do
				echo "$client: invalid name."
				read -rp "Name: " unsanitized_client
				[ -z "$unsanitized_client" ] && abort_and_exit
				set_client_name
			done
			new_client_dns
			new_client_setup add_client
			# Append new client configuration to the WireGuard interface
			wg addconf wg0 <(sed -n "/^# BEGIN_PEER $client/,/^# END_PEER $client/p" /etc/wireguard/wg0.conf)
			echo
			qrencode -t UTF8 < "$export_dir$client".conf
			echo -e '\xE2\x86\x91 That is a QR code containing the client configuration.'
			echo
			echo "$client �����. �ͻ��������ļ�: $export_dir$client.conf"
			exit
		;;
		2)
			echo
			echo "���ڼ�����пͻ���..."
			num_of_clients=$(grep -c '^# BEGIN_PEER' /etc/wireguard/wg0.conf)
			if [[ "$num_of_clients" = 0 ]]; then
				echo
				echo "��ǰ�޿ͻ���"
				exit
			fi
			echo
			grep '^# BEGIN_PEER' /etc/wireguard/wg0.conf | cut -d ' ' -f 3 | nl -s ') '
			if [ "$num_of_clients" = 1 ]; then
				printf '\n%s\n' "Total: 1 client"
			elif [ -n "$num_of_clients" ]; then
				printf '\n%s\n' "Total: $num_of_clients clients"
			fi
			exit
		;;
		3)
			num_of_clients=$(grep -c '^# BEGIN_PEER' /etc/wireguard/wg0.conf)
			if [[ "$num_of_clients" = 0 ]]; then
				echo
				echo "��ǰ�޿ͻ���"
				exit
			fi
			echo
			echo "ѡ��Ҫɾ���Ŀͻ���:"
			grep '^# BEGIN_PEER' /etc/wireguard/wg0.conf | cut -d ' ' -f 3 | nl -s ') '
			read -rp "Client: " client_num
			[ -z "$client_num" ] && abort_and_exit
			until [[ "$client_num" =~ ^[0-9]+$ && "$client_num" -le "$num_of_clients" ]]; do
				echo "$client_num: invalid selection."
				read -rp "Client: " client_num
				[ -z "$client_num" ] && abort_and_exit
			done
			client=$(grep '^# BEGIN_PEER' /etc/wireguard/wg0.conf | cut -d ' ' -f 3 | sed -n "$client_num"p)
			echo
			read -rp "ȷ��ɾ�� $client ? [y/N]: " remove
			until [[ "$remove" =~ ^[yYnN]*$ ]]; do
				echo "$remove: invalid selection."
				read -rp "ȷ��ɾ�� $client ? [y/N]: " remove
			done
			if [[ "$remove" =~ ^[yY]$ ]]; then
				echo
				echo "����ɾ�� $client..."
				# The following is the right way to avoid disrupting other active connections:
				# Remove from the live interface
				wg set wg0 peer "$(sed -n "/^# BEGIN_PEER $client$/,\$p" /etc/wireguard/wg0.conf | grep -m 1 PublicKey | cut -d " " -f 3)" remove
				# Remove from the configuration file
				sed -i "/^# BEGIN_PEER $client$/,/^# END_PEER $client$/d" /etc/wireguard/wg0.conf
				get_export_dir
				wg_file="$export_dir$client.conf"
				if [ -f "$wg_file" ]; then
					echo "����ɾ�� $wg_file..."
					rm -f "$wg_file"
				fi
				echo
				echo "$client ��ɾ��!"
			else
				echo
				echo "$client ɾ������!"
			fi
			exit
		;;
		4)
			num_of_clients=$(grep -c '^# BEGIN_PEER' /etc/wireguard/wg0.conf)
			if [[ "$num_of_clients" = 0 ]]; then
				echo
				echo "��ǰ�޿ͻ���"
				exit
			fi
			echo
			echo "ѡ��Ҫ��ʾQR code�Ŀͻ���:"
			grep '^# BEGIN_PEER' /etc/wireguard/wg0.conf | cut -d ' ' -f 3 | nl -s ') '
			read -rp "Client: " client_num
			[ -z "$client_num" ] && abort_and_exit
			until [[ "$client_num" =~ ^[0-9]+$ && "$client_num" -le "$num_of_clients" ]]; do
				echo "$client_num: ѡ����Ч"
				read -rp "Client: " client_num
				[ -z "$client_num" ] && abort_and_exit
			done
			client=$(grep '^# BEGIN_PEER' /etc/wireguard/wg0.conf | cut -d ' ' -f 3 | sed -n "$client_num"p)
			echo
			get_export_dir
			wg_file="$export_dir$client.conf"
			if [ ! -f "$wg_file" ]; then
				echo "����: �޷���ʾQR code. �ͻ��������ļ� $wg_file ��ʧ" >&2
				exit 1
			fi
			qrencode -t UTF8 < "$wg_file"
			echo -e '\xE2\x86\x91 That is a QR code containing the client configuration.'
			echo
			echo "'$client' �������ļ�: $wg_file"
			exit
		;;
		5)
			echo
			read -rp "ȷ��ж��WireGuard? [y/N]: " remove
			until [[ "$remove" =~ ^[yYnN]*$ ]]; do
				echo "$remove: ѡ����Ч"
				read -rp "ȷ��ж��WireGuard? [y/N]: " remove
			done
			if [[ "$remove" =~ ^[yY]$ ]]; then
				echo
				echo "����ж��WireGuard, ���Ժ�..."
				port=$(grep '^ListenPort' /etc/wireguard/wg0.conf | cut -d " " -f 3)
				if systemctl is-active --quiet firewalld.service; then
					ip=$(firewall-cmd --direct --get-rules ipv4 nat POSTROUTING | grep '\-s 10.7.0.0/24 '"'"'!'"'"' -d 10.7.0.0/24' | grep -oE '[^ ]+$')
					# Using both permanent and not permanent rules to avoid a firewalld reload.
					firewall-cmd -q --remove-port="$port"/udp
					firewall-cmd -q --zone=trusted --remove-source=10.7.0.0/24
					firewall-cmd -q --permanent --remove-port="$port"/udp
					firewall-cmd -q --permanent --zone=trusted --remove-source=10.7.0.0/24
					firewall-cmd -q --direct --remove-rule ipv4 nat POSTROUTING 0 -s 10.7.0.0/24 ! -d 10.7.0.0/24 -j MASQUERADE
					firewall-cmd -q --permanent --direct --remove-rule ipv4 nat POSTROUTING 0 -s 10.7.0.0/24 ! -d 10.7.0.0/24 -j MASQUERADE
					if grep -qs 'fddd:2c4:2c4:2c4::1/64' /etc/wireguard/wg0.conf; then
						ip6=$(firewall-cmd --direct --get-rules ipv6 nat POSTROUTING | grep '\-s fddd:2c4:2c4:2c4::/64 '"'"'!'"'"' -d fddd:2c4:2c4:2c4::/64' | grep -oE '[^ ]+$')
						firewall-cmd -q --zone=trusted --remove-source=fddd:2c4:2c4:2c4::/64
						firewall-cmd -q --permanent --zone=trusted --remove-source=fddd:2c4:2c4:2c4::/64
						firewall-cmd -q --direct --remove-rule ipv6 nat POSTROUTING 0 -s fddd:2c4:2c4:2c4::/64 ! -d fddd:2c4:2c4:2c4::/64 -j MASQUERADE
						firewall-cmd -q --permanent --direct --remove-rule ipv6 nat POSTROUTING 0 -s fddd:2c4:2c4:2c4::/64 ! -d fddd:2c4:2c4:2c4::/64 -j MASQUERADE
					fi
				else
					systemctl disable --now wg-iptables.service
					rm -f /etc/systemd/system/wg-iptables.service
				fi
				systemctl disable --now wg-quick@wg0.service
				rm -f /etc/sysctl.d/99-wireguard-forward.conf /etc/sysctl.d/99-wireguard-optimize.conf
				if [ ! -f /usr/sbin/openvpn ] && [ ! -f /usr/sbin/ipsec ] \
					&& [ ! -f /usr/local/sbin/ipsec ]; then
					echo 0 > /proc/sys/net/ipv4/ip_forward
					echo 0 > /proc/sys/net/ipv6/conf/all/forwarding
				fi
				ipt_cmd="systemctl restart wg-iptables.service"
				if grep -qs "$ipt_cmd" /etc/rc.local; then
					sed --follow-symlinks -i "/^$ipt_cmd/d" /etc/rc.local
				fi
				if [[ "$os" == "ubuntu" ]]; then
					(
						set -x
						rm -rf /etc/wireguard/
						apt-get remove --purge -y wireguard wireguard-tools >/dev/null
					)
				elif [[ "$os" == "debian" && "$os_version" -ge 11 ]]; then
					(
						set -x
						rm -rf /etc/wireguard/
						apt-get remove --purge -y wireguard wireguard-tools >/dev/null
					)
				elif [[ "$os" == "debian" && "$os_version" -eq 10 ]]; then
					(
						set -x
						rm -rf /etc/wireguard/
						apt-get remove --purge -y wireguard wireguard-dkms wireguard-tools >/dev/null
					)
				fi
				echo
				echo "WireGuard��ж��"
			else
				echo
				echo "ж��WireGuard����"
			fi
			exit
		;;
		6)
			exit
		;;
	esac
fi
}

## Defer setup until we have the complete script
wgsetup "$@"

exit 0
