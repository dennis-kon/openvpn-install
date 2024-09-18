#!/bin/bash
# https://github.com/Nyr/openvpn-install
# Copyright (c) 2013 Nyr. Released under the MIT License.
# refactored by https://github.com/dennis-kon/  

# Ensure the script is executed with bash
ensure_bash() {
    if readlink /proc/$$/exe | grep -q "dash"; then
        echo 'This installer needs to be run with "bash", not "sh".'
        exit 1
    fi
}

# Detect the OS and version
detect_os() {
    if grep -qs "ubuntu" /etc/os-release; then
        os="ubuntu"
        os_version=$(grep 'VERSION_ID' /etc/os-release | cut -d '"' -f 2 | tr -d '.')
        group_name="nogroup"
    elif [[ -e /etc/debian_version ]]; then
        os="debian"
        os_version=$(grep -oE '[0-9]+' /etc/debian_version | head -1)
        group_name="nogroup"
    elif [[ -e /etc/almalinux-release || -e /etc/rocky-release || -e /etc/centos-release ]]; then
        os="centos"
        os_version=$(grep -shoE '[0-9]+' /etc/almalinux-release /etc/rocky-release /etc/centos-release | head -1)
        group_name="nobody"
    elif [[ -e /etc/fedora-release ]]; then
        os="fedora"
        os_version=$(grep -oE '[0-9]+' /etc/fedora-release | head -1)
        group_name="nobody"
    else
        echo "Unsupported distribution. Supported distros: Ubuntu, Debian, AlmaLinux, Rocky Linux, CentOS, and Fedora."
        exit 1
    fi
}

# Validate OS compatibility
validate_os_version() {
    case "$os" in
        ubuntu)
            [[ "$os_version" -lt 2204 ]] && {
                echo "Ubuntu 22.04 or higher is required."
                exit 1
            }
            ;;
        debian)
            if grep -q '/sid' /etc/debian_version; then
                echo "Debian Testing/Unstable is unsupported."
                exit 1
            fi
            [[ "$os_version" -lt 11 ]] && {
                echo "Debian 11 or higher is required."
                exit 1
            }
            ;;
        centos)
            [[ "$os_version" -lt 9 ]] && {
                os_name=$(sed 's/ release.*//' /etc/almalinux-release /etc/rocky-release /etc/centos-release 2>/dev/null | head -1)
                echo "$os_name 9 or higher is required."
                exit 1
            }
            ;;
    esac
}

# Check necessary privileges and environment setup
check_requirements() {
    [[ "$EUID" -ne 0 ]] && {
        echo "Superuser privileges are required."
        exit 1
    }
    
    [[ ! -e /dev/net/tun ]] || ! ( exec 7<>/dev/net/tun ) 2>/dev/null && {
        echo "TUN device is unavailable. Please enable it."
        exit 1
    }

    [[ ! $PATH =~ sbin ]] && {
        echo 'Your $PATH does not include sbin. Try using "su -" instead of "su".'
        exit 1
    }
}

# Setup the client configuration file
generate_client_config() {
    local client=$1
    {
        cat /etc/openvpn/server/client-common.txt
        echo "<ca>"; cat /etc/openvpn/server/easy-rsa/pki/ca.crt; echo "</ca>"
        echo "<cert>"; sed -ne '/BEGIN CERTIFICATE/,$ p' /etc/openvpn/server/easy-rsa/pki/issued/"$client".crt; echo "</cert>"
        echo "<key>"; cat /etc/openvpn/server/easy-rsa/pki/private/"$client".key; echo "</key>"
        echo "<tls-crypt>"; sed -ne '/BEGIN OpenVPN Static key/,$ p' /etc/openvpn/server/tc.key; echo "</tls-crypt>"
    } > ~/"$client".ovpn
}

# Installation process
install_openvpn() {
    # Check for minimal setups
    if ! hash wget 2>/dev/null && ! hash curl 2>/dev/null; then
        echo "Wget or curl is required to proceed."
        read -n1 -r -p "Press any key to install wget..."
        apt-get update
        apt-get install -y wget
    fi
    # Clear terminal for a clean output
    clear
    
    # Check for single/multiple IPs
    ip=$(detect_ipv4)
    ip6=$(detect_ipv6)
    
    # Configure OpenVPN settings
    configure_openvpn "$ip" "$ip6"
    
    # Enable IP forwarding
    enable_ip_forwarding "$ip6"
    
    # Install firewall and OpenVPN packages
    install_dependencies
}

# Helper function to detect IPv4
detect_ipv4() {
    local ip4
    if [[ $(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}') -eq 1 ]]; then
        ip4=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}')
    else
        select_ip4
    fi
    echo "$ip4"
}

# Helper function to select IPv4 from a list
select_ip4() {
    local ip_number number_of_ip
    number_of_ip=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | wc -l)
    echo "Which IPv4 address should be used?"
    ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | nl -s ') '
    read -p "IPv4 address [1]: " ip_number
    until [[ -z "$ip_number" || "$ip_number" =~ ^[0-9]+$ && "$ip_number" -le "$number_of_ip" ]]; do
        echo "$ip_number: invalid selection."
        read -p "IPv4 address [1]: " ip_number
    done
    ip=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | sed -n "$ip_number"p)
    echo "$ip"
}

# Helper function to detect IPv6
detect_ipv6() {
    local ip6=""
    if [[ $(ip -6 addr | grep -c 'inet6 [23]') -eq 1 ]]; then
        ip6=$(ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}')
    elif [[ $(ip -6 addr | grep -c 'inet6 [23]') -gt 1 ]]; then
        select_ip6
    fi
    echo "$ip6"
}

# Helper function to select IPv6 from a list
select_ip6() {
    local ip6_number number_of_ip6
    number_of_ip6=$(ip -6 addr | grep -c 'inet6 [23]')
    echo "Which IPv6 address should be used?"
    ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}' | nl -s ') '
    read -p "IPv6 address [1]: " ip6_number
    until [[ -z "$ip6_number" || "$ip6_number" =~ ^[0-9]+$ && "$ip6_number" -le "$number_of_ip6" ]]; do
        echo "$ip6_number: invalid selection."
        read -p "IPv6 address [1]: " ip6_number
    done
    ip6=$(ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}' | sed -n "$ip6_number"p)
    echo "$ip6"
}

# Install necessary packages for OpenVPN
install_dependencies() {
    if [[ "$os" = "debian" || "$os" = "ubuntu" ]]; then
        apt-get update
        apt-get install -y --no-install-recommends openvpn openssl ca-certificates iptables
    else
        dnf install -y openvpn openssl ca-certificates iptables
    fi
}

# Configure OpenVPN settings
configure_openvpn() {
    local ip=$1 ip6=$2
    echo "local $ip
port 1194
proto udp
dev tun
ca ca.crt
cert server.crt
key server.key
dh dh.pem
auth SHA512
tls-crypt tc.key
topology subnet
server 10.8.0.0 255.255.255.0" > /etc/openvpn/server/server.conf
    [[ -z "$ip6" ]] && echo 'push "redirect-gateway def1 bypass-dhcp"' >> /etc/openvpn/server/server.conf || {
        echo 'server-ipv6 fddd:1194:1194:1194::/64' >> /etc/openvpn/server/server.conf
        echo 'push "redirect-gateway def1 ipv6 bypass-dhcp"' >> /etc/openvpn/server/server.conf
    }
}

# Enable IP forwarding
enable_ip_forwarding() {
    local ip6=$1
    echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-openvpn-forward.conf
    echo 1 > /proc/sys/net/ipv4/ip_forward
    [[ -n "$ip6" ]] && {
        echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.d/99-openvpn-forward.conf
        echo 1 > /proc/sys/net/ipv6/conf/all/forwarding
    }
}

# Main execution
main() {
    ensure_bash
    detect_os
    validate_os_version
    check_requirements
    install_openvpn
}

main "$@"
