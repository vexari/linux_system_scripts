#!/bin/bash

# Function to log messages with timestamps
log_message() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1"
}

# Function to check if the script is run with root privileges
check_root_privileges() {
    if [[ $EUID -ne 0 ]]; then
        log_message "This script must be run as root. Please use sudo."
        exit 1
    fi
}

# Function to install necessary packages
install_packages() {
    local package
    for package in "$@"; do
        if ! dpkg -s "$package" &>/dev/null; then
            log_message "Installing $package..."
            apt-get update
            apt-get install -y "$package"
            log_message "Installed $package successfully."
        else
            log_message "$package is already installed."
        fi
    done
}

# Function to prompt user for input with a default value
prompt_user_input() {
    read -rp "Enter the desired Ubuntu release [focal]: " ubuntu_release
    ubuntu_release=${ubuntu_release:-"focal"}

    read -rp "Enter the web server root directory [/var/www/html]: " repo_dir
    repo_dir=${repo_dir:-"/var/www/html"}

    read -rp "Enter your domain name for HTTPS (e.g., your_domain.com): " domain_name
    [[ -z $domain_name ]] && { log_message "Domain name cannot be empty."; exit 1; }

    read -rp "Enter a list of allowed IP addresses (comma-separated) for SSH (optional - leave empty for any): " allowed_ips

    read -rp "Enter your username for SSH access: " ssh_username
    [[ -z $ssh_username ]] && { log_message "SSH username cannot be empty."; exit 1; }

    read -rp "Enter your group name for SSH access (optional - leave empty to skip): " ssh_groupname

    read -rp "Do you want to change the default SSH port? [y/N]: " change_ssh_port
    change_ssh_port=${change_ssh_port:-"N"}

    read -rp "Do you want to restrict su access to members of the wheel group? [y/N]: " restrict_su_access
    restrict_su_access=${restrict_su_access:-"N"}
}

# Function to sync repository using rsync and update repository metadata
setup_local_repository() {
    log_message "Setting up the local Ubuntu apt repository mirror..."

    # Step 1: Create repository directory
    mkdir -p "$repo_dir"

    # Step 2: Sync repository using rsync
    log_message "Syncing repository from the official Ubuntu mirror..."
    rsync -av --delete-after "rsync://archive.ubuntu.com/ubuntu/" "$repo_dir"
    log_message "Repository sync completed."

    # Step 3: Update repository metadata
    log_message "Updating repository metadata..."
    apt-ftparchive packages "$repo_dir" > "$repo_dir/Packages"
    gzip -k -f "$repo_dir/Packages"
    apt-ftparchive release "$repo_dir" > "$repo_dir/Release"
    log_message "Repository metadata update completed."
}

# Function to configure Apache for HTTPS
configure_apache_https() {
    cat <<EOL > "/etc/apache2/sites-available/$domain_name.conf"
<VirtualHost *:80>
    ServerAdmin webmaster@localhost
    DocumentRoot $repo_dir
    ErrorLog \${APACHE_LOG_DIR}/error.log
    CustomLog \${APACHE_LOG_DIR}/access.log combined

    # Disable server signature
    ServerSignature Off

    # Disable directory listing
    Options -Indexes
</VirtualHost>

<VirtualHost *:443>
    ServerAdmin webmaster@localhost
    DocumentRoot $repo_dir
    ErrorLog \${APACHE_LOG_DIR}/error.log
    CustomLog \${APACHE_LOG_DIR}/access.log combined

    SSLEngine on
    SSLCertificateFile /etc/letsencrypt/live/$domain_name/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/$domain_name/privkey.pem

    # Disable server signature
    ServerSignature Off

    # Disable directory listing
    Options -Indexes
</VirtualHost>
EOL
}

# Function to enable Apache modules and reload Apache
enable_apache_modules() {
    a2enmod ssl
    a2ensite "$domain_name"
    systemctl reload apache2
}

# Function to obtain SSL certificate using Certbot
obtain_ssl_certificate() {
    log_message "Obtaining SSL certificate using Certbot..."
    certbot --non-interactive --apache --agree-tos --redirect --keep-until-expiring --no-eff-email -d "$domain_name"
    log_message "SSL certificate obtained successfully."
}

# Function to apply system hardening measures
apply_system_hardening() {
    log_message "Applying system hardening measures..."
    # Step 1: Secure shared memory
    echo "tmpfs     /run/shm     tmpfs     defaults,noexec,nosuid     0     0" >> /etc/fstab
    mount -o remount /run/shm

    # Step 2: Disable core dumps
    echo "*     hard     core     0" >> /etc/security/limits.conf

    # Step 3: Enable kernel level security features
    echo "fs.suid_dumpable = 0" >> /etc/sysctl.conf
    sysctl -p

    # Step 4: Enable and configure auditd
    install_packages auditd
    systemctl enable auditd

    # Step 5: Enable AppArmor
    install_packages apparmor apparmor-utils
    systemctl enable apparmor
    systemctl start apparmor

    # Step 6: Configure sysctl parameters for improved security
    cat <<EOL > /etc/sysctl.d/99-security.conf
# Protect against common attack vectors
net.ipv4.tcp_syncookies = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.tcp_rfc1337 = 1

# Disable IPv6 if not used
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
EOL
    sysctl -p

    # Step 7: Enable automatic security updates
    install_packages unattended-upgrades

    # Step 8: Disable unnecessary services
    services_to_disable=("avahi-daemon" "cups" "rpcbind")
    for service in "${services_to_disable[@]}"; do
        systemctl stop "${service}"
        systemctl disable "${service}"
    done

    # Step 9: Set umask to restrict default permissions
    echo "umask 027" >> /etc/profile

    # Step 10: Limit access to cron and at commands
    echo "root" > /etc/cron.allow
    echo "root" > /etc/at.allow
    chown root:root /etc/cron.allow /etc/at.allow
    chmod 400 /etc/cron.allow /etc/at.allow

    # Step 11: Enable and configure log rotation
    install_packages logrotate
    cat <<EOL > /etc/logrotate.d/apt-mirror
${REPO_DIR}/apt-mirror.log {
    daily
    missingok
    rotate 7
    compress
    delaycompress
    notifempty
}
EOL

    # Step 14: Set up automatic security updates
    cat <<EOL > /etc/apt/apt.conf.d/20auto-upgrades
    APT::Periodic::Update-Package-Lists "1";
    APT::Periodic::Unattended-Upgrade "1";
    APT::Periodic::AutocleanInterval "7";
    APT::Periodic::Download-Upgradeable-Packages "1";
EOL

    # Step 15: Harden the /tmp directory
    echo "tmpfs     /tmp     tmpfs     defaults,noexec,nosuid     0     0" >> /etc/fstab
    mount -o remount /tmp

    # Step 16: Disable IPv6 (optional - uncomment if not needed)
    echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.d/99-security.conf
    echo "net.ipv6.conf.default.disable_ipv6 = 1" >> /etc/sysctl.d/99-security.conf

    log_message "System hardening measures applied successfully."
}

# Function to apply SSH server hardening measures
apply_ssh_hardening() {
    log_message "Applying SSH server hardening measures..."

    # Step 1: Disable password-based authentication
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config

    # Step 2: Disable root login
    sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin no/' /etc/ssh/sshd_config

    # Step 3: Use SSH Protocol 2 only
    echo "Protocol 2" >> /etc/ssh/sshd_config

    # Step 4: Set a strong Modulus for DH Key Exchange
    echo "KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256" >> /etc/ssh/sshd_config

    # Step 5: Limit User Access
    echo "AllowUsers your_username" >> /etc/ssh/sshd_config
    # Uncomment the line below if you want to allow specific groups instead of individual users
    # echo "AllowGroups your_groupname" >> /etc/ssh/sshd_config

    # Step 6: Limit Concurrent Connections
    echo "MaxSessions 2" >> /etc/ssh/sshd_config

    # Step 7: Set Idle Timeout (300 seconds = 5 minutes)
    echo "ClientAliveInterval 300" >> /etc/ssh/sshd_config
    echo "ClientAliveCountMax 0" >> /etc/ssh/sshd_config

    # Step 8: Use Strong Encryption Algorithms (adjust to your needs)
    echo "Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr" >> /etc/ssh/sshd_config
    echo "MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-ripemd160-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,hmac-ripemd160,umac-128@openssh.com" >> /etc/ssh/sshd_config

    # Step 9: Use TCP Wrappers
    echo "sshd : ALL" >> /etc/hosts.deny
    echo "sshd : allowed_ip1 allowed_ip2" >> /etc/hosts.allow

    # Step 10: Change Default SSH Port (optional - uncomment if needed)
    # echo "Port 2222" >> /etc/ssh/sshd_config

    # Step 11: Restart SSH service
    systemctl restart sshd

    log_message "SSH server hardening measures applied successfully."
}

# Function to configure UFW
configure_ufw() {
    log_message "Configuring UFW..."
    
    # Log UFW status before making changes
    logger -t "ufw_setup" "UFW status before configuration:"
    ufw status numbered | logger -t "ufw_setup"
    ufw --force reset           # Reset UFW to default settings
    ufw default deny incoming   # Deny all incoming connections by default
    ufw default allow outgoing  # Allow all outgoing connections by default
    ufw allow ssh               # Allow SSH
    ufw allow http              # Allow HTTP
    ufw allow https             # Allow HTTPS
    ufw --force enable          # Enable UFW with force to prevent interactive prompt
    
    # Log UFW status after making changes
    logger -t "ufw_setup" "UFW status after configuration:"
    ufw status numbered | logger -t "ufw_setup"
    log_message "UFW configured and enabled."
}

# Main function for setting up the local Ubuntu apt repository mirror
setup_local_repo() {
    log_message "Starting Ubuntu apt repository mirror setup..."

    # Step 1: Check root privileges
    check_root_privileges

    # Step 2: Prompt user for input with default values
    prompt_user_input

    # Step 3: Install necessary packages
    install_packages apache2 rsync certbot ufw auditd apparmor logrotate

    # Step 5 & 6: Sync repository using rsync and update repository metadata
    setup_local_repository

    # Step 7: Configure Apache to serve the repository over HTTPS
    configure_apache_https

    # Step 8: Enable Apache modules and reload Apache
    enable_apache_modules

    # Step 9: Obtain SSL certificate using Certbot
    obtain_ssl_certificate

    # Step 10: Apply system hardening measures
    apply_system_hardening

    # Step 11: Apply SSH server hardening measures
    apply_ssh_hardening

    # Step 12: Configure UFW
    configure_ufw

    log_message "Local Ubuntu apt repository mirror has been set up successfully over HTTPS."
}

# Run the main function to set up the local repository
setup_local_repo
