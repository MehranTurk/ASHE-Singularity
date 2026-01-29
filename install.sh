#!/bin/bash

# A.S.H.E v5.0 - Installation Script
# Author: Mehran

# Colors for professional output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BLUE}------------------------------------------${NC}"
echo -e "${GREEN}   A.S.H.E v5.0 - Installer Engine${NC}"
echo -e "${BLUE}------------------------------------------${NC}"

# 1. Checking for Root privileges
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}[!] Please run as root (use sudo)${NC}"
  exit
fi

# 2. Updating System Repositories
echo -e "${BLUE}[*] Updating system repositories...${NC}"
apt-get update -y > /dev/null

# 3. Installing Python and Essentials
echo -e "${BLUE}[*] Installing Python3 and Pip...${NC}"
apt-get install -y python3 python3-pip python3-dev git binutils > /dev/null

# 4. Installing Pwntools
echo -e "${BLUE}[*] Installing Pwntools (Core Framework)...${NC}"
pip3 install --upgrade pwntools --break-system-packages

# 5. Configuring OS for Self-Healing (Core Dumps)
echo -e "${BLUE}[*] Configuring Linux Core Dumps...${NC}"
# Enable unlimited core dump size
ulimit -c unlimited
# Set core pattern to simple 'core' in current directory
echo "core" > /proc/sys/kernel/core_pattern

# 6. Setting Execution Permissions
echo -e "${BLUE}[*] Finalizing permissions...${NC}"
chmod +x ashe.py
chmod +x install.sh

echo -e "${GREEN}[+] Installation Complete!${NC}"
echo -e "${GREEN}[+] You can now run A.S.H.E using: ./ashe.py${NC}"
echo -e "${BLUE}------------------------------------------${NC}"