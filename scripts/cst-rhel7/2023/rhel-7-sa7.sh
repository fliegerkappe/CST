#! /bin/bash

# SA-7 USER INSTALLED SOFTWARE

# [Withdrawn: Incorporated into CM-11 and SI-7]

# Check if the script is being run as root
if [ "$EUID" -ne 0 ]
then
   echo "Please run with sudo or as root"
   exit
fi

# Color declarations
RED=`echo    "\e[31;1m"`        # bold red
GRN=`echo    "\e[32;1m"`        # bold green
BLD=`echo    "\e[0;1m"`         # bold black
CYN=`echo    "\e[33;1;35m"`     # bold cyan
BAR=`echo    "\e[32;1;46m"`     # aqua separator bar
NORMAL=`echo "\e[0m"`           # normal

stig="Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Version 2, Release: 5 Benchmark Date: 25 Oct 2019"

hostname="$(uname -n)"

if [[ -f /etc/redhat-release ]]
then
   os="$(cat /etc/redhat-release)"
else
   os="OS not defined"
fi

prog="$(basename $0)"

controlid="SA-7 User Installed Software"

title1a="Without cryptographic integrity protections, system command and files can be altered by unauthorized users without detection."
title1b="Checking with: rpm -Va --noconfig | grep '^..5'"
title1c="Expecting: Nothing returned
           Note: [Withdrawn: Incorporated into CM-11 and SI-7]"
cci1="CCI-000663"
stigid1="RHEL-07-010020"
severity1="CAT I"
ruleid1="SV-86479r4_rule"
vulnid1="V-71855"

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid1${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid1${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid1${NORMAL}"
echo -e "${NORMAL}CCI:       $cci1${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 1:    ${BLD}$title1a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title1b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title1c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity1${NORMAL}"

echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, ${CYN}VERIFY, System File Hashes - See SI-7 Software, Firmware, and Information Integrity (V-71855).${NORMAL}"

exit
