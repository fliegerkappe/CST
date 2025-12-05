#! /bin/bash

# SC-5 Denial of Service (DoS) Protection
#
# CONTROL: The information system protects against or limits the effects of the following
# types of denial of service attacks: [Assignment: organization-defined types of denial of
# service attacks or reference to source for such information] by employing [Assignment:
# organization-defined security safeguards].

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
YLO=`echo    "\e[93;1m"`        # bold yellow
BAR=`echo    "\e[11;1;44m"`     # blue separator bar
NORMAL=`echo "\e[0m"`           # normal

stig="Red Hat Enterprise Linux 9 Version: 2 Release: 5 Benchmark Date: 02 Jul 2025"

hostname="$(uname -n)"

if [[ -f /etc/redhat-release ]]
then
   os="$(cat /etc/redhat-release)"
else
   os="OS not defined"
fi

prog="$(basename $0)"

controlid="SC-5 Denial of Service (DoS) Protection"

title1a="RHEL 9 must protect against or limit the effects of denial-of-service (DoS) attacks by ensuring rate-limiting measures on impacted network interfaces are implemented."
title1b="Checking with 'grep -i firewallbackend /etc/firewalld/firewalld.conf'."
title1c="Expecting: ${YLO}
           # FirewallBackend
	   FirewallBackend=nftables
           Note: If the \"nftables\" is not set as the \"firewallbackend\" default, this is a finding."${BLD} 
cci1="CCI-002385"
stigid1="RHEL-09-251030"
severity1="CAT II"
ruleid1="SV-257939r1044997"
vulnid1="V-257939"

title2a="RHEL 9 must be configured to use TCP syncookies."
title2b="Checking with: 
           a. sysctl net.ipv4.tcp_syncookie
	   b. grep -r kernel.dmesg_restrict /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf /etc/sysctl.d/*.conf"
title2c="Expecting: ${YLO}
           a. net.ipv4.tcp_syncookies = 1
	   b. /etc/sysctl.d/99-sysctl.conf:net.ipv4.tcp_syncookies = 1
	   NOTE: If \"net.ipv4.tcp_syncookies\" is not set to \"1\", is missing, or commented out, this is a finding."${BLD}
cci2="CCI-001095 CCI-002385"
stigid2="RHEL-09-253010"
severity2="CAT II"
ruleid2="SV-257957r1106317"
vulnid2="V-257957"

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

IFS='
'

file1="/etc/firewalld/firewalld.conf"

fail=1

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file1 ]]
then
  backend="$(grep -i firewallbackend $file1)"
  if [[ $backend ]]
  then
    for line in ${backend[@]}
    do
      if [[ ${line:0:1} != "#" ]]
      then
        backendval="$(echo $line | awk -F= '{print $2}' | sed 's/ //')"
        if [[ $backendval == "nftables" ]]
        then
          fail=0
          echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
        else
          echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
        fi
      else
	echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
      fi
    done
  else
    echo -e "${NORMAL}RESULT:    ${RED}\"FirewallBackend\" is not defined in $file1${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}$file1 not found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${GRN}PASSED, RHEL 9 "nftables" is configured to allow rate limits on any connection to the system.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${RED}FAILED, RHEL 9 "nftables" is not configured to allow rate limits on any connection to the system.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid2${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid2${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid2${NORMAL}"
echo -e "${NORMAL}CCI:       $cci2${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 2:    ${BLD}$title2a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title2b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title2c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity2${NORMAL}"

IFS='
'

fail=1

datetime="$(date +%FT%H:%M:%S)"

syncookies="$(sysctl net.ipv4.tcp_syncookies)"

if [[ $syncookies ]]
then
  value="$(echo $syncookies | awk -F= '{print $2}' | sed 's/ //')"
  if [[ $value == 1 && ${syncookies:0:1} != "#" ]]
  then
    fail=0
    echo -e "${NORMAL}RESULT:    ${BLD}$syncookies${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}$syncookies${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${GRN}PASSED, RHEL 9 is configured to use TCP syncookies.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${RED}FAILED, RHEL 9 is not configured to use TCP syncookies.${NORMAL}"
fi






exit
