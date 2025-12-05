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
YLO=`echo    "\e[33;1m"`        # bold yellow
BAR=`echo    "\e[32;1;46m"`     # aqua separator bar
NORMAL=`echo "\e[0m"`           # normal

stig="Red Hat Enterprise Linux 8 Security Technical Implementation Guide :: Version 1, Release: 13 Benchmark Date: 24 Jan 2024"

hostname="$(uname -n)"

if [[ -f /etc/redhat-release ]]
then
   os="$(cat /etc/redhat-release)"
else
   os="OS not defined"
fi

prog="$(basename $0)"

controlid="SC-5 Denial of Service (DoS) Protection"

title1a="A firewall must be able to protect against or limit the effects of Denial of Service (DoS) attacks by ensuring RHEL 8 can implement rate-limiting measures on impacted network interfaces."
title1b="Checking with 'grep -i firewallbackend /etc/firewalld/firewalld.conf'."
title1c="Expecting: ${YLO}
           # FirewallBackend
	   FirewallBackend=nftables
           Note: If the \"nftables\" is not set as the \"firewallbackend\" default, this is a finding."${BLD} 
cci1="CCI-002385"
stigid1="RHEL-08-040150"
severity1="CAT II"
ruleid1="SV-230525r902735_rule"
vulnid1="V-230525"

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
      if [[ $line =~ "FirewallBackend=" ]]
      then
	backendval="$(echo $line | awk -F= '{print $2}')"
	if [[ $backendval == "nftables" ]]
        then
          echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
	  fail=0
	else
          echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
	fi
      elif [[ $line == "# FirewallBackend" ]]
      then
	echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
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
  echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${GRN}PASSED, A firewall is able to protect against or limit the effects of Denial of Service (DoS) attacks by ensuring RHEL 8 can implement rate-limiting measures on impacted network interfaces.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${RED}FAILED, A firewall is not able to protect against or limit the effects of Denial of Service (DoS) attacks by ensuring RHEL 8 can implement rate-limiting measures on impacted network interfaces.${NORMAL}"
fi

exit
