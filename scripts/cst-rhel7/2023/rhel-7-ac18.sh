#! /bin/bash

# AC-18 Wireless Access
#
# CONTROL: The organization:
# a. Establishes usage restrictions, configuration/connection requirements, and implementation
#    guidance for wireless access; and
# b. Authorizes wireless access to the information system prior to allowing such connections.

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

stig="Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Version 3, Release: 10 Benchmark Date: 26 Jan 2023"

hostname="$(uname -n)"

if [[ -f /etc/redhat-release ]]
then
   os="$(cat /etc/redhat-release)"
else
   os="OS not defined"
fi

prog="$(basename $0)"

controlid="AC-18 Wireless Access"

title1a="The Red Hat Enterprise Linux operating system must be configured so that all wireless network adapters are disabled."
title1b="Checking with 'nmcli device | egrep -i '(radio|wifi)''."
title1c="Expecting: ${YLO}eth0 ethernet connected
                      wlp3s0 wifi disconnected
                      lo loopback unmanaged
           Note: This is Not Applicable for systems that do not have wireless network adapters.
           Note: If a wireless interface is configured and its use on the system is not documented with the Information System Security Officer (ISSO), this is a finding.${BLD}"
cci1="CCI-001443"
stigid1="RHEL-07-041010"
severity1="CAT II"
ruleid1="SV-204634r603261_rule"
vulnid1="V-204634"

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

nmcli="$(nmcli device | egrep -i '(radio|wifi)')"
fail=0

datetime="$(date +%FT%H:%M:%S)"

if [[ $nmcli ]]
then
  for line in ${nmcli[@]}
  do
    if [[ ! $line =~ 'disconnected' ]]
    then
      echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
      echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${RED}FAILED, Wireless Access: Wireless network adapters are not disabled${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    $line${NORMAL}"
      echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${GRN}PASSED, Wireless Access: Wireless network adapters are disabled${NORMAL}"
    fi
  done
else
   echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${GRN}N/A, Wireless Access: Not Applicable - No wireless adapters were found${NORMAL}"
fi

exit
