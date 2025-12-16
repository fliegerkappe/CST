#! /bin/bash

# AC-12 Session Termination

# CONTROL: The information system automatically terminates a user session after
# [Assignment: organization-defined conditions or trigger events requiring session disconnect].

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

if [[ -f /etc/redhat-release ]]`
then
   os="$(cat /etc/redhat-release)"
else
   os="OS not defined"
fi

prog="$(basename $0)"

controlid="AC-12 Session Termination"

title1a="RHEL 9 must be configured so that all network connections associated with SSH traffic terminate after becoming unresponsive."
title1b="Checking with ${YLO}'/usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print \$4}' | tr -d '\\\\r' | tr '\\\\n' ' ' | xargs grep -iH '^\s*clientalivecountmax'."
title1c="Expecting: ${YLO}ClientAliveCountMax 1
           Note: If \"ClientAliveCountMax\" does not exist, is not set to a value of \"1\" in \"/etc/ssh/sshd_config\", or is commented out, this is a finding."${BLD}
cci1="CCI-001133 CCI-002361"
stigid1="RHEL-09-255095"
severity1="CAT II"
ruleid1="SV-257995r1045053"
vulnid1="V-257995"

title2a="RHEL 9 must be configured so that all network connections associated with SSH traffic are terminated after 10 minutes of becoming unresponsive."
title2b="Checking with '/usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print \$4}' | tr -d '\\\\r' | tr '\\\\n' ' ' | xargs grep -iH '^\s*clientaliveinterval'."
title2c="Expecting: ${YLO}ClientAliveInterval 600
           Note: If \"ClientAliveInterval\" does not exist, does not have a value of \"600\" or less in \"/etc/ssh/sshd_config\", or is commented out, this is a finding."${BLD}
cci2="CCI-001133"
stigid2="RHEL-09-255100"
severity2="CAT II"
ruleid2="SV-257996r1045055"
vulnid2="V-257996"

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

fail=1

datetime="$(date +%FT%H:%M:%S)"

calivemax="$(/usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs grep -iH '^\s*clientalivecountmax')"

if [[ $calivemax ]]
then
  calivemaxval="$(echo $calivemax | awk '{print $2}')"
  if [[ $calivemaxval == 1 ]]
  then
    fail=0
    file="$(echo $calivemax | awk -F: '{print $1}')"
    setting="$(echo $calivemax | awk -F: '{print $2}')"
    echo -e "${NORMAL}RESULT:    ${CYN}$file:${BLD}$setting${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${CYN}$file:${RED}$setting${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${BLD}\"ClientAliveCountMax\" is not defined${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${GRN}PASSED, RHEL 9 is configured so that all network connections associated with SSH traffic terminate after becoming unresponsive.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${RED}FAILED, RHEL 9 is not configured so that all network connections associated with SSH traffic terminate after becoming unresponsive.${NORMAL}"
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

caliveint="$(/usr/sbin/sshd -dd 2>&1 | grep -v "#" | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs grep -iH '^\s*clientaliveinterval')"

if [[ $caliveint ]]
then
  caliveintval="$(echo $caliveint | awk '{print $2}')"
  if (( $caliveintval <= 600 )) && [[ $caliveintval != 0 ]]
  then
    fail=0
    file="$(echo $caliveint | awk -F: '{print $1}')"
    setting="$(echo $caliveint | awk -F: '{print $2}')"
    echo -e "${NORMAL}RESULT:    ${CYN}$file:${BLD}$setting${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${CYN}$file:${RED}$setting${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${BLD}\"ClientAliveInterval\" is not defined${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${GRN}PASSED, RHEL 9 is configured so that all network connections associated with SSH traffic are terminated after 10 minutes of becoming unresponsive.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${RED}FAILED, RHEL 9 is not configured so that all network connections associated with SSH traffic are terminated after 10 minutes of becoming unresponsive.${NORMAL}"
fi

exit


