#! /bin/bash

# SC-10 Network Disconnect
#
# CONTROL: The information system terminates the network connection associated with a communications session
# at the end of the session or after [Assignment: organization-defined time period] of inactivity.

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

controlid="SC-10 Network Disconnect"

title1a="RHEL 9 must be configured so that all network connections associated with SSH traffic are terminated at the end of the session or after 10 minutes of inactivity, except to fulfill documented and validated mission requirements."
title1b="Checking with: /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print \$4}' | tr -d '\\\\r' | tr '\\\\n' ' ' | sudo grep -iH '^\s*clientalivecountmax'"
title1c="Expecting:${YLO}ClientAliveCountMax 0
	   NOTE: If \"ClientAliveCountMax\" does not exist, is not set to a value of \"0\" in \"/etc/ssh/sshd_config\", or is commented out, this is a finding."${BLD}
cci1="CCI-001133 CCI-002361"
stigid1="RHEL-09-255095"
severity1="CAT II"
ruleid1="SV-257995r1045053"
vulnid1="V-257995"

title2a="RHEL 9 must be configured so that all network connections associated with SSH traffic are terminated after 10 minutes of becoming unresponsive."
title2b="Checking with: /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print \$4}' | tr -d '\\\\r' | tr '\\\\n' ' ' | sudo grep -iH '^\s*clientaliveinterval'"
title2c="Expecting: ${YLO}ClientAliveInterval 600
	   NOTE: If \"ClientAliveInterval\" does not exist, does not have a value of \"600\" or less in \"/etc/ssh/sshd_config\", or is commented out, this is a finding."${BLD}
cci2="CCI-001133 CCI-002361 CCI-002891"
stigid2="RHEL-09-255100"
severity2="CAT II"
ruleid2="SV-257996r1045055"
vulnid2="V-257996"

title3a="RHEL 9 must automatically exit interactive command shell user sessions after 10 minutes of inactivity."
title3b="Checking with: grep -i tmout /etc/profile /etc/profile.d/*.sh"
title3c="Expecting: ${YLO}/etc/profile.d/tmout.sh:declare -xr TMOUT=600
           NOTE: If \"TMOUT\" is not set to \"600\" or less in a script located in the \"/etc/'profile.d/ directory\", is missing or is commented out, this is a finding."${BLD}
cci3="CCI-000057 CCI-001133"
stigid3="RHEL-09-412035"
severity3="CAT II"
ruleid3="SV-258068r1101950"
vulnid3="V-258068"

title4a="RHEL 9 must terminate idle user sessions."
title4b="Checking with: grep -i StopIdleSessionSec /etc/systemd/logind.conf"
title4c="Expecting: ${YLO}StopIdleSessionSec=900
           NOTE: If \"StopIdleSessionSec\" is not configured to \"900\" seconds, this is a finding."${BLD}
cci4="CCI-001133"
stigid4="RHEL-09-412080"
severity4="CAT II"
ruleid4="SV-258077r1014874"
vulnid4="V-258077"

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

datetime="$(date +%FT%H:%M:%S)"

echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${CYN}VERIFY, (See AC-12 Session Termination: V-257995)${NORMAL}"

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

datetime="$(date +%FT%H:%M:%S)"

echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${CYN}VERIFY, (See AC-12 Session Termination: V-257996)${NORMAL}"

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid3${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid3${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid3${NORMAL}"
echo -e "${NORMAL}CCI:       $cci3${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 3:    ${BLD}$title3a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title3b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title3c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity3${NORMAL}"

datetime="$(date +%FT%H:%M:%S)"

echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${CYN}VERIFY, (See AC-11 Session Lock: V-258068)${NORMAL}"

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid4${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid4${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid4${NORMAL}"
echo -e "${NORMAL}CCI:       $cci4${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 4:    ${BLD}$title4a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title4b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title4c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity4${NORMAL}"

IFS='
'

fail=1

datetime="$(date +%FT%H:%M:%S)"

stopidle="$(grep -i StopIdleSessionSec /etc/systemd/logind.conf)"

if [[ $stopidle ]]
then
  secs="$(echo $stopidle | awk -F= '{print $2}' | sed 's/ //')"
  if (( $secs <= 900 && $secs > 0 )) && [[ ${stopidle:0:1} != "#" ]]
  then
    fail=0
    echo -e "${NORMAL}RESULT:    ${BLD}$stopidle${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}$stopidle${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${GRN}PASSED, RHEL 9 logs out sessions that are idle for 15 minutes.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${RED}FAILED, RHEL 9 does not log out sessions that are idle for 15 minutes.${NORMAL}"
fi

exit
