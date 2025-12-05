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

controlid="SC-10 Network Disconnect"

title1a="RHEL 8 must be configured so that all network connections associated with SSH traffic are terminated at the end of the session or after 10 minutes of inactivity, except to fulfill documented and validated mission requirements."
title1b="Checking with 'grep -i clientalive /etc/ssh/sshd_config'."
title1c="Expecting:${YLO}
           ClientAliveInterval 600
	   ClientAliveCountMax 0
	   NOTE: If \"ClientAliveCountMax\" does not exist, is not set to a value of \"0\" in \"/etc/ssh/sshd_config\", or is commented out, this is a finding."${BLD}
cci1="CCI-001133"
stigid1="RHEL-08-010200"
severity1="CAT II"
ruleid1="SV-230244r743934_rule"
vulnid1="V-230244"

title2a="The RHEL 8 SSH daemon must be configured with a timeout interval."
title2b="Checking with 'grep -i clientalive /etc/ssh/sshd_config'."
title2c="Expecting:${YLO}
           ClientAliveInterval 600
	   ClientAliveCountMax 0
	   NOTE: If \"ClientAliveInterval\" does not exist, does not have a value of \"600\" or less in \"/etc/ssh/sshd_config\", or is commented out, this is a finding."${BLD}
cci2="CCI-001133"
stigid2="RHEL-08-010201"
severity2="CAT II"
ruleid2="SV-244525r743824_rule"
vulnid2="V-244525"

title3a="RHEL 8 must terminate idle user sessions."
title3b="Checking with: 'grep -i ^StopIdleSessionSec /etc/systemd/logind.conf'."
title3c="Expecting: ${YLO}StopIdleSessionSec=900
           NOTE: If \"StopIdleSessionSec\" is not configured to \"900\" seconds, this is a finding."${BLD}
cci3="CCI-001133"
stigid3="RHEL-08-020035"
severity3="CAT II"
ruleid3="SV-257258r942953_rule"
vulnid3="V-257258"

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

IFS=$'\n'

file1="/etc/ssh/sshd_config"
fail=1

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file1 ]]
then
  countmax="$(egrep -i '(clientalivecountmax)' $file1)"
  if [[ $countmax ]]
  then
    for line in ${countmax[@]}
    do
      if [[ $line:0:1 == "#" ]]
      then
	echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
      else
        countmaxval="$(echo $line | awk '{print $2}')"
        if (( $intervalval == 0 )) 
        then
          echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
          fail=0
        else
          echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
        fi
      fi
    done
  else
    echo -e "${NORMAL}RESULT:    ${RED}\"ClientAliveCountMax\" is not defined in $file1${NORMAL}"
  fi
  if [[ $fail == 0 ]]
  then
    echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${GRN}PASSED, All network connections associated with SSH traffic are automatically terminated at the end of the session or after 10 minutes of inactivity.${NORMAL}"
  else
    echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${RED}FAILED, All network connections associated with SSH traffic are not automatically terminated at the end of the session or after 10 minutes of inactivity.${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}$file1 not found${NORMAL}"
  echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${RED}FAILED, $file1 not found${NORMAL}"
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

IFS=$'\n'

file2="/etc/ssh/sshd_config"
fail=1

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file2 ]]
then
  interval="$(egrep -i '(clientaliveinterval)' $file2)"
  if [[ $interval ]]
  then
    for line in ${interval[@]}
    do
      if [[ $line:0:1 == "#" ]]
      then
	echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
      else
        intervalval="$(echo $line | awk '{print $2}')"
	if (( $intervalval <= 600 )) && (( $intervalval > 0 ))
        then
          echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
          fail=0
        else
          echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
        fi
      fi
    done
  else
    echo -e "${NORMAL}RESULT:    ${RED}\"ClientAliveInterval\" is not defined in $file2${NORMAL}"
  fi
  if [[ $fail == 0 ]]
  then
    echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${GRN}PASSED, All network connections associated with SSH traffic are automatically terminated at the end of the session or after 10 minutes of inactivity.${NORMAL}"
  else
    echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${RED}FAILED, All network connections associated with SSH traffic are not automatically terminated at the end of the session or after 10 minutes of inactivity.${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}$file2 not found${NORMAL}"
  echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${RED}FAILED, $file2 not found${NORMAL}"
fi

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

IFS=$'\n'

file3="/etc/systemd/logind.conf"
fail=1

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file3 ]]
then
  stopsecs="$(grep -i ^StopIdleSessionSec $file3)"
  if [[ $stopsecs ]]
  then
    stopsecval="$(echo $stopsecs | awk -F= '{print $2}')"
    if (( $stopsecval <= 900 ))
    then
      echo -e "${NORMAL}RESULT:    ${BLD}$stopsec${NORMAL}"
      fail=0
    else
      echo -e "${NORMAL}RESULT:    ${RED}$stopsecs${NORMAL}"
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}$file3 not found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${GRN}PASSED, RHEL 8 terminates idle user sessions in 900 seconds or less.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${RED}FAILED, RHEL 8 does not terminate idle user sessions in 900 seconds or less.${NORMAL}"
fi

exit
