#! /bin/bash

# SC-24 Fail In Known State
#
# CONTROL: Fail to a [Assignment: organization-defined known system state] for the following
# failures on the indicated components while preserving [Assignment: organization-defined system
# state information] in failure: [Assignment: list of organization-defined types of system failures
# on organization-defined system components].

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

controlid="SC-2 Separation of Systemand User Functionality"

title1a="RHEL 9 systemd-journald service must be enabled."
title1b="Checking with: systemctl is-active systemd-journald"
title1c="Expecting: ${YLO}active
           NOTE: If the systemd-journald service is not active, this is a finding."${BLD}
cci1="CCI-001665"
stigid1="RHEL-09-211040"
severity1="CAT II"
ruleid1="SV-257783r991562"
vulnid1="V-257783"

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

isactive="$(systemctl is-active systemd-journald)"

if [[ $isactive ]]
then
  if [[ $isactive == "active" ]]
  then
    fail=0
    echo -e "${NORMAL}RESULT:    ${BLD}$isactive${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}$isactive${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${GRN}PASSED, The RHEL 9 systemd-journald service is enabled.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${RED}FAILED, The RHEL 9 systemd-journald service is not enabled.${NORMAL}"
fi

exit
