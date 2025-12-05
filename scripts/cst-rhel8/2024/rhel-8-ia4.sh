#! /bin/bash

# IA-4 Identifier Management
#
# CONTROL: The organization manages information system identifiers by:
# a. Receiving authorization from [Assignment: organization-defined personnel or roles] to
#    assign an individual, group, role, or device identifier;
# b. Selecting an identifier that identifies an individual, group, role, or device;
# c. Assigning the identifier to the intended individual, group, role, or device;
# d. Preventing reuse of identifiers for [Assignment: organization-defined time period]; and
# e. Disabling the identifier after [Assignment: organization-defined time period of inactivity].

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

controlid="IA-4 Identifier Management"

title1a="RHEL 8 account identifiers (individuals, groups, roles, and devices) must be disabled after 35 days of inactivity."
title1b="Checking with 'grep -i inactive /etc/default/useradd'."
title1c="Expecting: ${YLO}INACTIVE 35
           NOTE: If \"INACTIVE\" is set to \"-1\", a value greater than \"35\", or is commented out, this is a finding."
cci1="CCI-000795"
stigid1="RHEL-08-020260"
severity1="CAT II"
ruleid1="SV-230373r627750_rule"
vulnid1="V-230373"

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

file1="/etc/default/useradd"

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file1 ]]
then
   inactive="$(grep -i ^inactive $file1)"
   if [[ $inactive ]]
   then
      echo -e "${NORMAL}RESULT:    ${BLD}$inactive${NORMAL}"
      inactivestatus="$(echo $inactive | awk -F= '{print $2}')"
      if (( $inactivestatus != -1 && $inactivestatus <= 35 ))
      then
        echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${GRN}PASSED, RHEL 8 account identifiers (individuals groups roles and devices) are disabled after 35 days (at most) of inactivity.${NORMAL}"
      else
         echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${RED}FAILED, RHEL 8 account identifiers (individuals groups roles and devices) are not disabled after 35 days (at most) of inactivity.${NORMAL}"
      fi
   else
      echo -e "${NORMAL}RESULT:    ${BLD}INACTIVE is not defined in $file1${NORMAL}"
      echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${RED}FAILED, The time limit for account inactivity is not defined in $file1${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${BLD}$file1 was not found${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${RED}FAILED, $file1 was not found${NORMAL}"
fi

exit

