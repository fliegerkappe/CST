#! /bin/bash

# SI-6 Security Function Verification

# CONTROL: The information system:
# a. Verified the correct operation of [Assignment: organization-defined security functions];
# b. Performs this verification [Selection (one or more): [Assigment: organization-defined
#    system transitional states]; upon command by user with apropriate privilege; [Assignment:
#    organization-defined frequency]];
# c. Notifies [Assignment: organization-defined personnel or roles] of failed security verification
#    tests; and
# d. [Selection (one or more); shuts the information system down; restarts theinformation
#    system; [Assmignment: organization-defined alternative action(s)]] when anomalies are
#    discovered.

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

controlid="SI-6 Security Function Verification"

title1a="RHEL 8 must enable the SELinux targeted policy."
title1b="Checking with:
           a. sestatus
	   b. grep -i \"selinuxtype\" /etc/selinux/config | grep -v '^#'"
title1c="Expecting: 
           a. ${YLO}
              SELinux status: enabled
              SELinuxfs mount: /sys/fs/selinux
              SELinux root directory: /etc/selinux
              ${GRN}Loaded policy name: targeted${YLO}
              Current mode: enforcing
              Mode from config file: enforcing
              Policy MLS status: enabled
              Policy deny_unknown status: allowed
              Memory protection checking: actual (secure)
              Max kernel policy version: 31${BLD}
	   b. ${YLO}SELINUXTYPE = targeted${BLD}
  	   NOTE: a. ${YLO}If the \"Loaded policy name\" is not set to \"targeted\", this is a finding.${BLD}
	   NOTE: b. ${YLO}If no results are returned or \"SELINUXTYPE\" is not set to \"targeted\", this is a finding."${BLD}
cci1="CCI-002696"
stigid1="RHEL-08-010450"
severity1="CAT II"
ruleid1="SV-230282r854035_rule"
vulnid1="V-230282"

title2a="The RHEL 8 operating system must use a file integrity tool to verify correct operation of all security functions."
title2b="Checking with: rpm -q aide"
title2c="Expecting: ${YLO}aide-0.16-14.el8.x86_64${BLD}
           NOTE: ${YLO}If AIDE is not installed, ask the System Administrator how file integrity checks are performed on the system${BLD}
	   NOTE: ${YLO}If there is no application installed to perform integrity checks, this is a finding."${BLD}
cci2="CCI-002696"
stigid2="RHEL-08-010359"
severity2="CAT II"
ruleid2="SV-251710r880730_rule"
vulnid2="V-251710"

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

file1="/etc/selinux/config"

fail=1
test1=0
test2=0

sestatus1="$(sestatus)"
sestatus2="$(grep -i "selinuxtype" $file1 | grep -v '^#')"

datetime="$(date +%FT%H:%M:%S)"

if [[ $sestatus1 ]]
then
  for line in ${sestatus1[@]}
  do
    if [[ $line =~ "Loaded policy name:" && $line =~ "targeted" ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}a. $line${NORMAL}"
      test1=1
    else
      echo -e "${NORMAL}RESULT:    a. $line${NORMAL}"
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${RED}a. Nothing returned${NORMAL}"
fi

if [[ $sestatus2 ]]
then
  if [[ $sestatus2 =~ "SELINUXTYPE" && $sestatus2 =~ "targeted" ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}b. $sestatus2${NORMAL}"
    test2=1
  else
    echo -e "${NORMAL}RESULT:    ${RED}b. $sestatus2${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}b. Nothing returned${NORMAL}"
fi

if [[ $test1 == 1 && $test2 == 1 ]]
then
  fail=0
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${GRN}PASSED, The information system verifies correct operation of organization-defined security functions.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${RED}FAILED, The information system does not verify correct operation of organization-defined security functions.${NORMAL}"
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

isinstalled="$(rpm -q aide 2>/dev/null | grep aide)"

datetime="$(date +%FT%H:%M:%S)"

if [[ $isinstalled ]]
then
  echo -e "${NORMAL}RESULT:    ${BLD}$isinstalled${NORMAL}"
  fail=0
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${GRN}PASSED, The information system verifies correct operation of organization-defined security functions.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${RED}FAILED, The information system does not verify correct operation of organization-defined security functions.${NORMAL}"
fi

exit
