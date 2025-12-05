#! /bin/bash

# SI-6 Security Functioon Verification

# CONTROL: The information system:
# a. Verifies the correct operation of [Assignment:  organization-defined security functions]:
# b. Performs this verification [Selection (oneor more): {Assignment: organization-defined system
#    transitional states]; uponcommand by user with apropriate privilege; [Assignment:
#    organization-defined frequency]];
# c. Notifies [Assignment: organization-defined personnel or roles] of failed security verification
#    tests; and
# d. [Selection (one or more); shuts the information system down; restarts the information system;
#    [Assignment: organization-defined alternative action(s)]] whenanomalies are discoverd.

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

controlid="SI-6 Security Functioon Verification"

title1a="The Red Hat Enterprise Linux operating system must enable SELinux."
title1b="Checking with 'getenforce'."
title1c="Expecting:${YLO}
           Enforcing
           Note: If \"SELinux\" is not active and not in \"Enforcing\" mode, this is a finding."${BLD}
cci1="CCI-002165"
stigid1="RHEL-07-020210"
severity1="CAT II"
ruleid1="SV-204453r754746_rule"
vulnid1="V-204453"

title2a="The Red Hat Enterprise Linux operating system must enable the SELinux targeted policy."
title2b="Checking with 'sestatus'."
title2c="Expecting:${YLO}
           SELinux status: enabled
           SELinuxfs mount: /selinux
           SELinux root directory: /etc/selinux
           Loaded policy name: targeted
           Current mode: enforcing
           Mode from config file: enforcing
           Policy MLS status: enabled
           Policy deny_unknown status: allowed
           Max kernel policy version: 28
           Note: .If the \"Loaded policy name\" is not set to \"targeted\", this is a finding."${BLD}
cci2="CCI-002165"
stigid2="RHEL-07-020220"
severity2="CAT II"
ruleid2="SV-204454r754748_rule"
vulnid2="V-204454"

title3a="The Red Hat Enterprise Linux operating system must use a file integrity tool to verify correct operation of all security functions."
title3b="Checking with:
           a. 'rpm -q aide'
	   b. /usr/sbin/aide --check"
title3c="Expecting:
           a. aide-0.15.1-13.el7.x86_64
           b. Nothing returned (the operation succeeded)
	   Note: If there is no application installed to perform integrity checks, this is a finding.
	   Note: If the output is \"Couldn't open file /var/lib/aide/aide.db.gz for reading\", this is a finding."${BLD}
cci3="CCI-002696"
stigid3="RHEL-07-020029"
severity3="CAT II"
ruleid3="SV-251705r833192_rule"
vulnid3="V-251705"

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

echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${CYN}VERIFY, (See AC-3 Access Enforcement: V-204453)${NORMAL}"

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

echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${CYN}VERIFY, (See AC-3 Access Enforcement: V-204454)${NORMAL}"

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

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

dbpath="/var/lib/aide"
dbname="aide.db.gz"
isinstalled="$(rpm -q aide 2>/dev/null)"
fail=0

if [[ $isinstalled && ! $isinstalled =~ "not installed" ]]
then
   echo -e "${NORMAL}RESULT:    ${BLD}a. $isinstalled${NORMAL}"
   dbexists="$(find $dbpath -name $dbname)"
   if [[ $dbexists ]]
   then
     init="$(/usr/sbin/aide --check)"
     if [[ $init ]]
     then
       if [[ $init =~ "Couldn't open file" ]]
       then
          echo -e "${NORMAL}RESULT:    ${RED}$init${NORMAL}"
          fail=1
       fi
     else
       echo -e "${NORMAL}RESULT:    ${BLD}b. Nothing returned${NORMAL}"
     fi
   else
     echo -e "${NORMAL}RESULT:    ${RED}b. $dbexists${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${RED}a. $isinstalled${NORMAL}"
fi

if [[ $fail == 0 ]]
then
   echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${GRN}PASSED, The Red Hat Enterprise Linux operating system uses a file integrity tool to verify correct operation of all security functions.${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${RED}FAILED, The Red Hat Enterprise Linux operating system does not use a file integrity tool to verify correct operation of all security functions.${NORMAL}"
fi

exit
