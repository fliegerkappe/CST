#! /bin/bash

# AC-2 Account Management
#
# CONTROL:
# a. Define and document the types of accounts allowed and specifically prohibited for use within the system;
# b. Assign account managers;
# c. Require [Assignment: organization-defined prerequisites and criteria] for group and role membership;
# d. Specify:
#    1. Authorized users of the system;
#    2. Group and role membership; and
#    3. Access authorizations (i.e., privileges) and [Assignment: organization-defined attributes (as required)] for each account;
# e. Require approvals by [Assignment: organization-defined personnel or roles] for requests to create accounts;
# f. Create, enable, modify, disable, and remove accounts in accordance with [Assignment: organization-defined policy, procedures, prerequisites, and criteria];
# g. Monitor the use of accounts;
# h. Notify account managers and [Assignment: organization-defined personnel or roles] within:
#    1. [Assignment: organization-defined time period] when accounts are no longer required;
#    2. [Assignment: organization-defined time period] when users are terminated or transferred; and
#    3. [Assignment: organization-defined time period] when system usage or need-to-know changes for an individual;
# i. Authorize access to the system based on:
#    1. A valid access authorization;
#    2. Intended system usage; and
#    3. [Assignment: organization-defined attributes (as required)];
# j. Review accounts for compliance with account management requirements [Assignment: organization-defined frequency];
# k. Establish and implement a process for changing shared or group account authenticators (if deployed) when individuals are removed from the group; and
# l. Align account management processes with personnel termination and transfer processes.

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

controlid="AC-2 Account Management"

title1a="RHEL 9 must automatically expire temporary accounts within 72 hours."
title1b="Checking with 'chage -l temp_account_name | grep -i \"account expires\"'."
title1c="Expecting: ${YLO}Temporary accounts have an expiration date set within 72 hours.${BLD}

           Example: temp-account:\$6\$...:19063:1:${YLO}3:${BLD}0:0:${YLO}19066${BLD}:
                      |           |       |   | | ||   |   *-----------9. reserved for future use
                      |           |       |   | | ||   *---------------8. ${YLO}"E" - date when account expires${BLD}
                      |           |       |   | | |*-------------------7. "I" - days before account inactive
                      |           |       |   | | *--------------------6. "W" - days warning for expiration
                      |           |       |   | *----------------------5. ${YLO}"M" - days before change required${BLD}
                      |           |       |   *------------------------4. "m" - days until change allowed
                      |           |       *----------------------------3. last password change
                      |           *------------------------------------2. encrypted password
                      *------------------------------------------------1. user login name
           NOTE: ${YLO}If any temporary accounts have no expiration date set or do not expire within 72 hours, this is a finding.${BLD}
	   FIX:  ${YLO}$ sudo chage -E \`date -d \"+3 days\" +%Y-%m-%d\` temp_account_name: sets the password expiration date, but
                 ${YLO}$ sudo chage -M 3 temp_acccount_name: sets the account expiration date to three days from when it was set.${BLD} 
                 ${YLO}$ sudo chage -m 1 temp_acccount_name: sets the number of days between password resets.${BLD}
                 ${YLO}$ sudo chage -I 1 temp_acccount_name: sets the number of days after password expiration that the account will be locked.${BLD}
                 ${YLO}$ sudo chage -W -1 temp_acccount_name: disables the password age warning.${BLD}
	   NOTE: ${YLO}If chage -M is set to 365, the account will be set to expire a year from the date in position 8."${BLD}
cci1="CCI-000016 CCI-001682"
stigid1="RHEL-09-411040"
severity1="CAT II"
ruleid1="SV-258047r1101951"
vulnid1="V-258047"

title2a="RHEL 9 must disable account identifiers (individuals, groups, roles, and devices) after 35 days of inactivity."
title2b="Checking with: grep -i inactive /etc/default/useradd"
title2c="Expecting: ${YLO}INACTIVE=35
           NOTE: If \"INACTIVE\" is set to \"-1\", a value greater than \"35\", or is commented out, this is a finding."${BLD}
cci2="CCI-003627 CCI-003628 CCI-000795"
stigid2="RHEL-09-411050"
severity2="CAT II"
ruleid2="SV-258049r1015092"
vulnid2="V-258049"

title3a="RHEL 9 must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/sudoers."
title3b="Checking with: 'auditctl -l | grep '/etc/sudoers[^.]'."
title3c="Expecting: ${YLO}-w /etc/sudoers -p wa -k identity
           NOTE: If the command does not return a line, or the line is commented out, this is a finding."${BLD}
cci3="CCI-000018 CCI-000130 CCI-000135 CCI-000169 CCI-000172 CCI-001403 CCI-001404 CCI-001405 CCI-002130 CCI-000015 CCI-002884 CCI-002132"
stigid3="RHEL-09-654215"
severity3="CAT II"
ruleid3="SV-258217r1045436"
vulnid3="V-258217"

title4a="RHEL 9 must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/sudoers.d directory."
title4b="Checking with: 'auditctl -l | grep '/etc/sudoers.d'."
title4c="Expecting: ${YLO}-w /etc/sudoers.d -p wa -k identity
           NOTE: If the command does not return a line, or the line is commented out, this is a finding."${BLD}
cci4="CCI-000018 CCI-000130 CCI-000135 CCI-000169 CCI-000172 CCI-001403 CCI-001404 CCI-001405 CCI-002130 CCI-000015 CCI-002884 CCI-002132"
stigid4="RHEL-09-654220"
severity4="CAT II"
ruleid4="SV-258218r1101981"
vulnid4="V-258218"

title5a="RHEL 9 must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/group."
title5b="Checking with: 'auditctl -l | egrep '(/etc/group)."
title5c="Expecting: ${YLO}-w /etc/group -p wa -k identity
           NOTE: If the command does not return a line, or the line is commented out, this is a finding."${BLD}
cci5="CCI-000018 CCI-000130 CCI-000135 CCI-000169 CCI-000172 CCI-001403 CCI-001404 CCI-001405 CCI-002130 CCI-000015 CCI-002884 CCI-002132"
stigid5="RHEL-09-654225"
severity5="CAT II"
ruleid5="SV-258219r1015130"
vulnid5="V-258219"

title6a="RHEL 9 must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/gshadow."
title6b="Checking with: 'auditctl -l | egrep '(/etc/gshadow)."
title6c="Expecting: ${YLO}-w /etc/gshadow -p wa -k identity
           NOTE: If the command does not return a line, or the line is commented out, this is a finding."${BLD}
cci6="CCI-000018 CCI-000130 CCI-000135 CCI-000169 CCI-000172 CCI-001403 CCI-001404 CCI-001405 CCI-002130 CCI-000015 CCI-002884 CCI-002132"
stigid6="RHEL-09-654230"
severity6="CAT II"
ruleid6="SV-258220r1015131"
vulnid6="V-258220"

title7a="RHEL 9 must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/security/opasswd."
title7b="Checking with: 'auditctl -l | egrep '(/etc/security/opasswd)."
title7c="Expecting: ${YLO}-w /etc/security/opasswd -p wa -k identity
           NOTE: If the command does not return a line, or the line is commented out, this is a finding."${BLD}
cci7="CCI-000018 CCI-000130 CCI-000135 CCI-000169 CCI-000172 CCI-001403 CCI-001404 CCI-001405 CCI-002130 CCI-000015 CCI-002884 CCI-002132"
stigid7="RHEL-09-654235"
severity7="CAT II"
ruleid7="SV-258221r1015132"
vulnid7="V-258221"

title8a="RHEL 9 must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/passwd."
title8b="Checking with: 'auditctl -l | egrep '(/etc/passwd)."
title8c="Expecting: ${YLO}-w /etc/passwd -p wa -k identity
           NOTE: If the command does not return a line, or the line is commented out, this is a finding."${BLD}
cci8="CCI-000018 CCI-000130 CCI-000135 CCI-000169 CCI-000172 CCI-001403 CCI-001404 CCI-001405 CCI-002130 CCI-000015 CCI-002884 CCI-002132"
stigid8="RHEL-09-654240"
severity8="CAT II"
ruleid8="SV-258222r1015133"
vulnid8="V-258222"

title9a="RHEL 9 must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/shadow."
title9b="Checking with: 'auditctl -l | egrep '(/etc/shadow)."
title9c="Expecting: ${YLO}-w /etc/shadow -p wa -k identity
           NOTE: If the command does not return a line, or the line is commented out, this is a finding."${BLD}
cci9="CCI-000018 CCI-000130 CCI-000135 CCI-000169 CCI-000172 CCI-001403 CCI-001404 CCI-001405 CCI-002130 CCI-000015 CCI-002884 CCI-002132"
stigid9="RHEL-09-654245"
severity9="CAT II"
ruleid9="SV-258223r1015134"
vulnid9="V-258223"

title10a="RHEL 9 must have the Postfix package installed."
title10b="Checking with: dnf list --installed postfix."
title10c="Expecting: ${YLO}(example) postfix.x86_64                             2:3.5.25-1.el9
           NOTE:If the \"postfix\" package is not installed, this is a finding. "${BLD}
cci10="CCI-000015"
stigid10="RHEL-09-215101"
severity10="CAT II"
ruleid10="SV-272488r1082178"
vulnid10="V-272488"

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

file1="/etc/shadow"

fail=0

sysapps="$(awk -F: '($2 == "*" || "!*" || "!!" || ".") {print $1}' $file1)"
usrs="$(awk -F: '($2 != "*" && $2 != "!*" && $2 != "!!" && $2 != ".") {print $1}' $file1)"

datetime="$(date +%FT%H:%M:%S)"

echo
echo "SYSTEM/APPLICATION ACCOUNTS:----------------------"
if [[ $sysapps ]]
then
  for name in ${sysapps[@]}
  do
    if [[ $name == 'games' || $name == 'gopher' ]]
    then
      echo -e "${NORMAL}RESULT:    ${RED}$name${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    $name${NORMAL}"
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${RED}No system/application accounts found${NORMAL}"
  fail=1
fi

echo "USER ACCOUNTS:-----------------------------------"
if [[ $usrs ]]
then
  for name in ${usrs[@]}
  do
    acct="$(grep $name $file1)"
    expdate="$(chage -l $name | grep 'Password expires' | awk -F: '{print $2}' | sed 's/^[ \t]//')"
    user="$(echo $acct | awk -F: '{print $1":(password omitted):"$3":"$4":"$5":"$6":"$7":"$8":"$9}')"
    acctexpires="$(echo $acct | awk -F: '{print $5}')"
    pw="$(echo acct | awk -F: '{print $2}')"
    if [[ $expdate == "never" && $name != 'root' ]]
    then
      echo -e "${RED}RESULT:    $user (expires: $expdate)${NORMAL}"
      fail=2
    else
      echo -e "${NORMAL}RESULT:    $user (expires: $expdate)${NORMAL}"
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${RED}No user accounts found${NORMAL}"
  fail=1
fi
echo "-------------------------------------------------"

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${CYN}VERIFY, Have the ISSO verify that all accounts are valid and that if temporary accounts exist that they expire within 72 hours.${NORMAL}"
elif [[ $fail == 2 ]]
then
  echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${CYN}VERIFY, Some user accounts are set to never expire.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${RED}FAILED, No accounts were found.${NORMAL}"
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

file2="/etc/default/useradd"
inactive="$(grep -i inactive $file2)"

if [[ $inactive ]]
then
  length="$(echo $inactive | awk -F= '{print $2}')"
  if (( $length <= 35 && $length != "-1" ))
  then
    echo -e "${NORMAL}RESULT:    ${BLD}$inactive${NORMAL}"
    fail=0
  else
    echo -e "${NORMAL}RESULT:    ${RED}$inactive${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}\"INACTIVE\" not defined in $file2${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${GRN}PASSED, RHEL 9 disables account identifiers (individuals groups roles and devices) after 35 days of inactivity."
else
  echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${RED}FAILED, RHEL 9 does not disable account identifiers (individuals groups roles and devices) after 35 days of inactivity."
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

datetime="$(date +%FT%H:%M:%S)"

echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${CYN}VERIFY, (See AU-12 Audit Configuration: V-258217)${NORMAL}"

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

datetime="$(date +%FT%H:%M:%S)"

echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${CYN}VERIFY, (See AU-12 Audit Configuration: V-258218)${NORMAL}"

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid5${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid5${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid5${NORMAL}"
echo -e "${NORMAL}CCI:       $cci5${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 5:    ${BLD}$title5a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title5b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title5c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity5${NORMAL}"

datetime="$(date +%FT%H:%M:%S)"

echo -e "${NORMAL}$hostname, $severity5, $controlid, $stigid5, $ruleid5, $cci5, $datetime, ${CYN}VERIFY, (See AU-12 Audit Configuration: V-258219)${NORMAL}"

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid6${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid6${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid6${NORMAL}"
echo -e "${NORMAL}CCI:       $cci6${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 6:    ${BLD}$title6a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title6b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title6c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity6${NORMAL}"

datetime="$(date +%FT%H:%M:%S)"

echo -e "${NORMAL}$hostname, $severity6, $controlid, $stigid6, $ruleid6, $cci6, $datetime, ${CYN}VERIFY, (See AU-12 Audit Configuration: V-258220)${NORMAL}"

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid7${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid7${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid7${NORMAL}"
echo -e "${NORMAL}CCI:       $cci7${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 7:    ${BLD}$title7a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title7b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title7c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity7${NORMAL}"

datetime="$(date +%FT%H:%M:%S)"

echo -e "${NORMAL}$hostname, $severity7, $controlid, $stigid7, $ruleid7, $cci7, $datetime, ${CYN}VERIFY, (See AU-12 Audit Configuration: V-258221)${NORMAL}"

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid8${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid8${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid8${NORMAL}"
echo -e "${NORMAL}CCI:       $cci8${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 8:    ${BLD}$title8a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title8b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title8c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity8${NORMAL}"

datetime="$(date +%FT%H:%M:%S)"

echo -e "${NORMAL}$hostname, $severity8, $controlid, $stigid8, $ruleid8, $cci8, $datetime, ${CYN}VERIFY, (See AU-12 Audit Configuration: V-258222)${NORMAL}"

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid9${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid9${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid9${NORMAL}"
echo -e "${NORMAL}CCI:       $cci9${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 9:    ${BLD}$title9a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title9b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title9c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity9${NORMAL}"

datetime="$(date +%FT%H:%M:%S)"

echo -e "${NORMAL}$hostname, $severity9, $controlid, $stigid9, $ruleid9, $cci9, $datetime, ${CYN}VERIFY, (See AU-12 Audit Configuration: V-258223)${NORMAL}"

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid10${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid10${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid10${NORMAL}"
echo -e "${NORMAL}CCI:       $cci10${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 10:   ${BLD}$title10a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title10b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title10c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity10${NORMAL}"

IFS='
'

fail=1

isinstalled="$(dnf list --installed 2>&1 postfix | grep -Ev 'Updating|Installed' )"

if [[ $isinstalled ]]
then
  echo -e "${NORMAL}RESULT:    ${BLD}$isinstalled${NORMAL}"
  fail=0
else
  echo -e "${NORMAL}RESULT:    ${RED}$\"postfix\" not found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity10, $controlid, $stigid10, $ruleid10, $cci10, $datetime, ${GRN}PASSED, RHEL 9 has the Postfix package installed."${NORMAL}
else
  echo -e "${NORMAL}$hostname, $severity10, $controlid, $stigid10, $ruleid10, $cci10, $datetime, ${RED}FAILED, RHEL 9 does not have the Postfix package installed."${NORMAL}
fi

exit
