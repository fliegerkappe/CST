#! /bin/bash

# AC-2 Account Management
#
# CONTROL: The organization:
# a. Identifies and selects the following types of information system accounts to
#    support organizational missions/business functions: [Assignment: organization-
#    defined information system account types];
# b. Assigns account managers for information system accounts;
# c. Establishes conditions for group and role membership;
# d. Specifies authorized users of the information system, group and role membership,
#    and access authorizations (i.e., privileges) and other attributes (as required)
#    for each account;
# e. Requires approvals by [Assignment: organization-defined personnel or roles]
#    for requests to create information system accounts;
# f. Creates, enables, modifies, disables, and removes information system accounts
#    in accordance with [Assignment: organization-defined procedures or conditions];
# g. Monitors the use of, information system accounts;
# h. Notifies account managers:
#    1. When accounts are no longer required;
#    2. When users are terminated or transferred; and
#    3. When individual information system usage or need-to-know changes;
# i. Authorizes access to the information system based on:
#    1. A valid access authorization;
#    2. Intended system usage; and
#    3. Other attributes as required by the organization or associated missions/business
#       functions;
# j. Reviews accounts for compliance with account management requirements [Assignment: 
#    organization-defined frequency]; and
# k. Establishes a process for reissuing shared/group account credentials (if deployed)
#    when individuals are removed from the group.

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

controlid="AC-2 Account Management"

title1a="RHEL 8 temporary user accounts must be provisioned with an expiration time of 72 hours or less."
title1b="Checking with 'chage -l temp_account_name'."
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
           NOTE: ${YLO}If any emergency accounts have no expiration date set or do not expire within 72 hours, this is a finding.${BLD}
	   FIX:  ${YLO}$ sudo chage -E `date -d "+3 days" +%Y-%m-%d` temp_account_name: sets the password expiration date, but
                 ${YLO}$ sudo chage -M 3 temp_acccount_name: sets the account expiration date to three days from when it was set.${BLD} 
                 ${YLO}$ sudo chage -m 1 temp_acccount_name: sets the number of days between password resets.${BLD}
                 ${YLO}$ sudo chage -I 1 temp_acccount_name: sets the number of days after password expiration that the account will be locked.${BLD}
                 ${YLO}$ sudo chage -W -1 temp_acccount_name: disables the password age warning.${BLD}
	   NOTE: ${YLO}If chage -M is set to 365, the account will be set to expire a year from the date in position 8."${BLD}
cci1="CCI-000016"
stigid1="RHEL-08-020000"
severity1="CAT II"
ruleid1="SV-230331r627750_rule"
vulnid1="V-230331"

title2a="RHEL 8 emergency accounts must be automatically removed or disabled after the crisis is resolved or within 72 hours"
title2b="Checking with 'chage -l emergency_acct_name'."
title2c="Expecting: ${YLO}Emergency accounts are automatically removed or disabled after the crisis is resolved or within 72 hours.${BLD}
           NOTE: ${YLO}If any emergency accounts have no expiration date set or do not expire within 72 hours, this is a finding.${BLD}
           Example: emergency-acct:\$6\$...:19063:1:${YLO}3:${BLD}:0:${YLO}19066${BLD}:
                      |             |       |   | | ||   |   *---------9. reserved for future use
                      |             |       |   | | ||   *-------------8. ${YLO}"E" - date when account expires${BLD}
                      |             |       |   | | |*-----------------7. "I" - days before account inactive
                      |             |       |   | | *------------------6. "W" - days warning for expiration
                      |             |       |   | *--------------------5. ${YLO}"M" - days before change required${BLD}
                      |             |       |   *----------------------4. "m" - days until change allowed
                      |             |       *--------------------------3. last password change
                      |             *----------------------------------2. encrypted password
                      *------------------------------------------------1. user login name
           NOTE: ${YLO}If any emergency accounts have no expiration date set or do not expire within 72 hours, this is a finding.${BLD}
	   FIX:  ${YLO}$ sudo chage -E `date -d "+3 days" +%Y-%m-%d` temp_account_name: sets the password expiration date, but
                 ${YLO}$ sudo chage -M 3 temp_acccount_name: sets the account expiration date to three days from when it was set.${BLD} 
                 ${YLO}$ sudo chage -m 1 temp_acccount_name: sets the number of days between password resets.${BLD}
                 ${YLO}$ sudo chage -I 1 temp_acccount_name: sets the number of days after password expiration that the account will be locked.${BLD}
                 ${YLO}$ sudo chage -W -1 temp_acccount_name: disables the password age warning.${BLD}
	   NOTE: ${YLO}If chage -M is set to 365, the account will be set to expire a year from the date in position 8."${BLD}
cci2="CCI-001682"
stigid2="RHEL-08-020270"
severity2="CAT II"
ruleid2="SV-230374r627750_rule"
vulnid2="V-230374"

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

sysapps="$(awk -F: '($2 == "*" || $2 == "!!" || $2 == ".") {print $1}' $file1)"
usrs="$(awk -F: '($2 != "*" && $2 != "!!" && $2 != ".") {print $1}' $file1)"

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

file2="/etc/shadow"

fail=0

sysapps="$(awk -F: '($2 == "*" || $2 == "!!" || $2 == ".") {print $1}' $file2)"
usrs="$(awk -F: '($2 != "*" && $2 != "!!" && $2 != ".") {print $1}' $file2)"

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
  echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${CYN}VERIFY, Have the ISSO verify that all accounts are valid and that if emergency accounts exist that they expire within 72 hours.${NORMAL}"
elif [[ $fail == 2 ]]
then
  echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${CYN}VERIFY, Some user accounts are set to never expire.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${RED}FAILED, No accounts were found.${NORMAL}"
fi

exit
