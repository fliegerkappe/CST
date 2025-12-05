#! /bin/bash

# IA-11 Re-Authentication

# CONTROL: Require users to re-authenticate when [Assignment: organization-defined circumstances or situations requiring re-authentication].

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

controlid="IA-11 Reauthentication"

title1a="RHEL 9 must require reauthentication when using the \"sudo\" command."
title1b="Checking with: 'grep -ir 'timestamp_timeout' /etc/sudoers /etc/sudoers.d/'."
title1c="Expecting: ${YLO}/etc/sudoers:Defaults timestamp_timeout=0
           NOTE: If results are returned from more than one file location, this is a finding.
           NOTE: If \"timestamp_timeout\" is set to a negative number, is commented out, or no results are returned, this is a finding."${BLD}
cci1="CCI-004895 CCI-002038"
stigid1="RHEL-09-432015"
severity1="CAT II"
ruleid1="SV-258084r1050789"
vulnid1="V-258084"

title2a="RHEL 9 must require users to reauthenticate for privilege escalation."
title2b="Checking with: egrep -iR '!authenticate' /etc/sudoers /etc/sudoers.d."
title2c="Expecting: ${YLO}Nothing returned
           NOTE: If any occurrences of \"!authenticate\" return from the command, this is a finding."${BLD}
cci2="CCI-004895 CCI-002038"
stigid2="RHEL-09-432025"
severity2="CAT II"
ruleid2="SV-258086r1102063"
vulnid2="V-258086"

title3a="RHEL 9 must restrict the use of the \"su\" command."
title3b="Checking with: grep pam_wheel /etc/pam.d/su"
title3c="Expecting: ${YLO}auth       required       pam_wheel.so use_uid
           NOTE: If a line for \"pam_wheel.so\" does not exist, or is commented out, this is a finding."${BLD}
cci3="CCI-004895 CCI-002038"
stigid3="RHEL-09-432035"
severity3="CAT II"
ruleid3="SV-258088r1050789"
vulnid3="V-258088"

title4a="RHEL 9 must require users to provide a password for privilege escalation."
title4b="Checking with 'grep -iR 'NOPASSWD' /etc/sudoers /etc/sudoers.d/"
title4c="Expecting: ${YLO}Nothing returned
           NOTE: If any occurrences of \"NOPASSWD\" are returned from the command and have not been documented with the information system security officer (ISSO) as an organizationally defined administrative group utilizing multifactor authentication (MFA), this is a finding."${BLD}
cci4="CCI-004895 CCI-002038"
stigid4="RHEL-09-611085"
severity4="CAT II"
ruleid4="SV-258106r1102061"
vulnid4="V-258106"

title5a="The RHEL 9 operating system must not be configured to bypass password requirements for privilege escalation."
title5b="Checking with: 'grep pam_succeed_if /etc/pam.d/sudo'."
title5c="Expecting: ${YLO}Nothing returned
           NOTE: If any occurrences of \"pam_succeed_if\" are returned, this is a finding."${BLD}
cci5="CCI-004895 CCI-002038"
stigid5="RHEL-09-611145"
severity5="CAT II"
ruleid5="SV-258118r1050789"
vulnid5="V-258118"

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

reauth="$(grep -ir 'timestamp_timeout' 2>/dev/null /etc/sudoers /etc/sudoers.d/)"

if [[ $reauth ]]
then
  file="$(echo $reauth | awk -F: '{print $1}')"
  setting="$(echo $reauth | awk -F: '{print $2}')"
  value="$(echo $reauth | awk -F= '{print $2}' | sed 's/ //')"
  if (( $value >= "0" )) && [[ ${setting:0:1} != "#" ]]
  then
    fail=0
    echo -e "${NORMAL}RESULT:    ${CYN}$file:${BLD}$setting${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${CYN}$file:${RED}$setting${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${GRN}PASSED, RHEL 9 requires reauthentication when using the "sudo" command.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${RED}FAILED, RHEL 9 does not require reauthentication when using the "sudo" command.${NORMAL}"
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

fail=0

datetime="$(date +%FT%H:%M:%S)"

reauth="$(egrep -iR '!authenticate' 2>/dev/null 2>/dev/null /etc/sudoers /etc/sudoers.d/)"

if [[ $reauth ]]
then
  fail=1
  for line in ${reauth[@]}
  do
    echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
  done
else
  echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${GRN}PASSED, RHEL 9 requires users to reauthenticate for privilege escalation.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${RED}FAILED, RHEL 9 does not require users to reauthenticate for privilege escalation.${NORMAL}"
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

echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${CYN}VERIFY, (See AC-3 Access Enforcement: V-258088)${NORMAL}"

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

fail=0

datetime="$(date +%FT%H:%M:%S)"

nopass="$(grep -iR 'NOPASSWD' 2>/dev/null /etc/sudoers /etc/sudoers.d/ | grep -v ":#")"

if [[ $nopass ]]
then
  file="$(echo $nopass | awk -F: '{print $1}')"
  setting="$(echo $nopass | awk -F: '{print $2}')"
  for line in ${nopass[@]}
  do
    if [[ ${setting:0:1} != "#" ]]
    then
      fail=1 
      echo -e "${NORMAL}RESULT:    ${CYN}$file:${RED}$setting${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${CYN}$file:${NORMAL}$setting${NORMAL}"
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${GRN}PASSED, RHEL 9 requires users to provide a password for privilege escalation.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${RED}FAILED, RHEL 9 does not require users to provide a password for privilege escalation.${NORMAL}"
fi

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

IFS='
'

fail=0

datetime="$(date +%FT%H:%M:%S)"

bypass="$(grep pam_succeed_if 2>/dev/null /etc/pam.d/sudo)"

if [[ -f $bypass ]]
then
  for line in ${bypass[@]}
  do
    if [[ ${line:0:1} != "#" ]]
    then
      fail=1
      echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    $line${NORMAL}"
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity5, $controlid, $stigid5, $ruleid5, $cci5, $datetime, ${GRN}PASSED, RHEL 9 is not configured to bypass password requirements for privilege escalation.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity5, $controlid, $stigid5, $ruleid5, $cci5, $datetime, ${RED}FAILED, RHEL 9 is configured to bypass password requirements for privilege escalation.${NORMAL}"
fi

exit

