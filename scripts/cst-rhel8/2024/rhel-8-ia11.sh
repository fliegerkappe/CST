#! /bin/bash

# IA-11 Re-Authentication

# CONTROL: The organization requires users and devices to re-authenticate when [Assignment:
# organization-defined circumstances or situations requiring re-authentication].

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

stig="Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 2 Benchmark Date: 25 Jan 2019"

hostname="$(uname -n)"

if [[ -f /etc/redhat-release ]]
then
   os="$(cat /etc/redhat-release)"
else
   os="OS not defined"
fi

prog="$(basename $0)"

controlid="IA-11 Re-Authentication"

title1a="RHEL 8 must require users to provide a password for privilege escalation."
title1b="Checking with 'grep -i nopasswd /etc/sudoers /etc/sudoers.d/*"
title1c="Expecting: ${YLO}Nothing returned
           NOTE: If any occurrences of \"NOPASSWD\" are returned from the command and have not been documented with the ISSO as an organizationally defined administrative group utilizing MFA, this is a finding."${BLD}
cci1="CCI-002038"
stigid1="RHEL-08-010380"
severity1="CAT II"
ruleid1="SV-230271r854026_rule"
vulnid1="V-230271"

title2a="RHEL 8 must require users to reauthenticate for privilege escalation."
title2b="grep -i !authenticate /etc/sudoers /etc/sudoers.d/*."
title2c="Expecting: ${YLO}the '!authenticate' tag is not found.
           NOTE: If any occurrences of \"!authenticate\" return from the command, this is a finding."
cci2="CCI-002038"
stigid2="RHEL-08-010381"
severity2="CAT II"
ruleid2="SV-230272r854027_rule"
vulnid2="V-230272"

title3a="RHEL 8 must require re-authentication when using the \"sudo\" command."
title3b="Checking with: 'grep -i 'timestamp_timeout' /etc/sudoers /etc/sudoers.d/*'."
title3c="Expecting: ${YLO}/etc/sudoers:Defaults timestamp_timeout=0
           NOTE: If results are returned from more than one file location, this is a finding.
           NOTE: If \"timestamp_timeout\" is set to a negative number, is commented out, or no results are returned, this is a finding."${BLD}
cci3="CCI-002038"
stigid3="RHEL-08-010384"
severity3="CAT II"
ruleid3="SV-237643r861088_rule"
vulnid3="V-237643"

title4a="The RHEL 8 operating system must not be configured to bypass password requirements for privilege escalation."
title4b="Checking with: 'grep pam_succeed_if /etc/pam.d/sudo'."
title4c="Expecting: ${YLO}Nothing returned
           NOTE: If any occurrences of \"pam_succeed_if\" is returned from the command, this is a finding."${BLD}
cci4="CCI-002038"
stigid4="RHEL-08-010385"
severity4="CAT II"
ruleid4="SV-251712r854083_rule"
vulnid4="V-251712"

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

file1="/etc/sudoers"
dir1="/etc/sudoers.d"

nopw="$(grep -i nopasswd $file1 $dir1/* | grep -v ':#')"

datetime="$(date +%FT%H:%M:%S)"

if [[ $nopw ]]
then
   for acct in ${nopw[@]}
   do
      echo -e "${NORMAL}RESULT:    ${RED}$acct${NORMAL}"
   done
   echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${RED}FAILED, Privilege Escalation (NOPASSWD): Users are not required to use a password for privilege escalation.${NORMAL}"
else
   echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${GRN}PASSED, Privilege Escalation (NOPASSWD): Users are required to use a password for privilege escalation.${NORMAL}"
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

file2="/etc/sudoers"
dir2="/etc/sudoers.d"

noreauth="$(grep -i !authenticate $file2 $dir2/* | grep -v ':#')"

datetime="$(date +%FT%H:%M:%S)"

if [[ $noreauth ]]
then
   for acct in ${noreauth[@]}
   do
      echo -e "${NORMAL}RESULT:    ${RED}$acct${NORMAL}"
   done
   echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${RED}FAILED, Privilege Escalation (!Authentication): Users are not required to reauthenticate prior to using privilege escalation.${NORMAL}"
else
   echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${GRN}PASSED, Privilege Escalation (!Authentication): Users are required to reauthenticate prior to using privilege escalation.${NORMAL}"
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

IFS='
'

file3="/etc/sudoers"
dir3="/etc/sudoers.d"

reauth="$(grep -i 'timestamp_timeout' $file3 $dir3/* | grep -v ':#')"

datetime="$(date +%FT%H:%M:%S)"

if [[ $reauth ]]
then
  if [[ ${#reauth[@]} == 1 ]]
  then
    rauthval="$(echo $rauth | awk -F= '{print $2}')"
    if [[ $reauthval > 0 ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}$reauth${NORMAL}"
      echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${GRN}PASSED, Re-Authentication: RHEL 8 requires re-authentication when using the \"sudo\" command.${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${BLD}$reauth${NORMAL}"
      echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${GRN}PASSED, Re-Authentication: RHEL 8 requires re-authentication when using the \"sudo\" command.${NORMAL}"
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}\"timestamp_timeout\" is defined in more than one file location.${NORMAL}"
    echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${RED}FAILED, Re-Authentication: Defining \"timestamp_timeout\" in more than one file location is not allowed.${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}$file3 not found${NORMAL}"
  echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${RED}FAILED, Re-Authentication: RHEL 8 does not require re-authentication when using the \"sudo\" command.${NORMAL}"
fi

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

file4="/etc/pam.d/sudo"

fail=0

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file4 ]]
then
  pwbypass="$(grep 'pam_succeed_if' $file4 | grep -v '^#')"
  if [[ $pwbypass ]]
  then
    fail=1
    for line in ${pwbypass[@]}
    do
      echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
    done
  else
    echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}$file4 not found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${GRN}PASSED, The RHEL 8 operating system is not configured to bypass password requirements for privilege escalation.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${GRN}PASSED, The RHEL 8 operating system is configured to bypass password requirements for privilege escalation.${NORMAL}"
fi

exit

