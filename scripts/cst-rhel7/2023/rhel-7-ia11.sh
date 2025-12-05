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

stig="Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Version 3, Release: 10 Benchmark Date: 26 Jan 2023"

hostname="$(uname -n)"

if [[ -f /etc/redhat-release ]]
then
   os="$(cat /etc/redhat-release)"
else
   os="OS not defined"
fi

prog="$(basename $0)"

controlid="IA-11 Re-Authentication"

title1a="The Red Hat Enterprise Linux operating system must be configured so that users must provide a password for privilege escalation."
title1b="Checking with 'grep -ir nopasswd /etc/sudoers /etc/sudoers.d"
title1c="Expecting:${YLO}
           Nothing returned
           Note: If any uncommented line is found with a \"NOPASSWD\" tag, this is a finding."${BLD}
cci1="CCI-002038"
stigid1="RHEL-07-010340"
severity1="CAT II"
ruleid1="SV-204429r833190_rule"
vulnid1="V-204429"

title2a="The Red Hat Enterprise Linux operating system must be configured so that users must re-authenticate for privilege escalation."
title2b="Checking with:
           grep -i authenticate /etc/sudoers /etc/sudoers.d/*."
title2c="Expecting:${YLO}
           Nothing returned
           Note: If any uncommented line is found with a \"!authenticate\" tag, this is a finding."${BLD}
cci2="CCI-002038"
stigid2="RHEL-07-010350"
severity2="CAT II"
ruleid2="SV-204430r603261_rule"
vulnid2="V-204430"

title3a="The Red Hat Enterprise Linux operating system must require re-authentication when using the "sudo" command."
title3b="Checking with:
           'grep -ir 'timestamp_timeout' /etc/sudoers /etc/sudoers.d'"
title3c="Expecting:${YLO}
           /etc/sudoers:Defaults timestamp_timeout=0
	   Note: If conflicting results are returned, this is a finding.
	   Note: If "timestamp_timeout" is set to a negative number, is commented out, or no results are returned, this is a finding."${BLD}
cci3="CCI-002038"
stigid3="RHEL-07-010343"
severity3="CAT II"
ruleid3="SV-237635r833179_rule"
vulnid3="V-237635"

title4a="The Red Hat Enterprise Linux operating system must not be configured to bypass password requirements for privilege escalation."
title4b="Checking with:
           'grep pam_succeed_if /etc/pam.d/sudo'"
title4c="Expecting:${YLO}
           Nothing returned
	   Note: If any occurrences of \"pam_succeed_if\" is returned from the command, this is a finding."${BLD}
cci4="CCI-002038"
stigid4="RHEL-07-010344"
severity4="CAT II"
ruleid4="SV-251704r809568_rule"
vulnid4="V-251704"

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

datetime="$(date +%FT%H:%M:%S)"

file1="/etc/sudoers"
dir1="/etc/sudoers.d"

fail=0

nopw="$(grep -i nopasswd $file1 $dir1/* 2>/dev/null)"

if [[ $nopw ]]
then
   for accts in ${nopw[@]}
   do
      file="$(echo $accts | awk -F: '{print $1}')"
      acct="$(echo $accts | awk -F: '{print $2}')"
      if [[ ${acct:0:1} != '#' ]]
      then
         echo -e "${NORMAL}RESULT:    ${CYN}$file:${RED}$acct${NORMAL}"
         fail=1
      else
         echo -e "${NORMAL}RESULT:    $file:$acct${NORMAL}"
      fi
   done
else
    echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
   echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${GRN}PASSED, Privilege Escalation (NOPASSWD): Users are required to use a password for privilege escalation.${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${RED}FAILED, Privilege Escalation (NOPASSWD): Users are not required to use a password for privilege escalation.${NORMAL}"
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

datetime="$(date +%FT%H:%M:%S)"

file2="/etc/sudoers"
dir2="/etc/sudoers.d"

fail=0

noreauth="$(grep -i authenticate $file2 $dir2/* 2>/dev/null)"

if [[ $noreauth ]]
then
   for acct in ${noreauth[@]}
   do
      file="$(echo $noreauth | awk -F: '{print $1}')"
      acct="$(echo $noreauth | awk -F: '{print $2}')"
      if [[ ${acct:0:1} != '#' ]]
      then 
         echo -e "${NORMAL}RESULT:    ${CYN}$file:${RED}$acct${NORMAL}"
         fail=1
      else
         echo -e "${NORMAL}RESULT:    $file:$acct${NORMAL}"
      fi
   done
else
   echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned.${NORMAL}"
fi

if [[ $fail == 0 ]]
then
   echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${GRN}PASSED, Users are required to reauthenticate prior to using privilege escalation.${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${RED}FAILED, Users are not required to reauthenticate prior to using privilege escalation.${NORMAL}"
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

datetime="$(date +%FT%H:%M:%S)"

file3arr=('/etc/sudoers' '/etc/sudoers.d')
fail=1

for file in ${file3arr[@]}
do
   tstimeout="$(grep -ir 'timestamp_timeout' $file 2>/dev/null)"
   if [[ $tstimeout ]]
   then
      for line in ${tstimeout[@]}
      do
	 if [[ $line =~ ":" ]]
         then
	    timeout="$(echo $line | awk -F: '{print $2}')"
	    val="$(echo $timeout | awk -F= '{print $2}')"
	    if [[ $val == 0 ]]
            then
               echo -e "${NORMAL}RESULT:    ${CYN}$file:${BLD}$timeout${NORMAL}"
               fail=0
	    else
               echo -e "${NORMAL}RESULT:    ${CYN}$file:${RED}$timeout${NORMAL}"
	    fi
	 else
	    val="$(echo $line | awk -F= '{print $2}')"
	    if [[ $val == 0 ]]
            then
               echo -e "${NORMAL}RESULT:    ${CYN}$file:${BLD}$line${NORMAL}"
               fail=0
            else
               echo -e "${NORMAL}RESULT:    ${CYN}$file:${RED}$line${NORMAL}"
            fi
         fi
      done
   else
      echo -e "${NORMAL}RESULT:    $file:Nothing returned${NORMAL}"
   fi
done

if [[ $fail == 0 ]]
then
   echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${GRN}PASSED, The Red Hat Enterprise Linux operating system requires re-authentication when using the "sudo" command.${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${RED}FAILED, The Red Hat Enterprise Linux operating system does not require re-authentication when using the "sudo" command.${NORMAL}"
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

datetime="$(date +%FT%H:%M:%S)"

file4="/etc/pam.d/sudo"
fail=0

succeedif="$(grep pam_succeed_if $file4 2</dev/null)"
if [[ $succeedif ]]
then
   for line in ${succeedif[@]}
   do
      echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
      fail=1
   done
else
   echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
   echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${GRN}PASSED, The Red Hat Enterprise Linux operating system is not configured to bypass password requirements for privilege escalation.${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${RED}FAILED, The Red Hat Enterprise Linux operating system is configured to bypass password requirements for privilege escalation.${NORMAL}"
fi

exit

