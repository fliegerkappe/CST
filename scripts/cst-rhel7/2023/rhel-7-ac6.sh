#! /bin/bash

# AC-6 Least Privilege

# Control: The organization employs the principle of least privilege, allowing only authorized
# accesses for users (or processes acting on behalf of users) which are necessary to accomplish
# assigned tasks in accordance with organizational missions and business functions.

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

controlid="AC-6 Least Privilege"

title1a="The Red Hat Enterprise Linux operating system must use the invoking user's password for privilege escalation when using \"sudo\"."
title1b="Checking with: grep -Eir '(rootpw|targetpw|runaspw)' /etc/sudoers /etc/sudoers.d* | grep -v '#'"
title1c="Expecting: 
           ${YLO}/etc/sudoers:Defaults !targetpw
           /etc/sudoers:Defaults !rootpw
           /etc/sudoers:Defaults !runaspw${BLD}
           NOTE: ${YLO}If no results are returned, this is a finding${BLD}
           NOTE: ${YLO}If \"Defaults !targetpw\" is not defined, this is a finding.${BLD}
           NOTE: ${YLO}If \"Defaults !rootpw\" is not defined, this is a finding.${BLD}
           NOTE: ${YLO}If \"Defaults !runaspw\" is not defined, this is a finding."${BLD}
cci1="CCI-002227"
stigid1="RHEL-07-010342"
severity1="CAT II"
ruleid1="SV-237634r833177_rule"
vulnid1="V-237634"

title2a="The Red Hat Enterprise Linux operating system must audit all executions of privileged functions."
title2b="Checking with 'grep -iw execve /etc/audit/audit.rules'"
title2c="Expecting: ${YLO}
           -a always,exit -F arch=b32 -S execve -C uid!=euid -F euid=0 -k setuid
           -a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -k setuid
           -a always,exit -F arch=b32 -S execve -C gid!=egid -F egid=0 -k setgid
           -a always,exit -F arch=b64 -S execve -C gid!=egid -F egid=0 -k setgid
           Note: The output lines of the command are duplicated to cover both 32-bit and 64-bit architectures.
           Note: Only the lines appropriate for the system architecture must be present. 
           Note: If the audit rule for \"SUID\" files is not defined, this is a finding.            Note: If the audit rule for \"SGID\" files is not defined, this is a finding.${BLD}"
cci2="CCI-002234"
stigid2="RHEL-07-030360"
severity2="CAT II"
ruleid2="SV-204516r603261_rule"
vulnid2="V-204516"

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

file1a='/etc/sudoers'
file1b='/etc/sudoers.d/*'
fail=0
rootpw=0
targetpw=0
runaspw=0

if [[ -f $file1a || $file1b ]]
then
  sudoer="$(grep -Eir '(rootpw|targetpw|runaspw)' $file1a $file1b 2>/dev/null | grep -v '#')"
  if [[ $sudoer ]]
  then
    for line in ${sudoer[@]}
    do
      if [[ $line =~ '!rootpw' ]]
      then
        echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
        rootpw=1
      elif [[ $line =~ '!targetpw' ]]
      then
        echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
        targetpw=1
      elif [[ $line =~ '!runaspw' ]]
      then
        echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
        runaspw=1
      fi
    done
    if [[ $rootpw == 0 || $targetpw == 0 || runaspw == 0 ]]
    then
      echo -e "${NORMAL}RESULT:    ${RED}Missing definitions${NORMAL}"
      fail=2
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
    fail=1
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}$file1a or $file1b not found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${GRN}PASSED, The sudoers security policy is configured to use the invoking user's password for privilege escalation.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${RED}FAILED, The sudoers security policy is not configured to use the invoking user's password for privilege escalation.${NORMAL}"
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

file2='/etc/audit/audit.rules'
fail=0

if [[ -f $file2 ]]
then
   execv="$(grep -iw execve $file2)"
   if [[ $execv ]]
   then
      for line in ${execv[@]}
      do
         if [[ $line =~ '-a exit,always' ]] 
         then
            echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
         else
            echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
            fail=1
         fi

         if ! [[ $line =~ '-C uid!=euid' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-C uid!=euid'${NORMAL}"
         fi
         if ! [[ $line =~ '-F euid=0' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-F euid=0'${NORMAL}"
         fi
         if ! [[ $line =~ '-k setuid' || $line =~ '-k setgid' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-k setuid (or -k setgid)'${NORMAL}"
         fi
      done
   else
      echo -e "${NORMAL}RESULT:    ${RED}'execve' not found in $file2${NORMAL}"
      fail=1
   fi

   if [[ $fail == 0 ]]
   then
      echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${GRN}PASSED, Privileged Function Auditing: All executions of privileged functions are audited${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${RED}FAILED, Privileged Function Auditing: All executions of privileged functions are not audited${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${BLD}$file2 not found${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${RED}FAILED, Privileged Function Auditing: $file2 not found${NORMAL}"
fi

exit
