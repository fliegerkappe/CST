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

stig="Red Hat Enterprise Linux 8 Security Technical Implementation Guide :: Version 1, Release: 13 Benchmark Date: 24 Jan 2024"

hostname="$(uname -n)"

if [[ -f /etc/redhat-release ]]
then
   os="$(cat /etc/redhat-release)"
else
   os="OS not defined"
fi

prog="$(basename $0)"

controlid="AC-6 Least Privilege"

title1a="The RHEL 8 audit system must be configured to audit the execution of privileged functions and prevent all software from executing at higher privilege levels than users executing the software."
title1b="Checking with 'grep execve /etc/audit/audit.rules'"
title1c="Expecting:
           ${YLO}-a always,exit -F arch=b32 -S execve -C uid!=euid -F euid=0 -k execpriv
           -a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -k execpriv
           -a always,exit -F arch=b32 -S execve -C gid!=egid -F egid=0 -k execpriv
           -a always,exit -F arch=b64 -S execve -C gid!=egid -F egid=0 -k execpriv${BLD}
           Note: ${YLO}If the command does not return all lines, or the lines are commented out, this is a finding."${BLD}
cci1="CCI-002233"
stigid1="RHEL-08-030000"
severity1="CAT II"
ruleid1="SV-230386r627750_rule"
vulnid1="V-230386"

title2a="RHEL 8 must use the invoking user's password for privilege escalation when using \"sudo\"."
title2b="Checking with: egrep -i '(!rootpw|!targetpw|!runaspw)' /etc/sudoers /etc/sudoers.d/* | grep -v '#'."
title2c="Expecting: 
           ${YLO}/etc/sudoers:Defaults !targetpw
           /etc/sudoers:Defaults !rootpw
           /etc/sudoers:Defaults !runaspw${BLD}
	   NOTE: ${YLO}If no results are returned, this is a finding${BLD}
           NOTE: ${YLO}If \"Defaults !targetpw\" is not defined, this is a finding.${BLD}
           NOTE: ${YLO}If \"Defaults !rootpw\" is not defined, this is a finding.${BLD}
           NOTE: ${YLO}If \"Defaults !runaspw\" is not defined, this is a finding."${BLD}
cci2="CCI-002227"
stigid2="RHEL-08-010383"
severity2="CAT II"
ruleid2="SV-237642r646896_rule"
vulnid2="V-237642"

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

file1='/etc/audit/audit.rules'
fail=0
count=0

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file1 ]]
then
   execv="$(grep execve $file1)"
   if [[ $execv ]]
   then
      for line in ${execv[@]}
      do
	(( count++ ))
         if [[ $line =~ '-a always,exit' ]] 
         then
		 if ! [[ ( $line =~ '-C uid!=euid' || $line =~ '-C gid!=egid' )&& 
			 ( $line =~ '-F euid=0' || $line =~ '-F egid=0' ) &&
			 ${line:0:1} != "#" ]]
            then
               echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
               fail=1
	    else
               echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
            fi
         else
            echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
         fi
      done
   else
      echo -e "${NORMAL}RESULT:    ${RED}'execve' not found in $file1${NORMAL}"
   fi

   if [[ $fail == 0 && $count >=4 ]]
   then
      echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${GRN}PASSED, Privileged Function Auditing: All executions of privileged functions are audited${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${RED}FAILED, Privileged Function Auditing: All executions of privileged functions are not audited${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${BLD}$file1 not found${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${RED}FAILED, Privileged Function Auditing: $file1 not found${NORMAL}"
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

file2a='/etc/sudoers'
file2b='/etc/sudoers.d/*'
fail=0
rootpw=0
targetpw=0
runaspw=0

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file2a || $file2b ]]
then
  sudoer="$(egrep -i '(!rootpw|!targetpw|!runaspw)' $file2a $file2b 2>/dev/null | grep -v '#')"
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
  echo -e "${NORMAL}RESULT:    ${RED}$file2a or $file2b not found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${GRN}PASSED, The sudoers security policy is configured to use the invoking user's password for privilege escalation.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${RED}FAILED, The sudoers security policy is not configured to use the invoking user's password for privilege escalation.${NORMAL}"
fi

exit
