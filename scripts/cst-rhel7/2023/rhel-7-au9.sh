#! /bin/bash

# AU-9 Protection of Audit Information

# CONTROL: The information system protects audit information and audit tools from
# unauthorized access, modification, and deletion.

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

controlid="AU-9 Protection of Audit Information"

title1a="The Red Hat Enterprise Linux operating system must be configured so that the file permissions, ownership, and group membership of system files and commands match the vendor values."
title1b="Checking with: 'for i in \`rpm -Va | grep '^.M' | cut -d \" \" -f4,5\`;do for j in \`rpm -qf \$i\`;do rpm -ql \$j --dump | cut -d \" \" -f1,5,6,7 | grep \$i;done;done.'"
title1c="Expecting:${YLO} Nothing returned
           Note: If the file is not owned by the default owner and is not documented with the Information System Security Officer (ISSO), this is a finding. 
           Note: If the file is not a member of the default group and is not documented with the Information System Security Officer (ISSO), this is a finding."${BLD}
cci1="CCI-001494"
stigid1="RHEL-07-010010"
severity1="CAT I"
ruleid1="SV-204392r646841_rule"
vulnid1="V-204392"

title2a="The Red Hat Enterprise Linux operating system must protect audit information from unauthorized read, modification, or deletion."
title2b="Checking with 'ls -la /var/log/audit'"
title2c="Expecting:${YLO}
           total 4512
           drwx------. 2 root root 23 Apr 25 16:53 .
           drwxr-xr-x. 17 root root 4096 Aug 9 13:09 ..
           -rw-------. 1 root root 8675309 Aug 9 12:54 audit.log
           Note: Audit logs must be mode 0600 or less permissive.
           Note: If any are more permissive, this is a finding.
           Note: The owner and group owner of all audit log files must both be "root". If any other owner or group owner is listed, this is a finding.${BLD}"
cci2="CCI-000162"
stigid2="RHEL-07-910055"
severity2="CAT II"
ruleid2="SV-228564r606407_rule"
vulnid2="V-228564"

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

echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${CYN}VERIFY, (See AC-3 Access Enforcement: V-204392)${NORMAL}"

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

fail=0

dir2="/var/log/audit"
aulogarr="$(find $dir2 -name "*.log")"

if [[ $aulogarr ]]
then
   for log in ${aulogarr[@]}
   do
      logperm="$(ls -al $log 2>/dev/null)"
      logmode="$(stat -c %a $log | grep -0 '...$')"
      logowner="$(stat -c '%U' $log)"
      loggroup="$(stat -c '%G' $log)"

      if (( ${logmode:0:1} <= 6 &&
            ${logmode:1:1} == 0 &&
            ${logmode:2:1} == 0
         )) &&
         [[ $logowner == "root" &&
            $loggroup == "root"
         ]] 
      then
         echo -e "${NORMAL}RESULT:    ${BLD}$logperm${NORMAL}"
      else
         echo -e "${NORMAL}RESULT:    ${RED}$logperm${NORMAL}"
         fail=1
      fi
   done
else
   echo -e "${NORMAL}RESULT:    ${RED}Could not find any \".log\" files under $dir2${NORMAL}"
fi

if [[ $fail == 0 ]]
then
   echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${GRN}PASSED, The Red Hat Enterprise Linux operating system protects audit information from unauthorized read modification or deletion.${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${RED}FAILED, The Red Hat Enterprise Linux operating system does not protect audit information from unauthorized read modification or deletion.${NORMAL}"
fi

exit

