#! /bin/bash

# SC-2 Separation of System and User Functionality
#
# CONTROL: Separate user functionality, including user interface services, from system management
# functionality.


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

controlid="SC-2 Separation of Systemand User Functionality"

title1a="RHEL 9 must restrict access to the kernel message buffer."
title1b="Checking with: sysctl kernel.dmesg_restrict"
title1c="Expecting: ${YLO}kernel.dmesg_restrict = 1
           NOTE: If \"kernel.dmesg_restrict\" is not set to \"1\" or is missing, this is a finding."${BLD}
cci1="CCI-001082 CCI-001090"
stigid1="RHEL-09-213010"
severity1="CAT II"
ruleid1="SV-257797r1117266"
vulnid1="V-257797"

title2a="RHEL 9 must prevent kernel profiling by nonprivileged users."
title2b="Checking with: 
           a. sysctl kernel.perf_event_paranoid
	   b. grep -r kernel.perf_event_paranoid /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf /etc/sysctl.d/*.conf"
title2c="Expecting: ${YLO}
           a. kernel.perf_event_paranoid = 2
	   b. /etc/sysctl.d/99-sysctl.conf:kernel.perf_event_paranoid = 2
	   NOTE: If \"kernel.perf_event_paranoid\" is not set to \"2\", is missing, or commented out, this is a finding.
	   NOTE: If conflicting results are returned, this is a finding."${BLD}
cci2="CCI-001082 CCI-001090"
stigid2="RHEL-09-213015"
severity2="CAT II"
ruleid2="SV-257798r1117266"
vulnid2="V-257798"

title3a="RHEL 9 must restrict exposed kernel pointer addresses access."
title3b="Checking with: 
           a. sysctl kernel.kptr_restrict
	   b. grep -r kernel.kptr_restrict /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf /etc/sysctl.d/*.conf"
title3c="Expecting: ${YLO}
           a. kernel.kptr_restrict = 1
           b. /etc/sysctl.d/99-sysctl.conf: kernel.kptr_restrict = 1
	   NOTE: If \"kernel.kptr_restrict\" is not set to \"1\" or \"2\", is missing, or commented out, this is a finding.
	   NOTE: If conflicting results are returned, this is a finding."${BLD}
cci3="CCI-001082 CCI-002824"
stigid3="RHEL-09-213025"
severity3="CAT II"
ruleid3="SV-257800r1117266"
vulnid3="V-257800"

title4a="RHEL 9 must disable access to network bpf system call from nonprivileged processes."
title4b="Checking with: sysctl kernel.unprivileged_bpf_disabled"
title4c="Expecting: ${YLO}kernel.unprivileged_bpf_disabled = 1
           NOTE: If the returned line does not have a value of \"1\", or a line is not returned, this is a finding."${BLD}
cci4="CCI-001082"
stigid4="RHEL-09-213075"
severity4="CAT II"
ruleid4="SV-257810r1117266"
vulnid4="V-257810"

title5a="RHEL 9 must restrict usage of ptrace to descendant processes."
title5b="Checking with: 
           a. sysctl kernel.yama.ptrace_scope
	   b. grep -r kernel.yama.ptrace_scope /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf /etc/sysctl.d/*.conf"
title5c="Expecting: ${YLO}
           a. kernel.yama.ptrace_scope = 1
           b. /etc/sysctl.d/99-sysctl.conf: kernel.yama.ptrace_scope = 1
           NOTE: If \"kernel.yama.ptrace_scope\" is not set to \"1\", is missing, or commented out, this is a finding.
           NOTE: If conflicting results are returned, this is a finding."${BLD}
cci5="CCI-001082"
stigid5="RHEL-09-213080"
severity5="CAT II"
ruleid5="SV-257811r1117266"
vulnid5="V-257811"

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

echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${CYN}VERIFY, (See SC-4 Information In Shared Resources: V-257797)${NORMAL}"

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

echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${CYN}VERIFY, (See SC-4 Information In Shared Resources: V-257798)${NORMAL}"

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

fail=0

datetime="$(date +%FT%H:%M:%S)"

dirarr3=("/run/sysctl.d" "/usr/local/lib/sysctl.d" "/usr/lib/sysctl.d" "/lib/sysctl.d" "/etc/sysctl.d")

testa=0
testb=0

restrict1="$(sysctl kernel.kptr_restrict)"

if [[ $restrict1 ]]
then
  value="$(echo $restrict1 | awk -F= '{print $2}' | sed 's/ \+//')"
  if [[ $value == 1 || $value == 2 && ${restrict1:0:1} != "#" ]]
  then
    testa=1
    echo -e "${NORMAL}RESULT:    ${BLD}a. $restrict1${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}a. $restrict1${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}a. Nothing returned${NORMAL}"
fi

restrict2="$(rep -r kernel.kptr_restrict 2>/dev/null /etc/sysctl.conf | grep -v "Per ")"

if [[ $restrict2 ]]
then
  value="$(echo $restrict2 | awk -F= '{print $2}' | sed 's/ \+//')"
  if [[ $value == 1 || $value == 2  && ${restrict2:0:1} != "#" ]]
  then
    testb=1
    echo -e "${NORMAL}RESULT:    ${BLD}b. $restrict2${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}b. $restrict2${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}b. ${CYN}/etc/sysctl.conf:${RED}Nothing returned${NORMAL}"
fi

for dir in ${dirarr3[@]}
do
  restrict3="$(grep -r kernel.kptr_restrict 2>/dev/null $dir/*.conf | grep -v "Per ")"
  if [[ $restrict3 ]]
  then
    for line in ${restrict3[@]}
    do
      file="$(echo $line | awk -F: '{print $1}')"
      setting="$(echo $line | awk -F: '{print $2}')"
      value="$(echo $setting | awk -F= '{print $2}' | sed 's/ //')"
      if [[ ( $value == 1 || $value == 2 ) && ${setting:0:1} != "#" ]]
      then
        testb=1
        echo -e "${NORMAL}RESULT:    ${BLD}b. ${CYN}$file:${BLD}$setting${NORMAL}"
      else
        if [[ $testa == 1 && ${setting:0:1} != "#" ]]
        then
          echo -e "${NORMAL}RESULT:    ${RED}b. ${CYN}$file:${RED}$setting${NORMAL}"
        else
          echo -e "${NORMAL}RESULT:    ${RED}b. ${CYN}$file:${NORMAL}$setting${NORMAL}"
        fi
      fi
    done
  fi
done

if [[ $testa == 1 && $testb == 1 ]]
then
  echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${GRN}PASSED, RHEL 9 restricts exposed kernel pointer addresses access.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${RED}FAILED, RHEL 9 does not restrict exposed kernel pointer addresses access.${NORMAL}"
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

fail=1

datetime="$(date +%FT%H:%M:%S)"

unpriv="$(sysctl kernel.unprivileged_bpf_disabled)"

if [[ $unpriv ]]
then
  value="$(echo $unpriv | awk -F= '{print $2}' | sed 's/ //')"
  if [[ $value == 1 ]]
  then
    fail=0
    echo -e "${NORMAL}RESULT:    ${BLD}$unpriv${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}$unpriv${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${GRN}PASSED, RHEL 9 disables access to network bpf system call from nonprivileged processes.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${RED}FAILED, RHEL 9 does not disable access to network bpf system call from nonprivileged processes${NORMAL}"
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

dirarr5=("/run/sysctl.d" "/usr/local/lib/sysctl.d" "/usr/lib/sysctl.d" "/lib/sysctl.d" "/etc/sysctl.d")

testa=0
testb=0

scope1="$(sysctl kernel.yama.ptrace_scope)"

if [[ $scope1 ]]
then
  value="$(echo $scope1 | awk -F= '{print $2}' | sed 's/ \+//')"
  if [[ $value == 1 && ${scope1:0:1} != "#" ]]
  then
    testa=1
    echo -e "${NORMAL}RESULT:    ${BLD}a. $restrict1${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}a. $restrict1${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}a. Nothing returned${NORMAL}"
fi

scope2="$(rep -r kernel.yama.ptrace_scope 2>/dev/null /etc/sysctl.conf | grep -v "Per ")"

if [[ $scope2 ]]
then
  value="$(echo $scope2 | awk -F= '{print $2}' | sed 's/ \+//')"
  if [[ $value == 1 && ${scope2:0:1} != "#" ]]
  then
    testb=1
    echo -e "${NORMAL}RESULT:    ${BLD}b. $restrict2${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}b. $restrict2${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}b. ${CYN}/etc/sysctl.conf:${RED}Nothing returned${NORMAL}"
fi

for dir in ${dirarr5[@]}
do
  scope3="$(grep -r kernel.yama.ptrace_scope 2>/dev/null $dir/*.conf | grep -v "Per ")"
  if [[ $scope3 ]]
  then
    for line in ${scope3[@]}
    do
      file="$(echo $line | awk -F: '{print $1}')"
      setting="$(echo $line | awk -F: '{print $2}')"
      value="$(echo $setting | awk -F= '{print $2}' | sed 's/ //')"
      if [[ ( $value == 1 || $value == 1 ) && ${setting:0:1} != "#" ]]
      then
        testb=1
        echo -e "${NORMAL}RESULT:    ${BLD}b. ${CYN}$file:${BLD}$setting${NORMAL}"
      else
        if [[ $testa == 1 && ${setting:0:1} != "#" ]]
        then
          echo -e "${NORMAL}RESULT:    ${RED}b. ${CYN}$file:${RED}$setting${NORMAL}"
        else
          echo -e "${NORMAL}RESULT:    ${RED}b. ${CYN}$file:${NORMAL}$setting${NORMAL}"
        fi
      fi
    done
  fi
done

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity5, $controlid, $stigid5, $ruleid5, $cci5, $datetime, ${GRN}PASSED, RHEL 9 restricts usage of ptrace to descendant processes.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity5, $controlid, $stigid5, $ruleid5, $cci5, $datetime, ${RED}FAILED, RHEL 9 does not restrict usage of ptrace to descendant processes.${NORMAL}"
fi

exit
