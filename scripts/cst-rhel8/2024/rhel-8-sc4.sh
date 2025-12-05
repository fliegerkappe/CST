#! /bin/bash

# SC-4 Information In Shared Resources
#
# CONTROL: The information system prevents unauthorized and unintended information transfer
# via shared system resources.


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

controlid="SC-4 Information In Shared Resources"

title1a="A sticky bit must be set on all RHEL 8 public directories to prevent unauthorized and unintended information transferred via shared system resources."
title1b="Checking with: find / -type d \\\( -perm -0002 -a ! -perm -1000 \\\) -print 2>/dev/null"
title1c="Expecting: ${YLO}Nothing returned${BLD}
           NOTE: ${YLO}If any of the returned directories are world-writable and do not have the sticky bit set, this is a finding.${BLD}
	   NOTE: ${YLO}If world-writable files or directories exist that have the the sticky bit set, they are compliant. The above command will not show them."${BLD}
cci1="CCI-001090"
stigid1="RHEL-08-010190"
severity1="CAT II"
ruleid1="SV-230243r792857_rule"
vulnid1="V-230243"

title2a="RHEL 8 must restrict access to the kernel message buffer."
title2b="Checking with: 
           a. sysctl kernel.dmesg_restrict
	   b. grep -r kernel.dmesg_restrict /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf /etc/sysctl.d/*.conf"${BLD}
title2c="Expecting: 
           a. ${YLO}kernel.dmesg_restrict = 1${BLD}
	   b. ${YLO}/etc/sysctl.d/99-sysctl.conf:kernel.dmesg_restrict = 1${BLD}
           NOTE: a. ${YLO}If \"kernel.dmesg_restrict\" is not set to \"1\" or is missing, this is a finding.${BLD}
	   NOTE: b. ${YLO}If \"kernel.dmesg_restrict\" is not set to \"1\", is missing or commented out, this is a finding.${BLD}
	   NOTE: ${YLO}If results are returned from more than one file location, this is a finding."${BLD}
cci2="CCI-001090"
stigid2="RHEL-08-010375"
severity2="CAT III"
ruleid2="SV-230269r858756_rule"
vulnid2="V-230269"

title3a="RHEL 8 must prevent kernel profiling by unprivileged users."
title3b="Checking with: 
           a. kernel.perf_event_paranoid = 2
	   b. grep -r kernel.perf_event_paranoid /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf /etc/sysctl.d/*.conf"
title3c="Expecting: 
           a. ${YLO}kernel.perf_event_paranoid = 2${BLD}
	   b. ${YLO}/etc/sysctl.d/99-sysctl.conf:kernel.perf_event_paranoid = 2${BLD}
	   NOTE: a. ${YLO}If \"kernel.perf_event_paranoid\" is not set to \"2\" or is missing, this is a finding.${BLD}
	   NOTE: b. ${YLO}If \"kernel.perf_event_paranoid\" is not set to \"2\", is missing or commented out, this is a finding.${BLD}
	   NOTE: ${YLO}If results are returned from more than one file location, this is a finding."${BLD}
cci3="CCI-001090"
stigid3="RHEL-08-010376"
severity3="CAT III"
ruleid3="SV-230270r858758_rule"
vulnid3="V-230270"

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

fail=0

worldwrite="$(find / -type d \( -perm -0002 -a ! -perm -1000 \) -print 2>/dev/null)"

datetime="$(date +%FT%H:%M:%S)"

if [[ $worldwrite ]]
then
  for file in ${worldwrite[@]}
  do
    item="$(ls -ld $file)"
    perm="$(echo $item | awk '{print $1}')"
    if [[ $perm =~ "t" ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}$item${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${RED}$item${NORMAL}"
      fail=1
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${GRN}PASSED, All world-writable directories have the sticky bit set.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${RED}FAILED, All world-writable directories do not have the sticky bit set.${NORMAL}"
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

file2="/etc/sysctl.conf"
dirarr2=("/run/sysctl.d" "/usr/local/lib/sysctl.d" "/usr/lib/sysctl.d" "/lib/sysctl.d" "/etc/sysctl.d")

restrict1="$(sysctl kernel.dmesg_restrict)"

datetime="$(date +%FT%H:%M:%S)"

if [[ $restrict1 ]]
then
  restrict1val="$(echo $restrict1 | awk -F= '{print $2}' | sed 's/ \+//')"
  if [[ $restrict1val == 1 ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}a. $restrict1${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}a. $restrict1${NORMAL}"
    fail=1
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}a. Nothing returned${NORMAL}"
fi

count=0
for dir in ${dirarr2[@]}
do
  restrict2="$(grep -r kernel.dmesg_restrict 2>/dev/null $dir/*.conf)"
  if [[ $restrict2 ]]
  then
    for line in ${restrict2[@]}
    do
      path="$(echo $line | awk -F: '{print $1}')"
      restrict="$(echo $line | awk -F: '{print $2}')"
      if [[ $restrict && ${restrict:0:1} != "#" ]]
      then
        restrict2val="$(echo $restrict | awk -F= '{print $2}' | sed 's/ \+//')"
        if [[ $restrict2val == 1 ]]
        then
          if [[ $count < 1 ]]
	  then
            echo -e "${NORMAL}RESULT:    ${BLD}b. $path:$restrict${NORMAL}"
          else
            echo -e "${NORMAL}RESULT:    ${RED}b. $path:$restrict${NORMAL}"
          fi
	else
	  echo -e "${NORMAL}RESULT:    ${RED}b. $path:$restrict${NORMAL}"
	  fail=1
	fi
	path=""
        restrict=""
        restrict2val=""
	(( count++ ))
      else
	if [[ ${restrict:0:1} == "#" ]]  && ! [[ $restrict =~ "Per CCE" ]]
	then
	  echo -e "${NORMAL}RESULT:    ${RED}b. $path:$restrict${NORMAL}"
	  fail=1
	fi
      fi
    done
    if [[ $count > 1 ]]
    then
      fail=1
    fi
  fi
done

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${GRN}PASSED, RHEL 8 restricts access to the kernel message buffer.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${RED}FAILED, RHEL 8 does not restrict access to the kernel message buffer.${NORMAL}"
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

fail=0

file3="/etc/sysctl.conf"
dirarr3=("/run/sysctl.d" "/usr/local/lib/sysctl.d" "/usr/lib/sysctl.d" "/lib/sysctl.d" "/etc/sysctl.d")

paranoid1="$(sysctl kernel.perf_event_paranoid)"

datetime="$(date +%FT%H:%M:%S)"

if [[ $paranoid1 ]]
then
  paranoid1val="$(echo $paranoid1 | awk -F= '{print $2}' | sed 's/ \+//')"
  if [[ $paranoid1val == 2 ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}a. $paranoid1${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}a. $paranoid1${NORMAL}"
    fail=1
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}a. Nothing returned${NORMAL}"
fi

count=0
for dir in ${dirarr2[@]}
do
  paranoid2="$(grep -r kernel.perf_event_paranoid 2>/dev/null $dir/*.conf)"
  if [[ $paranoid2 ]]
  then
    for line in ${paranoid2[@]}
    do
      path="$(echo $line | awk -F: '{print $1}')"
      paranoid="$(echo $line | awk -F: '{print $2}')"
      if [[ $paranoid && ${paranoid:0:1} != "#" ]]
      then
        paranoid2val="$(echo $paranoid | awk -F= '{print $2}' | sed 's/ \+//')"
        if [[ $paranoid2val == 2 ]]
        then
          if [[ $count < 1 ]]
	  then
            echo -e "${NORMAL}RESULT:    ${BLD}b. $path:$paranoid${NORMAL}"
          else
            echo -e "${NORMAL}RESULT:    ${RED}b. $path:$paranoid${NORMAL}"
          fi
	else
	  echo -e "${NORMAL}RESULT:    ${RED}b. $path:$paranoid${NORMAL}"
	  fail=1
	fi
	path=""
        paranoid=""
        parnoid2val=""
	(( count++ ))
      else
	if [[ ${paranoid:0:1} == "#" ]]  && ! [[ $paranoid =~ "Per CCE" ]]
	then
	  echo -e "${NORMAL}RESULT:    ${RED}b. $path:$paranoid${NORMAL}"
	  fail=1
	fi
      fi
    done
    if [[ $count > 1 ]]
    then
      fail=1
    fi
  fi
done

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${GRN}PASSED, RHEL 8 prevents kernel profiling by unprivileged users.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${RED}FAILED, RHEL 8 does not prevent kernel profiling by unprivileged users.${NORMAL}"
fi

exit
