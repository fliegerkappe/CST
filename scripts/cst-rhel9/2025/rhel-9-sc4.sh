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

controlid="SC-4 Information In Shared Resources"

title1a="RHEL 9 must restrict access to the kernel message buffer."
title1b="Checking with: 
           a. sysctl kernel.dmesg_restrict
           b. grep -r kernel.dmesg_restrict /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf /etc/sysctl.d/*.conf"
title1c="Expecting: ${YLO}
           a. kernel.dmesg_restrict = 1
           b. /etc/sysctl.d/99-sysctl.conf:kernel.dmesg_restrict = 1
           NOTE: a. If \"kernel.dmesg_restrict\" is not set to \"1\" or is missing, this is a finding.
           NOTE: b. If \"kernel.dmesg_restrict\" is not set to \"1\", is missing or commented out, this is a finding.
           NOTE: ${YLO}If results are returned from more than one file location, this is a finding."${BLD}
cci1="CCI-001082 CCI-001090"
stigid1="RHEL-09-213010"
severity1="CAT II"
ruleid1="SV-257797r1117266"
vulnid1="V-257797"

title2a="RHEL 9 must prevent kernel profiling by nonprivileged users."
title2b="Checking with: 
           a. kernel.perf_event_paranoid = 2
           b. grep -r kernel.perf_event_paranoid /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf /etc/sysctl.d/*.conf"
title2c="Expecting: ${YLO}
           a. kernel.perf_event_paranoid = 2
           b. /etc/sysctl.d/99-sysctl.conf:kernel.perf_event_paranoid = 2
           NOTE: a. If \"kernel.perf_event_paranoid\" is not set to \"2\" or is missing, this is a finding.
           NOTE: b. If \"kernel.perf_event_paranoid\" is not set to \"2\", is missing or commented out, this is a finding.
           NOTE: If results are returned from more than one file location, this is a finding."${BLD}
cci2="CCI-001082 CCI-001090"
stigid2="RHEL-09-213015"
severity2="CAT II"
ruleid2="SV-257798r1117266"
vulnid2="V-257798"

title3a="All RHEL 9 world-writable directories must be owned by root, sys, bin, or an application user."
title3b="Checking with: find  PART  -xdev -type d -perm -0002 -uid +0 -print"
title3c="Expecting: ${YLO}Nothing returned
           NOTE: If there is output, this is a finding."${BLD}
cci3="CCI-001090"
stigid3="RHEL-09-232240"
severity3="CAT II"
ruleid3="SV-257928r1044992"
vulnid3="V-257928"

title4a="A sticky bit must be set on all RHEL 9 public directories."
title4b="Checking with: find / -type d \\\( -perm -0002 -a ! -perm -1000 \\\) -print 2>/dev/null"
title4c="Expecting: ${YLO}drwxrwxrwt 7 root root 4096 Jul 26 11:19 /tmp
           NOTE: If any of the returned directories are world-writable and do not have the sticky bit set, this is a finding."${BLD}
cci4="CCI-001090"
stigid4="RHEL-09-232245"
severity4="CAT II"
ruleid4="SV-257929r1117267"
vulnid4="V-257929"

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

datetime="$(date +%FT%H:%M:%S)"

dirarr1=("/run/sysctl.d" "/usr/local/lib/sysctl.d" "/usr/lib/sysctl.d" "/lib/sysctl.d" "/etc/sysctl.d")

testa=0
testb=0

restrict1="$(sysctl kernel.dmesg_restrict)"

if [[ $restrict1 ]]
then
  value="$(echo $restrict1 | awk -F= '{print $2}' | sed 's/ \+//')"
  if [[ $value == 1 && ${restrict1:0:1} != "#" ]]
  then
    testa=1
    echo -e "${NORMAL}RESULT:    ${BLD}a. $restrict1${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}a. $restrict1${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}a. Nothing returned${NORMAL}"
fi

restrict2="$(rep -r kernel.dmesg_restrict 2>/dev/null /etc/sysctl.conf | grep -v "Per ")"

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

for dir in ${dirarr1[@]}
do
  restrict3="$(grep -r kernel.dmesg_restrict 2>/dev/null $dir/*.conf | grep -v "Per ")"
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
        if [[ $testa == 1 || $testb == 1 && ${setting:0:1} != "#" ]]
        then
          fail=1
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
  echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${GRN}PASSED, RHEL 9 restricts access to the kernel message buffer.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${RED}FAILED, RHEL 9 does not restrict access to the kernel message buffer.${NORMAL}"
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
  echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${GRN}PASSED, RHEL 9 prevents kernel profiling by nonprivileged users.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${RED}FAILED, RHEL 9 does not prevent kernel profiling by nonprivileged users.${NORMAL}"
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

datetime="$(date +%FT%H:%M:%S)"

partitions="$(cat /etc/fstab | grep -Ev '^#|none|^$' | awk '{print $2}')"

for PART in ${partitions[@]}
do
  worldwrite="$(find $PART -xdev -type d -perm -0002 -uid +0 -print)"
  if [[ $worldwrite ]]
  then
    fail=1
    for line in ${worldwrite[@]}
    do
      echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
    done
  else
    echo -e "${NORMAL}RESULT:    ${BLD}No world-writable directories found in \"$PART\" that aren't owned by root.${NORMAL}"
  fi
done

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${GRN}PASSED, All RHEL 9 world-writable directories are owned by root sys bin or an application user.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${GRN}PASSED, All RHEL 9 world-writable directories are not owned by root sys bin or an application user.${NORMAL}"
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
  echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${GRN}PASSED, All world-writable directories have the sticky bit set.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${RED}FAILED, All world-writable directories do not have the sticky bit set.${NORMAL}"
fi

exit
