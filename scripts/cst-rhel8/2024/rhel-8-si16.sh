#! /bin/bash

# SI-16 Memory Protection

# CONTROL: The information system implements [Assignmenet: organization-defined security
# safeguards] to protect its memory from unauthorized code execution.

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

controlid="SI-16 Memory Protection"

title1a="RHEL 8 must implement non-executable data to protect its memory from unauthorized code execution."
title1b="Checking with: 
           a. dmesg | grep NX
	   b. less /proc/cpuinfo | grep -i flags"
title1c="Expecting 
           a. ${YLO}[ 0.000000] NX (Execute Disable) protection: active${BLD}
	   b. ${YLO}flags : fpu vme de pse tsc ms nx rdtscp lm constant_tsc${BLD}
           NOTE: a. ${YLO}If \"dmesg\" does not show \"NX (Execute Disable) protection\" active, check the cpuinfo settings with the following command (b):${BLD}
	   NOTE: b. ${YLO}If \"flags\" does not contain the \"nx\" flag, this is a finding."${BLD}
cci1="CCI-002824"
stigid1="RHEL-08-010420"
severity1="CAT II"
ruleid1="SV-230276r854031_rule"
vulnid1="V-230276"

title2a="RHEL 8 must implement address space layout randomization (ASLR) to protect its memory from unauthorized code execution."
title2b="Checking with: 
           a. sysctl kernel.randomize_va_space
	   b. grep -r kernel.randomize_va_space /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf /etc/sysctl.d/*.conf"
title2c="Expecting:
           a. ${YLO}kernel.randomize_va_space = 2${BLD}
	   b. ${YLO}/etc/sysctl.d/99-sysctl.conf:kernel.randomize_va_space = 2${BLD}
	   NOTE: a. ${YLO}If \"kernel.randomize_va_space\" is not set to \"2\", this is a finding.${BLD}
	   NOTE: b. ${YLO}If "kernel.randomize_va_space" is not set to "2", is missing or commented out, this is a finding.${BLD}
	   NOTE: ${YLO}If results are returned from more than one file location, this is a finding."${BLD}
cci2="CCI-002824"
stigid2="RHEL-08-010430"
severity2="CAT II"
ruleid2="SV-230280r858767_rule"
vulnid2="V-230280"

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

dmesg="$(dmesg | grep NX)"
flags="$(less /proc/cpuinfo | grep -i flags)"

datetime="$(date +%FT%H:%M:%S)"

if [[ $dmesg ]]
then
  if [[ $dmesg =~ "NX (Execute Disable) protection: active" ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}a. $dmesg${NORMAL}"
    echo -e "${NORMAL}           ${BLD}b. (skipping)"
    fail=0
  else
    flags="$(echo $flags | awk -F: '{print $2}')"
    IFS=' '
    for flag in ${flags[@]}
    do
      if [[ $flag == "nx" ]]
      then
	echo -e "${NORMAL}RESULT:    ${BLD}b. $flags${NORMAL}"
	fail=0
      else
	echo -e "${NORMAL}RESULT:    ${RED}b. $flags${NORMAL}"
      fi
    done
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}a. Nothing returned.${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${GRN}PASSED, The information system implements organization-defined security safeguards to protect its memory from unauthorized code execution.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${RED}FAILED, The information system does not implement organization-defined security safeguards to protect its memory from unauthorized code execution.${NORMAL}"
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

randomize1="$(sysctl kernel.randomize_va_space)"

datetime="$(date +%FT%H:%M:%S)"

if [[ $randomize1 ]]
then
  randomize1val="$(echo $randomize1 | awk -F= '{print $2}' | sed 's/ \+//')"
  if [[ $randomize1val == 2 ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}a. $randomize1${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}a. $randomize1${NORMAL}"
    fail=1
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}a. Nothing returned${NORMAL}"
fi

count=0
for dir in ${dirarr2[@]}
do
  randomize2="$(grep -r kernel.randomize_va_space 2>/dev/null $dir/*.conf)"
  if [[ $randomize2 ]]
  then
    for line in ${randomize2[@]}
    do
      path="$(echo $line | awk -F: '{print $1}')"
      randomize="$(echo $line | awk -F: '{print $2}')"
      if [[ $randomize && ${randomize:0:1} != "#" ]]
      then
        randomize2val="$(echo $randomize | awk -F= '{print $2}' | sed 's/ \+//')"
        if [[ $randomize2val == 2 ]]
        then
          if [[ $count < 1 ]]
          then
            echo -e "${NORMAL}RESULT:    ${BLD}b. $path:$randomize${NORMAL}"
          else
            echo -e "${NORMAL}RESULT:    ${RED}b. $path:$randomize${NORMAL}"
          fi
        else
          echo -e "${NORMAL}RESULT:    ${RED}b. $path:$randomize${NORMAL}"
          fail=1
        fi
        path=""
        randomize=""
        randomize2val=""
        (( count++ ))
      else
        if [[ ${randomize:0:1} == "#" ]]  && ! [[ $randomize =~ "Per CCE" ]]
        then
          echo -e "${NORMAL}RESULT:    ${RED}b. $path:$randomize${NORMAL}"
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
  echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${GRN}PASSED, RHEL 8 implements organization-defined security safeguards to protect its memory from unauthorized code execution.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${RED}FAILED, RHEL 8 does not implement organization-defined security safeguards to protect its memory from unauthorized code execution.${NORMAL}"
fi

exit
