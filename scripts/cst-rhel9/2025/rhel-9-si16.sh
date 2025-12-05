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

controlid="SI-16 Memory Protection"

title1a="RHEL 9 must clear memory when it is freed to prevent use-after-free attacks."
title1b="Checking with: grep -i grub_cmdline_linux /etc/default/grub"
title1c="Expecting: ${YLO}GRUB_CMDLINE_LINUX=\"... init_on_free=1\"
           NOTE: If \"init_on_free=1\" is missing or commented out, this is a finding."${BLD}
cci1="CCI-001084 CCI-002824"
stigid1="RHEL-09-212045"
severity1="CAT II"
ruleid1="SV-257794r1069362"
vulnid1="V-257794"

title2a="RHEL 9 must enable mitigations against processor-based vulnerabilities."
title2b="Checking with: 
           a. grubby --info=ALL | grep args | grep -v 'pti=on'
	   b. grep pti /etc/default/grub"
title2c="Expecting: ${YLO}
           a. Nothing returned
	   b. GRUB_CMDLINE_LINUX=\"pti=on\"
	   NOTE: a. If any output is returned, this is a finding
	   NOTE: b. If \"pti\" is not set to \"on\", is missing or commented out, this is a finding."${BLD}
cci2="CCI-000381 CCI-002824"
stigid2="RHEL-09-212050"
severity2="CAT III"
ruleid2="SV-257795r1044845"
vulnid2="V-257795"

title3a="RHEL 9 must restrict exposed kernel pointer addresses access."
title3b="Checking with: 
           a. sysctl kernel.kptr_restrict
	   b. grep -r kernel.kptr_restrict /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf /etc/sysctl.d/*.conf"
title3c="Expecting: ${YLO}
           a. kernel.kptr_restrict = 1
	   b. /etc/sysctl.d/99-sysctl.conf: kernel.kptr_restrict = 1
	   NOTE: a. If the returned line does not have a value of \"1\" or \"2\", or a line is not returned, this is a finding.
	   NOTE: b. If \"kernel.kptr_restrict\" is not set to \"1\" or \"2\", is missing, or commented out, this is a finding."${BLD}
cci3="CCI-001082 CCI-002824"
stigid3="RHEL-09-213025"
severity3="CAT II"
ruleid3="SV-257800r1117266"
vulnid3="V-257800"

title4a="RHEL 9 must implement address space layout randomization (ASLR) to protect its memory from unauthorized code execution."
title4b="Checking with: 
           a. sysctl kernel.randomize_va_space
	   b. grep -r kernel.randomize_va_space /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf /etc/sysctl.d/*.conf"
title4c="Expecting: ${YLO}
           a. kernel.randomize_va_space = 2
	   b. /etc/sysctl.d/99-sysctl.conf:kernel.randomize_va_space = 2
	   NOTE: a. If \"kernel.randomize_va_space\" is not set to \"2\", this is a finding.
	   NOTE: b. If \"kernel.randomize_va_space\" is not set to \"2\", is missing, or commented out, this is a finding."${BLD}
cci4="CCI-002824"
stigid4="RHEL-09-213070"
severity4="CAT II"
ruleid4="SV-257809r1106288"
vulnid4="V-257809"

title5a="RHEL 9 must implement nonexecutable data to protect its memory from unauthorized code execution."
title5b="Checking with: 
           a. grep ^flags /proc/cpuinfo | grep -Ev '([^[:alnum:]])(nx)([^[:alnum:]]|$)'
	   b. grubby --info=ALL | grep args | grep -E '([^[:alnum:]])(noexec)([^[:alnum:]])'"
title5c="Expecting: ${YLO}
           a. Nothing returned
	   b. Nothing returned
	   NOTE: a. If any output is returned, this is a finding.
	   NOTE: b. If any output is returned, this is a finding."${BLD}
cci5="CCI-002824"
stigid5="RHEL-09-213110"
severity5="CAT II"
ruleid5="SV-257817r1069383"
vulnid5="V-257817"

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

echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${CYN}VERIFY, (See SC-3 Security Functioon Isolation: V-257794)${NORMAL}"

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

echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${CYN}VERIFY, (See CM-7 Least Functionality: V-257795)${NORMAL}"

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

echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${CYN}VERIFY, (See SC-2 Separation of Systemand User Functionality: V-257800)${NORMAL}"


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

dirarr4=("/run/sysctl.d" "/usr/local/lib/sysctl.d" "/usr/lib/sysctl.d" "/lib/sysctl.d" "/etc/sysctl.d")

testa=0
testb=0

space1="$(sysctl kernel.randomize_va_space)"

if [[ $space1 ]]
then
  value="$(echo $space1 | awk -F= '{print $2}' | sed 's/ \+//')"
  if [[ $value == 1 || $value == 2 && ${space1:0:1} != "#" ]]
  then
    testa=1
    echo -e "${NORMAL}RESULT:    ${BLD}a. $space1${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}a. $space1${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}a. Nothing returned${NORMAL}"
fi

space2="$(rep -r kernel.randomize_va_space 2>/dev/null /etc/sysctl.conf | grep -v "Per ")"

if [[ $space2 ]]
then
  value="$(echo $space2 | awk -F= '{print $2}' | sed 's/ \+//')"
  if [[ $value == 1 || $value == 2  && ${space2:0:1} != "#" ]]
  then
    testb=1
    echo -e "${NORMAL}RESULT:    ${BLD}b. $space2${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}b. $space2${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}b. ${CYN}/etc/sysctl.conf:${RED}Nothing returned${NORMAL}"
fi

for dir in ${dirarr4[@]}
do
  space3="$(grep -r kernel.randomize_va_space 2>/dev/null $dir/*.conf | grep -v "Per ")"
  if [[ $space3 ]]
  then
    for line in ${space3[@]}
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
  echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${GRN}PASSED, RHEL 9 implements address space layout randomization (ASLR) to protect its memory from unauthorized code execution.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${RED}FAILED, RHEL 9 does not implement address space layout randomization (ASLR) to protect its memory from unauthorized code execution.${NORMAL}"
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

flags1="$(grep ^flags /proc/cpuinfo | grep -Ev '([^[:alnum:]])(nx)([^[:alnum:]]|$)')"
flags2="$(grubby --info=ALL | grep args | grep -E '([^[:alnum:]])(noexec)([^[:alnum:]])')"

if [[ $flags1 ]]
then
  fail=1
  for line in ${flags1[@]}
  do
    echo -e "${NORMAL}RESULT:    ${RED}a. $line${NORMAL}"
  done
else
  echo -e "${NORMAL}RESULT:    ${BLD}a. Nothing returned${NORMAL}"
fi

if [[ $flags2 ]]
then
  fail=1
  for line in ${flags2[@]}
  do
    echo -e "${NORMAL}RESULT:    ${RED}b. $line${NORMAL}"
  done
else
  echo -e "${NORMAL}RESULT:    ${BLD}b. Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity5, $controlid, $stigid5, $ruleid5, $cci5, $datetime, ${GRN}PASSED, RHEL 9 implements nonexecutable data to protect its memory from unauthorized code execution.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity5, $controlid, $stigid5, $ruleid5, $cci5, $datetime, ${RED}FAILED, RHEL 9 does not implement nonexecutable data to protect its memory from unauthorized code execution.${NORMAL}"
fi

exit
