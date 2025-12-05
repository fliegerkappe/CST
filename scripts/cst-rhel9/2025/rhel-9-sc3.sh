#! /bin/bash

# SC-3 Security Function Isolation
#
# CONTROL: The information system isolates security functions from nonsecurity functions.

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

controlid="SC-3 Security Functioon Isolation"

title1a="RHEL 9 must use a Linux Security Module configured to enforce limits on system services."
title1b="Checking with: getenforce"
title1c="Expecting: ${YLO}Enforcing${BLD}
           NOTE: ${YLO}If \"SELinux\" is not active and not in \"Enforcing\" mode, this is a finding."${BLD}
cci1="CCI-001084 CCI-002696"
stigid1="RHEL-09-431010"
severity1="CAT I"
ruleid1="SV-258078r958944"
vulnid1="V-258078"

title2a="RHEL 9 must disable virtual syscalls."
title2b="Checking with:
           a. grubby --info=ALL | grep args | grep -v 'vsyscall=none'
           b. grep vsyscall /etc/default/grub"
title2c="Expecting: ${YLO}
           a. Nothing returned
           b. GRUB_CMDLINE_LINUX=\"vsyscall=none\
		   NOTE: If \"vsyscall\" is not set to \"none\", is missing or commented out, and is not documented with the information system security officer (ISSO) as an operational rerquirement, this is a finding"${BLD}
cci2="CCI-001084"
stigid2="RHEL-09-212035"
severity2="CAT II"
ruleid2="SV-257792r1044842"
vulnid2="V-257792"

title3a="RHEL 9 must clear the page allocator to prevent use-after-free attacks."
title3b="Checking with:
           a. grubby --info=ALL | grep args | grep -v 'page_poison=1'
           b. grep page_poison /etc/default/grub"
title3c="Expecting: ${YLO}
           a. Nothing returned
           b. GRUB_CMDLINE_LINUX=\"page_poison=1\"${BLD}
           NOTE: ${YLO}If \"page_poison\" is not set to \"1\", is commented out or is missing, this is a finding."${BLD}
cci3="CCI-001084"
stigid3="RHEL-09-212040"
severity3="CAT II"
ruleid3="SV-257793r1044843"
vulnid3="V-257793"

title4a="RHEL 9 must clear memory when it is freed to prevent use-after-free attacks."
title4b="Checking with: grep -i grub_cmdline_linux /etc/default/grub"
title4c="Expecting: ${YLO}GRUB_CMDLINE_LINUX=\"... init_on_free=1 ...\"
           NOTE: If \"init_on_free=1\" is missing or commented out, this is a finding."${BLD}
cci4="CCI-001084 CCI-002824"
stigid4="RHEL-09-212045"
severity4="CAT II"
ruleid4="SV-257794r1069362"
vulnid4="V-257794"

title5a="RHEL 9 must have policycoreutils package installed."
title5b="Checking with: dnf list --installed policycoreutils"
title5c="Expecting: ${YLO}policycoreutils.x86_64          3.3-6.el9_0${BLD}
           NOTE: ${YLO}If the policycoreutils package is not installed, this is a finding."${BLD}
cci5="CCI-001084"
stigid5="RHEL-09-431025"
severity5="CAT II"
ruleid5="SV-258081r1045164"
vulnid5="V-258081"

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

isenforcing="$(getenforce)"

datetime="$(date +%FT%H:%M:%S)"

if [[ $isenforcing == "Enforcing" ]]
then
  echo -e "${NORMAL}RESULT:    ${BLD}$isenforcing${NORMAL}"
  fail=0
else
  echo -e "${NORMAL}RESULT:    ${RED}$isenforcing${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${GRN}PASSED, RHEL 9 uses a Linux Security Module configured to enforce limits on system services.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${RED}FAILED, RHEL 9 does not use a Linux Security Module configured to enforce limits on system services.${NORMAL}"
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

fail=1
file2="/etc/default/grub"
test1=0
test2=0

vsyscall1="$(grubby --info=ALL | grep args | grep -v 'vsyscall=none')"

datetime="$(date +%FT%H:%M:%S)"

if [[ $vsyscall1 ]]
then
  echo -e "${NORMAL}RESULT:    ${RED}a. $vsyscall1${NORMAL}"
else
  echo -e "${NORMAL}RESULT:    ${BLD}a. Nothing returned${NORMAL}" 
  test1=1
fi

if [[ -f $file2 ]]
then
  vsyscall2="$(grep vsyscall $file2)"
  if [[ $vsyscall2 ]]
  then
    if [[ $vsyscall2 =~ "GRUB_CMDLINE_LINUX=" && $vsyscall2 =~ "vsyscall=none"  && ${vsyscall2:0:1} != "#" ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}b. $vsyscall2${NORMAL}"
      test2=1
    else
      echo -e "${NORMAL}RESULT:    ${RED}b. $vsyscall2${NORMAL}"
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}b. Nothing returned${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}b. $file2 not found${NORMAL}"
fi

if [[ $test1 == 1 && $test2 == 1 ]]
then
  echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${GRN}PASSED, RHEL 9 disables virtual syscalls.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${RED}FAILED, RHEL 9 does not disable virtual syscalls.${NORMAL}"
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

fail=1
file3="/etc/default/grub"

datetime="$(date +%FT%H:%M:%S)"

poison1="$(grubby --info=ALL | grep args | grep -v 'page_poison=1')"

if [[ $poison1 ]]
then
  echo -e "${NORMAL}RESULT:    ${RED}a. $poison1${NORMAL}"
else
  echo -e "${NORMAL}RESULT:    ${BLD}a. Nothing returned${NORMAL}"
  test1=1
fi

if [[ -f $file3 ]]
then
  poison2="$(grep page_poison $file3)"
  if [[ $poison2 ]]
  then
    if [[ $poison2 =~ "GRUB_CMDLINE_LINUX" && $poison2 =~ "page_poison=1" && ${poison2:0:1} != "#" ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}b. $poison2${NORMAL}"
      test2=1
    else
      echo -e "${NORMAL}RESULT:    ${RED}b. $poison2${NORMAL}"
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}b. Nothing returned${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}b. $file3 not found${NORMAL}"
fi

if [[ $test1 == 1 && $test2 == 1 ]]
then
  echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${GRN}PASSED, RHEL 9 clears the page allocator to prevent use-after-free attacks.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${RED}FAILED, RHEL 9 does not clear the page allocator to prevent use-after-free attacks.${NORMAL}"
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

onfree="$(grep -i grub_cmdline_linux /etc/default/grub)"

if [[ $onfree ]]
then
  if [[ $onfree =~ "GRUB_CMDLINE_LINUX=" && $onfree =~ "init_on_free=1" && ${onfree:0:1} != "#" ]]
  then
    fail=0
    echo -e "${NORMAL}RESULT:    ${BLD}$onfree${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}$onfree${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${GRN}PASSED, RHEL 9 clears memory when it is freed to prevent use-after-free attacks.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${RED}FAILED, RHEL 9 does not clear memory when it is freed to prevent use-after-free attacks.${NORMAL}"
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

fail=1

isinstalled="$(dnf list --installed 2>&1 policycoreutils | grep -Ev 'Updating|Installed')"

datetime="$(date +%FT%H:%M:%S)"

if [[ $isinstalled ]]
then
  echo -e "${NORMAL}RESULT:    ${BLD}$isinstalled${NORMAL}"
  fail=0
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity5, $controlid, $stigid5, $ruleid5, $cci5, $datetime, ${GRN}PASSED, RHEL 9 has the policycoreutils package installed.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity5, $controlid, $stigid5, $ruleid5, $cci5, $datetime, ${RED}FAILED, RHEL 9 does not have the policycoreutils package installed.${NORMAL}"
fi

exit
