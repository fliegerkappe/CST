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

controlid="SC-3 Security Functioon Isolation"

title1a="RHEL 8 must use a Linux Security Module configured to enforce limits on system services."
title1b="Checking with: getenforce"
title1c="Expecting: ${YLO}Enforcing${BLD}
           NOTE: ${YLO}If \"SELinux\" is not active and not in \"Enforcing\" mode, this is a finding."${BLD}
cci1="CCI-001084"
stigid1="RHEL-08-010170"
severity1="CAT II"
ruleid1="SV-230240r627750_rule"
vulnid1="V-230240"

title2a="RHEL 8 must have policycoreutils package installed."
title2b="Checking with: yum list installed policycoreutils"
title2c="Expecting: ${YLO}policycoreutils.x86_64        2.9-3.el8          @anaconda${BLD}
           NOTE: ${YLO}If the policycoreutils package is not installed, this is a finding."${BLD}
cci2="CCI-001084"
stigid2="RHEL-08-010171"
severity2="CAT III"
ruleid2="SV-230241r627750_rule"
vulnid2="V-230241"

title3a="RHEL 8 must clear the page allocator to prevent use-after-free attacks."
title3b="Checking with: 
           a. grub2-editenv list | grep page_poison
	   b. grep page_poison /etc/default/grub"
title3c="Expecting: ${YLO}
           a. kernelopts=root=/dev/mapper/rhel-root ro crashkernel=auto resume=/dev/mapper/rhel-swap rd.lvm.lv=rhel/root rd.lvm.lv=rhel/swap rhgb quiet fips=1 ${GRN}page_poison=1${YLO} vsyscall=none audit=1 audit_backlog_limit=8192 boot=UUID=8d171156-cd61-421c-ba41-1c021ac29e82
	   b. GRUB_CMDLINE_LINUX="page_poison=1"${BLD}
           NOTE: ${YLO}If \"page_poison\" is not set to \"1\" or is missing, this is a finding."${BLD}
cci3="CCI-001084"
stigid3="RHEL-08-010421"
severity3="CAT II"
ruleid3="SV-230277r792884_rule"
vulnid3="V-230277"

title4a="RHEL 8 must disable virtual syscalls."
title4b="Checking with: 
           a. grub2-editenv list | grep vsyscall
	   b. rep vsyscall /etc/default/grub"
title4c="Expecting: ${YLO}
           a. kernelopts=root=/dev/mapper/rhel-root ro crashkernel=auto resume=/dev/mapper/rhel-swap rd.lvm.lv=rhel/root rd.lvm.lv=rhel/swap rhgb quiet fips=1 page_poison=1 ${GRN}vsyscall=none${YLO} audit=1 audit_backlog_limit=8192 boot=UUID=8d171156-cd61-421c-ba41-1c021ac29e82
	   b. GRUB_CMDLINE_LINUX=\"vsyscall=none\"${BLD}
           NOTE: ${YLO}If \"vsyscall\" is not set to \"none\" or is missing, this is a finding"${BLD}
cci4="CCI-001084"
stigid4="RHEL-08-010422"
severity4="CAT II"
ruleid4="SV-230278r792886_rule"
vulnid4="V-230278"

title5a="RHEL 8 must clear SLUB/SLAB objects to prevent use-after-free attacks."
title5b="Checking with: 
           a. grub2-editenv list | grep slub_debug
	   b. grep slub_debug /etc/default/grub"
title5c="Expecting: ${YLO}
           a. kernelopts=root=/dev/mapper/rhel-root ro crashkernel=auto resume=/dev/mapper/rhel-swap rd.lvm.lv=rhel/root rd.lvm.lv=rhel/swap rhgb quiet fips=1 slub_debug=P page_poison=1 vsyscall=none audit=1 audit_backlog_limit=8192 boot=UUID=8d171156-cd61-421c-ba41-1c021ac29e82
	   b. GRUB_CMDLINE_LINUX=\"slub_debug=P\"${BLD}
           NOTE: ${YLO}If \"slub_debug\" is not set to \"P\" or is missing, this is a finding."${BLD}
cci5="CCI-001084"
stigid5="RHEL-08-010423"
severity5="CAT II"
ruleid5="SV-230279r792888_rule"
vulnid5="V-230279"

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
  echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${GRN}PASSED, RHEL 8 uses a Linux Security Module configured to enforce limits on system services.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${RED}FAILED, RHEL 8 does not use a Linux Security Module configured to enforce limits on system services.${NORMAL}"
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

isinstalled="$(yum list installed policycoreutils | grep policycoreutils)"

datetime="$(date +%FT%H:%M:%S)"

if [[ $isinstalled && $isinstalled =~ "policycoreutils.x86_64" ]]
then
  echo -e "${NORMAL}RESULT:    ${BLD}$isinstalled${NORMAL}"
  fail=0
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${GRN}PASSED, RHEL 8 has the policycoreutils package installed.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${RED}FAILED, RHEL 8 does not have the policycoreutils package installed.${NORMAL}"
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
test1=0
test2=0

poison1="$(grub2-editenv list | grep page_poison)"

datetime="$(date +%FT%H:%M:%S)"

if [[ $poison1 =~ "page_poison=1" ]]
then
  echo -e "${NORMAL}RESULT:    ${BLD}a. $poison1${NORMAL}"
  test1=1
  if [[ -f $file3 ]]
  then
    poison2="$(grep page_poison $file3)"
    if [[ $poison2 =~ "page_poison=1" ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}b. $poison2${NORMAL}"
      test2=1
    else
      echo -e "${NORMAL}RESULT:    ${RED}b. $poison2${NORMAL}"
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}b. $file3 not found${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}a. $poison1${NORMAL}"
fi

if [[ $test1 == 1 && $test2 == 1 ]]
then
  fail=0
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${GRN}PASSED, RHEL 8 clears the page allocator to prevent use-after-free attacks.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${RED}FAILED, RHEL 8 does not clear the page allocator to prevent use-after-free attacks.${NORMAL}"
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
file4="/etc/default/grub"
test1=0
test2=0

vsyscall1="$(grub2-editenv list | grep vsyscall)"

datetime="$(date +%FT%H:%M:%S)"

if [[ $vsyscall1 =~ "vsyscall=none" ]]
then
  echo -e "${NORMAL}RESULT:    ${BLD}a. $vsyscall1${NORMAL}"
  test1=1
  if [[ -f $file4 ]]
  then
    vsyscall2="$(grep vsyscall $file4)"
    if [[ $vsyscall2 =~ "vsyscall=none" ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}b. $vsyscall2${NORMAL}"
      test2=1
    else
      echo -e "${NORMAL}RESULT:    ${RED}b. $vsyscall2${NORMAL}"
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}b. $file4 not found${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}a. $vsyscall1${NORMAL}"
fi

if [[ $test1 == 1 && $test2 == 1 ]]
then
  fail=0
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${GRN}PASSED, RHEL 8 disables virtual syscalls.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${RED}FAILED, RHEL 8 does not disable virtual syscalls.${NORMAL}"
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
file5="/etc/default/grub"
test1=0
test2=0

slubdebug1="$(grub2-editenv list | grep slub_debug)"

datetime="$(date +%FT%H:%M:%S)"

if [[ $slubdebug1 =~ "slub_debug=P" ]]
then
  echo -e "${NORMAL}RESULT:    ${BLD}a. $slubdebug1${NORMAL}"
  test1=1
  if [[ -f $file5 ]]
  then
    slubdebug2="$(grep slub_debug $file5)"
    if [[ $slubdebug2 =~ "slub_debug=P" ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}b. $slubdebug2${NORMAL}"
      test2=1
    else
      echo -e "${NORMAL}RESULT:    ${RED}b. $slubdebug2${NORMAL}"
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}b. $file5 not found${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}a. $slubdebug1${NORMAL}"
fi

if [[ $test1 == 1 && $test2 == 1 ]]
then
  fail=0
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity5, $controlid, $stigid5, $ruleid5, $cci5, $datetime, ${GRN}PASSED, RHEL 8 clears SLUB/SLAB objects to prevent use-after-free attacks.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity5, $controlid, $stigid5, $ruleid5, $cci5, $datetime, ${RED}FAILED, RHEL 8 does not clear SLUB/SLAB objects to prevent use-after-free attacks.${NORMAL}"
fi	

exit
