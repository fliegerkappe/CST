#! /bin/bash

# AC-3 Access Enforcement
#
# CONTROL: The information system enforces approved authorizations for logical access to information
# and system resources in accordance with applicable access control policies.

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

controlid="AC-3 Access Enforcement"

title1a="RHEL 9 must require a boot loader superuser password."
title1b="Checking with:
           a. 'grep password_pbkdf2 /etc/grub2.cfg'
	   b. 'cat /boot/grub2/user.cfg"
title1c="Expecting: ${YLO}
           a. password_pbkdf2  <a non-default superusers-accountname>   \${GRUB2_PASSWORD}
	   b. GRUB2_PASSWORD=grub.pbkdf2.sha512.10000.(password hash)
	   NOTE: If superusers contains easily guessable usernames, this is a finding."${BLD}
cci1="CCI-000213"
stigid1="RHEL-09-212010"
severity1="CAT II"
ruleid1="SV-257787r1117265"
vulnid1="V-257787"

title2a="RHEL 9 must require a unique superusers name upon booting into single-user and maintenance modes."
title2b="Checking with: 'grep -A1 \"superusers\" /etc/grub2.cfg'."
title2c="Expecting: ${YLO}
           set superusers=\"<accountname>\"
           export superusers
           password_pbkdf2 <accountname> \${GRUB2_PASSWORD}
	   NOTE: If superusers contains easily guessable usernames, this is a finding."${BLD}
cci2="CCI-000213"
stigid2="RHEL-09-212020"
severity2="CAT I"
ruleid2="SV-257789r1117265"
vulnid2="V-257789"

title3a="RHEL 9 must enable kernel parameters to enforce discretionary access control on hardlinks."
title3b="Checking with:
           a. 'sysctl fs.protected_hardlinks'
	   b. 'grep -r fs.protected_hardlinks /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf /etc/sysctl.d/*.conf'."
title3c="Expecting: ${YLO}
           a. fs.protected_hardlinks = 1
	   b. /etc/sysctl.d/99-sysctl.conf:fs.protected_hardlinks = 1
           NOTE: If \"fs.protected_hardlinks\" is not set to "1" or is missing, this is a finding."${BLD}
cci3="CCI-002165 CCI-002235"
stigid3="RHEL-09-213030"
severity3="CAT II"
ruleid3="SV-257801r1106279"
vulnid3="V-257801"

title4a="RHEL 9 must enable kernel parameters to enforce discretionary access control on symlinks."
title4b="Checking with: 'sysctl fs.protected_symlinks'."
title4c="Expecting: ${YLO}
           a. sysctl fs.protected_symlinks
	   b. grep -r fs.protected_symlinks /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf /etc/sysctl.d/*.conf
	   NOTE: If \"fs.protected_symlinks\" is not set to "1" is missing, or commented out, this is a finding."${BLD}
cci4="CCI-002165 CCI-002235"
stigid4="RHEL-09-213035"
severity4="CAT II"
ruleid4="SV-257802r1106282"
vulnid4="V-257802"

title5a="RHEL 9 must restrict the use of the \"su\" command."
title5b="Checking with: 'grep pam_wheel /etc/pam.d/su'."
title5c="Expecting: ${YLO}auth             required        pam_wheel.so use_uid
           NOTE: If a line for \"pam_wheel.so\" does not exist, or is commented out, this is a finding."${BLD}
cci5="CCI-004895 CCI-002165 CCI-002038"
stigid5="RHEL-09-432035"
severity5="CAT II"
ruleid5="SV-258088r1050789"
vulnid5="V-258088"

title6a="RHEL 9 must require authentication to access emergency mode."
title6b="Checking with: 'grep sulogin /usr/lib/systemd/system/emergency.service'."
title6c="Expecting: ${YLO}ExecStart=-/usr/lib/systemd/systemd-sulogin-shell emergency
           NOTE: If this line is not returned, or is commented out, this is a finding.
	   NOTE: If the output is different, this is a finding."${BLD}
cci6="CCI-000213"
stigid6="RHEL-09-611195"
severity6="CAT II"
ruleid6="SV-258128r1117265"
vulnid6="V-258128"

title7a="RHEL 9 must require authentication to access single-user mode."
title7b="Checking with:
           a. grep sulogin /usr/lib/systemd/system/rescue.service
	   b. grep sulogin /etc/systemd/system/rescue.service.d/*.conf"
title7c="Expecting: ${YLO}
           a. ExecStart=-/usr/lib/systemd/systemd-sulogin-shell rescue (or)
	   b. ExecStart=-/usr/lib/systemd/systemd-sulogin-shell rescue
           NOTE: If the line is not returned from either location this is a finding."${BLD}
cci7="CCI-000213"
stigid7="RHEL-09-611200"
severity7="CAT II"
ruleid7="SV-258129r1117265"
vulnid7="V-258129"

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

fail=1

superpw="$(grep password_pbkdf2 2>/dev/null /etc/grub2.cfg)"

if [[ $superpw =~ "password_pbkdf2" && $superpw =~ "GRUB2_PASSWORD" ]]
then
	v1="$(echo $superpw | awk '{print $1}')"
	v2="$(echo $superpw | awk '{print $3}')"
	user="$(echo $v1 \(username omitted\) $v2)"
  echo -e "${NORMAL}RESULT:    ${BLD}a. $user${NORMAL}"
  pw="$(cat 2>/dev/null /boot/grub2/user.cfg)"
  if [[ $pw =~ "GRUB2_PASSWORD=grub.pbkdf2.sha512.10000." ]]
  then
    fail=0
    nohash="GRUB2_PASSWORD=grub.pbkdf2.sha512.10000.(password hash omitted)"
    echo -e "${NORMAL}RESULT:    ${BLD}b. $nohash${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}An encrypted superuser password is not set.${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}An encrypted superuser password is not set${NORMAL}" 
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${GRN}PASSED, RHEL 9 requires an encrypted boot loader superuser password.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${RED}FAILED, RHEL 9 does not require an encrypted boot loader superuser password.${NORMAL}"
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

file2="/etc/grub2.cfg"

fail=1

if [[ -f $file2 ]]
then

  superuser="$(grep -A1 "superusers" $file2)"

  if ! [[ $superuser =~ 'root' ]]
  then
    fail=0
    echo -e "${NORMAL}RESULT:    ${BLD}A unique username is defined for the superuser.${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}A unique username is not defined for the superuser.${NORMAL}" 
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}$file2 not found.${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${GRN}PASSED, A unique superusers name is used for booting into single-user and maintenance modes.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${RED}FAILED, A unique superusers name is not used for booting into single-user and maintenance modes.${NORMAL}"
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

hard1=0
hard2=0
fail=1

hardlinks1="$(sysctl fs.protected_hardlinks)"

datetime="$(date +%FT%H:%M:%S)"

if [[ $hardlinks1 ]]
then
  hardlinks1val="$(echo $hardlinks1 | awk -F " = " '{print $2}')"
  if [[ $hardlinks1val == 1 ]]
  then
    hard1=1
    echo -e "${NORMAL}RESULT:    ${BLD}a. $hardlinks1${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}a. $hardlinks1${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}a. Nothing returned${NORMAL}"
fi

hardlinks2="$(grep -r fs.protected_hardlinks 2>/dev/null /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf /etc/sysctl.d/*.conf | grep -v "#")"

if [[ $hardlinks2 ]]
then
  for hlink in ${hardlinks2[@]}
  do
    hlink2val="$(echo $hlink | awk -F= '{print $2}' | sed 's/ //')"
    if [[ $hlink2val == 1 ]]
    then
      hard2=1
      echo -e "${NORMAL}RESULT:    ${BLD}b. $hlink${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${RED}b. $hlink${NORMAL}"
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${RED}b. Nothing returned${NORMAL}"
fi

if [[ $hard1 == 1 && $hard2 == 1  ]]
then
  fail=0
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${GRN}PASSED, RHEL 9 enables kernel parameters to enforce discretionary access control on hardlinks.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${RED}FAILED, RHEL 9 does not enable kernel parameters to enforce discretionary access control on hardlinks.${NORMAL}"
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

sym1=0
sym2=0
fail=1

symlinks1="$(sysctl fs.protected_hardlinks)"

datetime="$(date +%FT%H:%M:%S)"

if [[ $symlinks1 ]]
then
  symlinks1val="$(echo $symlinks1 | awk -F= '{print $2}' | sed 's/ //')"
  if [[ $symlinks1val == 1 ]]
  then
    sym1=1
    echo -e "${NORMAL}RESULT:    ${BLD}a. $symlinks1${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}a. $symlinks1${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}a. Nothing returned${NORMAL}"
fi

symlinks2="$(grep -r fs.protected_symlinks 2>/dev/null /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf /etc/sysctl.d/*.conf | grep -v "#")"

if [[ $symlinks2 ]]
then
  for slink in ${symlinks2[@]}
  do
    slink2val="$(echo $slink | awk -F " = " '{print $2}')"
    if [[ $slink2val == 1 ]]
    then
      sym2=1
      echo -e "${NORMAL}RESULT:    ${BLD}b. $slink${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${RED}b. $slink${NORMAL}"
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${RED}b. Nothing returned${NORMAL}"
fi

if [[ $sym1 == 1 && $sym2 == 1  ]]
then
  fail=0
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${GRN}PASSED, RHEL 9 enables kernel parameters to enforce discretionary access control on symlinks.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${RED}FAILED, RHEL 9 does not enable kernel parameters to enforce discretionary access control on symlinks.${NORMAL}"
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

file5="/etc/pam.d/su"

fail=1

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file5 ]]
then
  wheel="$(grep pam_wheel 2>/dev/null $file5)"
  if [[ $wheel ]]
  then
    for line in ${wheel[@]}
    do
      if [[ $line =~ "required" && $line =~ 'use_uid' && ! ${line:0:1} == "#" ]]
      then
	fail=0
        echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
      else
	echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
      fi
    done
  else
    echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}$file5 not found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity5, $controlid, $stigid5, $ruleid5, $cci5, $datetime, ${GRN}PASSED, RHEL 9 restricts the use of the \"su\" command.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity5, $controlid, $stigid5, $ruleid5, $cci5, $datetime, ${RED}FAILED, RHEL 9 does not restrict the use of the \"su\" command.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid6${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid6${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid6${NORMAL}"
echo -e "${NORMAL}CCI:       $cci6${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 6:    ${BLD}$title6a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title6b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title6c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity6${NORMAL}"

IFS='
'

file6="/usr/lib/systemd/system/emergency.service"

fail=1

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file6 ]]
then
  esvc="$(grep sulogin $file6 | grep 'emergency')"
  if [[ $esvc && ! ${esvc:0:1} == "#" ]]
  then
    fail=0
    echo -e "${NORMAL}RESULT:    ${BLD}$esvc${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}$esvc${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}$file6 not found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity6, $controlid, $stigid6, $ruleid6, $cci6, $datetime, ${GRN}PASSED, RHEL 9 requires authentication to access emergency mode.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity6, $controlid, $stigid6, $ruleid6, $cci6, $datetime, ${RED}FAILED, RHEL 9 does not require authentication to access emergency mode.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid7${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid7${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid7${NORMAL}"
echo -e "${NORMAL}CCI:       $cci7${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 7:    ${BLD}$title7a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title7b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title7c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity7${NORMAL}"

IFS='
'

sulogin1=0
sulogin2=0
fail=1

datetime="$(date +%FT%H:%M:%S)"

rescue1="$(grep sulogin 2>/dev/null /usr/lib/systemd/system/rescue.service | grep 'rescue')"
rescue2="$(grep sulogin 2>/dev/null /etc/systemd/system/rescue.service.d/*.conf | grep 'rescue')"

if [[ $rescue1 ]]
then
  if [[ $rescue1 && ! ${rescue1:0:1} == "#" ]]
  then
    sulogin1=1
    echo -e "${NORMAL}RESULT:    ${BLD}a. $rescue1${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}a. $rescue1${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}a. Nothing returned${NORMAL}"
fi

if [[ $rescue2 ]]
then
  for line in ${rescue2[@]}
  do
    if ! [[ ${line:0:1} == "#" ]]
    then
      sulogin2=1
      echo -e "${NORMAL}RESULT:    ${BLD}b. $line${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${RED}b. $line${NORMAL}"
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${RED}b. Nothing returned${NORMAL}"
fi

if [[ $sulogin1 == 1 || $sulogin2 == 1 ]]
then
  fail=0
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity7, $controlid, $stigid7, $ruleid7, $cci7, $datetime, ${GRN}PASSED, RHEL 9 requires authentication to access single-user mode.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity7, $controlid, $stigid7, $ruleid7, $cci7, $datetime, ${RED}FAILED, RHEL 9 does not require authentication to access single-user mode.${NORMAL}"
fi

exit

