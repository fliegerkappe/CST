#! /bin/bash

# AC-7 Unsuccessful Logon Attempts
#
# CONTROL: The information system:
# a. Enforces a limit of [Assignment: organization-defined number] consecutive invalid logon
#    attempts by a user during a [Assignment: organization-defined time period]; and
# b. Automatically [Selection: locks the account/node for an [Assignment: organization-defined
#    time period]; locks the account/node until released by an administrator; delays next logon
#    prompt according to [Assignment: organization-defined delay algorithm]] when the maximum
#     number of unsuccessful attempts is exceeded.

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

controlid="AC-7 Unsuccessful Logon Attempts"

title1a="RHEL 9 must automatically lock an account when three unsuccessful logon attempts occur."
title1b="Checking with: grep 'deny =' /etc/security/faillock.conf"
title1c="Expecting: ${YLO}deny = 3
           NOTE: If the \"deny\" option is not set to \"3\" or less (but not \"0\"), is missing or commented out, this is a finding."${BLD}
cci1="CCI-000044 CCI-002238"
stigid1="RHEL-09-411075"
severity1="CAT II"
ruleid1="SV-258054r958736"
vulnid1="V-258054"

title2a="RHEL 9 must automatically lock the root account until the root account is released by an administrator when three unsuccessful logon attempts occur during a 15-minute time period."
title2b="Checking with: grep even_deny_root /etc/security/faillock.conf"
title2c="Expecting: ${YLO}even_deny_root
           NOTE: If the \"even_deny_root\" option is not set or is missing or commented out, this is a finding."${BLD}
cci2="CCI-000044 CCI-002238"
stigid2="RHEL-09-411080"
severity2="CAT II"
ruleid2="SV-258055r1045140"
vulnid2="V-258055"

title3a="RHEL 9 must automatically lock an account when three unsuccessful logon attempts occur during a 15-minute time period."
title3b="Checking with: grep fail_interval /etc/security/faillock.conf"
title3c="Expecting: ${YLO}fail_interval = 900
           NOTE: If the "fail_interval" option is not set to "900" or less (but not "0"), the line is commented out, or the line is missing, this is a finding."${BLD}
cci3="CCI-000044 CCI-002238"
stigid3="RHEL-09-411085"
severity3="CAT II"
ruleid3="SV-258056r1045143"
vulnid3="V-258056"

title4a="RHEL 9 must maintain an account lock until the locked account is released by an administrator."
title4b="Checking with: grep -w unlock_time /etc/security/faillock.conf"
title4c="Expecting: ${YLO}unlock_time = 0
           NOTE: If the \"unlock_time\" option is not set to \"0\" or the line is missing or commented out, this is a finding."${BLD}
cci4="CCI-000044 CCI-002238"
stigid4="RHEL-09-411090"
severity4="CAT II"
ruleid4="SV-258057r1045146"
vulnid4="V-258057"

title5a="RHEL 9 must ensure account lockouts persist."
title5b="Checking with: grep -w dir /etc/security/faillock.conf"
title5c="Expecting: ${YLO}dir = /var/log/faillock
           NOTE: If the \"dir\" option is not set to a nondefault documented tally log directory or is missing or commented out, this is a finding."${BLD}
cci5="CCI-000044"
stigid5="RHEL-09-411105"
severity5="CAT II"
ruleid5="SV-258060r1045150"
vulnid5="V-258060"

title6a="RHEL 9 must log username information when unsuccessful logon attempts occur."
title6b="Checking with: grep audit /etc/security/faillock.conf"
title6c="Expecting: ${YLO}audit
           NOTE: If the \"audit\" option is not set, is missing, or is commented out, this is a finding."${BLD}
cci6="CCI-000044"
stigid6="RHEL-09-412045"
severity6="CAT II"
ruleid6="SV-258070r1045153"
vulnid6="V-258070"

title7a="RHEL 9 must configure SELinux context type to allow the use of a nondefault faillock tally directory."
title7b="Checking with:
           a. grep -w dir /etc/security/faillock.conf
	   b. ls -Zd /var/log/faillock"
title7c="Expecting: ${YLO}
           a. dir = /var/log/faillock
	   b. unconfined_u:object_r:faillog_t:s0 /var/log/faillock
	   NOTE: If the security context type of the nondefault tally directory is not \"faillog_t\", this is a finding."${BLD}
cci7="CCI-000044"
stigid7="RHEL-09-431020"
severity7="CAT II"
ruleid7="SV-258080r1045162"
vulnid7="V-258080"

title8a="RHEL 9 must configure the use of the pam_faillock.so module in the /etc/pam.d/system-auth file."
title8b="Checking with: grep pam_faillock.so /etc/pam.d/system-auth"
title8c="Expecting: ${YLO}
           auth required pam_faillock.so preauth
           auth required pam_faillock.so authfail
           account required pam_faillock.so
           NOTE: If the pam_faillock.so module is not present in the \"/etc/pam.d/system-auth\" file with the \"preauth\" line listed before pam_unix.so, this is a finding."${BLD}
cci8="CCI-000044"
stigid8="RHEL-09-611030"
severity8="CAT II"
ruleid8="SV-258095r1045189"
vulnid8="V-258095"

title9a="RHEL 9 must configure the use of the pam_faillock.so module in the /etc/pam.d/password-auth file."
title9b="Checking with: grep pam_faillock.so /etc/pam.d/password-auth"
title9c="Expecting: ${YLO}
           auth required pam_faillock.so preauth
           auth required pam_faillock.so authfail
           account required pam_faillock.so
           NOTE: If the pam_faillock.so module is not present in the \"/etc/pam.d/password-auth\" file with the \"preauth\" line listed before pam_unix.so, this is a finding."${BLD}
cci9="CCI-000044"
stigid9="RHEL-09-611035"
severity9="CAT II"
ruleid9="SV-258096r1045191"
vulnid9="V-258096"

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

datetime="$(date +%FT%H:%M:%S)"

deny="$(grep 'deny =' /etc/security/faillock.conf)"

if [[ $deny ]]
then
  for line in ${deny[@]}
  do
    if ! [[ ${line:0:1} == "#" ]]
    then
      denyval="$(echo $line | awk -F " = " '{print $2}')"
      if (( $denyval <= 3 && $denyval > 0 ))
      then
        fail=0
        echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
      else
        echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
      fi
    else
      echo -e "${NORMAL}RESULT:    $line${NORMAL}"
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${GRN}PASSED, RHEL 9 automatically locks an account when three unsuccessful logon attempts occur.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${RED}FAILED, RHEL 9 does not automatically lock an account when three unsuccessful logon attempts occur.${NORMAL}"
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

datetime="$(date +%FT%H:%M:%S)"

denyroot="$(grep even_deny_root /etc/security/faillock.conf)"

if [[ $denyroot ]]
then
  for line in ${denyroot[@]}
  do
    if ! [[ ${line:0:1} == "#" ]]
    then
      fail=0
      echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    $line${NORMAL}"
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${GRN}PASSED, RHEL 9 automatically locks the root account until the root account is released by an administrator when three unsuccessful logon attempts occur during a 15-minute time period.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${RED}FAILED, RHEL 9 automatically locks the root account until the root account is released by an administrator when three unsuccessful logon attempts occur during a 15-minute time period.${NORMAL}"
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

datetime="$(date +%FT%H:%M:%S)"

fint="$(grep fail_interval /etc/security/faillock.conf)"

if [[ $fint ]]
then
  for line in ${fint[@]}
  do
    if ! [[ ${line:0:1} == "#" ]]
    then
      fintval="$(echo $line | awk -F " = " '{print $2}')"
      if (( $fintval <= 900 && $fintval > 0 ))
      then
        fail=0
        echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
      else
        echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
      fi
    else
      echo -e "${NORMAL}RESULT:    $line${NORMAL}"
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${GRN}PASSED, RHEL 9 automatically locks an account when three unsuccessful logon attempts occur during a 15-minute time period.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${RED}FAILED, RHEL 9 does not automatically lock an account when three unsuccessful logon attempts occur during a 15-minute time period.${NORMAL}"
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

utime="$(grep -w unlock_time /etc/security/faillock.conf)"

if [[ $utime ]]
then
  for line in ${utime[@]}
  do
    if ! [[ ${line:0:1} == "#" ]]
    then
      utimeval="$(echo $line | awk -F " = " '{print $2}')"
      if [[ $utimeval == 0 ]]
      then
        fail=0
        echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
      else
        echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
      fi
    else
      echo -e "${NORMAL}RESULT:    $line${NORMAL}"
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${GRN}PASSED, RHEL 9 maintains an account lock until the locked account is released by an administrator.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${RED}FAILED, RHEL 9 does not maintain an account lock until the locked account is released by an administrator.${NORMAL}"
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

datetime="$(date +%FT%H:%M:%S)"

fldir="$(grep -w dir /etc/security/faillock.conf)"

if [[ $fldir ]]
then
  for line in ${fldir[@]}
  do
    if ! [[ ${line:0:1} == "#" ]]
    then
      fldirval="$(echo $line | awk -F " = " '{print $2}')"
      if ! [[ $fldirval == "/var/log/audit" ||
	      $fldirval == "/run/log/faillock" ]]
      then
        fail=0
        echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
      else
        echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
      fi
    else
      echo -e "${NORMAL}RESULT:    $line${NORMAL}"
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity5, $controlid, $stigid5, $ruleid5, $cci5, $datetime, ${GRN}PASSED, RHEL 9 ensures account lockouts persist and the \"dir\" option is set to a nondefault documented tally log directory.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity5, $controlid, $stigid5, $ruleid5, $cci5, $datetime, ${RED}FAILED, RHEL 9 does not ensure account lockouts persist or the \"dir\" option is not set to a nondefault documented tally log directory.${NORMAL}"
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

fail=1

datetime="$(date +%FT%H:%M:%S)"

audit="$(grep audit /etc/security/faillock.conf)"

if [[ $audit ]]
then
  for line in ${audit[@]}
  do
    if ! [[ ${line:0:1} == "#" ]]
    then
      fail=0
      echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    $line${NORMAL}"
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity6, $controlid, $stigid6, $ruleid6, $cci6, $datetime, ${GRN}PASSED, RHEL 9 logs username information when unsuccessful logon attempts occur.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity6, $controlid, $stigid6, $ruleid6, $cci6, $datetime, ${RED}FAILED, RHEL 9 does not log username information when unsuccessful logon attempts occur.${NORMAL}"
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

fail=1

datetime="$(date +%FT%H:%M:%S)"

flcfg="$(grep -w dir /etc/security/faillock.conf)"

if [[ $flcfg ]]
then
  for line in ${flcfg[@]}
  do
    if ! [[ ${line:0:1} == "#" ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}a. $line${NORMAL}"
      dir="$(echo $line | awk -F " = " '{print $2}')"
      context="$(ls -Zd $dir)"
      if [[ $context =~ "faillog_t:s0" ]]
      then
        fail=0
        echo -e "${NORMAL}RESULT:    ${BLD}b. $context${NORMAL}"
      else
        echo -e "${NORMAL}RESULT:    ${RED}b. $context${NORMAL}"
      fi
    else
      echo -e "${NORMAL}RESULT:    a. $line (not checked)${NORMAL}"
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${RED}a. Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity7, $controlid, $stigid7, $ruleid7, $cci7, $datetime, ${GRN}PASSED, RHEL 9 configures SELinux context type to allow the use of a nondefault faillock tally directory.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity7, $controlid, $stigid7, $ruleid7, $cci7, $datetime, ${RED}FAILED, RHEL 9 does not configure SELinux context type to allow the use of a nondefault faillock tally directory.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid8${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid8${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid8${NORMAL}"
echo -e "${NORMAL}CCI:       $cci8${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 8:    ${BLD}$title8a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title8b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title8c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity8${NORMAL}"

IFS='
'

fail=1
found1=0
found2=0

datetime="$(date +%FT%H:%M:%S)"

file8="/etc/pam.d/system-auth"
module="$(grep -nE 'pam_faillock.so|pam_unix' $file8)"

if [[ $module ]]
then
  for line in ${module[@]}
  do
    mod="$(echo $line | awk '{print $3}')"
    case $mod in
      'pam_faillock.so')
	 echo -e "${NORMAL}RESULT:    Line $line${NORMAL}"
	 if [[ $line =~ 'preauth' ]]
	 then
	   found1=1
           faillock_linenum="$(echo $line | awk -F: '{print $1}')"
	 fi
	 ;;
      'pam_unix.so')
	 found2=1
	 unix_linenum="$(echo $line | awk -F: '{print $1}')"
	 echo -e "${NORMAL}RESULT:    Line $line${NORMAL}"
	 ;;
    esac
  done

  if [[ $found1 == 1 && $found2 == 1 ]]
  then
    if (( $faillock_linenum < $unix_linenum ))
    then
      fail=0
    fi
  elif [[ $found1 == 0 ]]
  then
    echo -e "${NORMAL}RESULT:    ${RED}\"pam_faillock.so preauth\" is not present in $file8${NORMAL}"
  elif [[ $found2 == 0 ]]
  then
    echo -e "${NORMAL}RESULT:    \"pam_unix.so\" is not present in $file8${NORMAL}"
    fail=0
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity8, $controlid, $stigid8, $ruleid8, $cci8, $datetime, ${GRN}PASSED, RHEL 9 correctly configures the use of the pam_faillock.so module in the /etc/pam.d/system-auth file.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity8, $controlid, $stigid8, $ruleid8, $cci8, $datetime, ${RED}FAILED, RHEL 9 does not correctly configure the use of the pam_faillock.so module in the /etc/pam.d/system-auth file.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid9${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid9${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid9${NORMAL}"
echo -e "${NORMAL}CCI:       $cci9${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 9:    ${BLD}$title9a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title9b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title9c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity9${NORMAL}"

IFS='
'

fail=1
found1=0
found2=0

datetime="$(date +%FT%H:%M:%S)"

file9="/etc/pam.d/password-auth"
module="$(grep -nE 'pam_faillock.so|pam_unix' $file9)"

if [[ $module ]]
then
  for line in ${module[@]}
  do
    mod="$(echo $line | awk '{print $3}')"
    case $mod in
      'pam_faillock.so')
         echo -e "${NORMAL}RESULT:    Line $line${NORMAL}"
         if [[ $line =~ 'preauth' ]]
         then
           found1=1
           faillock_linenum="$(echo $line | awk -F: '{print $1}')"
         fi
         ;;
      'pam_unix.so')
         found2=1
         unix_linenum="$(echo $line | awk -F: '{print $1}')"
         echo -e "${NORMAL}RESULT:    Line $line${NORMAL}"
         ;;
    esac
  done

  if [[ $found1 == 1 && $found2 == 1 ]]
  then
    if (( $faillock_linenum < $unix_linenum ))
    then
      fail=0
    fi
  elif [[ $found1 == 0 ]]
  then
    echo -e "${NORMAL}RESULT:    ${RED}\"pam_faillock.so preauth\" is not present in $file8${NORMAL}"
  elif [[ $found2 == 0 ]]
  then
    echo -e "${NORMAL}RESULT:    \"pam_unix.so\" is not present in $file8${NORMAL}"
    fail=0
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity9, $controlid, $stigid9, $ruleid9, $cci9, $datetime, ${GRN}PASSED, RHEL 9 correctly configures the use of the pam_faillock.so module in the /etc/pam.d/password-auth file.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity9, $controlid, $stigid9, $ruleid9, $cci9, $datetime, ${RED}FAILED, RHEL 9 does not correctly configure the use of the pam_faillock.so module in the /etc/pam.d/password-auth file.${NORMAL}"
fi

exit
