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

controlid="AU-9 Protection of Audit Information"

title1a="RHEL 9 audit tools must have a mode of 0755 or less permissive."
title1b="Checking with: stat -c \"%a %n\" /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/rsyslogd /sbin/augenrules"
title1c="Expecting: ${YLO}
           755 /sbin/auditctl
           755 /sbin/aureport
           755 /sbin/ausearch
           750 /sbin/autrace
           755 /sbin/auditd
           755 /sbin/rsyslogd
           755 /sbin/augenrules
           NOTE: If any of the audit tool files have a mode more permissive than "0755", this is a finding."${BLD}
cci1="CCI-001493"
stigid1="RHEL-09-232035"
severity1="CAT II"
ruleid1="SV-257887r991557"
vulnid1="V-257887"

title2a="RHEL 9 audit tools must be owned by root."
title2b="Checking with: sudo stat -c \"%U %n\" /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/rsyslogd /sbin/augenrules"
title2c="Expecting: ${YLO}
           root /sbin/auditctl
           root /sbin/aureport
           root /sbin/ausearch
           root /sbin/autrace
           root /sbin/auditd
           root /sbin/rsyslogd
           root /sbin/augenrules
           NOTE: If any audit tools do not have an owner of \"root\", this is a finding."${BLD}
cci2="CCI-001493"
stigid2="RHEL-09-232220"
severity2="CAT II"
ruleid2="SV-257924r991557"
vulnid2="V-257924"

title3a="RHEL 9 audit tools must be group-owned by root."
title3b="Checking with: sudo stat -c \"%G %n\" /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/rsyslogd /sbin/augenrules"
title3c="Expecting: ${YLO}
           root /sbin/auditctl
           root /sbin/aureport
           root /sbin/ausearch
           root /sbin/autrace
           root /sbin/auditd
           root /sbin/rsyslogd
           root /sbin/augenrules
           NOTE: If any audit tools do not have a group owner of \"root\", this is a finding."${BLD}
cci3="CCI-001493"
stigid3="RHEL-09-232225"
severity3="CAT II"
ruleid3="SV-257925r991557"
vulnid3="V-257925"

title4a="RHEL 9 audit logs must be group-owned by root or by a restricted logging group to prevent unauthorized read access."
title4b="Checking with: 
           a. grep log_group /etc/audit/auditd.conf
           b. grep -iw log_file /etc/audit/auditd.conf
           c. stat -c \"%G %n\" /var/log/audit/audit.log"
title4c="Expecting: ${YLO}
           a. log_group = root
           b. log_file = /var/log/audit/audit.log
           c. root /var/log/audit/audit.log
           NOTE: If the audit log is not group-owned by \"root\" or the configured alternative logging group, this is a finding."${BLD}
cci4="CCI-000162 CCI-000163 CCI-000164 CCI-001314"
stigid4="RHEL-09-653080"
severity4="CAT II"
ruleid4="SV-258165r958434"
vulnid4="V-258165"

title5a="RHEL 9 audit system must protect logon UIDs from unauthorized change."
title5b="Checking with: grep -i immutable /etc/audit/audit.rules"
title5c="Expecting: ${YLO}--loginuid-immutable
           NOTE: If the \"--loginuid-immutable\" option is not returned in the \"/etc/audit/audit.rules\", or the line is commented out, this is a finding."${BLD}
cci5="CCI-000162 CCI-000163 CCI-000164 CCI-000172"
stigid5="RHEL-09-654270"
severity5="CAT II"
ruleid5="SV-258228r991572"
vulnid5="V-258228"

title6a="RHEL 9 audit system must protect auditing rules from unauthorized change."
title6b="Checking with: grep \"^\s*[^#]\" /etc/audit/audit.rules | tail -1"
title6c="Expecting: ${YLO}-e 2
           NOTE: If the audit system is not set to be immutable by adding the \"-e 2\" option to the end of \"/etc/audit/audit.rules\", this is a finding."${BLD}
cci6="CCI-000162 CCI-000163 CCI-000164"
stigid6="RHEL-09-654275"
severity6="CAT II"
ruleid6="SV-258229r958434"
vulnid6="V-258229"

title7a="RHEL 9 must use cryptographic mechanisms to protect the integrity of audit tools."
title7b="Checking with: grep /usr/sbin/au /etc/aide.conf"
title7c="Expecting: ${YLO}
           /usr/sbin/auditctl p+i+n+u+g+s+b+acl+xattrs+sha512
           /usr/sbin/auditd p+i+n+u+g+s+b+acl+xattrs+sha512
           /usr/sbin/ausearch p+i+n+u+g+s+b+acl+xattrs+sha512
           /usr/sbin/aureport p+i+n+u+g+s+b+acl+xattrs+sha512
           /usr/sbin/autrace p+i+n+u+g+s+b+acl+xattrs+sha512
           /usr/sbin/augenrules p+i+n+u+g+s+b+acl+xattrs+sha512
           NOTE: If AIDE is not installed, ask the system administrator (SA) how file integrity checks are performed on the system."${BLD}
cci7="CCI-001493 CCI-001494 CCI-001495 CCI-001496"
stigid7="RHEL-09-651025"
severity7="CAT II"
ruleid7="SV-258137r1102081"
vulnid7="V-258137"

title8a="RHEL 9 audit log directory must be owned by root to prevent unauthorized read access."
title8b="Checking with: 
           a. grep -iw log_file /etc/audit/auditd.conf
           b. stat -c '%U %n' /var/log/audit"
title8c="Expecting: ${YLO}
           a. log_file = /var/log/audit/audit.log
           b. root /var/log/audit
           NOTE: If the audit log directory is not owned by \"root\", this is a finding."${BLD}
cci8="CCI-000162 CCI-000163 CCI-000164 CCI-001314"
stigid8="RHEL-09-653085"
severity8="CAT II"
ruleid8="SV-258166r1045303"
vulnid8="V-258166"

title9a="RHEL 9 audit logs file must have mode 0600 or less permissive to prevent unauthorized access to the audit log."
title9b="Checking with: 
           a. grep -iw log_file /etc/audit/auditd.conf;
           b. find /var/log/audit/ -type f -exec stat -c '%a %n' {} \;"
title9c="Expecting: ${YLO}
           a. log_file = /var/log/audit/audit.log
           b. 600 /var/log/audit/audit.log
           b. 400 /var/log/audit/audit.log.1
           b. 400 /var/log/audit/audit.log.2
           b. 400 /var/log/audit/audit.log.3
           b. 400 /var/log/audit/audit.log.4
	   NOTE: If the audit logs have a mode more permissive than "0600", this is a finding."${BLD}
cci9="CCI-000162 CCI-000163 CCI-000164 CCI-001314"
stigid9="RHEL-09-653090"
severity9="CAT II"
ruleid9="SV-258167r1101918"
vulnid9="V-258167"

title10a="RHEL 9 \"/etc/audit/\" must be owned by root."
title10b="Checking with: stat -c \"%U %n\" /etc/audit/"
title10c="Expecting: ${YLO}root /etc/audit/
           NOTE: If the \"/etc/audit/\" directory does not have an owner of \"root\", this is a finding."${BLD}
cci10="CCI-000162"
stigid10="RHEL-09-232103"
severity10="CAT II"
ruleid10="SV-270175r1117265"
vulnid10="V-270175"

title11a="RHEL 9 \"/etc/audit/\" must be group-owned by root."
title11b="Checking with: stat -c \"%G %n\" /etc/audit/"
title11c="Expecting: ${YLO}root /etc/audit/
           NOTE: If \"/etc/audit/\" does not have a group owner of \"root\", this is a finding."${BLD}
cci11="CCI-000162"
stigid11="RHEL-09-232104"
severity11="CAT II"
ruleid11="SV-270176r1117265"
vulnid11="V-270176"

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

tools="$(stat -c "%a %n" /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/rsyslogd /sbin/augenrules)"

if [[ $tools ]]
then
  for line in ${tools[@]}
  do
    mode="$(echo $line | awk '{print $1}')"
    if ! (( ${mode:1:1} <= 5 &&
	    ${mode:2:1} <= 5
	  ))
    then
      fail=1
      echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${GRN}PASSED, RHEL 9 audit tools have a mode of 0755 or less permissive.${NORMAL}" 
else
  echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${RED}FAILED, RHEL 9 audit tools do not have a mode of 0755 or less permissive.${NORMAL}"
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

datetime="$(date +%FT%H:%M:%S)"

owner="$(sudo stat -c "%U %n" /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/rsyslogd /sbin/augenrules)"

if [[ $owner ]]
then
  for line in ${owner[@]}
  do
    user="$(echo $line | awk '{print $1}')"
    if ! [[ $user == "root" ]]
    then
      fail=1
      echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${GRN}PASSED, RHEL 9 audit tools are owned by root.${NORMAL}" 
else
  echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${RED}FAILED, RHEL 9 audit tools are not owned by root.${NORMAL}"
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

gowner="$(stat -c "%G %n" /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/rsyslogd /sbin/augenrules)"

if [[ $gowner ]]
then
  for line in ${gowner[@]}
  do
    user="$(echo $line | awk '{print $1}')"
    if ! [[ $user == "root" ]]
    then
      fail=1
      echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${GRN}PASSED, RHEL 9 audit tools are group-owned by root.${NORMAL}" 
else
  echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${RED}FAILED, RHEL 9 audit tools are not group-owned by root.${NORMAL}"
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

datetime="$(date +%FT%H:%M:%S)"

lgroup="$(grep log_group /etc/audit/auditd.conf)"
group1="$(echo $lgroup | awk -F= '{print $2}' | sed 's/ //')"
lfile="$(grep -iw log_file /etc/audit/auditd.conf)"
file="$(echo $lfile | awk -F= '{print $2}' | sed 's/ //')"
gowner="$(stat -c "%G %n" $file)"
group2="$(echo $gowner | awk '{print $1}')"

if [[ $group1 ]]
then
  if [[ $group1 == "root" ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}a. $lgroup${NORMAL}"
  else
    fail=1
    echo -e "${NORMAL}RESULT:    ${RED}a. $lgroup${NORMAL}"
  fi
else
  fail=1
  echo -e "${NORMAL}RESULT:    ${RED}a. Nothing returned${NORMAL}"
fi

if [[ $lfile ]]
then
  echo -e "${NORMAL}RESULT:    ${BLD}b. $file${NORMAL}"
else
  fail=1
  echo -e "${NORMAL}RESULT:    ${RED}b. Nothing returned${NORMAL}"
fi

if [[ $lfile ]]
then
  if [[ $group2 == "root" ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}c. $gowner${NORMAL}"
  else
    fail=1
    echo -e "${NORMAL}RESULT:    ${RED}c. $gowner${NORMAL}"
  fi
else
  fail=1
  echo -e "${NORMAL}RESULT:    ${RED}c. Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${GRN}PASSED, RHEL 9 audit logs are group-owned by root.${NORMAL}" 
else
  echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${RED}FAILED, RHEL 9 audit tools are not group-owned by root.${NORMAL}"
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

datetime="$(date +%FT%H:%M:%S)"

echo -e "${NORMAL}$hostname, $severity5, $controlid, $stigid5, $ruleid5, $cci5, $datetime, ${CYN}VERIFY, (See AU-12 Audit Generation: V-258228)${NORMAL}"

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}$hostname, $severity9, $controlid, $stigid9, $ruleid9, $cci9, $datetime, ${GRN}PASSED, RHEL 9 audit log files have mode 0600 or less permissive to prevent unauthorized access to the audit log.${NORMAL}"ho -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
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

immutable="$(sudo grep "^\s*[^#]" /etc/audit/audit.rules | tail -1)"

if [[ $immutable ]]
then
  if [[ $immutable == "-e 2" ]]
  then
    fail=0
    echo -e "${NORMAL}RESULT:    ${BLD}$immutable${NORMAL}" 
  else
    echo -e "${NORMAL}RESULT:    ${RED}$immutable${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity6, $controlid, $stigid6, $ruleid6, $cci6, $datetime, ${GRN}PASSED, RHEL 9 audit system protects auditing rules from unauthorized change.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity6, $controlid, $stigid6, $ruleid6, $cci6, $datetime, ${RED}FAILED, RHEL 9 audit system does not protect auditing rules from unauthorized change.${NORMAL}"
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

fail=0

datetime="$(date +%FT%H:%M:%S)"

isinstalled="$(dnf list --installed 2>&1 aide | grep -Ev 'Updating|Installed')"

if [[ $isinstalled ]]
then
  crypto="$(grep /usr/sbin/au /etc/aide.conf)"
  if [[ $crypto ]]
  then
    for line in ${crypto[@]}
    do
      if ! [[ $line =~ 'acl' && $line =~ 'xattrs' && $line =~ 'sha512' &&
  	    $line =~ 'p+' && $line =~ 'i+' && $line =~ 'n+' && $line =~ 'u+' &&
  	    $line =~ 'g+' && $line =~ 's+' && $line =~ 'b+'
  	 ]]
      then
        fail=1
        echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
      else
        echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
      fi
    done
  else
    fail=1
    echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
  fi
else
  fail=1
  echo -e "${NORMAL}RESULT:    ${RED}The aide package is not installed.${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity7, $controlid, $stigid7, $ruleid7, $cci7, $datetime, ${GRN}PASSED, RHEL 9 uses cryptographic mechanisms to protect the integrity of audit tools.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity7, $controlid, $stigid7, $ruleid7, $cci7, $datetime, ${CYN}VERIFY, Ask he system administrator (SA) how file integrity checks are performed on the system.${NORMAL}"
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

fail=0

datetime="$(date +%FT%H:%M:%S)"

lfile="$(grep -iw log_file /etc/audit/auditd.conf)"
file="$(echo $lfile | awk -F= '{print $2}' | sed 's/ //')"
stat="$(stat -c '%U %n' $file)"
owner="$(echo $stat | awk '{print $1}')"

if [[ $lfile ]]
then
  echo -e "${NORMAL}RESULT:    ${BLD}a. $lfile${NORMAL}"
else
  fail=1
  echo -e "${NORMAL}RESULT:    ${RED}a. $lfile${NORMAL}"
fi

if [[ $stat && $owner == "root" ]]
then
    echo -e "${NORMAL}RESULT:    ${BLD}b. $stat${NORMAL}"
else
  fail=1
  echo -e "${NORMAL}RESULT:    ${RED}b. $stat${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity8, $controlid, $stigid8, $ruleid8, $cci8, $datetime, ${GRN}PASSED, The RHEL 9 RHEL 9 audit log directory is owned by root to prevent unauthorized read access.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity8, $controlid, $stigid8, $ruleid8, $cci8, $datetime, ${RED}FAILED, The RHEL 9 RHEL 9 audit log directory is not owned by root to prevent unauthorized read access.${NORMAL}"
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

fail=0

datetime="$(date +%FT%H:%M:%S)"

logfile="$(grep -iw log_file /etc/audit/auditd.conf)"
dir="$(dirname $(echo $logfile | awk -F= '{print $2}' | sed 's/ //'))"
logdir="$(stat -c '%a %n' $dir)"

if [[ $logdir ]]
then
  echo -e "${NORMAL}RESULT:    ${BLD}a. $logfile${NORMAL}"
else
  echo -e "${NORMAL}RESULT:    ${RED}a. Nothing returned${NORMAL}"
fi

files="$(find $dir -type f -exec stat -c '%a %n' {} \;)"
if [[ $files ]]
then
  for line in ${files[@]}
  do
    mode="$(echo $line | awk '{print $1}')"
    if (( ${mode:0:1} <= 6 )) &&
       [[ ${mode:1:1} == 0 &&
          ${mode:2:1} == 0
       ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}b. $line${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${RED}b. $line${NORMAL}"
      fail=1
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${RED}b. Nothing returned${NORMAL}"
  fail=1
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity9, $controlid, $stigid9, $ruleid9, $cci9, $datetime, ${GRN}PASSED, RHEL 9 audit log files have mode 0600 or less permissive to prevent unauthorized access to the audit log.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity9, $controlid, $stigid9, $ruleid9, $cci9, $datetime, ${RED}FAILED, RHEL 9 audit log files do not have mode 0600 or less permissive to prevent unauthorized access to the audit log.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid10${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid10${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid10${NORMAL}"
echo -e "${NORMAL}CCI:       $cci10${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 10:   ${BLD}$title10a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title10b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title10c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity10${NORMAL}"

IFS='
'

fail=1

datetime="$(date +%FT%H:%M:%S)"

owner="$(stat -c "%U %n" /etc/audit/)"

if [[ $owner ]]
then
  user="$(echo $owner | awk '{print $1}')"
  if [[ $user == "root" ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}$user${NORMAL}"
    fail=0
  else
    echo -e "${NORMAL}RESULT:    ${RED}$user${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity10, $controlid, $stigid10, $ruleid10, $cci10, $datetime, ${GRN}PASSED, RHEL 9 "/etc/audit/" is owned by root.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity10, $controlid, $stigid10, $ruleid10, $cci10, $datetime, ${RED}FAILED, RHEL 9 "/etc/audit/" is not owned by root.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid11${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid11${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid11${NORMAL}"
echo -e "${NORMAL}CCI:       $cci11${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 11:   ${BLD}$title11a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title11b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title11c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity11${NORMAL}"

IFS='
'

fail=1

datetime="$(date +%FT%H:%M:%S)"

gowner="$(stat -c "%U %n" /etc/audit/)"

if [[ $gowner ]]
then
  grp="$(echo $gowner | awk '{print $1}')"
  if [[ $grp == "root" ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}$grp${NORMAL}"
    fail=0
  else
    echo -e "${NORMAL}RESULT:    ${RED}$grp${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity11, $controlid, $stigid11, $ruleid11, $cci11, $datetime, ${GRN}PASSED, RHEL 9 "/etc/audit/" is group-owned by root.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity11, $controlid, $stigid11, $ruleid11, $cci11, $datetime, ${RED}FAILED, RHEL 9 "/etc/audit/" is not group-owned by root.${NORMAL}"
fi

exit

