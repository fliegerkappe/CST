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

controlid="AU-9 Protection of Audit Information"

title1a="RHEL 8 audit logs must have a mode of 0600 or less permissive to prevent unauthorized read access."
title1b="Checking with:
           a. grep -iw log_file /etc/audit/auditd.conf
	   b. stat -c \"%a %n\" /var/log/audit/audit.log"
title1c="Expecting: ${YLO}
           a. log_file = /var/log/audit/audit.log
	   b. 600 /var/log/audit/audit.log
	   NOTE: If the audit log has a mode more permissive than "0600", this is a finding."${BLD}
cci1="CCI-000162"
stigid1="RHEL-08-030070"
severity1="CAT II"
ruleid1="SV-230396r627750_rule"
vulnid1="V-230396"

title2a="RHEL 8 audit logs must be owned by root to prevent unauthorized read access."
title2b="Checking with: 
           a. grep -iw log_file /etc/audit/auditd.conf
	   b. ls -al /var/log/audit/audit.log"
title2c="Expecting: ${YLO}
           a. log_file = /var/log/audit/audit.log
	   b. rw------- 2 root root 23 Jun 11 11:56 /var/log/audit/audit.log
	   NOTE: If the audit log is not owned by \"root\", this is a finding."${BLD}
cci2="CCI-000162"
stigid2="RHEL-08-030080"
severity2="CAT II"
ruleid2="SV-230397r627750_rule"
vulnid2="V-230397"

title3a="RHEL 8 audit logs must be group-owned by root to prevent unauthorized read access."
title3b="Checking with:
           a. grep -iw log_file /etc/audit/auditd.conf
	   b. ls -al /var/log/audit/audit.log"
title3c="Expecting: ${YLO}
           a. log_file = /var/log/audit/audit.log
	   b. rw------- 2 root root 23 Jun 11 11:56 /var/log/audit/audit.log
	   NOTE: If the audit log is not group-owned by \"root\", this is a finding."${BLD}
cci3="CCI-000162"
stigid3="RHEL-08-030090"
severity3="CAT II"
ruleid3="SV-230398r627750_rule"
vulnid3="V-230398"

title4a="RHEL 8 audit log directory must be owned by root to prevent unauthorized read access."
title4b="Checking with:
           a. grep -iw log_file /etc/audit/auditd.conf
	   b. ls -ld /var/log/audit"
title4c="Expecting: ${YLO}
           a. log_file = /var/log/audit/audit.log
	   b. drw------- 2 root root 23 Jun 11 11:56 /var/log/audit
	   NOTE: If the audit log directory is not owned by \"root\", this is a finding."${BLD}
cci4="CCI-000162"
stigid4="RHEL-08-030100"
severity4="CAT II"
ruleid4="SV-230399r627750_rule"
vulnid4="V-230399"

title5a="RHEL 8 audit log directory must be group owned by root to prevent unauthorized read access."
title5b="Checking with:
           a. grep -iw log_file /etc/audit/auditd.conf
	   b. ls -ld /var/log/audit"
title5c="Expecting: ${YLO}
           a. log_file = /var/log/audit/audit.log
	   b. drw------- 2 root root 23 Jun 11 11:56 /var/log/audit
	   NOTE: If the audit log directory is not group owned by \"root\", this is a finding."${BLD}
cci5="CCI-000162"
stigid5="RHEL-08-030110"
severity5="CAT II"
ruleid5="SV-230400r627750_rule"
vulnid5="V-230400"

title6a="RHEL 8 audit log directory must have a mode of 0700 or less permissive to prevent unauthorized read access."
title6b="Checking with:
           a. grep -iw log_file /etc/audit/auditd.conf
	   b. stat -c \"%a %n\" /var/log/audit"
title6c="Expecting: ${YLO}
           a. log_file = /var/log/audit/audit.log
	   b. 700 /var/log/audit
	   NOTE: If the audit log directory has a mode more permissive than "0700", this is a finding."${BLD}
cci6="CCI-000162"
stigid6="RHEL-08-030120"
severity6="CAT II"
ruleid6="SV-230401r627750_rule"
vulnid6="V-230401"

title7a="RHEL 8 audit system must protect auditing rules from unauthorized change."
title7b="Checking with: grep \"^\s*[^#]\" /etc/audit/audit.rules | tail -1"
title7c="Expecting: ${YLO}-e 2${BLD}
           NOTE: If the audit system is not set to be immutable by adding the \"-e 2\" option to the \"/etc/audit/audit.rules\", this is a finding."${BLD}
cci7="CCI-000162"
stigid7="RHEL-08-030121"
severity7="CAT II"
ruleid7="SV-230402r627750_rule"
vulnid7="V-230402"

title8a="RHEL 8 audit system must protect logon UIDs from unauthorized change."
title8b="Checking with: grep -i immutable /etc/audit/audit.rules."
title8c="Expecting: ${YLO}--loginuid-immutable
           NOTE: If the login UIDs are not set to be immutable by adding the \"--loginuid-immutable\" option to the \"/etc/audit/audit.rules\", this is a finding.${BLD}"
cci8="CCI-000162"
stigid8="RHEL-08-030122"
severity8="CAT II"
ruleid8="SV-230403r627750_rule"
vulnid8="V-230403"

title9a="RHEL 8 audit tools must have a mode of 0755 or less permissive."
title9b="Checking with: stat -c \"%a %n\" /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/rsyslogd /sbin/augenrules"
title9c="Expecting: ${YLO}
           755 /sbin/auditctl
           755 /sbin/aureport
           755 /sbin/ausearch
           750 /sbin/autrace
           755 /sbin/auditd
           755 /sbin/rsyslogd
           755 /sbin/augenrules
	   NOTE: If any of the audit tools has a mode more permissive than \"0755\", this is a finding."${BLD}
cci9="CCI-001493"
stigid9="RHEL-08-030620"
severity9="CAT II"
ruleid9="SV-230472r627750_rule"
vulnid9="V-230472"

title10a="RHEL 8 audit tools must be owned by root."
title10b="Checking with: stat -c \"%U %n\" /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/rsyslogd /sbin/augenrules"
title10c="Expecting: ${YLO}
           root /sbin/auditctl
           root /sbin/aureport
           root /sbin/ausearch
           root /sbin/autrace
           root /sbin/auditd
           root /sbin/rsyslogd
           root /sbin/augenrules
	   NOTE: If any of the audit tools are not owned by \"root\", this is a finding."${BLD}
cci10="CCI-001493"
stigid10="RHEL-08-030630"
severity10="CAT II"
ruleid10="SV-230473r744008_rule"
vulnid10="V-230473"

title11a="RHEL 8 audit tools must be group owned by root."
title11b="Checking with: stat -c \"%G %n\" /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/rsyslogd /sbin/augenrules"
title11c="Expecting: ${YLO}
           root /sbin/auditctl
           root /sbin/aureport
           root /sbin/ausearch
           root /sbin/autrace
           root /sbin/auditd
           root /sbin/rsyslogd
           root /sbin/augenrules
	   NOTE: If any of the audit tools are not group-owned by \"root\", this is a finding."${BLD}
cci11="CCI-001493"
stigid11="RHEL-08-030640"
severity11="CAT II"
ruleid11="SV-230474r627750_rule"
vulnid11="V-230474"

title12a="RHEL 8 must use cryptographic mechanisms to protect the integrity of audit tools."
title12b="Checking with: egrep '(\/usr\/sbin\/(audit|au))' /etc/aide.conf"
title12c="Expecting: ${YLO}
           /usr/sbin/auditctl p+i+n+u+g+s+b+acl+xattrs+sha512
           /usr/sbin/auditd p+i+n+u+g+s+b+acl+xattrs+sha512
           /usr/sbin/ausearch p+i+n+u+g+s+b+acl+xattrs+sha512
           /usr/sbin/aureport p+i+n+u+g+s+b+acl+xattrs+sha512
           /usr/sbin/autrace p+i+n+u+g+s+b+acl+xattrs+sha512
           /usr/sbin/rsyslogd p+i+n+u+g+s+b+acl+xattrs+sha512
           /usr/sbin/augenrules p+i+n+u+g+s+b+acl+xattrs+sha512
           NOTE: If any of the audit tools listed above do not have an appropriate selection line, ask the system administrator to indicate what cryptographic mechanisms are being used to protect the integrity of the audit tools.  If there is no evidence of integrity protection, this is a finding."${BLD}
cci12="CCI-001496"
stigid12="RHEL-08-030650"
severity12="CAT II"
ruleid12="SV-230475r627750_rule"
vulnid12="V-230475"

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

file1="/etc/audit/auditd.conf"

fail=1

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file1 ]]
then
  logfile="$(grep -iw log_file $file1)"
  if [[ $logfile ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}$logfile${NORMAL}"
    filepath="$(echo $logfile | awk -F= '{print $2}' | sed 's/ //g')"
    if [[ -f $filepath ]]
    then
      stat="$(stat -c "%a %n" $filepath)"
      mode="$(echo $stat | awk '{print $1}')"
      if (( ${mode:0:1} <= 6 &&
	    ${mode:1:1} == 0 &&
	    ${mode:2:1} == 0
         ))
      then
        echo -e "${NORMAL}RESULT:    ${BLD}$stat${NORMAL}"
        fail=0
      else
        echo -e "${NORMAL}RESULT:    ${RED}$stat${NORMAL}"
      fi
    else
      echo -e "${NORMAL}RESULT:    ${RED}$filepath not found${NORMAL}"
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}\"log_file\" not defined in $file1.${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}$file1 not found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${GRN}PASSED, RHEL 8 audit logs have a mode of 0600 or less permissive to prevent unauthorized read access.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${RED}FAILED, RHEL 8 audit logs do not have a mode of 0600 or less permissive to prevent unauthorized read access.${NORMAL}"
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

file2="/etc/audit/auditd.conf"

fail=1

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file2 ]]
then
  logfile="$(grep -iw log_file $file2)"
  if [[ $logfile ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}a. $logfile${NORMAL}"
    filepath="$(echo $logfile | awk -F= '{print $2}' | sed 's/ //g')"
    if [[ -f $filepath ]]
    then
      filestat="$(ls -al $filepath)"
      fileowner="$(echo $filestat | awk '{print $3}')"
      if [[ $fileowner == "root" ]]
      then
        echo -e "${NORMAL}RESULT:    ${BLD}b. $filestat${NORMAL}"
        fail=0
      else
        echo -e "${NORMAL}RESULT:    ${RED}b. $filestat${NORMAL}"
      fi
    else
      echo -e "${NORMAL}RESULT:    ${RED}b. $filepath not found${NORMAL}"
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}a. \"log_file\" not defined in $file2.${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}a. $file2 not found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${GRN}PASSED, RHEL 8 audit logs are owned by root to prevent unauthorized read access.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${RED}FAILED, RHEL 8 audit logs are not owned by root to prevent unauthorized read access.${NORMAL}"
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

file3="/etc/audit/auditd.conf"

fail=1

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file3 ]]
then
  logfile="$(grep -iw log_file $file3)"
  if [[ $logfile ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}a. $logfile${NORMAL}"
    filepath="$(echo $logfile | awk -F= '{print $2}' | sed 's/ //g')"
    if [[ -f $filepath ]]
    then
      filestat="$(ls -al $filepath)"
      filegroup="$(echo $filestat | awk '{print $4}')"
      if [[ $filegroup == "root" ]]
      then
        echo -e "${NORMAL}RESULT:    ${BLD}b. $filestat${NORMAL}"
        fail=0
      else
        echo -e "${NORMAL}RESULT:    ${RED}b. $filestat${NORMAL}"
      fi
    else
      echo -e "${NORMAL}RESULT:    ${RED}b. $filepath not found${NORMAL}"
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}a. \"log_file\" not defined in $file3.${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}a. $file3 not found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${GRN}PASSED, RHEL 8 audit logs are group owned by root to prevent unauthorized read access.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${RED}FAILED, RHEL 8 audit logs are not group owned by root to prevent unauthorized read access.${NORMAL}"
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

file4="/etc/audit/auditd.conf"

fail=1

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file4 ]]
then
  logfile="$(grep -iw log_file $file4)"
  if [[ $logfile ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}a. $logfile${NORMAL}"
    filepath="$(echo $logfile | awk -F= '{print $2}' | sed 's/ //g')"
    if [[ -f $filepath ]]
    then
      logdir="$(dirname $filepath)"
      logdirstat="$(ls -ld $logdir)"
      logdirowner="$(echo $logdirstat | awk '{print $3}')"
      if [[ $logdirowner == "root" ]]
      then
        echo -e "${NORMAL}RESULT:    ${BLD}b. $logdirstat${NORMAL}"
        fail=0
      else
        echo -e "${NORMAL}RESULT:    ${RED}b. $logdirstat${NORMAL}"
      fi
    else
      echo -e "${NORMAL}RESULT:    ${RED}b. $filepath not found${NORMAL}"
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}a. \"log_file\" not defined in $file4.${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}a. $file4 not found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${GRN}PASSED, RHEL 8 audit log directory is owned by root to prevent unauthorized read access.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${RED}FAILED, RHEL 8 audit log directory is not owned by root to prevent unauthorized read access.${NORMAL}"
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

file5="/etc/audit/auditd.conf"

fail=1

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file5 ]]
then
  logfile="$(grep -iw log_file $file5)"
  if [[ $logfile ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}a. $logfile${NORMAL}"
    filepath="$(echo $logfile | awk -F= '{print $2}' | sed 's/ //g')"
    if [[ -f $filepath ]]
    then
      logdir="$(dirname $filepath)"
      logdirstat="$(ls -ld $logdir)"
      logdirgroup="$(echo $logdirstat | awk '{print $4}')"
      if [[ $logdirgroup == "root" ]]
      then
        echo -e "${NORMAL}RESULT:    ${BLD}b. $logdirstat${NORMAL}"
        fail=0
      else
        echo -e "${NORMAL}RESULT:    ${RED}b. $logdirstat${NORMAL}"
      fi
    else
      echo -e "${NORMAL}RESULT:    ${RED}b. $filepath not found${NORMAL}"
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}a. \"log_file\" not defined in $file4.${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}a. $file4 not found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity5, $controlid, $stigid5, $ruleid5, $cci5, $datetime, ${GRN}PASSED, RHEL 8 audit log directory is group owned by root to prevent unauthorized read access.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity5, $controlid, $stigid5, $ruleid5, $cci5, $datetime, ${RED}FAILED, RHEL 8 audit log directory is not group owned by root to prevent unauthorized read access.${NORMAL}"
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

file6="/etc/audit/auditd.conf"

fail=1

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file6 ]]
then
  logfile="$(grep -iw log_file $file6)"
  if [[ $logfile ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}a. $logfile${NORMAL}"
    filepath="$(echo $logfile | awk -F= '{print $2}' | sed 's/ //g')"
    if [[ -f $filepath ]]
    then
      logdir="$(dirname $filepath)"
      stat="$(stat -c "%a %n" $logdir)"
      mode="$(echo $stat | awk '{print $1}')"
      if (( ${mode:0:1} <= 7 &&
	    ${mode:1:1} == 0 &&
	    ${mode:2:1} == 0
         )) 
      then
        echo -e "${NORMAL}RESULT:    ${BLD}b. $stat${NORMAL}"
        fail=0
      else
        echo -e "${NORMAL}RESULT:    ${RED}b. $stat${NORMAL}"
      fi
    else
      echo -e "${NORMAL}RESULT:    ${RED}b. $filepath not found${NORMAL}"
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}a. \"log_file\" not defined in $file6.${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}a. $file6 not found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity6, $controlid, $stigid6, $ruleid6, $cci6, $datetime, ${GRN}PASSED, RHEL 8 audit log directory is mode 0700 or less permissive to prevent unauthorized read access.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity6, $controlid, $stigid6, $ruleid1, $cci6, $datetime, ${RED}FAILED, RHEL 8 audit log directory is not mode 0700 or less permissive to prevent unauthorized read access.${NORMAL}"
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

file7="/etc/audit/audit.rules"

fail=1

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file7 ]]
then
  immutable="$(grep "^\s*[^#]" $file7 | tail -1)"
  if [[ $immutable == "-e 2" ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}$immutable${NORMAL}"
    fail=0
  else
    echo -e "${NORMAL}RESULT:    ${RED}$immutable${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}$file7 not found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity7, $controlid, $stigid7, $ruleid7, $cci7, $datetime, ${GRN}PASSED, RHEL 8 audit system protects auditing rules from unauthorized change.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity7, $controlid, $stigid7, $ruleid7, $cci7, $datetime, ${RED}FAILED, RHEL 8 audit system does not protect auditing rules from unauthorized change.${NORMAL}"
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

file8="/etc/audit/audit.rules"

fail=1

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file8 ]]
then
  immutable="$(grep -i immutable $file8)"
  if [[ $immutable == "--loginuid-immutable" ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}$immutable${NORMAL}"
    fail=0
  else
    echo -e "${NORMAL}RESULT:    ${RED}$immutable${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}$file8 not found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity8, $controlid, $stigid8, $ruleid8, $cci8, $datetime, ${GRN}PASSED, RHEL 8 audit system protects logon UIDs from unauthorized change.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity8, $controlid, $stigid8, $ruleid8, $cci8, $datetime, ${RED}FAILED, RHEL 8 audit system does not protect logon UIDs from unauthorized change.${NORMAL}"
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

file9arr=("/sbin/auditctl" "/sbin/aureport" "/sbin/ausearch" "/sbin/autrace" "/sbin/auditd" "/sbin/rsyslogd" "/sbin/augenrules")

fail=0

datetime="$(date +%FT%H:%M:%S)"

for file in ${file9arr[@]}
do
  if [[ -f $file ]]
  then
    stat="$(stat -c "%a %n" $file)"
    mode="$(echo $stat | awk '{print $1}')"
    if (( ${mode:0:1} <= 7 &&
	  ${mode:1:1} <= 5 &&
	  ${mode:2:1} <= 5
       ))
    then
      echo -e "${NORMAL}RESULT:    ${BLD}$stat${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${RED}$stat${NORMAL}"
      fail=1
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}$file not found${NORMAL}"
  fi
done

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity9, $controlid, $stigid9, $ruleid9, $cci9, $datetime, ${GRN}PASSED, RHEL 8 audit tools are mode 0755 or less permissive.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity9, $controlid, $stigid9, $ruleid9, $cci9, $datetime, ${RED}FAILED, RHEL 8 audit tools are not mode 0755 or less permissive.${NORMAL}"
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

file10arr=("/sbin/auditctl" "/sbin/aureport" "/sbin/ausearch" "/sbin/autrace" "/sbin/auditd" "/sbin/rsyslogd" "/sbin/augenrules")

fail=0

datetime="$(date +%FT%H:%M:%S)"

for file in ${file10arr[@]}
do
  if [[ -f $file ]]
  then
    stat="$(stat -c "%U %n" $file)"
    owner="$(echo $stat | awk '{print $1}')"
    if [[ $owner == "root" ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}$stat${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${RED}$stat${NORMAL}"
      fail=1
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}$file not found${NORMAL}"
  fi
done

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity10, $controlid, $stigid10, $ruleid10, $cci10, $datetime, ${GRN}PASSED, RHEL 8 audit tools are owned by \"root\" to prevent any unauthorized access, deletion, or modification.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity10, $controlid, $stigid10, $ruleid10, $cci10, $datetime, ${RED}FAILED, RHEL 8 audit tools are not owned by \"root\" to prevent any unauthorized access, deletion, or modification.${NORMAL}"
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

file11arr=("/sbin/auditctl" "/sbin/aureport" "/sbin/ausearch" "/sbin/autrace" "/sbin/auditd" "/sbin/rsyslogd" "/sbin/augenrules")

fail=0

datetime="$(date +%FT%H:%M:%S)"

for file in ${file11arr[@]}
do
  if [[ -f $file ]]
  then
    stat="$(stat -c "%G %n" $file)"
    owner="$(echo $stat | awk '{print $1}')"
    if [[ $owner == "root" ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}$stat${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${RED}$stat${NORMAL}"
      fail=1
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}$file not found${NORMAL}"
  fi
done

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity11, $controlid, $stigid11, $ruleid11, $cci11, $datetime, ${GRN}PASSED, RHEL 8 audit tools are group owned by \"root\" to prevent any unauthorized access, deletion, or modification.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity11, $controlid, $stigid11, $ruleid11, $cci11, $datetime, ${RED}FAILED, RHEL 8 audit tools are not group owned by \"root\" to prevent any unauthorized access, deletion, or modification.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid12${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid12${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid12${NORMAL}"
echo -e "${NORMAL}CCI:       $cci12${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 12:   ${BLD}$title12a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title12b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title12c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity12${NORMAL}"

IFS='
'

file12="/etc/aide.conf"

fail=0

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file12 ]]
then
  aidecrypto="$(egrep '(\/usr\/sbin\/(audit|au))' $file12)"
  if [[ $aidecrypto ]]
  then
    for line in ${aidecrypto[@]}
    do
      if [[ $line =~ 'p+i+n+u+g+s+b+acl+xattrs+sha512' ]]
      then
        echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
      else
	echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
	fail=1
      fi
    done
  else
    echo -e "${NORMAL}RESULT:    ${RED}audit tools not listed in $file12${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}$file12 not found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity12, $controlid, $stigid12, $ruleid12, $cci12, $datetime, ${GRN}PASSED, RHEL 8 uses cryptographic mechanisms to protect the integrity of audit tools.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity12, $controlid, $stigid12, $ruleid12, $cci12, $datetime, ${RED}FAILED, RHEL 8 does not use cryptographic mechanisms to protect the integrity of audit tools.${NORMAL}"
fi

exit

