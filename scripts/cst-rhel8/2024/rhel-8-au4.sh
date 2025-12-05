#! /bin/bash

# AU-4 Audit Storage Capacity
#
# CONTROL: The organization allocates audit record storage capacity in accordance with
# [Assignment: organization-defined audit record storage requirements].

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

controlid="AU-4 Audit Storage Capacity"

title1a="RHEL 8 must label all off-loaded audit logs before sending them to the central log server."
title1b="Checking with 'grep \"name_format\" /etc/audit/auditd.conf."
title1c="Expecting: ${YLO}name_format = hostname
           Note: If the \"name_format\" option is not \"hostname\", \"fqd\", or \"numeric\", or the line is commented out, this is a finding."
cci1="CCI-001851"
stigid1="RHEL-08-030062"
severity1="CAT II"
ruleid1="SV-230394r627750_rule"
vulnid1="V-230394"

title2a="RHEL 8 must allocate an audit_backlog_limit of sufficient size to capture processes that start prior to the audit daemon."
title2b="Checking with:
           a. grub2-editenv list | grep audit
           b. grep audit /etc/default/grub"
title2c="Expecting: ${YLO}
           a. kernelopts=root=/dev/mapper/rhel-root ro crashkernel=auto resume=/dev/mapper/rhel-swap rd.lvm.lv=rhel/root rd.lvm.lv=rhel/swap rhgb quiet fips=1 audit=1 ${GRN}audit_backlog_limit=8192${YLO} boot=UUID=8d171156-cd61-421c-ba41-1c021ac29e82
           b. GRUB_CMDLINE_LINUX=${GRN}\"audit_backlog_limit=8192\"${YLO}
           NOTE: If the \"audit_backlog_limit\" entry does not equal \"8192\" or greater, is missing, or the line is commented out, this is a finding."${BLD}
cci2="CCI-001849"
stigid2="RHEL-08-030602"
severity2="CAT III"
ruleid2="SV-230469r792906_rule"
vulnid2="V-230469"

title3a="RHEL 8 must allocate audit record storage capacity to store at least one week of audit records, when audit records are not immediately sent to a central audit record storage facility."
title3b="Checking with:
           a. grep -iw log_file /etc/audit/auditd.conf
           b. df -h /var/log/audit/
           c. du -sh [audit_partition]"
title3c="Expecting: ${YLO}
           a. log_file = /var/log/audit/audit.log
           b. /dev/sda2 24G 10.4G 13.6G 43% /var/log/audit
           c. 1.8G /var/log/audit
           NOTE: If the audit records are not written to a partition made specifically for audit records (/var/log/audit is a separate partition), determine the amount of space being used by other files in the partition.
           NOTE: Check the size of the partition to which audit records are written (with the example being /var/log/audit/)
           NOtE: If the audit record partition is not allocated for sufficient storage capacity, this is a finding.
           NOTE: The partition size needed to capture a week of audit records is based on the activity level of the system and the total storage capacity available. Typically 10.0 GB of storage space for audit records should be sufficient."${BLD}
cci3="CCI-001849"
stigid3="RHEL-08-030660"
severity3="CAT II"
ruleid3="SV-230476r809313_rule"
vulnid3="V-230476"

title4a="The RHEL 8 audit records must be off-loaded onto a different system or storage media from the system being audited."
title4b="Checking with: grep @@ /etc/rsyslog.conf /etc/rsyslog.d/*.conf"
title4c="Expecting: ${YLO}etc/rsyslog.conf:*.* @@[remoteloggingserver]:[port]
           NOTE: If a remote server is not configured, or the line is commented out, ask the System Administrator to indicate how the audit logs are off-loaded to a different system or media. 
           NOTE: If there is no evidence that the audit logs are being off-loaded to another system or media, this is a finding."${BLD}
cci4="CCI-001851"
stigid4="RHEL-08-030690"
severity4="CAT II"
ruleid4="SV-230479r627750_rule"
vulnid4="V-230479"

title5a="RHEL 8 must take appropriate action when the internal event queue is full."
title5b="Checking with 'grep -i overflow_action /etc/audit/auditd.conf'."
title5c="Expecting: ${YLO}overflow_action = syslog
           NOTE: If the value of the \"overflow_action\" option is not set to \"syslog\", \"single\", \"halt\", or the line is commented out, ask the System Administrator to indicate how the audit logs are off-loaded to a different system or media.
           NOTE: If there is no evidence that the transfer of the audit logs being off-loaded to another system or media takes appropriate action if the internal event queue becomes full, this is a finding."${BLD}
cci5="CCI-001851"
stigid5="RHEL-08-030700"
severity5="CAT II"
ruleid5="SV-230480r627750_rule"
vulnid5="V-230480"

title6a="RHEL 8 must encrypt the transfer of audit records off-loaded onto a different system or media from the system being audited."
title6b="Checking with:
           a. grep -i '\$DefaultNetstreamDriver' /etc/rsyslog.conf /etc/rsyslog.d/*.conf'.
           b. grep -i '\$ActionSendStreamDriverMode' /etc/rsyslog.conf /etc/rsyslog.d/*.conf"
title6c="Expecting: ${YLO}
           a. /etc/rsyslog.conf:\$DefaultNetstreamDriver gtls
           b. /etc/rsyslog.conf:\$ActionSendStreamDriverMode 1
           NOTE: If the value of the \"\$DefaultNetstreamDriver\" option is not set to \"gtls\" or the line is commented out, this is a finding.
           NOTE: If the value of the \"\$ActionSendStreamDriverMode\" option is not set to \"1\" or the line is commented out, this is a finding.
           NOTE: If neither of the definitions above are set, ask the System Administrator to indicate how the audit logs are off-loaded to a different system or media. 
           NOTE: If there is no evidence that the transfer of the audit logs being off-loaded to another system or media is encrypted, this is a finding."${BLD}
cci6="CCI-001851"
stigid6="RHEL-08-030710 "
severity6="CAT II"
ruleid6="SV-230481r818840_rule"
vulnid6="V-230481"

title7a="RHEL 8 must authenticate the remote logging server for off-loading audit logs."
title7b="Checking with: 'grep -i '$ActionSendStreamDriverAuthMode' /etc/rsyslog.conf /etc/rsyslog.d/*.conf'."
title7c="Expecting: ${YLO}/etc/rsyslog.conf:\$ActionSendStreamDriverAuthMode x509/name
           NOTE: If the value of the "$ActionSendStreamDriverAuthMode" option is not set to "x509/name" or the line is commented out, ask the System Administrator to indicate how the audit logs are off-loaded to a different system or media. 
	   NOTE: If there is no evidence that the transfer of the audit logs being off-loaded to another system or media is encrypted, this is a finding."${BLD}
cci7="CCI-001851"
stigid7="RHEL-08-030720"
severity7="CAT II"
ruleid7="SV-230482r627750_rule"
vulnid7="V-230482"
 
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

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file1 ]]
then
   nformat="$(grep name_format $file1)"
   if [[ $nformat ]]
   then
      format="$(echo $nformat | awk -F= '{print tolower($2)}' | sed -e 's/^[[:space:]]*//')"
      if [[ $format == 'hostname' || $format == 'fqd' || $format == 'numeric' ]]
      then
         echo -e "${NORMAL}RESULT:    ${BLD}$nformat${NORMAL}"
         echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${GRN}PASSED, RHEL 8 labels all off-loaded audit logs before sending them to the central log server.${NORMAL}"
      else
         echo -e "${NORMAL}RESULT:    ${RED}$nformat${NORMAL}"
         echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci11, $datetime, ${RED}FAILED, RHEL 8 does not label all off-loaded audit logs before sending them to the central log server.${NORMAL}"
      fi
   else
      echo -e "${NORMAL}RESULT:    ${RED}'name_format' is not defined in $file1${NORMAL}"
      echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${RED}FAILED, RHEL 8 does not label all off-loaded audit logs before sending them to the central log server.${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${RED}$file1 not found${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, $datetime, ${RED}FAILED, RHEL 8 does not label all off-loaded audit logs before sending them to the central log server.${NORMAL}"
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

file2="/etc/default/grub"

fail=1
editenv=0
limit=0

datetime="$(date +%FT%H:%M:%S)"

grubbacklog="$(grub2-editenv list | grep audit)"
if [[ $grubbacklog ]]
then
  IFS=' '
  read -a fieldvals <<< ${grubbacklog[@]}
  for element in ${fieldvals[@]}
  do
    if [[ $element =~ "audit_backlog_limit" ]]
    then
      limit="$(echo $element | awk -F= '{print $2}')"
      if (( limit >= 8192 ))
      then
        echo -e "${NORMAL}RESULT:    ${BLD}a. $grubbacklog${NORMAL}"
        editenv=1
      else
        echo -e "${NORMAL}RESULT:    ${RED}a. $grubbacklog${NORMAL}"
      fi
    fi
  done
  IFS=$'\n'
else
  echo -e "${NORMAL}RESULT:    ${RED}b. \"audit_backlog_limit\" not defined in \"grub-editenv list\".${NORMAL}"
fi

if [[ -f $file2 ]]
then
  backloglimit="$(grep audit $file2)"
  if [[ $backloglimit ]]
  then
    IFS=' '
    read -a fieldvals <<< "${backloglimit}"
    for element in ${fieldvals[@]}
    do
      if [[ $element =~ "audit_backlog_limit" ]]
      then
        limit="$(echo $element | awk -F= '{print $2}')"
        if (( limit >= 8192 ))
        then
          echo -e "${NORMAL}RESULT:    ${BLD}b. $backloglimit${NORMAL}"
          limit=1
        else
          echo -e "${NORMAL}RESULT:    ${RED}b. $backloglimit${NORMAL}"
        fi
      fi
    done
    IFS=$'\n'
  else
    echo -e "${NORMAL}RESULT:    ${RED}b. \"audit_backlog_limit\" not defined in $file2${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}$file2 not found${NORMAL}"
fi

if [[ $editenv == 1 && $limit == 1 ]]
then
  fail=0
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${GRN}PASSED, RHEL 8 allocates an audit_backlog_limit of sufficient size to capture processes that start prior to the audit daemon.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${RED}FAILED, RHEL 8 does not allocate an audit_backlog_limit of sufficient size to capture processes that start prior to the audit daemon.${NORMAL}"
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

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file3 ]]
then
  logfile="$(grep -iw log_file $file3 | awk -F= '{print $2}' | sed -e 's/^[[:space:]]*//')"
  if [[ $logfile ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}a. $logfile${NORMAL}"
    partition="$(dirname $logfile)"
    if [[ $partition ]]
    then
      sizeused="$(df -h $partition | grep -v "Filesystem")"
      echo -e "${NORMAL}RESULT:    ${BLD}b. $sizeused${NORMAL}"
      utilization="$(du -sh $partition)"
      percentused="$(echo $sizeused | awk '{print $5}' | sed 's/\%//g')"
      if (( $percentused <= 75 ))
      then
        echo -e "${NORMAL}RESULT:    ${BLD}c. $utilization${NORMAL}"
	fail=0
      else
	echo -e "${NORMAL}RESULT:    ${RED}c. $utilization${NORMAL}"
      fi
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}a. \"log_file\" not defined in $file3${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}a. $file3 not found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${GRN}PASSED, RHEL 8 allocates sufficient audit record storage capacity to store at least one week of audit records, when audit records are not immediately sent to a central audit record storage facility.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${RED}FAILED, RHEL 8 does not allocate sufficient audit record storage capacity to store at least one week of audit records, when audit records are not immediately sent to a central audit record storage facility.${NORMAL}"
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

file4="/etc/rsyslog.conf"
dir4="/etc/rsyslog.d"

fail=0

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file4 ]]
then
  remote="$(grep @@ $file4 $dir4/*)"
  if [[ $remote ]]
  then
    for line in ${remote[@]}
    do
      filename="$(echo $line | awk -F: '{print $1}')"
      collector="$(echo $line | awk -F: '{print $2}')"
      if [[ ${collector:0:1} != "#" ]]
      then
	loghost="$(echo $collector | awk -F @@ '{print $2}' | awk '{print $1}')"
	echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
	loghoststatus="$(systemctl status rsyslog | grep $loghost)"
	for line in ${loghoststatus[@]}
	do
	  if [[ $line =~ 'cannot resolve hostname' ]]
	  then
	    echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
	    fail=1
	  else
	    echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
	  fi
	done
      else
	echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
      fi
    done
  else
    echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}$file4 not found.${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${GRN}PASSED, The RHEL 8 audit records are off-loaded onto a different system or storage media from the system being audited.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${RED}FAILED, The RHEL 8 audit records are not off-loaded onto a different system or storage media from the system being audited.${NORMAL}"
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
   overflowaction="$(grep -i overflow_action $file5)"
   if [[ $overflowaction ]]
   then
      if ! [[ ${overflowaction:0:1} == '#' ]]
      then
         action="$(echo $overflowaction | awk -F= '{print tolower($2)}' | sed 's/ //g')"
         if [[ $action == 'syslog' || $action == 'single' || $action == 'halt' ]]
         then
            echo -e "${NORMAL}RESULT:    ${BLD}$overflowaction${NORMAL}"
            fail=0
         else
            echo -e "${NORMAL}RESULT:    ${RED}$overflowaction${NORMAL}"
         fi
      else
         echo -e "${NORMAL}RESULT:    ${RED}$overflowaction${NORMAL}"
      fi
   else
      echo -e "${NORMAL}RESULT:    ${RED}\"overflow_action\" is not defined in $file5${NORMAL}"
   fi
   if (( $fail == 0 ))
   then
      echo -e "${NORMAL}$hostname, $severity5, $controlid, $stigid5, $ruleid5, $cci5, $datetime, ${GRN}PASSED, RHEL 8 takes appropriate action when the internal event queue is full.${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity5, $controlid, $stigid5, $ruleid5, $cci5, $datetime, ${RED}FAILED, RHEL 8 does not take appropriate action when the internal event queue is full.${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${RED}$file5 not found${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity5, $controlid, $stigid5, $ruleid5, $datetime, ${RED}FAILED, RHEL 8 does not take appropriate action when the internal event queue is full.${NORMAL}"
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

file6="/etc/rsyslog.conf"
dir6="/etc/rsyslog.d"

driver=0
fail=1

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file6 ]]
then
   nsdriver="$(grep -i '$DefaultNetstreamDriver' $file6 $dir6/*.conf)"
   if [[ $nsdriver ]]
   then
      driver="$(echo $nsdriver | awk -F: '{print $2}')"
      if [[ ! ${driver:0:1} == '#' ]]
      then
         echo -e "${NORMAL}RESULT:    ${BLD}a. $nsdriver${NORMAL}"
         driver=1
       else
         echo -e "${NORMAL}RESULT:    ${RED}a. $nsdriver${NORMAL}"
      fi
   else
      echo -e "${NORMAL}RESULT:    ${RED}\"DefaultNetstreamDriver\" is not defined.${NORMAL}"
   fi
   drivermode="$(grep -i '$ActionSendStreamDriverMode' $file6 $dir6/*.conf)"
   if [[ $drivermode ]]
   then
     mode="$(echo $drivermode | awk -F: '{print $2}')"
     if ! [[ ${mode:0:1} == "#" ]]
     then
       echo -e "${NORMAL}RESULT:    ${BLD}b. $drivermode${NORMAL}"
       mode=1
     else
       echo -e "${NORMAL}RESULT:    ${RED}b. $drivermode${NORMAL}"
     fi
   else
     echo -e "${NORMAL}RESULT:    ${RED}\"ActionSendStreamDriverMode\" is not defined.${NORMAL}"
   fi

   if [[ $driver == 1 && $mode == 1 ]]
   then
     fail=0
   fi

   if (( $fail == 0 ))
   then
      echo -e "${NORMAL}$hostname, $severity6, $controlid, $stigid6, $ruleid6, $cci6, $datetime, ${GRN}PASSED, RHEL 8 encrypts the transfer of audit records off-loaded onto a different system or media from the system being audited.${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity6, $controlid, $stigid6, $ruleid6, $cci6, $datetime, ${RED}FAILED, RHEL 8 does not encrypt the transfer of audit records off-loaded onto a different system or media from the system being audited.${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${RED}$file6 not found${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity6, $controlid, $stigid6, $ruleid6, $cci6, $datetime, ${RED}FAILED, Audit Log Off-Loading: File transfer encryption is not enabled${NORMAL}"
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

file7="/etc/rsyslog.conf"
dir7="/etc/rsyslog.d"

fail=1

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file7 ]]
then
  x509name="$(grep -i '$ActionSendStreamDriverAuthMode' $file7 $dir7/*.conf)"
  if [[ $x509name ]]
  then
    setting="$(echo $x509name | awk '{print $2}')"
    if [[ $setting == 'x509/name' ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}$x509name${NORMAL}"
      fail=0
    else
      echo -e "${NORMAL}RESULT:    ${RED}$x509name${NORMAL}"
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}\"ActionSendStreamDriverAuthMode\" is not defined${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}$file7 not found.${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity7, $controlid, $stigid7, $ruleid7, $cci7, $datetime, ${GRN}PASSED, RHEL 8 authenticates the remote logging server for off-loading audit logs.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity7, $controlid, $stigid7, $ruleid7, $cci7, $datetime, ${RED}FAILED, RHEL 8 does not authenticate the remote logging server for off-loading audit logs.${NORMAL}"
fi

exit
