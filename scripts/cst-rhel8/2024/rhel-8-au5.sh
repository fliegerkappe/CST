#! /bin/bash

# AU-5 Response to Audit Processing Failures

# CONTROL: The information system:
# a. Alerts [Assignment: organization-defined personnel or roles] in the event of an
#    audit processing failure; and
# b. Takes the following additional actions: [Assignment: organization-defined actions
#    to be taken (e.g. shut down information system overwrite oldest audit records
#    stop generating audit records)].

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

controlid="AU-5 Response to Audit Processing Failures"

title1a="The RHEL 8 System Administrator (SA) and Information System Security Officer (ISSO) (at a minimum) must be alerted of an audit processing failure event."
title1b="Checking with: 'grep action_mail_acct /etc/audit/auditd.conf'."
title1c="Expecting: ${YLO}action_mail_acct = root
           NOTE: If the value of the \"action_mail_acct\" keyword is not set to \"root\" and/or other accounts for security personnel, the \"action_mail_acct\" keyword is missing, or the retuned line is commented out, ask the system administrator to indicate how they and the ISSO are notified of an audit process failure.  If there is no evidence of the proper personnel being notified of an audit processing failure, this is a finding."${BLD}
cci1="CCI-000139"
stigid1="RHEL-08-030020"
severity1="CAT II"
ruleid1="SV-230388r627750_rule"
vulnid1="V-230388"

title2a="The RHEL 8 Information System Security Officer (ISSO) and System Administrator (SA) (at a minimum) must have mail aliases to be notified of an audit processing failure."
title2b="Checking with: 'grep \"postmaster:\\s*root\$\" /etc/aliases'."
title2c="Expecting: ${YLO}postmaster: root
           NOTE: If the command does not return a line, or the line is commented out, ask the system administrator to indicate how they and the ISSO are notified of an audit process failure.  If there is no evidence of the proper personnel being notified of an audit processing failure, this is a finding."${BLD}
cci2="CCI-000139"
stigid2="RHEL-08-030030"
severity2="CAT II"
ruleid2="SV-230389r627750_rule"
vulnid2="V-230389"

title3a="The RHEL 8 audit system must take appropriate action when an audit processing failure occurs."
title3b="Checking with: 'grep disk_error_action /etc/audit/auditd.conf'."
title3c="Expecting: ${YLO}disk_error_action = HALT
           NOTE: If the value of the \"disk_error_action\" option is not \"SYSLOG\", \"SINGLE\", or \"HALT\", or the line is commented out, ask the system administrator to indicate how the system takes appropriate action when an audit processing failure occurs.  If there is no evidence of appropriate action, this is a finding."${BLD}
cci3="CCI-000140"
stigid3="RHEL-08-030040"
severity3="CAT II"
ruleid3="SV-230390r627750_rule"
vulnid3="V-230390"

title4a="The RHEL 8 audit system must take appropriate action when the audit storage volume is full."
title4b="Checking with: 'grep disk_full_action /etc/audit/auditd.conf'."
title4c="Expecting: ${YLO}disk_full_action = HALT
           NOTE: If the value of the \"disk_full_action\" option is not \"SYSLOG\", \"SINGLE\", or \"HALT\", or the line is commented out, ask the system administrator to indicate how the system takes appropriate action when an audit storage volume is full.  If there is no evidence of appropriate action, this is a finding."${BLD}
cci4="CCI-000140"
stigid4="RHEL-08-030060"
severity4="CAT II"
ruleid4="SV-230392r627750_rule"
vulnid4="V-230392"

title5a="RHEL 8 must take action when allocated audit record storage volume reaches 75 percent of the repository maximum audit record storage capacity."
title5b="Checking with:
           a. grep -iw log_file /etc/audit/auditd.conf
           b. df -h /var/log/audit/ (or the otherwise designated log partition)
           c. grep -i ^space_left /etc/audit/auditd.conf
           d. grep -w ^space_left_action /etc/audit/auditd.conf"
title5c="Expecting: ${YLO}
           a. /var/log/audit/audit.log
           b. a value that represents 25% of size of the partition where the audit records are being written.
           c. space_left = 25%
           d. space_left_action = email
           NOTE: If the value of the \"space_left\" keyword is not set to \"25%\" or if the line is commented out, ask the System Administrator to indicate how the system is providing real-time alerts to the SA and ISSO.
           NOTE: If there is no evidence that real-time alerts are configured on the system, this is a finding."${BLD}
cci5="CCI-001855"
stigid5="RHEL-08-030730"
severity5="CAT II"
ruleid5="SV-230483r744014_rule"
vulnid5="V-230483"

title6a="RHEL 8 must notify the System Administrator (SA) and Information System Security Officer (ISSO) (at a minimum) when allocated audit record storage volume 75 percent utilization."
title6b="Checking with:
           a. grep -iw log_file /etc/audit/auditd.conf
	   b. df -h /var/log/audit/ (or the otherwise designated log partition)
	   c. grep -i ^space_left /etc/audit/auditd.conf
	   d. grep -w ^space_left_action /etc/audit/auditd.conf" 
title6c="Expecting: ${YLO}
           a. /var/log/audit/audit.log
           b. a value that represents 25% of size of the partition where the audit records are being written.
	   c. space_left = 25%
	   d. space_left_action = email
	   NOTE: If the value of the \"space_left_action\" is not set to \"email\", or if the line is commented out, ask the System Administrator to indicate how the system is providing real-time alerts to the SA and ISSO.
	   NOTE: If there is no evidence that real-time alerts are configured on the system, this is a finding."${BLD}
cci6="CCI-001855"
stigid6="RHEL-08-030731"
severity6="CAT II"
ruleid6="SV-244543r743878_rule"
vulnid6="V-244543"

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
  mailacct="$(grep action_mail_acct $file1)"
  if [[ $mailacct ]]
  then
    acctname="$(echo $mailacct | awk -F= '{print $2}' | sed 's/ //g')"
    if [[ $acctname == "root" ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}$mailacct${NORMAL}"
      fail=0
    else
      echo -e "${NORMAL}RESULT:    ${CYN}$mailacct${NORMAL}"
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}\"action_mail_acct\" is not defined in $file1${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}$file1 not found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${GRN}PASSED, The RHEL 8 System Administrator (SA) and Information System Security Officer (ISSO) (at a minimum) are alerted of an audit processing failure event.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${CYN}VERIFY, The RHEL 8 System Administrator (SA) and Information System Security Officer (ISSO) (at a minimum) are alerted of an audit processing failure event.${NORMAL}"
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

file2="/etc/aliases"

fail=1

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file2 ]]
then
  alias="$(grep "postmaster:\s*root$" $file2)"
  if [[ $alias ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}$alias${NORMAL}"
    fail=0
  else
    echo -e "${NORMAL}RESULT:    ${BLD}$alias${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}$file2 not found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${GRN}PASSED, The RHEL 8 Information System Security Officer (ISSO) and System Administrator (SA) (at a minimum) have mail aliases to be notified of an audit processing failure.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${RED}FAILED, The RHEL 8 Information System Security Officer (ISSO) and System Administrator (SA) (at a minimum) do not have mail aliases to be notified of an audit processing failure.${NORMAL}"
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
  deaction="$(grep disk_error_action $file3)"
  if [[ $deaction ]]
  then
    deactionval="$(echo $deaction | awk -F= '{print toupper($2)}' | sed 's/ //g')"
    if [[ $deactionval == "SYSLOG" || $deactionval == "SINGLE" || $deactionval == "HALT" ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}$deaction${NORMAL}"
      fail=0
    else
      echo -e "${NORMAL}RESULT:    ${RED}$deaction${NORMAL}"
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}\"disk_error_action\" is not defined in $file3${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}$file3 not found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${GRN}PASSED, The RHEL 8 audit system takes appropriate action when an audit processing failure occurs.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${RED}FAILED, The RHEL 8 audit system does not take appropriate action when an audit processing failure occurs.${NORMAL}"
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
  dfaction="$(grep disk_full_action $file4)"
  if [[ $dfaction ]]
  then
    dfactionval="$(echo $dfaction | awk -F= '{print toupper($2)}' | sed 's/ //g')"
    if [[ $dfactionval == "SYSLOG" || $dfactionval == "SINGLE" || $dfactionval == "HALT" ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}$dfaction${NORMAL}"
      fail=0
    else
      echo -e "${NORMAL}RESULT:    ${RED}$dfaction${NORMAL}"
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}\"disk_full_action\" is not defined in $file4${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}$file4 not found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${GRN}PASSED, The RHEL 8 audit system takes appropriate action when the audit storage volume is full.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${RED}FAILED, The RHEL 8 audit system does not take appropriate action when the audit storage volume is full.${NORMAL}"
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
aupart=""

v=0
vla=0
found=0

fail=1

logpath="$(grep -iw log_file $file5 | awk -F= '{print $2}' | sed 's/ //g')"
logfile="$(echo $logpath | awk -F/ '{print ($NF)}')"
logdir="$(dirname $logpath)"

datetime="$(date +%FT%H:%M:%S)"

echo "-------------------------------------------------"
partitions="$(df -hl)"
for line in ${partitions[@]}
do
   p="$(echo $line | awk '{print $6}')"

   if [[ $p == $logdir ]]
   then
     echo -e "${NORMAL}RESULT:    ${GRN}$line${NORMAL}"
     spaceused="$(echo $line | awk '{print $3}')"
     suset="$(echo $line | awk '{print $3//\ /}')"
     sumult="$(echo ${spaceused: -1})"
   else
     echo -e "${NORMAL}RESULT:    $line${NORMAL}"
   fi
done
echo "-------------------------------------------------"

if [[ -f $file5 ]]
then

  slset="$(grep -w '^space_left ' $file5)"
  slsize="$(echo $slset | awk -F= '{print $2//\ /}')"

  if [[ -d $logdir ]]
  then
    logpartsz="$(df -hl | grep $logdir | awk '{print $2}')"
    szmult="$(echo ${logpartsz: -1})"
    aupartsz="$(df -hl | grep $logdir | awk '{print $2//\ /}')"

    case $szmult in
      'T')
         let "sz = $aupartsz * 1000000"
         ;;
      'G')
         let "sz = $aupartsz * 1000"
         ;;
      'M')
         let "sz = $aupartsz"
         ;;
    esac

    lpavailsz="$(df -hl | grep $logdir | awk '{print $4}')"
    avmult="$(echo ${lpavailsz: -1})"
    availsz="$(df -hl | grep $logdir | awk '{print $4//\ /}')"

    case $avmult in
      'T')
         let "avsz = $availsz * 1000000"
         ;;
      'G')
         let "avsz = $availsz * 1000"
         ;;
      'M')
         let "avsz = $availsz"
         ;;
    esac

    case $sumult in
      'T')
         let "susz = $suset * 1000000"
         ;;
      'G')
         let "susz = $suset * 1000"
         ;;
      'M')
         let "susz = $suset"
         ;;
    esac

    calc(){ awk "BEGIN { print "$*" }"; }
    warnat=`calc $slsize/100*$sz` 

    let "available = $sz - $susz"

    echo -e "${NORMAL}RESULT:    ${BLD}The log partition is:      $logdir${NORMAL}"
    echo -e "${NORMAL}RESULT:    ${BLD}The log partition size is: $sz MB${NORMAL}"
    echo -e "${NORMAL}RESULT:    ${BLD}The space used size is:    $susz MB${NORMAL}"
    if (( $avsz > $warnat ))
    then
      echo -e "${NORMAL}RESULT:    ${BLD}The space available is:    $available MB${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${RED}The space available is:    $available MB${NORMAL}"
    fi

    if (( $slsize == 25 ))
    then
      echo -e "${NORMAL}RESULT:    ${GRN}The space_left setting is: \"$slset\" ($warnat MB)${NORMAL}"
      fail=0
    else
      echo -e "${NORMAL}RESULT:    ${RED}The space_left setting is: \"$slset\" ($warnat MB)${NORMAL}"
    fi

    slaction="$(grep -w space_left_action $file5)"
    slactionval="$(echo $slaction | awk -F= '{print $2}' | sed 's/ //g')"

    if [[ $slactionval == "email" ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}$slaction${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${RED}$slaction${NORMAL}"
    fi

  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}$file5 not found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity5, $controlid, $stigid5, $ruleid5, $cci5, $datetime, ${GRN}PASSED, RHEL 8 takes action when allocated audit record storage volume reaches 75 percent of the repository maximum audit record storage capacity.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity5, $controlid, $stigid5, $ruleid5, $cci5, $datetime, ${RED}FAILED, RHEL 8 does not take action when allocated audit record storage volume reaches 75 percent of the repository maximum audit record storage capacity.${NORMAL}"
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
aupart=""

v=0
vla=0
found=0

fail=1

logpath="$(grep -iw log_file $file6 | awk -F= '{print $2}' | sed 's/ //g')"
logfile="$(echo $logpath | awk -F/ '{print ($NF)}')"
logdir="$(dirname $logpath)"

datetime="$(date +%FT%H:%M:%S)"

echo "-------------------------------------------------"
partitions="$(df -hl)"
for line in ${partitions[@]}
do
   p="$(echo $line | awk '{print $6}')"

   if [[ $p == $logdir ]]
   then
     echo -e "${NORMAL}RESULT:    ${GRN}$line${NORMAL}"
     spaceused="$(echo $line | awk '{print $3}')"
     suset="$(echo $line | awk '{print $3//\ /}')"
     sumult="$(echo ${spaceused: -1})"
   else
     echo -e "${NORMAL}RESULT:    $line${NORMAL}"
   fi
done
echo "-------------------------------------------------"

if [[ -f $file6 ]]
then

  slset="$(grep -w '^space_left ' $file6)"
  slsize="$(echo $slset | awk -F= '{print $2//\ /}')"

  if [[ -d $logdir ]]
  then
    logpartsz="$(df -hl | grep $logdir | awk '{print $2}')"
    szmult="$(echo ${logpartsz: -1})"
    aupartsz="$(df -hl | grep $logdir | awk '{print $2//\ /}')"

    case $szmult in
      'T')
         let "sz = $aupartsz * 1000000"
         ;;
      'G')
         let "sz = $aupartsz * 1000"
         ;;
      'M')
         let "sz = $aupartsz"
         ;;
    esac

    lpavailsz="$(df -hl | grep $logdir | awk '{print $4}')"
    avmult="$(echo ${lpavailsz: -1})"
    availsz="$(df -hl | grep $logdir | awk '{print $4//\ /}')"

    case $avmult in
      'T')
         let "avsz = $availsz * 1000000"
         ;;
      'G')
         let "avsz = $availsz * 1000"
         ;;
      'M')
         let "avsz = $availsz"
         ;;
    esac

    case $sumult in
      'T')
         let "susz = $suset * 1000000"
         ;;
      'G')
         let "susz = $suset * 1000"
         ;;
      'M')
         let "susz = $suset"
         ;;
    esac

    calc(){ awk "BEGIN { print "$*" }"; }
    warnat=`calc $slsize/100*$sz` 

    let "available = $sz - $susz"

    echo -e "${NORMAL}RESULT:    ${BLD}The log partition is:      $logdir${NORMAL}"
    echo -e "${NORMAL}RESULT:    ${BLD}The log partition size is: $sz MB${NORMAL}"
    echo -e "${NORMAL}RESULT:    ${BLD}The space used size is:    $susz MB${NORMAL}"
    if (( $avsz > $warnat ))
    then
      echo -e "${NORMAL}RESULT:    ${BLD}The space available is:    $available MB${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${RED}The space available is:    $available MB${NORMAL}"
    fi
    echo -e "${NORMAL}RESULT:    ${BLD}The space_left setting is: \"$slset\" ($warnat MB)${NORMAL}"


    slaction="$(grep -w space_left_action $file6)"
    slactionval="$(echo $slaction | awk -F= '{print $2}' | sed 's/ //g')"

    if [[ $slactionval == "email" ]]
    then
      echo -e "${NORMAL}RESULT:    ${GRN}$slaction${NORMAL}"
      fail=0
    else
      echo -e "${NORMAL}RESULT:    ${RED}$slaction${NORMAL}"
    fi

  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}$file6 not found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity6, $controlid, $stigid6, $ruleid6, $cci6, $datetime, ${GRN}PASSED, RHEL 8 notifies the System Administrator (SA) and Information System Security Officer (ISSO) (at a minimum) when allocated audit record storage volume 75 percent utilization.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity6, $controlid, $stigid6, $ruleid6, $cci6, $datetime, ${RED}FAILED, RHEL 8 does not notify the System Administrator (SA) and Information System Security Officer (ISSO) (at a minimum) when allocated audit record storage volume 75 percent utilization.${NORMAL}"
fi

exit
