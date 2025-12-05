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

stig="Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Version 3, Release: 10 Benchmark Date: 26 Jan 2023"

hostname="$(uname -n)"

if [[ -f /etc/redhat-release ]]
then
   os="$(cat /etc/redhat-release)"
else
   os="OS not defined"
fi

prog="$(basename $0)"

controlid="AU-5 Response to Audit Processing Failures"

title1a="The Red Hat Enterprise Linux operating system must shut down upon audit processing failure, unless availability is an overriding concern. If availability is a concern, the system must alert the designated staff (System Administrator [SA] and Information System Security Officer [ISSO] at a minimum) in the event of an audit processing failure."
title1b="Checking with 'auditctl -s | grep -i 'fail'."
title1c="Expecting:${YLO}
           failure 2 (or failure 1 if documented)
           Note: If the value of \"failure\" is set to \"2\", the system is configured to panic (shut down) in the event of an auditing failure. If the value of \"failure\" is set to \"1\", the system will not shut down and instead will record the audit failure in the kernel log. If the system is configured as per requirement RHEL-07-031000, the kernel log will be sent to a log aggregation server and generate an alert.
           Note: If the \"failure\" setting is set to any value other than \"1\" or \"2\", this is a finding.
           Note: If the \"failure\" setting is not set, this is a CAT I finding.
           Note: If the \"failure\" setting is set to \"1\" but the availability concern is not documented or there is no monitoring of the kernel log, this should be downgraded to a CAT III finding."${BLD}
cci1="CCI-000139"
stigid1="RHEL-07-030010"
severity1="CAT II"
ruleid1="SV-204504r603261_rule"
vulnid1="V-204504"

title2a="The Red Hat Enterprise Linux operating system must initiate an action to notify the System Administrator (SA) and Information System Security Officer ISSO, at a minimum, when allocated audit record storage volume reaches 75% of the repository maximum audit record storage capacity."
title2b="Checking with 'grep -iw log_file /etc/audit/auditd.conf' then df -h /var/log/audit/
                   then 'grep -i space_left /etc/audit/auditd.conf'."
title2c="Expecting:${YLO}
           \"25%\" (including the \"%\" percent sign) or a numeric value that represents 25% of the total size (in Megabytes) of the partition the audit records are being written to.
           Note: Determine what the threshold is for the system to take action when 75 percent of the repository maximum audit record storage capacity is reached: (25% 'SPACE_LEFT') 
           Note: If the value of the \"space_left\" keyword is not set to \"25%\" or a numeric value that represents 25 percent of the total partition size, this is a finding."${BLD}
cci2="CCI-001855"
stigid2="RHEL-07-030330"
severity2="CAT II"
ruleid2="SV-204513r714112_rule"
vulnid2="V-204513"

title3a="The Red Hat Enterprise Linux operating system must immediately send a notification via email when the threshold for the repository maximum audit record storage capacity is reached."
title3b="Checking with 'grep -i space_left_action /etc/audit/auditd.conf'."
title3c="Expecting:${YLO}
           space_left_action = email
           Note: If the value of the \"space_left_action\" keyword is not set to \"email\", this is a finding."${BLD}
cci3="CCI-001855"
stigid3="RHEL-07-030340"
severity3="CAT II"
ruleid3="SV-204514r603261_rule"
vulnid3="V-204514"

title4a="The Red Hat Enterprise Linux operating system must immediately notify the System Administrator (SA) and Information System Security Officer (ISSO) (at a minimum) when the threshold for the repository maximum audit record storage capacity is reached."
title4b="Checking with 'grep -i action_mail_acct /etc/audit/auditd.conf'."
title4c="Expecting:${YLO}
           action_mail_acct = root
           Note: If the value of the \"action_mail_acct\" keyword is not set to \"root\" and other accounts for security personnel, this is a finding."${BLD}
cci4="CCI-001855"
stigid4="RHEL-07-030350"
severity4="CAT II"
ruleid4="SV-204515r603261_rule"
vulnid4="V-204515"

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

aulvl="$(auditctl -s | grep -i 'fail')"
fail=0

if [[ $aulvl ]]
then
   failval="$(echo $aulvl | awk '{print $2}')"
   if (( $failval == 2 ))
   then
      echo -e "${NORMAL}RESULT:    ${BLD}$aulvl (panic: shutdown)${NORMAL}"
   elif (( $failval == 1 ))
   then
      echo -e "${NORMAL}RESULT:    ${CYN}$aulvl (log: failure to log)${NORMAL}"
      fail=1
   else
      echo -e "${NORMAL}RESULT:    ${RED}$aulvl (other)${NORMAL}"
      fail=2
   fi

   datetime="$(date +%FT%H:%M:%S)"

   if [[ $fail == 0 ]]
   then
      echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${GRN}PASSED, Audit Failure ($aulvl): The operating system shuts down upon audit processing failure${NORMAL}"
   elif (( $fail == 1 ))
   then
      echo -e "${NORMAL}$hostname, CAT III, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${CYN}VERIFY, Audit Failure ($aulvl): The operating system alerts the designated staff (System Administrator [SA] and Information System Security Officer [ISSO] at a minimum) in the event of an audit processing failure.${NORMAL}"
   else
       echo -e "${NORMAL}$hostname, CAT I, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${RED}FAILED, Audit Failure: The operating ststem is not configured to either shutdown or alert the designated staff (System Administrator [SA] and Information System Security Officer [ISSO] at a minimum) in the event of an audit processing failure.${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${RED}The 'failure' setting is not configured (CAT I)${NORMAL}"
   echo -e "${NORMAL}$hostname, CAT I, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${RED}FAILED, Audit Failure: The operating ststem is not configured to either shutdown or alert the designated staff (System Administrator [SA] and Information System Security Officer [ISSO] at a minimum) in the event of an audit processing failure.${NORMAL}"
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

auconf="$(find /etc -noleaf -name auditd.conf)"
if [[ -f $auconf ]]
then
   logfile="$(grep ^log_file $auconf | awk -F= '{print $2}' | sed 's/^ //')"
   slset="$(grep '^space_left ' $auconf)"
   slsz="$(echo $slset | awk -F= '{print $2//\ /}')"

   if [[ $slsz == "25%" ]]
   then
      echo -e "${NORMAL}RESULT:    ${BLD}$slset${NORMAL}"
      fail=0
   else
      echo -e "${NORMAL}RESULT:    ${RED}$slset${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${RED}\"auditd.conf\" not found${NORMAL}"
fi

datetime="$(date +%FT%H:%M:%S)"

if [[ $fail == 0 ]]
then
   echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${GRN}PASSED, The operating system initiates an action when allocated audit record storage volume reaches 75% of the repository maximum audit record storage capacity.${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${RED}FAILED, The operating system does not initiate an action when allocated audit record storage volume reaches 75% of the repository maximum audit record storage capacity.${NORMAL}"
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

if [[ -f $file3 ]]
then

   slaction="$(grep -i ^space_left_action $file3 | grep -v '^#')"

   if [[ $slaction ]]
   then
      for line in ${slaction[@]}
      do

         slactionval="$(echo $line| awk -F= '{print $2}' | sed 's/^ //')"

         if [[ $slactionval == 'email' ]]
         then
            echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
            fail=0
         else
            echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
         fi
      done
   else
      echo -e "${NORMAL}RESULT:    ${RED}\"space_left_action\" not defined in $file3${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${RED}$file3 not found${NORMAL}"
fi

datetime="$(date +%FT%H:%M:%S)"

if [[ $fail == 0 ]]
then
   echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${GRN}PASSED, The operating system immediately sends a notification via email when the threshold for the repository maximum audit record storage capacity is reached.${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${RED}FAILED, The operating system does not immediately send a notification via email when the threshold for the repository maximum audit record storage capacity is reached.${NORMAL}"
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

if [[ -f $file4 ]]
then

   actionma="$(grep -i '^action_mail_acct' $file4)"

   if [[ $actionma ]]
   then
      for line in ${actionma[@]}
      do

         actionmaval="$(echo $line| awk -F= '{print $2}' | sed 's/^ //')"

         if [[ $actionmaval == 'root' ]]
         then
            echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
            fail=0
         else
            echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
         fi
      done
   else
      echo -e "${NORMAL}RESULT:    ${RED}\"action_mail_acct\" is not defined in $file4${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${RED}$file4 does not exist${NORMAL}"
fi

datetime="$(date +%FT%H:%M:%S)"

if [[ $fail == 0 ]]
then
   echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${GRN}PASSED, The operating system immediately notifies the System Administrator (SA) and Information System Security Officer (ISSO) (at a minimum) when the threshold for the repository maximum audit record storage capacity is reached.${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${RED}FAILED, The operating system does not immediately notify the System Administrator (SA) and Information System Security Officer (ISSO) (at a minimum) when the threshold for the repository maximum audit record storage capacity is reached.${NORMAL}"
fi

exit
