#! /bin/bash

# AC-2 Account Management
#
# CONTROL: The organization:
# a. Identifies and selects the following types of information system accounts to
#    support organizational missions/business functions: [Assignment: organization-
#    defined information system account types];
# b. Assigns account managers for information system accounts;
# c. Establishes conditions for group and role membership;
# d. Specifies authorized users of the information system, group and role membership,
#    and access authorizations (i.e., privileges) and other attributes (as required)
#    for each account;
# e. Requires approvals by [Assignment: organization-defined personnel or roles]
#    for requests to create information system accounts;
# f. Creates, enables, modifies, disables, and removes information system accounts
#    in accordance with [Assignment: organization-defined procedures or conditions];
# g. Monitors the use of, information system accounts;
# h. Notifies account managers:
#    1. When accounts are no longer required;
#    2. When users are terminated or transferred; and
#    3. When individual information system usage or need-to-know changes;
# i. Authorizes access to the information system based on:
#    1. A valid access authorization;
#    2. Intended system usage; and
#    3. Other attributes as required by the organization or associated missions/business
#       functions;
# j. Reviews accounts for compliance with account management requirements [Assignment: 
#    organization-defined frequency]; and
# k. Establishes a process for reissuing shared/group account credentials (if deployed)
#    when individuals are removed from the group.

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

controlid="AC-2 Account Management"

title1a="The Red Hat Enterprise Linux operating system must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/passwd."
title1b="Checking with 'grep /etc/passwd /etc/audit/audit.rules"
title1c="Expecting: ${YLO}-w /etc/passwd -p wa -k identity
           Note: If the command does not return a line, or the line is commented out, this is a finding.${BLD}"
cci1="CCI-000018"
stigid1="RHEL-07-030870"
severity1="CAT II"
ruleid1="SV-204564r603261_rule"
vulnid1="V-204564"

title2a="The Red Hat Enterprise Linux operating system must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/group."
title2b="Checking with 'grep /etc/group /etc/audit/audit.rules."
title2c="Expecting: ${YLO}-w /etc/group -p wa -k identity
           Note: If the command does not return a line, or the line is commented out, this is a finding."${BLD}
cci2="CCI-000018"
stigid2="RHEL-07-030871"
severity2="CAT II"
ruleid2="SV-204565r603261_rule"
vulnid2="V-204565"

title3a="The Red Hat Enterprise Linux operating system must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/gshadow."
title3b="Checking with 'grep /etc/gshadow /etc/audit/audit.rules."
title3c="Expecting: ${YLO}-w /etc/gshadow -p wa -k identity
           Note: If the command does not return a line, or the line is commented out, this is a finding."${BLD}
cci3="CCI-000018"
stigid3="RHEL-07-030872"
severity3="CAT II"
ruleid3="SV-204566r603261_rule"
vulnid3="V-204566"

title4a="The Red Hat Enterprise Linux operating system must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/shadow."
title4b="Checking with 'grep /etc/shadow /etc/audit/audit.rules."
title4c="Expecting: ${YLO}-w /etc/shadow -p wa -k identity
           Note: If the command does not return a line, or the line is commented out, this is a finding."${BLD}
cci4="CCI-000018"
stigid4="RHEL-07-030873"
severity4="CAT II"
ruleid4="SV-204567r603261_rule"
vulnid4="V-204567"

title5a="The Red Hat Enterprise Linux operating system must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/opasswd."
title5b="Checking with 'grep /etc/security/opasswd /etc/audit/audit.rules."
title5c="Expecting: -w /etc/security/opasswd -p wa -k identity
           Note: If the command does not return a line, or the line is commented out, this is a finding."
cci5="CCI-000018"
stigid5="RHEL-07-030874"
severity5="CAT II"
ruleid5="SV-204568r744155_rule"
vulnid5="V-204568"

title6a="The Red Hat Enterprise Linux operating system emergency accounts must be automatically removed or disabled after the crisis is resolved or within 72 hours."
title6b="Checking with 'chage <system_account_name>' (using a system account from /etc/passwd)"
title6c="Expecting: ${YLO}(if applicable, verify emergency accounts have been provisioned with an expiration date of 72 hours)
           Note: If any emergency accounts have no expiration date set or do not expire within 72 hours, this is a finding."${BLD}
cci6="CCI-001682"
stigid6="RHEL-07-010271"
severity6="CAT II"
ruleid6="SV-254523r858501_rule"
vulnid6="V-254523"

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

echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${CYN}VERIFY, (See AU-12 Audit Generation: V-204564)${NORMAL}"

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

echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${CYN}VERIFY, (See AU-12 Audit Generation: V-204565)${NORMAL}"

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

echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${CYN}VERIFY, (See AU-12 Audit Generation: V-204566)${NORMAL}"

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

datetime="$(date +%FT%H:%M:%S)"

echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${CYN}VERIFY, (See AU-12 Audit Generation: V-204567)${NORMAL}"

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

echo -e "${NORMAL}$hostname, $severity5, $controlid, $stigid5, $ruleid5, $cci4, $datetime, ${CYN}VERIFY, (See AU-12 Audit Generation: V-204568)${NORMAL}"

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

datetime="$(date +%FT%H:%M:%S)"

file6="/etc/passwd"
fail=0

usraccts="$(awk -F: '($3>=1000)&&($7 !~ /nologin/){print $1, $3, $6}' $file6)"
if [[ $usraccts ]]
then
   for usracct in ${usraccts[@]}
   do
      usr="$(echo $usracct | awk '{print $1}')"
      usrgrps="$(groups $usr 2>/dev/null | awk -F": " '{print $2}')"
      IFS=' ' read -a grparr <<< "$usrgrps"
      for grp in ${grparr[@]}
      do
         if [[ $grp == 'root' ||
               $grp == 'adm'  ||
               $grp == 'wheel'
            ]]
         then
            pwlch="$(chage -l $usr | grep 'Last password change' | awk -F": " '{print $2}')"
            pwlch="$(( ($(date -d $pwlch +%Y%m%d)) ))"
            hrsago="$( echo $(( ($(date +%s) - $(date -d $pwlch +%s))/(60*60) )) )"
            dysago="$( echo $(( ($(date +%s) - $(date -d $pwlch +%s))/(60*60*24) )) )"
            if (( $hrsago <= 72 ))
            then
               echo -e "${NORMAL}RESULT:    ${CYN}$usr's last password change: ${GRN}$hrsago hours ($dysago days) ago.${NORMAL}"
            else
               echo -e "${NORMAL}RESULT:    ${CYN}$usr's last password change: ${RED}$hrsago hours ($dysago days) ago.${NORMAL}"
               fail=1
            fi
         fi
      done
   done
else
   echo -e "${NORMAL}RESULT:    ${GRN}No local interactive user account found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
   echo -e "${NORMAL}$hostname, $severity6, $controlid, $stigid6, $ruleid6, $cci6, $datetime, ${GRN}PASSED, Emergency accounts are automatically removed or disabled after the crisis is resolved or within 72 hours.${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity6, $controlid, $stigid6, $ruleid6, $cci6, $datetime, ${CYN}VERIFY, Ask the System Administrator to show evidence that emergency accounts are automatically removed or disabled after the crisis is resolved or within 72 hours or that a documented process exists for creating emergency accounts so that they are automatically disabled after 72 hours.${NORMAL}"
fi
      
exit
