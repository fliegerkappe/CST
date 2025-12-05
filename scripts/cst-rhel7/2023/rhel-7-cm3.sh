#! /bin/bash

# CM-3 Configuration Change Control
#
# CONTROL: The organization:
# a. Determines the types of changes to the information system that are configuration-controlled;
# b. Reviews proposed configuration-controlled changes to the information system and approves or
#    disapproves such changes with explicit consideration for security impact analyses;
# c. Documents configuration change decisions associated with the information system;
# d. Implements approved configuration-controlled changes to the information system;
# e. Retains records of configuration-controlled changes to the information system for [Assignment:
#    organization-defined time period];
# f. Audits and reviews activities associated with configuration-controlled changes to the information
#    system; and
# g. Coordinates and provides oversight for configuration change control activities through [Assignment:
#    organization-defined configuration change control element (e.g., committee, board] that convenes
#    [Selection (one or more): [Assignment: organization-defined frequency]; [Assignment: organization-defined configuration change conditions]].

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

controlid="CM-3 Configuration Change Control"

title1a="The Red Hat Enterprise Linux operating system must be configured so that a file integrity tool verifies the baseline operating system configuration at least weekly."
title1b="Checking with
           a. 'yum list installed | grep aide' 
           b. 'ls -al /etc/cron.* | grep aide'
           c. 'cat /etc/cron.daily/aide'."
title1c="Expecting:${YLO}
           a. AIDE is installed 
           b. '-rwxr-xr-x 1 root root 29 Nov 22 2015 aide'
           c. '0 0 * * * /usr/sbin/aide --check' | /bin/mail -s 'aide integrity check run for <system name>i' root@sysname.mil (or localhost)'.
           Note: A file integrity tool other than Advanced Intrusion Detection Environment (AIDE) may be used, but the tool must be executed at least once per week.
           Note: If the file integrity application does not exist, or a script file controlling the execution of the file integrity application does not exist, this is a finding."${BLD}
cci1="CCI-001744"
stigid1="RHEL-07-020030"
severity1="CAT II"
ruleid1="SV-204445r603261_rule"
vulnid1="V-204445"

title2a="The Red Hat Enterprise Linux operating system must be configured so that designated personnel are notified if baseline configurations are changed in an unauthorized manner."
title2b="Checking with
           a. 'yum list installed aide'
           b. 'ls -al /etc/cron.daily | grep aide'
           c. 'more /etc/cron.daily/aide --check | /bin/mail'."
title2c="Expecting:${YLO}
           a. AIDE is installed,
           b. '-rwxr-xr-x 1 root root 32 Jul 1 2011 aide',
           c. '0 0 * * * /usr/sbin/aide --check | /bin/mail -s '\$HOSTNAME - Daily aide integrity check run' root@sysname.mil (or localhost)'.
           Note: A file integrity tool other than Advanced Intrusion Detection Environment (AIDE) may be used, but the tool must be executed and notify specified individuals via email or an alert.
           Note: AIDE does not have a configuration that will send a notification, so the cron job uses the mail application on the system to email the results of the file integrity run.
           Note: If the file integrity application does not notify designated personnel of changes, this is a finding."${BLD}
cci2="CCI-001744"
stigid2="RHEL-07-020040"
severity2="CAT II"
ruleid2="SV-204446r603261_rule"
vulnid2="V-204446"

title3a="The Red Hat Enterprise Linux operating system must be configured so that all system device files are correctly labeled to prevent unauthorized modification."
title3b="Checking with
           a. 'find /dev -context *:device_t:* \( -type c -o -type b \) -printf \"%p %Z\"'
           b. 'find /dev -context *:unlabeled_t:* \( -type c -o -type b \) -printf \"%p %Z\"'."
title3c="Expecting: ${YLO}Nothing returned
           Note:  (/dev/vmci is an exception for VMs)
           Note: If SELinux is not running, this is a finding"${BLD}
cci3="CCI-000318"
stigid3="RHEL-07-020900"
severity3="CAT II"
ruleid3="SV-204479r603261_rule"
vulnid3="V-204479"

title4a="The Red Hat Enterprise Linux operating system must set the umask value to 077 for all local interactive user accounts."
title4b="Checking with 'grep -ir ^umask /home' | grep -v '.bash_history'"
title4c="Expecting:${YLO}
           If any local interactive user initialization files are found to have a umask statement that has a value less restrictive than "077", this is a finding.
           Note: If the \"/home\" directory is not where an interactive user's home directory is, you have to check there too (see /etc/shadow for that user's home directory path)"${BLD}
cci4="CCI-000318"
stigid4="RHEL-07-021040"
severity4="CAT II"
ruleid4="SV-204488r603261_rule"
vulnid4="V-204488"

title5a="The Red Hat Enterprise Linux operating system must not allow removable media to be used as the boot loader unless approved."
title5b="Checking with
           a. 'find / -name grub.cfg
           b. 'grep -cw menuentry /boot/grub2/grub.cfg'
               (or grep -c /boot/efi/EFI/redhat/grub.cfg)'
           c. 'grep ‘set root’ /boot/grub2/grub.cfg'
               (or grep 'set root' /boot/efi/EFI/redhat/grub.cfg)"
title5c="Expecting:${YLO}
           a. /boot/grub2/grub.cfg (for systems that use BIOS)
              or /boot/efi/EFI/redhat/grub.cfg (for systems that use UEFI)
           b. 1
           c. set root=(hd0,1)
           Note: If the system is using an alternate boot loader on removable media, and documentation does not exist approving the alternate configuration, this is a finding."${BLD}
cci5="CCI-000318"
stigid5="RHEL-07-021700"
severity5="CAT II"
ruleid5="SV-204501r603261_rule"
vulnid5="V-204501"

title6a="The Red Hat EnV-403479terprise Linux operating system must be configured so that the rsyslog daemon does not accept log messages from other servers unless the server is being used for log aggregation."
title6b="Checking with 
           a. 'grep imtcp /etc/rsyslog.conf'
           b. 'grep imudp /etc/rsyslog.conf'
           c. 'grep imrelp /etc/rsyslog.conf'"
title6c="Expecting:${YLO}
           Nothing returned, or
           a. \$ModLoad imtcp  (if documented)
           b. \$ModLoad imudp  (if documented)
           c. \$ModLoad imrelp (if documented)
           Note: If any of the above modules are being loaded in the \"/etc/rsyslog.conf\" file, ask to see the documentation for the system being used for log aggregation.
           Note: If the documentation does not exist, or does not specify the server as a log aggregation system, this is a finding."${BLD}
cci6="CCI-000318"
stigid6="RHEL-07-031010"
severity6="CAT II"
ruleid6="SV-204575r603261_rule"
vulnid6="V-204575"

title7a="The Red Hat Enterprise Linux operating system must be configured so that the SSH daemon does not permit Generic Security Service Application Program Interface (GSSAPI) authentication unless needed."
title7b="Checking with 'grep -i ^gssapiauth /etc/ssh/sshd_config'."
title7c="Expecting:${YLO}
           GSSAPIAuthentication no
           If the \"GSSAPIAuthentication\" keyword is missing, is set to \"yes\" and is not documented with the Information System Security Officer (ISSO), or the returned line is commented out, this is a finding."${BLD}
cci7="CCI-000368"
stigid7="RHEL-07-040430"
severity7="CAT II"
ruleid7="SV-204598r603261_rule"
vulnid7="V-204598"

title8a="The Red Hat Enterprise Linux operating system must be configured so that the SSH daemon does not permit Kerberos authentication unless needed."
title8b="Checking with 'grep -i ^kerberosauth /etc/ssh/sshd_config'."
title8c="Expecting:${YLO}
           KerberosAuthentication no
           Note: If the \"KerberosAuthentication\" keyword is missing, or is set to \"yes\" and is not documented with the Information System Security Officer (ISSO), or the returned line is commented out, this is a finding."
cci8="CCI-000318"
stigid8="RHEL-07-040440"
severity8="CAT II"
ruleid8="SV-204599r603261_rule"
vulnid8="V-204599"

title9a="The Red Hat Enterprise Linux operating system must not have the Trivial File Transfer Protocol (TFTP) server package installed if not required for operational support."
title9b="CheckiV-403479ng with 'yum list installed tftp-server'."
title9c="Expecting:${YLO}
           Nothing returned
           Note: If TFTP is installed and the requirement for TFTP is not documented with the ISSO, this is a finding."${BLD}
cci9="CCI-000368"
stigid9="RHEL-07-040700"
severity9="CAT I"
ruleid9="SV-204621r603261_rule"
vulnid9="V-204621"

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

daily=0
weekly=0

isinstalled="$(yum list installed | grep aide)"

if [[ $isinstalled ]]
then

   for pkg in ${isinstalled[@]}
   do
      echo -e "${NORMAL}RESULT:    ${BLD}$pkg${NORMAL}"
   done

   if [[ -d /etc/cron.daily ]]
   then
      echo -e "${NORMAL}RESULT:    /etc/cron.daily-----------------------------------------${NORMAL}"
      aidejob="$(ls -al 2>/dev/null /etc/cron.daily | grep aide)" >/dev/null
      if [[ $aidejob ]]
      then
         echo -e "${NORMAL}RESULT:    ${BLD}$aidejob${NORMAL}"
         jobname="$(echo $aidejob | awk '{print $9}')"
         jobcmd="$(cat /etc/cron.daily/$jobname)"
         if [[ $jobcmd ]]
         then
            echo -e "${NORMAL}RESULT:    ${BLD}$jobcmd${NORMAL}"
            daily=1 
         else
            echo -e "${NORMAL}RESULT:    /etc/cron.daily/$jobname is empty${NORMAL}"  
         fi
      else
         echo -e "${NORMAL}RESULT:    No cronjobs for aide in /etc/cron.daily${NORMAL}"
      fi
   else
      echo -e "${NORMAL}RESULT:    /etc/cron.daily not found${NORMAL}"
   fi

   aidejob=null
   jobname=null
   jobcmd=null

   if [[ -d /etc/cron.weekly ]]
   then
      echo -e "${NORMAL}RESULT:    /etc/cron.weekly-----------------------------------------${NORMAL}"
      aidejob="$(ls -al 2>/dev/null /etc/cron.weekly | grep aide)"
      if [[ $aidejob ]]
      then
         echo -e "${NORMAL}RESULT:    ${BLD}$aidejob${NORMAL}"
         jobname="$(echo $aidejob | awk '{print $9}')"
         jobcmd="$(cat /etc/cron.weekly/$jobname)"
         if [[ $jobcmd ]]
         then
            echo -e "${NORMAL}RESULT:    ${BLD}$jobcmd${NORMAL}"
            weekly=1
         elseV-204501
            echo -e "${NORMAL}RESULT:    /etc/cron.weekly/$jobname is empty${NORMAL}"        
         fi
      else
         echo -e "${NORMAL}RESULT:    No cronjobs for aide in /etc/cron.weekly${NORMAL}"
      fi
   else
      echo -e "${NORMAL}RESULT:    /etc/cron.weekly not found${NORMAL}"
   fi
   if (( $daily == 1 || $weekly == 1 ))
   then
      echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${GRN}PASSED, File Integrity Checking (AIDE): A file integrity tool verifies the baseline operating system configuration at least weekly.${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${RED}FAILED, File Integrity Checking (AIDE): A file integrity tool does not verify the baseline operating system configuration at least weekly.${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${RED}The AIDE package was not found${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${RED}FAILED, File Integrity Checking (AIDE): The AIDE package is not installed.${NORMAL}"
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

alert=0

isinstalled="$(yum list installed | grep aide)"

if [[ $isinstalled ]]
then

   for pkg in ${isinstalled[@]}
   do
      echo -e "${NORMAL}RESULT:    ${BLD}$pkg${NORMAL}"
   done

   if [[ -d /etc/cron.daily ]]
   then
      echo -e "${NORMAL}RESULT:    /etc/cron.daily-----------------------------------------${NORMAL}"
      aidejob="$(ls -al 2>/dev/null /etc/cron.daily | grep aide)" >/dev/null
      if [[ $aidejob ]]
      then
         echo -e "${NORMAL}RESULT:    ${BLD}$aidejob${NORMAL}"
         jobname="$(echo $aidejob | awk '{print $9}')"
         jobcmd="$(cat 2>&1 /etc/cron.daily/$jobname)"
         if [[ $jobcmd ]]
         then
            alert=1
         else
            echo -e "${NORMAL}RESULT:    /etc/cron.daily/$jobname is empty${NORMAL}"
         fi
      else
         echo -e "${NORMAL}RESULT:    No cronjobs for aide in /etc/cron.daily${NORMAL}"
      fi
   else
      echo -e "${NORMAL}RESULT:    /etc/cron.daily not found${NORMAL}"
   fi

   if (( $alert == 1 ))
   then
      echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${GRN}PASSED, Daily File Integrity Alerting (AIDE): Designated personnel are notified if baseline configurations are changed in an unauthorized manner${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${RED}FAILED, Daily File Integrity Alerting (AIDE): Designated personnel are not notified if baseline configurations are changed in an unauthorized manner${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${RED}The AIDE package was not found${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${RED}FAILED, Daily File Integrity Alerting (AIDE): The AIDE package is not installed${NORMAL}"
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

datetime="$(date +%FT%H:%M:%S)"

echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${CYN}VERIFY, (See CM-6 Configuration Settings: V-204479)${NORMAL}"

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

echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${CYN}VERIFY, (See CM-6 Configuration Settings: V-204488)${NORMAL}"

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

echo -e "${NORMAL}$hostname, $severity5, $controlid, $stigid5, $ruleid5, $cci5, $datetime, ${CYN}VERIFY, (See CM-6 Configuration Settings: V-204501)${NORMAL}"

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

datetime="$(date +%FT%H:%M:%S)"

echo -e "${NORMAL}$hostname, $severity6, $controlid, $stigid6, $ruleid6, $cci6, $datetime, ${CYN}VERIFY, (See CM-6 Configuration Settings: V-204575)${NORMAL}"

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

datetime="$(date +%FT%H:%M:%S)"

echo -e "${NORMAL}$hostname, $severity7, $controlid, $stigid7, $ruleid7, $cci7, $datetime, ${CYN}VERIFY, (See CM-6 Configuration Settings: V-204598)${NORMAL}"

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

datetime="$(date +%FT%H:%M:%S)"

echo -e "${NORMAL}$hostname, $severity8, $controlid, $stigid8, $ruleid8, $cci8, $datetime, ${CYN}VERIFY, (See CM-6 Configuration Settings: V-204599)${NORMAL}"

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

datetime="$(date +%FT%H:%M:%S)"

echo -e "${NORMAL}$hostname, $severity9, $controlid, $stigid9, $ruleid9, $cci9, $datetime, ${CYN}VERIFY, (See CM-6 Configuration Settings: V-204621)${NORMAL}"

exit
