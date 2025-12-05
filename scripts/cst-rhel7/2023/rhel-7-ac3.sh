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

controlid="AC-3 Access Enforcement"

title1a="The Red Hat Enterprise Linux operating system must be configured so that the file permissions, ownership, and group membership of system files and commands match the vendor values."
title1b="Checking with:
           a. 'for i in \`rpm -Va | grep -E '^.{1}M|^.{5}U|^.{6}G' | cut -d \" \" -f 4,5\`;do for j in \`rpm -qf \$i\`;do rpm -ql \$j --dump | cut -d \" \" -f 1,5,6,7 | grep \$i;done;done'
           b. 'ls -la <filename>'"
title1c="Expecting: ${YLO}Nothing returned
           Note: If the file is more permissive than the default permissions, this is a finding.
           Note: If the file is not owned by the default owner and is not documented with the Information System Security Officer (ISSO), this is a finding.
           Note: If the file is not a member of the default group and is not documented with the Information System Security Officer (ISSO), this is a finding.${BLD}"
cci1="CCI-001494"
stigid1="RHEL-07-010010"
severity1="CAT I"
ruleid1="SV-204392r646841_rule"
vulnid1="V-204392"

title3a="The Red Hat Enterprise Linux operating system must prevent non-privileged users from executing privileged functions to include disabling, circumventing, or altering implemented security safeguards/countermeasures."
title3b="Checking with 'semanage login -l | more'."
title3c="Expecting: ${YLO}
           Login Name       SELinux User    MLS/MCS Range       Service
           __default__      user_u          s0-s0:c0.c1023      *
           root             unconfined_u    s0-s0:c0.c1023      *
           system_u         system_u        s0-s0:c0.c1023      *
           joe              staff_u         s0-s0:c0.c1023      * 
           Note: If an HBSS or HIPS is active on the system, this is Not Applicable.
           Note: All administrators must be mapped to the \"sysadm_u\" or \"staff_u\" users role.
           Note: All authorized non-administrative users must be mapped to the \"user_u\" role.
           Note: If they are not mapped in this way, this is a finding.${BLD}"
cci3="CCI-002165"
stigid3="RHEL-07-020020"
severity3="CAT II"
ruleid3="SV-204444r792826_rule"
vulnid3="V-204444"

title4a="The Red Hat Enterprise Linux operating system must enable SELinux."
title4b="Checking with 'getenforce'."
title4c="Expecting: ${YLO}Enforcing
           Note: If an HBSS or HIPS is active on the system, this is Not Applicable.
           Note: If \"SELinux\" is not active and not in \"Enforcing\" mode, this is a finding.${BLD}"
cci4="CCI-002165"
stigid4="RHEL-07-020210"
severity4="CAT I"
ruleid4="SV-204453r754746_rule"
vulnid4="V-204453"

title5a="The Red Hat Enterprise Linux operating system must enable the SELinux targeted policy."
title5b="Checking with 'sestatus'."
title5c="Expecting: ${YLO}
           SELinux status: enabled
           SELinuxfs mount: /selinux
           SELinux root directory: /etc/selinux
           Loaded policy name: targeted
           Mode from config file: enforcing
           Policy MLS status: enabled
           Policy deny_unknown status: allowed
           Max kernel policy version: 28
           Note: If an HBSS or HIPS is active on the system, this is Not Applicable.
           Note: If the \"Policy from config file\" is not set to \"targeted\", or the \"Loaded policy name\" is not set to \"targeted\", this is a finding.${BLD}"
cci5="CCI-002165"
stigid5="RHEL-07-020220"
severity5="CAT I"
ruleid5="SV-204454r754748_rule"
vulnid5="V-204454"

#title6a="The Red Hat Enterprise Linux operating system must be configured so that all files and directories have a valid owner."
#title6b="Checking with 'find / -fstype xfs -nouser'."
#title6c="Expecting: ${YLO}Nothing returned
#           Note: If any files on the system do not have an assigned owner, this is a finding.${BLD}"
#cci6="CCI-002165"
#stigid6="RHEL-07-020320"
#severity6="CAT II"
#ruleid6="SV-204463r603261_rule"
#vulnid6="V-204463"
#
#title7a="The Red Hat Enterprise Linux operating system must be configured so that all files and directories have a valid group owner."
#title7b="Checking with 'find / -fstype xfs -nogroup'."
#title7c="Expecting: ${YLO}Nothing returned
#           Note: If any files on the system do not have an assigned group, this is a finding.${BLD}"
#cci7="CCI-002165"
#stigid7="RHEL-07-020330"
#severity7="CAT II"
#ruleid7="SV-204464r603261_rule"
#vulnid7="V-204464"

title8a="The Red Hat Enterprise Linux operating system must require authentication upon booting into single-user and maintenance modes."
title8b="Checking with 'grep -i execstart /usr/lib/systemd/system/rescue.service'."
title8c="Expecting:${YLO} 
           ExecStart=-/bin/sh -c '/usr/sbin/sulogin; /usr/bin/systemctl --fail --no-block default'
           Note: If \"ExecStart\" does not have \"/usr/sbin/sulogin\" as an option, this is a finding.${BLD}"
cci8="CCI-000213"
stigid8="RHEL-07-010481"
severity8="CAT II"
ruleid8="SV-204437r603261_rule"
vulnid8="V-204437"

title9a="Red Hat Enterprise Linux operating systems version 7.2 or newer with a Basic Input/Output System (BIOS) must require authentication upon booting into single-user and maintenance modes."
title9b="Checking with:
           a. 'more /etc/redhat-release | awk '{print \$7}'
           b. 'grep -iw grub2_password /boot/grub2/user.cfg"
title9c="Expecting: ${YLO}
           a. 'Red Hat Enterprise Server 7.2 or greater'
           b. 'GRUB2_PASSWORD=grub.pbkdf2.sha512.{password_hash}'
           Note: For systems that use UEFI, this is Not Applicable.
           Note: If the grub superusers password does not begin with \"grub.pbkdf2.sha512\", this is a finding.${BLD}"
cci9="CCI-000213"
stigid9="RHEL-07-010482"
severity9="CAT I"
ruleid9="SV-204438r744095_rule"
vulnid9="V-204438"

title10a="Red Hat Enterprise Linux operating systems version 7.2 or newer using Unified Extensible Firmware Interface (UEFI) must require authentication upon booting into single-user and maintenance modes."
title10b="Checking with:
           a. 'more /etc/redhat-release | awk '{print \$7}'
           b. 'grep -i pbkdf2 /etc/grub.d/*"
title10c="Expecting:${YLO}
           a. 'Red Hat Enterprise Server 7.2 or greater'
           b. 'GRUB2_PASSWORD=grub.pbkdf2.sha512.{password_hash}'
           Note: For systems that use BIOS, this is Not Applicable.
           Note: If the grub superusers password does not begin with \"grub.pbkdf2.sha512\", this is a finding.${BLD}"
cci10="CCI-000213"
stigid10="RHEL-07-010491"
severity10="CAT I"
ruleid10="SV-204440r744098_rule"
vulnid10="V-204440"

title11a="Red Hat Enterprise Linux operating systems version 7.2 or newer booted with a BIOS must have a unique name for the grub superusers account when booting into single-user and maintenance modes."
title11b="Checking with: 'grep -iw \"superusers\" /boot/grub2/grub.cfg'"
title11c="Expecting: ${YLO}set superusers=\"[someuniquestringhere]\"
                     export superusers
           Note: For systems that are running a version of RHEL prior to 7.2, this is Not Applicable.
           Note: If \"superusers\" is identical to any OS account name or is missing a name, this is a finding.${BLD}"
cci11="CCI-000213"
stigid11="RHEL-07-010483"
severity11="CAT II"
ruleid11="SV-244557r833185_rule"
vulnid11="V-244557"

title12a="Red Hat Enterprise Linux operating systems version 7.2 or newer booted with United Extensible Firmware Interface (UEFI) must have a unique name for the grub superusers account when booting into single-user and maintenance modes."
title12b="Checking with: 'grep -iw \"superusers\" /boot/efi/EFI/redhat/grub.cfg'"
title12c="Expecting: ${YLO}
           set superusers=\"[someuniquestringhere]\"
           export superusers
           Note: For systems that are running a version of RHEL prior to 7.2, this is Not Applicable.
           Note: If \"superusers\" is identical to any OS account name or is missing a name, this is a finding.${BLD}"
cci12="CCI-000213"
stigid12="RHEL-07-010492"
severity12="CAT II"
ruleid12="SV-244558r833187_rule"
vulnid12="V-244558"

title13a="The Red Hat Enterprise Linux operating system must confine SELinux users to roles that conform to least privilege."
title13b="Checking with 'sudo semanage user -l'"
title13c="Expecting: ${YLO}
           SELinuxUser LabelingPrefix MLS/MCSLevel MLS/MCSRange SELinuxRoles
           guest_u       user  s0  s0              guest_r
           root          user  s0  s0-s0:c0.c1023  staff_r sysadm_r system_r unconfined_r
           staff_u       user  s0  s0-s0:c0.c1023  staff_r sysadm_r
           sysadm_u      user  s0  s0-s0:c0.c1023  sysadm_r 
           system_u      user  s0  s0-s0:c0.c1023  system_r unconfined_r
           unconfined_u  user  s0  s0-s0:c0.c1023  system_r unconfined_r
           user_u        user  s0  s0              user_r
           xguest_u      user  s0  s0              xguest_r
           Note: If the output differs from the above example, ask the SA to demonstrate how the SELinux User mappings are exercising least privilege. If deviations from the example are not documented with the ISSO and do not demonstrate least privilege, this is a finding.${BLD}"
cci13="CCI-002165"
stigid13="RHEL-07-020021"
severity13="CAT II"
ruleid13="SV-250312r792843_rule"
vulnid13="V-250312"

title14a="The Red Hat Enterprise Linux operating system must not allow privileged accounts to utilize SSH."
title14b="Checking with 'getsebool ssh_sysadm_login'"
title14c="Expecting: ${YLO}ssh_sysadm_login --> off
           Note: If the \"ssh_sysadm_login\" boolean is not \"off\" and is not documented with the ISSO as an operational requirement, this is a finding.${BLD}"
cci14="CCI-002165"
stigid14="RHEL-07-020022"
severity14="CAT II"
ruleid14="SV-250313r792846_rule"
vulnid14="V-250313"

title15a="The Red Hat Enterprise Linux operating system must elevate the SELinux context when an administrator calls the sudo command."
title15b="Checking with: 'grep -r sysadm_r /etc/sudoers /etc/sudoers.d'."
title15c="Expecting: ${YLO}%wheel ALL=(ALL) TYPE=sysadm_t ROLE=sysadm_r ALL
           Note: If conflicting results are returned, this is a finding.
           Note: If a designated sudoers administrator group or account(s) is not configured to elevate the SELinux type and role to \"sysadm_t\" and \"sysadm_r\" with the use of the sudo command, this is a finding.${BLD}"
cci15="CCI-002165"
stigid15="RHEL-07-020023"
severity15="CAT II"
ruleid15="SV-250314r833181_rule"
vulnid15="V-250314"

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

fail=0

modechg="$(for i in `rpm -Va | grep -E '^.{1}M|^.{5}U|^.{6}G' | cut -d " " -f 4,5`;do for j in `rpm -qf $i 2>/dev/null`;do rpm -ql $j --dump | cut -d " " -f 1,5,6,7 | grep $i;done;done)"

if [[ $modechg ]]
then
   for i in ${modechg[@]}
   do
      file="$(echo $i | awk '{print $1}')"
      fchg="$(rpm -qf $file)"
      if [[ $fchg ]]
      then
         for j in ${fchg[@]}
         do
            vendor="$(rpm -ql $j --dump | cut -d ' ' -f1,5,6,7 | grep $file)"
            for x in ${vendor[@]}
            do
               mode1="$(echo $x | cut -d ' ' -f2 | grep -o '...$')"
               owner1="$(echo $x | cut -d ' ' -f3)"
               group1="$(echo $x | cut -d ' ' -f4)"
               filex="$(echo $x | cut -d ' ' -f1)"
               if [[ -f $filex || -d $filex ]]
               then
                  ownerx="$(stat -c '%U' $filex)"
                  groupx="$(stat -c '%G' $filex)"
                  mode2="$(stat -c %a $filex | grep -0 '...$')"

                  echo -n -e "${NORMAL}RESULT:    $x ($mode1) - is now - "

                  if [[ $owner1 != $ownerx ]]
                  then
                     echo -n -e "${RED}($ownerx)${NORMAL}"
                     fail=1
                  else
                     echo -n -e "${GRN}($ownerx)${NORMAL}"
                  fi
                  if [[ $group1 != $groupx ]]
                  then
                     echo -n -e "${RED}($groupx)${NORMAL}"
                     fail=1
                  else
                     echo -n -e "${GRN}($groupx)${NORMAL}"
                  fi
                  if [[ ${mode1:0:1} < ${mode2:0:1} ||
                        ${mode1:1:1} < ${mode2:1:1} ||
                        ${mode1:2:1} < ${mode2:2:1}
                     ]]
                  then
                     echo -e "${RED}($mode2)${NORMAL}"
                     fail=1
                  else
                     echo -e "${GRN}($mode2)${NORMAL}"
                  fi
               fi
            done
         done
      fi
   done

   if [[ $fail == 0 ]]
   then
      echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${GRN}PASSED, Discretionary Access Control (DAC): The file permissions ownership and group membership of system files and commands match or are less permissive than the vendor values.${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${RED}FAILED, Discretionary Access Control (DAC): The file permissions ownership and group membership of system files and commands do not match the vendor values.${NORMAL}"
   fi
else
   echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${GRN}PASSED, Discretionary Access Control (DAC): The file permissions ownership and group membership of system files and commands match the vendor values.${NORMAL}"
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

datetime="$(date +%FT%H:%M:%S)"

authusrs="$(semanage login -l | more)"
fail=0

if [[ $authusrs ]]
then
   for usr in ${authusrs[@]}
   do
      IFS=' ' read -a fieldvals <<< "${usr}"
      if [[ ${fieldvals[0]} == '__default__' && ${fieldvals[2]} != 'user_u' ]] ||
         [[ ${fieldvals[0]} == 'system_u' && ${fieldvals[1]} != 'system_u' ]] ||
         [[ ${fieldvals[0]} == 'root' && ${fieldvals[1]} != 'unconfined_u' ]]
      then
         echo  -e "${NORMAL}RESULT:    ${RED}$usr${NORMAL}"
         fail=1
      else
         echo  -e "${NORMAL}RESULT:    ${BLD}$usr${NORMAL}"
      fi
   done

   if [[ $fail == 0 ]]
   then
      echo -e "${NORMAL}RESULT:    ${BLD}Default SELinux user list found${NORMAL}"
      echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${GRN}PASSED, SEMANAGE LOGIN - The operating system prevents non-privileged users from executing privileged functions to include disabling circumventing or altering implemented security safeguards/countermeasures.${NORMAL}"
   else
      echo -e "${NORMAL}RESULT:    ${RED}Non-Default SELinux user list found${NORMAL}"
      echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${RED}FAILED, SEMANAGE LOGIN - The operating does not prevent non-privileged users from executing privileged functions to include disabling circumventing or altering implemented security safeguards/countermeasures.${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    Nothing returned${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${RED}FAILED, SEMANAGE LOGIN - The 'semanage login -l' command returned nothing. There are no mappings between local users and SELinux confined users.${NORMAL}"
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

datetime="$(date +%FT%H:%M:%S)"

getenf="$(getenforce)"

if [[ $getenf == 'Enforcing' ]]
then
   echo -e "${NORMAL}RESULT:    ${BLD}getenforce = $getenf${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${GRN}PASSED, SELinux Active - SELinux is set to $getenf.${NORMAL}"
else
   echo -e "${NORMAL}RESULT:    ${RED}getenforce = $getenf${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${RED}FAILED, SELinux Active - SELinux is set to $getenf.${NORMAL}"
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

datetime="$(date +%FT%H:%M:%S)"

sestat="$(sestatus)"
enabled=0
targeted=0
enforcing=0
configfile=0

if [[ $sestat ]]
then
   for line in ${sestat[@]}
   do
      if [[ $line =~ 'SELinux' && $line =~ 'disabled' ]]
      then
         echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
      elif [[ $line =~ 'SELinux' && $line =~ 'enabled' ]]
      then
         echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
         enabled=1
      elif [[ $line =~ 'Loaded' && $line =~ 'targeted' ]]
      then
         echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
         targeted=1
      elif [[ $line =~ 'Current mode' && $line =~ 'enforcing' ]]
      then
         echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
         enforcing=1
      elif [[ $line =~ 'Policy from config file' && $line =~ 'targeted' ]]
      then
         configfile=1
      else
         echo -e "${NORMAL}RESULT:    $line${NORMAL}"
      fi
   done

   if [[ $enabled == 1 && $targeted == 1 && $enforcing == 1 && $configgile == 1 ]]
   then
      echo -e "${NORMAL}$hostname, $severity5, $controlid, $stigid5, $ruleid5, $cci5, $datetime, ${GRN}PASSED, SELinux Status - SELinux is active.${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity5, $controlid, $stigid5, $ruleid5, $cci5, $datetime, ${RED}FAILED, SELinux Status - SELinux is not configured properly.${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity5, $controlid, $stigid5, $ruleid5, $cci5, $datetime, ${RED}FAILED, SELinux Status - SELinux is not active.${NORMAL}"
fi

#echo
#echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
#echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
#echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
#echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
#echo -e "${NORMAL}STIG ID:   $stigid6${NORMAL}"
#echo -e "${NORMAL}RULE ID:   $ruleid6${NORMAL}"
#echo -e "${NORMAL}VULN ID:   $vulnid6${NORMAL}"
#echo -e "${NORMAL}CCI:       $cci6${NORMAL}"
#echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
#echo -e "${NORMAL}TEST 6:    ${BLD}$title6a${NORMAL}"
#echo -e "${NORMAL}           ${BLD}$title6b${NORMAL}"
#echo -e "${NORMAL}           ${BLD}$title6c${NORMAL}"
#echo -e "${NORMAL}SEVERITY:  ${BLD}$severity6${NORMAL}"
#
#IFS='
#'
#
#datetime="$(date +%FT%H:%M:%S)"
#
#nouser="$(find / -type d -name mnt -prune -o -fstype xfs -nouser)"
#fail=0
#
#if [[ $nouser ]]
#then
#   for line in ${nouser[@]}
#   do
#      if [[ ! $line =~ 'No such file' && ! $line =~ 'Permission denied' ]]
#      then
#         echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
#         fail=1
#      fi
#   done
#fi
#
#if [[ $fail == 0 ]]
#then
#   echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
#   echo -e "${NORMAL}$hostname, $severity6, $controlid, $stigid6, $ruleid6, $cci6, $datetime, ${GRN}PASSED, All files and directories have a valid owner${NORMAL}"
#else
#   echo -e "${NORMAL}$hostname, $severity6, $controlid, $stigid6, $ruleid6, $cci6, $datetime, ${RED}FAILED, All files and directories do not have a valid owner${NORMAL}"  
#fi
#
#echo
#echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
#echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
#echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
#echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
#echo -e "${NORMAL}STIG ID:   $stigid7${NORMAL}"
#echo -e "${NORMAL}RULE ID:   $ruleid7${NORMAL}"
#echo -e "${NORMAL}VULN ID:   $vulnid7${NORMAL}"
#echo -e "${NORMAL}CCI:       $cci7${NORMAL}"
#echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
#echo -e "${NORMAL}TEST 7:    ${BLD}$title7a${NORMAL}"
#echo -e "${NORMAL}           ${BLD}$title7b${NORMAL}"
#echo -e "${NORMAL}           ${BLD}$title7c${NORMAL}"
#echo -e "${NORMAL}SEVERITY:  ${BLD}$severity7${NORMAL}"
#
#IFS='
#'
#
#datetime="$(date +%FT%H:%M:%S)"
#
#nogroup="$(find / -type d -name mnt -prune -o -fstype xfs -nogroup 2>/dev/null)"
#fail=0
#
#if [[ $nogroup ]]
#then
#   for line in ${nogroup[@]}
#   do
#      if [[ ! $line =~ 'No such file' && ! $line =~ 'Permission denied' ]]
#      then
#         echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
#         fail=1
#      fi
#   done
#fi
#
#if [[ $fail == 0 ]]
#then
#   echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
#   echo -e "${NORMAL}$hostname, $severity7, $controlid, $stigid7, $ruleid7, $cci7, $datetime, ${GRN}PASSED, All files and directories have a valid group owner${NORMAL}"
#else
#   echo -e "${NORMAL}$hostname, $severity7, $controlid, $stigid7, $ruleid7, $cci7, $datetime, ${RED}FAILED, All files and directories do not have a valid group owner${NORMAL}"
#fi


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

datetime="$(date +%FT%H:%M:%S)"

file8="/usr/lib/systemd/system/rescue.service"
fail=1

if [[ -f $file8 ]]
then

   execstart="$(grep -i execstart $file8)"

   if [[ $execstart ]]
   then
      for line in ${execstart[@]}
      do
         if [[ $line =~ '/usr/sbin/sulogin' ]]
         then
            echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
            fail=0
         else
            echo -e "${NORMAL}RESULT:    $line${NORMAL}"
         fi
      done

      if [[ $fail == 0 ]]
      then
         echo -e "${NORMAL}$hostname, $severity8, $controlid, $stigid8, $ruleid8, $cci8, $datetime, ${GRN}PASSED, Single-User Mode Authentication: The operating system requires authentication upon booting into single-user and maintenance modes${NORMAL}"
      else
         echo -e "${NORMAL}RESULT:    ${RED}Missing '/usr/sbin/sulogin'${NORMAL}"
         echo -e "${NORMAL}$hostname, $severity8, $controlid, $stigid8, $ruleid8, $cci8, $datetime, ${RED}FAILED, Single-User Mode Authentication: The operating system does not require authentication upon booting into single-user and maintenance modes${NORMAL}"
      fi
   else
      echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
      echo -e "${NORMAL}$hostname, $severity8, $controlid, $stigid8, $ruleid8, $cci8, $datetime, ${RED}FAILED, Single-User Mode Authentication: The operating system does not require authentication upon booting into single-user and maintenance modes${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    $file8 not found${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity8, $controlid, $stigid8, $ruleid8, $cci8, $datetime, ${RED}FAILED, Single-User Mode Authentication: The operating system does not require authentication upon booting into single-user and maintenance modes${NORMAL}"
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

datetime="$(date +%FT%H:%M:%S)"

file9="/boot/grub2/user.cfg"
fail=0

osmake="$(echo $os | awk '{print $1}')"

case $osmake in
  'Red')
     release="$(echo $os | awk '{print $7}')"
     ;;
  'CentOS')
     release="$(echo $os | awk '{print $4}')"
     ;;
esac

minver="7.2"

major="$(echo $release | awk -F. '{print $1}')"
minor="$(echo $release | awk -F. '{print $2}')"

if (( $major < 7 || ( $major == 7 && $minor < 2 ) ))
then
  echo -e "${NORMAL}RESULT:    ${BLD}a. $os${NORMAL}"
  echo -e "${NORMAL}$hostname, $severity9, $controlid, $stigid9, $ruleid9, $cci9, $datetime, ${GRN}PASSED, GRUB2 Password: Not Applicabl - The Linux operating system is less than version $minver.${NORMAL}"
else
  echo -e "${NORMAL}RESULT:    ${BLD}a. $os${NORMAL}"
  if [[ -f $file9 ]]
  then
    g2pw="$(grep -iw grub2_password $file9)"
    if [[ $g2pw ]]
    then
      for line in ${g2pw[@]}
      do
        if [[ $line =~ "grub.pbkdf2.sha512" ]]
        then
          line="$(echo $line | sed -e 's/10000..*$/10000.(password hash omitted)/g')"
          echo -e "${NORMAL}RESULT:    ${BLD}b. $line${NORMAL}"
        else
          echo -e "${NORMAL}RESULT:    ${RED}b. $line${NORMAL}"
          fail=1
        fi
      done
    else
      echo -e "${NORMAL}RESULT:    ${RED}b. The sha512 \"GRUB2_PASSWORD\" is missing.${NORMAL}"
      fail=1
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}b. $file9 not found${NORMAL}"
    fail=1
  fi
fi

if [[ $fail == 0 ]]
then      
  echo -e "${NORMAL}$hostname, $severity9, $controlid, $stigid9, $ruleid9, $cci9, $datetime, ${GRN}PASSED, Red Hat Enterprise Linux operating systems version 7.2 or newer using Basic Input/Output System (BIOS) requires authentication upon booting into single-user and maintenance modes.${NORMAL}"
elif [[ $fail == 2 ]]
then
  echo -e "${NORMAL}$hostname, $severity9, $controlid, $stigid9, $ruleid9, $cci9, $datetime, ${GRN}N/A, For Red Hat Enterprise Linux operating systems using Unified Extensible Firmware Interface (UEFI) this is Not Applicable.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity9, $controlid, $stigid9, $ruleid9, $cci9, $datetime, ${RED}FAILED, BIOS GRUB2 User Password: The operating system does not require authentication upon booting into single-user and maintenance modes.${NORMAL}"
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

datetime="$(date +%FT%H:%M:%S)"

file10="/boot/efi/EFI"
fail=0

osmake="$(echo $os | awk '{print $1}')"

case $osmake in
  'Red')
     release="$(echo $os | awk '{print $7}')"
     ;;
  'CentOS')
     release="$(echo $os | awk '{print $4}')"
     ;;
esac

minver="7.2"

major="$(echo $release | awk -F. '{print $1}')"
minor="$(echo $release | awk -F. '{print $2}')"

if (( $major < 7 || ( $major == 7 && $minor < 2 ) ))
then
  echo -e "${NORMAL}RESULT:    ${BLD}$os${NORMAL}"
  echo -e "${NORMAL}$hostname, $severity10, $controlid, $stigid10, $ruleid10, $cci10, $datetime, ${GRN}N/A, GRUB2 Password: Not Applicable - The Linux operating system is less than version $minver.${NORMAL}"
else
  echo -e "${NORMAL}RESULT:    ${BLD}a. $os${NORMAL}"
  if [[ -f $file10 ]]
  then
    g2pw="$(grep -iw grub2_password $file10)"
    if [[ $g2pw ]]
    then
      for line in ${g2pw[@]}
      do
        if [[ $line == "grub.pbkdf2.sha512" ]]
        then
          line="$(echo $line | sed -e 's/10000..*$/10000.(password hash omitted)/g')"
          echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
        else
          echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
          fail=1
        fi
      done
    else
      echo -e "${NORMAL}RESULT:    ${RED}b. The sha512 \"GRUB2_PASSWORD\" is missing.${NORMAL}"
      fail=1
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}b. $file10 not found${NORMAL}"
    fail=2
  fi
fi

if [[ $fail == 0 ]]
then      
  echo -e "${NORMAL}$hostname, $severity10, $controlid, $stigid10, $ruleid10, $cci10, $datetime, ${GRN}PASSED, Red Hat Enterprise Linux operating systems version 7.2 or newer using Basic Input/Output System (BIOS) requires authentication upon booting into single-user and maintenance modes.${NORMAL}"
elif [[ $fail == 2 ]]
then
  echo -e "${NORMAL}$hostname, $severity10, $controlid, $stigid10, $ruleid10, $cci10, $datetime, ${GRN}N/A, For Red Hat Enterprise Linux operating systems using Basic Input/Output System (BIOS) this is Not Applicable.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity10, $controlid, $stigid10, $ruleid10, $cci10, $datetime, ${RED}FAILED, UEFI GRUB2 User Password: The operating system does not require authentication upon booting into single-user and maintenance modes.${NORMAL}"
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

file11a="/boot/grub2/grub.cfg"
fail=0

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

if [[ -d /sys/firmware/efi ]]
then
   firmware='UEFI'
else
   firmware='BIOS'
fi

if [[ $firmware == 'BIOS' ]]
then
  if [[ -f $file11a ]]
  then
    grubsu="$(cat $file11a | grep 'set superusers' | grep -v "^#" | sed -e 's/ //g')"
    if [[ $grubsu ]]
    then
      for line in ${grubsu[@]}
      do
        isunique="$(echo $grubsu | awk -F= '{print $2}' | tr -d '"')"
        if [[ $isunique == "root"  || $isunique == "" ]]
        then
          echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
          fail=1
        else
          echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
        fi
      done
    else
      echo -e "${NORMAL}RESULT:    ${RED}\"superusers\" is not defined in $file11a${NORMAL}"
      fail=1
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}$file11a not found${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${BLD}BIOS firmware not found${NORMAL}"
  fail=2
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity11, $controlid, $stigid11, $ruleid11, $cci11, $datetime, ${GRN}PASSED, A unique name is set as the grub \"superusers\" account${NORMAL}"
elif [[ $fail == 2 ]]
then
  echo -e "${NORMAL}$hostname, $severity11, $controlid, $stigid11, $ruleid11, $cci11, $datetime, ${GRN}N/A, The system uses UEFI${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity11, $controlid, $stigid11, $ruleid11, $cci11, $datetime, ${RED}FAILED, A unique name is not set as the grub \"superusers\" account${NORMAL}"
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

file12a="/boot/efi/EFI/redhat/grub.cfg"
fail=0

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

if [[ -d /sys/firmware/efi ]]
then
   firmware='UEFI'
else
   firmware='BIOS'
fi

if [[ $firmware == 'UEFI' ]]
then
  if [[ -f $file12a ]]
  then
    grubsu="$(cat $file12a | grep 'set superusers' | grep -v "^#" | sed -e 's/ //g')"
    if [[ $grubsu ]]
    then
      for line in ${grubsu[@]}
      do
        isunique="$(echo $grubsu | awk -F= '{print $2}' | tr -d '"')"
        if [[ $isunique == "root"  || $isunique == "" ]]
        then
          echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
          fail=1
        else
          echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
        fi
      done
    else
      echo -e "${NORMAL}RESULT:    ${RED}\"superusers\" is not defined in $file12a${NORMAL}"
      fail=1
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}$file12a not found${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${BLD}UEFI firmware not found${NORMAL}"
  fail=2
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity12, $controlid, $stigid12, $ruleid12, $cci12, $datetime, ${GRN}PASSED, A unique name is set as the \"superusers\" account${NORMAL}"
elif [[ $fail == 2 ]]
then
  echo -e "${NORMAL}$hostname, $severity12, $controlid, $stigid12, $ruleid12, $cci12, $datetime, ${GRN}N/A, The system uses BIOS${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity12, $controlid, $stigid12, $ruleid12, $cci12, $datetime, ${RED}FAILED, A unique name is not set as the \"superusers\" account${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid13${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid13${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid13${NORMAL}"
echo -e "${NORMAL}CCI:       $cci13${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 13:   ${BLD}$title13a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title13b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title13c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity13${NORMAL}"

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

selinuxuser="$(semanage user -l)"

if [[ $selinuxuser ]]
then
  for line in ${selinuxuser[@]}
  do
    if ! [[ $line =~ ("MLS"|"MCS") ]]
    then
      xline="$(echo $line | awk '{$2=$2};1')"
      user="$(echo $xline | awk '{print $1}')"
      prefix="$(echo $xline | awk '{print $2}')"
      level="$(echo $xline | awk '{print $3}')"
      range="$(echo $xline | awk '{print $4}')"
      roles="$(echo $xline | cut -d' ' -f5-)"
      case $user in
        'guest_u')
           if [[ $prefix == "user" &&
                 $level == "s0" &&
                 $range == "s0" &&
                 $roles == "guest_r"
              ]]
           then
             echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
           else
             echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
             fail=1
           fi
           ;;
        'root')
           if [[ $prefix == "user" &&
                 $level == "s0" &&
                 $range == "s0-s0:c0.c1023" &&
                 $roles == "staff_r sysadm_r system_r unconfined_r"
              ]]
           then
             echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
           else
             echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
             fail=1
           fi
           ;;
        'staff_u')
           if [[ $prefix == "user" &&
                 $level == "s0" &&
                 $range == "s0-s0:c0.c1023" &&
                 $roles == "staff_r sysadm_r"
              ]]
           then
             echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
           else
             echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
             fail=1
           fi
           ;;
        'sysadm_u')
           if [[ $prefix == "user" &&
                 $level == "s0" &&
                 $range == "s0-s0:c0.c1023" &&
                 $roles == "sysadm_r"
              ]]
           then
             echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
           else
             echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
             fail=1
           fi
           ;;
        'system_u')
           if [[ $prefix == "user" &&
                 $level == "s0" &&
                 $range == "s0-s0:c0.c1023" &&
                 $roles == "system_r unconfined_r"
              ]]
           then
             echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
           else
             echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
             fail=1
           fi
           ;;
        'unconfined_u')
           if [[ $prefix == "user" &&
                 $level == "s0" &&
                 $range == "s0-s0:c0.c1023" &&
                 $roles == "system_r unconfined_r"
              ]]
           then
             echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
           else
             echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
             fail=1
           fi
           ;;
        'user_u')
           if [[ $prefix == "user" &&
                 $level == "s0" &&
                 $range == "s0" &&
                 $roles == "user_r"
              ]]
           then
             echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
           else
             echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
             fail=1
           fi
           ;;
        'xguest_u')
           if [[ $prefix == "user" &&
                 $level == "s0" &&
                 $range == "s0" &&
                 $roles == "xguest_r"
              ]]
           then
             echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
           else
             echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
             fail=1
           fi
           ;;
      esac
    else
      echo -e "${NORMAL}RESULT:    $line${NORMAL}"
    fi
  done

else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned ${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity13, $controlid, $stigid13, $ruleid13, $cci13, $datetime, ${GRN}PASSED, The operating system confines SELinux users to roles that conform to least privilege.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity13, $controlid, $stigid13, $ruleid13, $cci13, $datetime, ${RED}FAILED, The operating system does not confine SELinux users to roles that conform to least privilege.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid14${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid14${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid14${NORMAL}"
echo -e "${NORMAL}CCI:       $cci14${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 14:   ${BLD}$title14a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title14b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title14c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity14${NORMAL}"

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

fail=1

login="$(getsebool ssh_sysadm_login)"

if [[ $login ]]
then
  isoff="$(echo $login | awk -F"--> " '{print $2}')"
  if [[ $isoff == "off" ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}$isoff${NORMAL}"
    fail=0
  else
    echo -e "${NORMAL}RESULT:    ${RED}$isoff${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity14, $controlid, $stigid14, $ruleid14, $cci14, $datetime, ${GRN}PASSED, The operating system prevents privileged accounts from utilizing SSH.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity14, $controlid, $stigid14, $ruleid14, $cci14, $datetime, ${RED}FAILED, The operating system does not prevent privileged accounts from utilizing SSH.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid15${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid15${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid15${NORMAL}"
echo -e "${NORMAL}CCI:       $cci15${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 15:   ${BLD}$title15a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title15b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title15c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity15${NORMAL}"

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

fail=0

secontext="$(grep -r sysadm_r /etc/sudoers /etc/sudoers.d/* 2>/dev/null)"

if [[ $secontext ]]
then
  for line in ${secontext[@]}
  do
    group="$(echo $line | awk '{print $1}')"
    perms="$(echo $line | awk '{print $2}')"
    types="$(echo $line | awk '{print $3}')"
    roles="$(echo $line | awk '{print $4}')"
    limit="$(echo $line | awk '{print $5}')"
    case $group in
      '%wheel')
        if [[ $perms == 'ALL=(ALL)' &&
              $types == 'TYPE=sysadm_t' &&
              $roles == 'ROLE=sysadm_r' &&
              $limit == 'ALL'
           ]]
        then
          echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
        else
          echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
          fail=1
        fi
        ;;
      *)
        echo -e "${NORMAL}RESULT:    $line${NORMAL}"
        ;;
    esac
  done
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned.${NORMAL}"
  fail=1
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity15, $controlid, $stigid15, $ruleid15, $cci15, $datetime, ${GRN}PASSED,The operating system elevates the SELinux context when an administrator calls the sudo command.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity15, $controlid, $stigid15, $ruleid15, $cci15, $datetime, ${RED}FAILED, The operating system does not elevate the SELinux context when an administrator calls the sudo command.${NORMAL}"
fi

exit
