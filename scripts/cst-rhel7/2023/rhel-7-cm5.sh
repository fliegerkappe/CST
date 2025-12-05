#! /bin/bash

# CM-5 Access Restrictions for Change

# CONTROL: The organization defines, documents, approves, and enforces physical and logical
# access restriction associated with changes to the information system.

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

controlid="CM-5 Access Restrictions for Change"

title1a="The Red Hat Enterprise Linux operating system must prevent the installation of software, patches, service packs, device drivers, or operating system components from a repository without verification they have been digitally signed using a certificate that is issued by a Certificate Authority (CA) that is recognized and approved by the organization."
title1b="Checking with 'grep gpgcheck /etc/yum.conf'."
title1c="Expecting:${YLO}
           gpgcheck=1
           Note: If \"gpgcheck\" is not set to \"1\", or if options are missing or commented out, ask the System Administrator how the certificates for patches and other operating system components are verified. 
           Note: If there is no process to validate certificates that is approved by the organization, this is a finding.
           Note: If there is no process to validate certificates that is approved by the organization, this is a finding."${BLD}
cci1="CCI-001749"
stigid1="RHEL-07-020050"
severity1="CAT I"
ruleid1="SV-204447r603261_rule"
vulnid1="V-204447"

title2a="The Red Hat Enterprise Linux operating system must prevent the installation of software, patches, service packs, device drivers, or operating system components of local packages without verification they have been digitally signed using a certificate that is issued by a Certificate Authority (CA) that is recognized and approved by the organization."
title2b="Checking with 'grep localpkg_gpgcheck /etc/yum.conf'."
title2c="Expecting:${YLO}
           localpkg_gpgcheck=1
           Note: If \"localpkg_gpgcheck\" is not set to \"1\", or if options are missing or commented out, ask the System Administrator how the signatures of local packages and other operating system components are verified. 
           Note: If there is no process to validate the signatures of local packages that is approved by the organization, this is a finding."${BLD}
cci2="CCI-001749"
stigid2="RHEL-07-020060"
severity2="CAT I"
ruleid2="SV-204448r603261_rule"
vulnid2="V-204448"

title3a="The Red Hat Enterprise Linux operating system must be configured so that all system device files are correctly labeled to prevent unauthorized modification."
title3b="Checking with
           a. 'find /dev -context *:device_t:* \( -type c -o -type b \) -printf \"\%p \%Z'
           b. 'find /dev -context *:unlabeled_t:* \( -type c -o -type b \) -printf \"\%p \%Z'."
title3c="Expecting:${YLO}
           Nothing returned.
           Note: There are device files, such as \"/dev/vmci\", that are used when the operating system is a host virtual machine. They will not be owned by a user on the system and require the \"device_t\" label to operate. These device files are not a finding. 
           Note: If there is output from either of these commands, other than already noted, this is a finding."${BLD}
cci3="CCI-000318"
stigid3="RHEL-07-020900"
severity3="CAT II"
ruleid3="SV-204479r603261_rule"
vulnid3="V-204479"

title4a="The Red Hat Enterprise Linux operating system must set the umask value to 077 for all local interactive user accounts."
title4b="Checking with 'grep -i umask /home/*/.*'."
title4c="Expecting:${YLO}
           Nothing returned
           Note: If any local interactive user initialization files are found to have a umask statement that has a value less restrictive than \"077\", this is a finding."${BLD}
cci4="CCI-000318"
stigid4="RHEL-07-021040"
severity4="CAT II"
ruleid4="SV-204488r603261_rule"
vulnid4="V-204488"

title5a="The Red Hat Enterprise Linux operating system must not allow removable media to be used as the boot loader unless approved."
title5b="Checking with
           a. 'find / -name grub.cfg' then 'grep -c menuentry /boot/grub2/grub.cfg'
           b. 'grep ‘set root’ /boot/grub2/grub.cfg'.."
title5c="Expecting:${YLO}
           a. /boot/grub2/grub.cfg (for systems that use BIOS)
              (or /boot/efi/EFI/redhat/grub.cfg for systems that use UEFI)
           b. set root=(hd0,1)
           Note: If a \"grub.cfg\" is found in any subdirectories other than \"/boot/grub2\" and \"/boot/efi/EFI/redhat\", ask the System Administrator if there is documentation signed by the ISSO to approve the use of removable media as a boot loader.
           Note: If the system is using an alternate boot loader on removable media, and documentation does not exist approving the alternate configuration, this is a finding."${BLD}
cci5="CCI-000318"
stigid5="RHEL-07-021700"
severity5="CAT II"
ruleid5="SV-204501r603261_rule"
vulnid5="V-204501"

title6a="The Red Hat Enterprise Linux operating system must be configured so that the rsyslog daemon does not accept log messages from other servers unless the server is being used for log aggregation."
title6b="Checking with
           a. 'grep imtcp /etc/rsyslog.conf'.
           b. 'grep imudp /etc/rsyslog.conf'
           c. 'grep imrelp /etc/rsyslog.conf'"
title6c="Expecting:${YLO}
           Nothing returned, or
           a. \$ModLoad imtpc  (if documented)
           b. \$ModLoad imudp  (if documented)
           c. \$ModLoad imrelp (if documented)
           Note: If any of the above modules are being loaded in the \"/etc/rsyslog.conf\" file, ask to see the documentation for the system being used for log aggregation. 
           Note: If the documentation does not exist, or does not specify the server as a log aggregation system, this is a finding."
cci6="CCI-000318"
stigid6="RHEL-07-031010"
severity6="CAT II"
ruleid6="SV-204575r603261_rule"
vulnid6="V-204575"

title7a="The Red Hat Enterprise Linux operating system must be configured so that the SSH daemon does not permit Generic Security Service Application Program Interface (GSSAPI) authentication unless needed."
title7b="Checking with 'grep -i gssapiauth /etc/ssh/sshd_config'."
title7c="Expecting:${YLO}
           GSSAPIAuthentication no
           Note: If the \"GSSAPIAuthentication\" keyword is missing, is set to \"yes\" and is not documented with the Information System Security Officer (ISSO), or the returned line is commented out, this is a finding."${BLD}
cci7="CCI-000318"
stigid7="RHEL-07-040430"
severity7="CAT II"
ruleid7="SV-204598r603261_rule"
vulnid7="V-204598"

title8a="The Red Hat Enterprise Linux operating system must be configured so that the SSH daemon does not permit Kerberos authentication unless needed."
title8b="Checking with 'grep -i kerberosauth /etc/ssh/sshd_config'."
title8c="Expecting:${YLO}
           KerberosAuthentication no
           Note: If the \"KerberosAuthentication\" keyword is missing, or is set to \"yes\" and is not documented with the Information System Security Officer (ISSO), or the returned line is commented out, this is a finding."${BLD}
cci8="CCI-000318"
stigid8="RHEL-07-040440"
severity8="CAT II"
ruleid8="SV-204599r603261_rule"
vulnid8="V-204599"

title9a="The Red Hat Enterprise Linux operating system must not have the Trivial File Transfer Protocol (TFTP) server package installed if not required for operational support."
title9b="Checking with 'yum list installed | grep tftp-server'."
title9c="Expecting:${YLO}
           Nothing returned - or tftp-server-0.49-9.el7.x86_64.rpm if documented
           Note: If TFTP is installed and the requirement for TFTP is not documented with the ISSO, this is a finding."${BLD}
cci9="CCI-000318"
stigid9="RHEL-07-040700"
severity9="CAT I"
ruleid9="SV-204621r603261_rule"
vulnid9="V-204621"

title10a="The Red Hat Enterprise Linux operating system must be configured so that the cryptographic hash of system files and commands matches vendor values."
title10b="Checking with 'rpm -Va --noconfig | grep '^..5'"
title10c="Expecting: ${YLO}
           Nothing returned
           Note: If there is any output from the command for system files or binaries, this is a finding.${BLD}"
cci10="CCI-001749"
stigid10="RHEL-07-010020"
severity10="CAT I"
ruleid10="SV-214799r603261_rule"
vulnid10="V-214799"

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

file1='/etc/yum.conf'
fail=0

if [[ -f $file1 ]]
then
   gpgchk="$(grep ^gpgcheck $file1)"
   if [[ $gpgchk ]]
   then
      gpgchkval="$(echo $gpgchk | awk -F= '{print $2}')"
      if (( $gpgchkval == 1 ))
      then
         echo -e "${NORMAL}RESULT:    ${BLD}$gpgchk${NORMAL}"
      else
         echo -e "${NORMAL}RESULT:    ${RED}$gpgchk${NORMAL}"
         fail=1
      fi
   else
      echo -e "${NORMAL}RESULT:    ${RED}'gpgcheck' is not defined in $file1${NORMAL}"
      fail=1
   fi
   if [[ $fail == 0 ]]
   then
      echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${GRN}PASSED, YUM GPGCHECK: The operating system prevents the installation of software patches service packs device drivers or operating system components from a repository without verification they have been digitally signed using a certificate that is issued by a Certificate Authority (CA) that is recognized and approved by the organization.${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${RED}FAILED, YUM GPGCHECK: The operating system does not prevent the installation of software patches service packs device drivers or operating system components from a repository without verification they have been digitally signed using a certificate that is issued by a Certificate Authority (CA) that is recognized and approved by the organization.${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${RED}$file1 not found${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${RED}FAILED, YUM GPGCHECK: $file1 was not found.${NORMAL}"
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

file2='/etc/yum.conf'
fail=0

if [[ -f $file2 ]]
then
   lclgpgchk="$(grep ^localpkg_gpgcheck $file2)"
   if [[ $lclgpgchk ]]
   then
      lclgpgchkval="$(echo $lclgpgchk | awk -F= '{print $2}')"
      if (( $lclgpgchkval == 1 ))
      then
         echo -e "${NORMAL}RESULT:    ${BLD}$lclgpgchk${NORMAL}"
      else
         echo -e "${NORMAL}RESULT:    ${RED}$lclgpgchk${NORMAL}"
         fail=1
      fi
   else
      echo -e "${NORMAL}RESULT:    ${RED}'localpkg_gpgcheck' is not defined in $file2${NORMAL}"
      fail=1
   fi
   if [[ $fail == 0 ]]
   then
      echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${GRN}PASSED, YUM LOCAL_GPGCHECK: The operating system prevents the installation of software patches service packs device drivers or operating system components of local packages without verification they have been digitally signed using a certificate that is issued by a Certificate Authority (CA) that is recognized and approved by the organization.${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${RED}FAILED, YUM LOCAL_GPGCHECK: The operating system does not prevent the installation of software patches service packs device drivers or operating system components of local packages without verification they have been digitally signed using a certificate that is issued by a Certificate Authority (CA) that is recognized and approved by the organization.${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${RED}$file2 not found${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${RED}FAILED, YUM LOCAL_GPGCHECK: $file2 was not found.${NORMAL}"
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

datetime="$(date +%FT%H:%M:%S)"

echo -e "${NORMAL}$hostname, $severity10, $controlid, $stigid10, $ruleid10, $cci10, $datetime, ${CYN}VERIFY, (See SI-7 Configuration Settings: V-214799)${NORMAL}"

exit
