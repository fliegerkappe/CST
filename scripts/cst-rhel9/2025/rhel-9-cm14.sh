#! /bin/bash

# CM-14 Signed Components
#
# CONTROL:
# Prevent the installation of [Assignment: organization-defined software and firmware components] without 
# verification that the component has been digitally signed using a certificate that is recognized and
# approved by the organization.

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

controlid="CM-14 Signed Components"

title1a="RHEL 9 must prevent the loading of a new kernel for later execution."
title1b="Checking with: 
           a. sysctl kernel.kexec_load_disabled
	   b. grep -r kernel.kexec_load_disabled /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf /etc/sysctl.d/*.conf"
title1c="Expecting: ${YLO}
           a. kernel.kexec_load_disabled = 1
	   b. /etc/sysctl.d/99-sysctl.conf:kernel.kexec_load_disabled = 1
	   NOTE: a. If \"kernel.kexec_load_disabled\" is not set to \"1\" or is missing, this is a finding.
	   NOTE: b. If \"kernel.kexec_load_disabled\" is not set to \"1\", is missing, or commented out, this is a finding.
	   NOTE: If conflicting results are returned, this is a finding."${BLD}
cci1="CCI-003992 CCI-001749"
stigid1="RHEL-09-213020"
severity1="CAT II"
ruleid1="SV-257799r1106273"
vulnid1="V-257799"

title2a="RHEL 9 must ensure cryptographic verification of vendor software packages."
title2b="Checking with: 
           a. rpm -q --queryformat \"%{SUMMARY}\n\" gpg-pubkey | grep -i \"red hat\"
	   b. gpg -q --keyid-format short --with-fingerprint /etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release"
title2c="Expecting: ${YLO}
           a. Red Hat, Inc. (release key 2) <security@redhat.com> public key
           a. Red Hat, Inc. (auxiliary key 3) <security@redhat.com> public key
           b. pub   rsa4096/FD431D51 2009-10-22 [SC]
           b.       Key fingerprint = 567E 347A D004 4ADE 55BA  8A5F 199E 2F91 FD43 1D51
           b. uid                   Red Hat, Inc. (release key 2) <security@redhat.com>
           b. pub   rsa4096/5A6340B3 2022-03-09 [SC]
           b.       Key fingerprint = 7E46 2425 8C40 6535 D56D  6F13 5054 E4A4 5A63 40B3
           b. uid                   Red Hat, Inc. (auxiliary key 3) <security@redhat.com>
           NOTE: a. If Red Hat GPG keys \"release key 2\" and \"auxiliary key 3\" are not installed, this is a finding.
           NOTE: b. If key file \"/etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release\" is missing, this is a finding.
           NOTE: If key fingerprints do not match, this is a finding."${BLD}
cci2="CCI-003992 CCI-001749"
stigid2="RHEL-09-214010"
severity2="CAT II"
ruleid2="SV-257819r1015075"
vulnid2="V-257819"

title3a="RHEL 9 must check the GPG signature of software packages originating from external software repositories before installation."
title3b="Checking with: grep -w gpgcheck /etc/dnf/dnf.conf"
title3c="Expecting: ${YLO}gpgcheck=1
           NOTE: If \"gpgcheck\" is not set to \"1\", or if the option is missing or commented out, ask the system administrator how the GPG signatures of software packages are being verified.
	   NOTE: If there is no process to verify GPG signatures that is approved by the organization, this is a finding."${BLD}
cci3="CCI-003992 CCI-001749"
stigid3="RHEL-09-214015"
severity3="CAT I"
ruleid3="SV-257820r1044878"
vulnid3="V-257820"

title4a="RHEL 9 must check the GPG signature of locally installed software packages before installation."
title4b="Checking with: grep localpkg_gpgcheck /etc/dnf/dnf.conf"
title4c="Expecting: ${YLO}localpkg_gpgcheck=1
           NOTE: If \"localpkg_gpgcheck\" is not set to \"1\", or if the option is missing or commented out, ask the system administrator how the GPG signatures of local software packages are being verified.
	   NOTE: If there is no process to verify GPG signatures that is approved by the organization, this is a finding."${BLD}
cci4="CCI-003992 CCI-001749"
stigid4="RHEL-09-214020"
severity4="CAT I"
ruleid4="SV-257821r1015077"
vulnid4="V-257821"

title5a="RHEL 9 must have GPG signature verification enabled for all software repositories."
title5b="Checking with: grep -w gpgcheck /etc/yum.repos.d/*.repo | more"
title5c="Expecting: ${YLO}gpgcheck = 1
           NOTE: If \"gpgcheck\" is not set to \"1\" for all returned lines, this is a finding."${BLD}
cci5="CCI-003992 CCI-001749"
stigid5="RHEL-09-214025"
severity5="CAT I"
ruleid5="SV-257822r1044880"
vulnid5="V-257822"

title6a="RHEL 9 subscription-manager package must be installed."
title6b="Checking with: dnf list --installed subscription-manager"
title6c="Expecting: ${YLO}subscription-manager.x86_64          1.29.26-3.el9_0
           NOTE: If the \"subscription-manager\" package is not installed, this is a finding."${BLD}
cci6="CCI-003992 CCI-001749"
stigid6="RHEL-09-215010"
severity6="CAT II"
ruleid6="SV-257825r1044888"
vulnid6="V-257825"

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

echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${CYN}VERIFY, (See CM-5 Access Restrictions For Change: V-257799)${NORMAL}"
         
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

echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${CYN}VERIFY, (See CM-5 Access Restrictions For Change: V-257819)${NORMAL}"

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

echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${CYN}VERIFY, (See CM-5 Access Restrictions For Change: V-257820)${NORMAL}"

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

echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${CYN}VERIFY, (See CM-5 Access Restrictions For Change: V-257821)${NORMAL}"

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

echo -e "${NORMAL}$hostname, $severity5, $controlid, $stigid5, $ruleid5, $cci5, $datetime, ${CYN}VERIFY, (See CM-5 Access Restrictions For Change: V-257822)${NORMAL}"

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

echo -e "${NORMAL}$hostname, $severity6, $controlid, $stigid6, $ruleid6, $cci6, $datetime, ${CYN}VERIFY, (See CM-5 Access Restrictions For Change: V-257825)${NORMAL}"

exit
