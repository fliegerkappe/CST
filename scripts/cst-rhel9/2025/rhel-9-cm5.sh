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

controlid="CM-5 Access Restrictions for Change"

title1a="RHEL 9 system commands must have mode 755 or less permissive."
title1b="Checking with: find -L /bin /sbin /usr/bin /usr/sbin /usr/libexec /usr/local/bin /usr/local/sbin -perm /022 -exec ls -l {} \;"
title1c="Expecting: ${YLO}Nothing returned
           NOTE: If any system commands are found to be group-writable or world-writable, this is a finding."${BLD}
cci1="CCI-001499"
stigid1="RHEL-09-232010"
severity1="CAT II"
ruleid1="SV-257882r991560"
vulnid1="V-257882"

title2a="RHEL 9 library directories must have mode 755 or less permissive."
title2b="Checking with: find -L /lib /lib64 /usr/lib /usr/lib64 -perm /022 -type d -exec ls -l {} \;"
title2c="Expecting: ${YLO}Nothing returned
           NOTE: If any system-wide shared library file is found to be group-writable or world-writable, this is a finding."${BLD}
cci2="CCI-001499"
stigid2="RHEL-09-232015"
severity2="CAT II"
ruleid2="SV-257883r991560"
vulnid2="V-257883"

title3a="RHEL 9 must prevent the loading of a new kernel for later execution."
title3b="Checking with:
           a. sysctl kernel.kexec_load_disable
           b. grep -r kernel.kexec_load_disabled /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf /etc/sysctl.d/*.conf"
title3c="Expecting: ${YLO}
           a. kernel.kexec_load_disabled = 1
           b. /etc/sysctl.d/99-sysctl.conf:kernel.kexec_load_disabled = 1
           NOTE: a. If \"kernel.kexec_load_disabled\" is not set to \"1\" or is missing, this is a finding.
           NOTE: b. If \"kernel.kexec_load_disabled\" is not set to \"1\", is missing, or commented out, this is a finding.
           NOTE: If \"kernel.kexec_load_disabled\" is not set to \"1\" or is missing, this is a finding."${BLD}
cci3="CCI-003992 CCI-001749"
stigid3="RHEL-09-213020"
severity3="CAT II"
ruleid3="SV-257799r1106273"
vulnid3="V-257799"

title4a="RHEL 9 must ensure cryptographic verification of vendor software packages."
title4b="Checking with: 
           a. rpm -q --queryformat \"%{SUMMARY}\n\" gpg-pubkey | grep -i \"red hat\"
           b. gpg -q --keyid-format short --with-fingerprint /etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release"
title4c="Expecting: ${YLO}
           a. Red Hat, Inc. (release key 2) <security@redhat.com> public key
           a. Red Hat, Inc. (auxiliary key 3) <security@redhat.com> public key
           b. pub   rsa4096/FD431D51 2009-10-22 [SC]
           b.       Key fingerprint = 567E 347A D004 4ADE 55BA  8A5F 199E 2F91 FD43 1D51
           b. uid                   Red Hat, Inc. (release key 2) <security@redhat.com>
           b. pub   rsa4096/5A6340B3 2022-03-09 [SC]
           b.       Key fingerprint = 7E46 2425 8C40 6535 D56D  6F13 5054 E4A4 5A63 40B3
           b. uid                   Red Hat, Inc. (auxiliary key 3) <security@redhat.com>
           NOTE: If Red Hat GPG keys \"release key 2\" and \"auxiliary key 3\" are not installed, this is a finding.
           NOTE: Compare key fingerprints of installed Red Hat GPG keys with fingerprints listed for RHEL 9 on Red Hat \"Product Signing Keys\" webpage at https://access.redhat.com/security/team/key. If key fingerprints do not match, this is a finding."${BLD}
cci4="CCI-003992 CCI-001749"
stigid4="RHEL-09-214010"
severity4="CAT II"
ruleid4="SV-257819r1015075"
vulnid4="V-257819"

title5a="RHEL 9 must check the GPG signature of software packages originating from external software repositories before installation."
title5b="Checking with: grep -w gpgcheck /etc/dnf/dnf.conf"
title5c="Expecting: ${YLO}gpgcheck=1
           NOTE: If there is no process to verify GPG signatures that is approved by the organization, this is a finding."${BLD}
cci5="CCI-003992 CCI-001749"
stigid5="RHEL-09-214015"
severity5="CAT I"
ruleid5="SV-257820r1044878"
vulnid5="V-257820"

title6a="RHEL 9 must check the GPG signature of locally installed software packages before installation."
title6b="Checking with: grep localpkg_gpgcheck /etc/dnf/dnf.conf"
title6c="Expecting: ${YLO}localpkg_gpgcheck=1
           NOTE If there is no process to verify GPG signatures that is approved by the organization, this is a finding."${BLD}
cci6="CCI-003992 CCI-001749"
stigid6="RHEL-09-214020"
severity6="CAT I"
ruleid6="SV-257821r1015077"
vulnid6="V-257821"

title7a="RHEL 9 must have GPG signature verification enabled for all software repositories."
title7b="Checking with: grep -w gpgcheck /etc/yum.repos.d/*.repo | more"
title7c="Expecting: ${YLO}gpgcheck = 1
           NOTE: If \"gpgcheck\" is not set to \"1\" for all returned lines, this is a finding."${BLD}
cci7="CCI-003992 CCI-001749"
stigid7="RHEL-09-214025"
severity7="CAT I"
ruleid7="SV-257822r1044880"
vulnid7="V-257822"

title8a="RHEL 9 subscription-manager package must be installed."
title8b="Checking with: dnf list --installed subscription-manager"
title8c="Expecting: ${YLO}subscription-manager.x86_64          1.29.26-3.el9_0
           NOTE: If the \"subscription-manager\" package is not installed, this is a finding."${BLD}
cci8="CCI-003992 CCI-001749"
stigid8="RHEL-09-215010"
severity8="CAT II"
ruleid8="SV-257825r1044888"
vulnid8="V-257825"

title9a="RHEL 9 library files must have mode 755 or less permissive."
title9b="Checking with: find /lib /lib64 /usr/lib /usr/lib64 -type f -name '*.so*' -perm /022 -exec stat -c \"%a %an\" {} +"
title9c="Expecting: ${YLO}Nothing returned
           NOTE: If any output is returned, this is a finding."${BLD}
cci9="CCI-001499"
stigid9="RHEL-09-232020"
severity9="CAT II"
ruleid9="SV-257884r1106306"
vulnid9="V-257884"

title10a="RHEL 9 system commands must be owned by root."
title10b="Checking with: find -L /bin /sbin /usr/bin /usr/sbin /usr/libexec /usr/local/bin /usr/local/sbin ! -user root -exec stat -L -c \"%U %n\" {} \;"
title10c="Expecting: ${YLO}NOthing returned
           NOTE: If any system commands are found to not be owned by root, this is a finding."${BLD}
cci10="CCI-001499"
stigid10="RHEL-09-232190"
severity10="CAT II"
ruleid10="SV-257918r1044977"
vulnid10="V-257918"

title11a="RHEL 9 system commands must be group-owned by root or a system account."
title11b="Checking with: find -L /bin /sbin /usr/bin /usr/sbin /usr/libexec /usr/local/bin /usr/local/sbin ! -group root -exec stat -L -c \"%G %n\" {} \;"
title11c="Expecting: ${YLO}Nothing returned
           NOTE: If any system commands are returned and are not group-owned by a required system account, this is a finding."${BLD}
cci11="CCI-001499"
stigid11="RHEL-09-232195"
severity11="CAT II"
ruleid11="SV-257919r1044979"
vulnid11="V-257919"

title12a="RHEL 9 library files must be owned by root."
title12b="Checking with: find /lib /lib64 /usr/lib /usr/lib64 -type f -name '*.so*' ! -user root -exec stat -c \"%U %n\" {} +"
title12c="Expecting: ${YLO}Nothing returned
           NOTE: If any output is returned, this is a finding."${BLD}
cci12="CCI-001499"
stigid12="RHEL-09-232200"
severity12="CAT II"
ruleid12="SV-257920r1101926"
vulnid12="V-257920"

title13a="RHEL 9 library files must be group-owned by root or a system account."
title13b="Checking with: find /lib /lib64 /usr/lib /usr/lib64 -type f -name '*.so*' ! -group root -exec stat -c \"%G %n\" {} +"
title13c="Expecting: ${YLO}Nothing returned
           NOTE: If any output is returned, this is a finding."${BLD}
cci13="CCI-001499"
stigid13="RHEL-09-232205"
severity13="CAT II"
ruleid13="SV-257921r1106308"
vulnid13="V-257921"

title14a="RHEL 9 library directories must be owned by root."
title14b="Checking with: find /lib /lib64 /usr/lib /usr/lib64 ! -user root -type d -exec stat -c \"%U %n\" {} \;"
title14c="Expecting: ${YLO}Nothing returned
           NOTE: If any systemwide shared library directory is not owned by \"root\", this is a finding."${BLD}
cci14="CCI-001499"
stigid14="RHEL-09-232210"
severity14="CAT II"
ruleid14="SV-257922r1044988"
vulnid14="V-257922"

title15a="RHEL 9 library directories must be group-owned by root or a system account."
title15b="Checking with: find /lib /lib64 /usr/lib /usr/lib64 ! -group root -type d -exec stat -c \"%G %n\" {} \;"
title15c="Expecting: ${YLO}Nothing returned
           NOTE: If any systemwide shared library directory is returned and is not group-owned by a required system account, this is a finding."${BLD}
cci15="CCI-001499"
stigid15="RHEL-09-232215"
severity15="CAT II"
ruleid15="SV-257923r1044991"
vulnid15="V-257923"

title16a="RHEL 9 SSH daemon must not allow GSSAPI authentication."
title16b="Checking with: /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print \$4}' | tr -d '\\\\r' | tr '\\\\n' ' ' | xargs grep -iH '^\s*gssapiauthentication'"
title16c="Expecting: ${YLO}GSSAPIAuthentication no
           NOTE: If the value is returned as \"yes\", the returned line is commented out, no output is returned, and the use of GSSAPI authentication has not been documented with the information system security officer (ISSO), this is a finding."${BLD}
cci16="CCI-001813"
stigid16="RHEL-09-255135"
severity16="CAT II"
ruleid16="SV-258003r1045065"
vulnid16="V-258003"

title17a="RHEL 9 SSH daemon must not allow Kerberos authentication."
title17b="Checking with: /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print \$4}' | tr -d '\\\\r' | tr '\\\\n' ' ' | xargs grep -iH '^\s*kerberosauthentication'"
title17c="Expecting: ${YLO}KerberosAuthentication no
           NOTE: If the value is returned as \"yes\", the returned line is commented out, no output is returned, and the use of Kerberos authentication has not been documented with the information system security officer (ISSO), this is a finding."${BLD}
cci17="CCI-001813"
stigid17="RHEL-09-255140"
severity17="CAT II"
ruleid17="SV-258004r1045067"
vulnid17="V-258004"

title18a="RHEL 9 audit package must be installed."
title18b="Checking with: dnf list --installed audit"
title18c="Expecting: ${YLO}audit-3.0.7-101.el9_0.2.x86_64
           NOTE: If the \"audit\" package is not installed, this is a finding."${BLD}
cci18="CCI-000130 CCI-000131 CCI-000132 CCI-000133 CCI-000134 CCI-000135 CCI-000154 CCI-000158 CCI-000159 CCI-000169 CCI-000172 CCI-001464 CCI-001487 CCI-003938 CCI-001875 CCI-001876 CCI-001877 CCI-001878 CCI-001879 CCI-001880 CCI-001881 CCI-001882 CCI-001889 CCI-001914 CCI-002884 CCI-001814"
stigid18="RHEL-09-653010"
severity18="CAT II"
ruleid18="SV-258151r1045298"
vulnid18="V-258151"

title19a="RHEL 9 audit service must be enabled."
title19b="Checking with: systemctl status auditd.service"
title19c="Expecting: ${YLO}
           auditd.service - Security Auditing Service
           Loaded:loaded (/usr/lib/systemd/system/auditd.service; enabled; vendor preset: enabled)
           Active: active (running) since Tues 2022-05-24 12:56:56 EST; 4 weeks 0 days ago
           NOTE: If the audit service is not \"active\" and \"running\", this is a finding."${BLD}
cci19="CCI-000130 CCI-000131 CCI-000132 CCI-000133 CCI-000134 CCI-000135 CCI-000154 CCI-000158 CCI-000159 CCI-000169 CCI-000172 CCI-001464 CCI-001487 CCI-003938 CCI-001875 CCI-001876 CCI-001877 CCI-001878 CCI-001879 CCI-001880 CCI-001881 CCI-001882 CCI-001889 CCI-001914 CCI-002884 CCI-001814"
stigid19="RHEL-09-653015"
severity19="CAT II"
ruleid19="SV-258152r1015127"
vulnid19="V-258152"

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

syscmd="$(find -L /bin /sbin /usr/bin /usr/sbin /usr/libexec /usr/local/bin /usr/local/sbin -perm /022 -exec ls -l {} \;)"

if [[ $syscmd ]]
then
  fail=1
  for line in ${syscmd[@]}
  do
    echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
  done
else
  echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${GRN}PASSED, RHEL 9 system commands are mode 755 or less permissive.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${RED}FAILED, RHEL 9 system commands are not mode 755 or less permissive.${NORMAL}"
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

libdir="$(find -L /bin /sbin /usr/bin /usr/sbin /usr/libexec /usr/local/bin /usr/local/sbin -perm /022 -exec ls -l {} \;)"

if [[ $libdir ]]
then
  fail=1
  for line in ${libdir[@]}
  do
    echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
  done
else
  echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${GRN}PASSED, RHEL 9 library directories are mode 755 or less permissive.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${RED}FAILED, RHEL 9 library directories are not mode 755 or less permissive.${NORMAL}"
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

fail=1

datetime="$(date +%FT%H:%M:%S)"

disabled1="$(sysctl kernel.kexec_load_disabled)"
disabled2="$(grep -r kernel.kexec_load_disabled 2>/dev/null /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf /etc/sysctl.d/*.conf)"
test1=0
test2=0

if [[ $disabled1 ]]
then
  value="$(echo $disabled1 | awk -F= '{print $2}' | sed 's/ //')"
  if [[ $value == 1 ]]
  then
    test1=1
    echo -e "${NORMAL}RESULT:    ${BLD}a. $disabled1${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}a. $disabled1${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $disabled2 ]]
then
  for line in ${disabled2[@]}
  do
    file="$(echo $line | awk -F: '{print $1}')"
    setting="$(echo $line | awk -F: '{print $2}')"
    value="$(echo $setting | awk -F= '{print $2}' | sed 's/ //')"
    if [[ $value == 1 ]]
    then
      test2=1
      echo -e "${NORMAL}RESULT:    ${CYN}b. $file:${BLD}$setting${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${CYN}b. $file:${RED}$setting${NORMAL}"
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $test1 == 1 && $test2 == 1 ]]
then
  echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${GRN}PASSED, RHEL 9 prevents the loading of a new kernel for later execution.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${RED}FAILED, RHEL 9 does not prevent the loading of a new kernel for later execution.${NORMAL}"
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

keys="$(rpm -q --queryformat "%{SUMMARY}\n" gpg-pubkey | grep -i "red hat")"
if [[ $keys ]]
then
  for key in ${keys[@]}
  do
    if [[ $key =~ 'release key 2' ]]
    then
      key2=1
      echo -e "${NORMAL}RESULT:    a. ${BLD}$key${NORMAL}"
    elif [[ $key =~ 'auxiliary key 3' ]]
    then
      auxkey3=1
      echo -e "${NORMAL}RESULT:    a. ${BLD}$key${NORMAL}"
    else
      fail=1
      echo -e "${NORMAL}RESULT:    a. $key${NORMAL}"
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${RED}a. Nothing returned${NORMAL}"
fi

installedkeys="$(gpg -q --keyid-format short --with-fingerprint 2>/dev/null /etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release)"
if [[ $installedkeys ]]
then
  for key in ${installedkeys[@]}
  do
    echo -e "${NORMAL}RESULT:    b. $key${NORMAL}"
  done
else
  fail=1
  echo -e "${NORMAL}RESULT:    ${RED}b. Nothing returned${NORMAL}"
fi

if [[ $key2 == 1 && $auxkey3 == 1 ]]
then
  echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${CYN}VERIFY, RHEL 9 ensures cryptographic verification of vendor software packages. Compare key fingerprints of installed Red Hat GPG keys with fingerprints listed for RHEL 9 on Red Hat \"Product Signing Keys\" webpage at https://access.redhat.com/security/team/key.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${RED}FAILED, RHEL 9 does not ensure cryptographic verification of vendor software packages.${NORMAL}"
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

fail=1

datetime="$(date +%FT%H:%M:%S)"

check="$(grep -w gpgcheck /etc/dnf/dnf.conf)"
if [[ $check ]]
then
  for line in ${check[@]}
  do
    value="$(echo $line | awk -F= '{print $2}' | sed 's/ //')"
    if [[ $value == 1 && ${line:0:1} != "#" ]]
    then
      fail=0
      echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity5, $controlid, $stigid5, $ruleid5, $cci5, $datetime, ${GRN}PASSED, RHEL 9 checks the GPG signature of software packages originating from external software repositories before installation.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity5, $controlid, $stigid5, $ruleid5, $cci5, $datetime, ${RED}FAILED, RHEL 9 does not check the GPG signature of software packages originating from external software repositories before installation.${NORMAL}"
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

fail=0

datetime="$(date +%FT%H:%M:%S)"

check="$(grep localpkg_gpgcheck /etc/dnf/dnf.conf)"
if [[ $check ]]
then
  for line in ${check[@]}
  do
    value="$(echo $line | awk -F= '{print $2}' | sed 's/ //')"
    if [[ $value == 1 && ${line:0:1} != "#" ]]
    then
      fail=0
      echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity6, $controlid, $stigid6, $ruleid6, $cci6, $datetime, ${GRN}PASSED, RHEL 9 checks the GPG signature of locally installed software packages before installation.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity6, $controlid, $stigid6, $ruleid6, $cci6, $datetime, ${RED}FAILED, RHEL 9 does not check the GPG signature of locally installed software packages before installation.${NORMAL}"
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

passcnt=0
failcnt=0

check="$(grep -w gpgcheck /etc/yum.repos.d/*.repo | more)"
if [[ $check ]]
then
  for line in ${check[@]}
  do
    value="$(echo $line | awk -F= '{print $2}' | sed 's/ //')"
    if [[ $value == 1 || ${line:0:1} != "#" ]]
    then
      (( passcnt++ ))
    else
      (( failcnt++ ))   
      echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if (( $passcnt > 0 )) && [[ $failcnt == 0 ]]
then
  echo -e "${NORMAL}RESULT:    ${BLD}Signatures with \"gpgcheck = 1\"       $passcnt${NORMAL}"
  echo -e "${NORMAL}RESULT:    ${BLD}Signatures without \"gpgcheck = 1\"    $failcnt${NORMAL}"
  fail=0
else
  echo -e "${NORMAL}RESULT:    ${BLD}Signatures with \"gpgcheck = 1\"       $passcnt${NORMAL}"
  echo -e "${NORMAL}RESULT:    ${RED}Signatures without \"gpgcheck = 1\"    $failcnt${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity7, $controlid, $stigid7, $ruleid7, $cci7, $datetime, ${GRN}PASSED, RHEL 9 has GPG signature verification enabled for all software repositories.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity7, $controlid, $stigid7, $ruleid7, $cci7, $datetime, ${RED}FAILED, RHEL 9 does not have GPG signature verification enabled for all software repositories.${NORMAL}"
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

fail=1

datetime="$(date +%FT%H:%M:%S)"

isinstalled="$(dnf list --installed 2>&1 subscription-manager | grep -Ev 'Updating|Installed')"
if [[ $isinstalled ]]
then
  fail=0
  echo -e "${NORMAL}RESULT:    ${BLD}$isinstalled${NORMAL}"
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity8, $controlid, $stigid8, $ruleid8, $cci8, $datetime, ${GRN}PASSED, The RHEL 9 subscription-manager package is installed.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity8, $controlid, $stigid8, $ruleid8, $cci8, $datetime, ${BLD}PASSED, The RHEL 9 subscription-manager package is not installed.${NORMAL}"
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

fail=1

datetime="$(date +%FT%H:%M:%S)"

libfiles="$(find /lib /lib64 /usr/lib /usr/lib64 -type f -name '*.so*' -perm /022 -exec stat -c "%n %a" {} +)"
if [[ $libfiles ]]
then
  fail=1
  for line in ${libfiles[@]}
  do
    echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
  done
else
  echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity9, $controlid, $stigid9, $ruleid9, $cci9, $datetime, ${GRN}PASSED, RHEL 9 library files are mode 755 or less permissive.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity9, $controlid, $stigid9, $ruleid9, $cci9, $datetime, ${GRN}PASSED, RHEL 9 library files are not mode 755 or less permissive.${NORMAL}"
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

fail=0

datetime="$(date +%FT%H:%M:%S)"

owner="$(find -L /bin /sbin /usr/bin /usr/sbin /usr/libexec /usr/local/bin /usr/local/sbin ! -user root -exec stat -L -c "%U %n" {} \;)"

if [[ $owner ]]
then
  fail=1
  for line in ${owner[@]}
  do
    echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
  done
else
  echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity10, $controlid, $stigid10, $ruleid10, $cci10, $datetime, ${GRN}PASSED, RHEL 9 system commands are owned by root.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity10, $controlid, $stigid10, $ruleid10, $cci10, $datetime, ${GRN}PASSED, RHEL 9 system commands are not owned by root.${NORMAL}"
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

fail=0

datetime="$(date +%FT%H:%M:%S)"

gowner="$(find -L /bin /sbin /usr/bin /usr/sbin /usr/libexec /usr/local/bin /usr/local/sbin ! -user root -exec stat -L -c "%G %n" {} \;)"

if [[ $gowner ]]
then
  fail=1
  for line in ${gowner[@]}
  do
    echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
  done
else
  echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity11, $controlid, $stigid11, $ruleid11, $cci11, $datetime, ${GRN}PASSED, RHEL 9 system commands are group-owned by root.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity11, $controlid, $stigid11, $ruleid11, $cci11, $datetime, ${GRN}PASSED, RHEL 9 system commands are not group-owned by root.${NORMAL}"
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

fail=0

datetime="$(date +%FT%H:%M:%S)"

libfiles="$(find /lib /lib64 /usr/lib /usr/lib64 -type f -name '*.so*' ! -user root -exec stat -c "%U %n" {} +)"

if [[ $libfiles ]]
then
  fail=1
  for line in ${libfiles[@]}
  do
    echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
  done
else
  echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity12, $controlid, $stigid12, $ruleid12, $cci12, $datetime, ${GRN}PASSED, RHEL 9 library files are owned by root.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity12, $controlid, $stigid12, $ruleid12, $cci12, $datetime, ${GRN}PASSED, RHEL 9 library files are not owned by root.${NORMAL}"
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

fail=0

datetime="$(date +%FT%H:%M:%S)"

libdirs="$(find /lib /lib64 /usr/lib /usr/lib64 ! -user root -type d -exec stat -c "%U %n" {} \;)"

if [[ $libdirs ]]
then
  fail=1
  for line in ${libdirs[@]}
  do
    echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
  done
else
  echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity13, $controlid, $stigid13, $ruleid13, $cci13, $datetime, ${GRN}PASSED, RHEL 9 library directories are owned by root.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity13, $controlid, $stigid13, $ruleid13, $cci13, $datetime, ${GRN}PASSED, RHEL 9 library directories are not owned by root.${NORMAL}"
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

fail=0

datetime="$(date +%FT%H:%M:%S)"

libdirs="$(find /lib /lib64 /usr/lib /usr/lib64 ! -user root -type d -exec stat -c "%U %n" {} \;)"

if [[ $libdirs ]]
then
  fail=1
  for line in ${libdirs[@]}
  do
    echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
  done
else
  echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity14, $controlid, $stigid14, $ruleid14, $cci14, $datetime, ${GRN}PASSED, RHEL 9 library directories are owned by root.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity14, $controlid, $stigid14, $ruleid14, $cci14, $datetime, ${GRN}PASSED, RHEL 9 library directories are not owned by root.${NORMAL}"
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

fail=0

datetime="$(date +%FT%H:%M:%S)"

libdirs="$(find /lib /lib64 /usr/lib /usr/lib64 ! -user root -type d -exec stat -c "%G %n" {} \;)"

if [[ $libdirs ]]
then
  fail=1
  for line in ${libdirs[@]}
  do
    echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
  done
else
  echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity15, $controlid, $stigid15, $ruleid15, $cci15, $datetime, ${GRN}PASSED, RHEL 9 library directories are group-owned by root.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity15, $controlid, $stigid15, $ruleid15, $cci15, $datetime, ${GRN}PASSED, RHEL 9 library directories are not group-owned by root.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid16${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid16${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid16${NORMAL}"
echo -e "${NORMAL}CCI:       $cci16${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 16:   ${BLD}$title16a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title16b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title16c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity16${NORMAL}"

IFS='
'

fail=1

datetime="$(date +%FT%H:%M:%S)"

auth="$(/usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs grep -iH '^\s*gssapiauthentication')"

if [[ $auth ]]
then
  file="$(echo $auth | awk -F: '{print $1}')"
  setting="$(echo $auth | awk -F: '{print $2}')"
  value="$(echo $setting | awk '{print tolower($2)}')"
  if [[ $value == "no" ]]
  then
    fail=0
    echo -e "${NORMAL}RESULT:    ${CYN}$file:${BLD}$setting${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${CYN}$file:${BLD}$setting${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity16, $controlid, $stigid16, $ruleid16, $cci16, $datetime, ${GRN}PASSED, The RHEL 9 SSH daemon does not allow GSSAPI authentication.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity16, $controlid, $stigid16, $ruleid16, $cci16, $datetime, ${GRN}PASSED, The RHEL 9 SSH daemon allows GSSAPI authentication.${NORMAL}"
fi



echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid17${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid17${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid17${NORMAL}"
echo -e "${NORMAL}CCI:       $cci17${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 17:   ${BLD}$title17a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title17b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title17c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity17${NORMAL}"

IFS='
'

fail=0

datetime="$(date +%FT%H:%M:%S)"

auth="$(/usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs grep -iH '^\s*kerberosauthentication')"

if [[ $auth ]]
then
  file="$(echo $auth | awk -F: '{print $1}')"
  setting="$(echo $auth | awk -F: '{print $2}')"
  value="$(echo $setting | awk '{print tolower($2)}')"
  if [[ $value == "no" ]]
  then
    fail=0
    echo -e "${NORMAL}RESULT:    ${CYN}$file:${BLD}$setting${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${CYN}$file:${BLD}$setting${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity17, $controlid, $stigid17, $ruleid17, $cci17, $datetime, ${GRN}PASSED, The RHEL 9 SSH daemon does not allow Kerberos authentication.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity17, $controlid, $stigid17, $ruleid17, $cci17, $datetime, ${GRN}PASSED, The RHEL 9 SSH daemon allows Kerberos authentication.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid18${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid18${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid18${NORMAL}"
echo -e "${NORMAL}CCI:       $cci18${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 18:   ${BLD}$title18a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title18b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title18c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity18${NORMAL}"

datetime="$(date +%FT%H:%M:%S)"

echo -e "${NORMAL}$hostname, $severity18, $controlid, $stigid18, $ruleid18, $cci18, $datetime, ${CYN}VERIFY, (See AU-12 Audit Generation: V-258151)${NORMAL}"

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid19${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid19${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid19${NORMAL}"
echo -e "${NORMAL}CCI:       $cci19${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 19:   ${BLD}$title19a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title19b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title19c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity19${NORMAL}"

datetime="$(date +%FT%H:%M:%S)"

echo -e "${NORMAL}$hostname, $severity19, $controlid, $stigid19, $ruleid19, $cci19, $datetime, ${CYN}VERIFY, (See AU-12 Audit Generation: V-258152)${NORMAL}"









exit
