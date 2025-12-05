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

stig="Red Hat Enterprise Linux 8 Security Technical Implementation Guide :: Version 1, Release: 13 Benchmark Date: 24 Jan 2024"

hostname="$(uname -n)"

if [[ -f /etc/redhat-release ]]
then
   os="$(cat /etc/redhat-release)"
else
   os="OS not defined"
fi

prog="$(basename $0)"

controlid="CM-5 Access Restrictions for Change"

title1a="RHEL 8 system commands must have a mode of 0755 or less permissive."
title1b="Checking with: find -L /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -perm /022 -exec ls -l {} \;"
title1c="Expecting: ${YLO}Nothing returned
           NOTE: If any system commands are found to be group-writable or world-writable, this is a finding."${BLD}
cci1="CCI-001499"
stigid1="RHEL-08-010300"
severity1="CAT II"
ruleid1="SV-230257r792862_rule"
vulnid1="V-230257"

title2a="RHEL 8 system commands must be owned by root."
title2b="Checking with: find -L /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -user root -exec ls -l {} \;"
title2c="Expecting: ${YLO}Nothing returned
           NOTE: If any system commands are returned, this is a finding."${BLD}
cci2="CCI-001499"
stigid2="RHEL-08-010300"
severity2="CAT II"
ruleid2="SV-230258r627750_rule"
vulnid2="V-230258"

title3a="RHEL 8 system commands must be group-owned by root."
title3b="Checking with: find -L /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -group root -exec ls -l {} \;"
title3c="Expecting: ${YLO}Nothing returned
           NOTE: If any system commands are returned, this is a finding."${BLD}
cci3="CCI-001499"
stigid3="RHEL-08-010320"
severity3="CAT II"
ruleid3="SV-230259r792864_rule"
vulnid3="V-230259"

title4a="RHEL 8 library files must have mode of 0755 or less permissive."
title4b="Checking with: find -L /lib /lib64 /usr/lib /usr/lib64 -perm /022 -type f -exec ls -l {} \;"
title4c="Expecting: ${YLO}Nothing returned
           NOTE: If any system-wide shared library file is found to be group-writable or world-writable, this is a finding."${BLD}
cci4="CCI-001499"
stigid4="RHEL-08-010330"
severity4="CAT II"
ruleid4="SV-230260r792867_rule"
vulnid4="V-230260"

title5a="RHEL 8 library files must be owned by root."
title5b="Checking with: find -L /lib /lib64 /usr/lib /usr/lib64 ! -user root -exec ls -l {} \;"
title5c="Expecting: ${YLO}Nothing returned
           NOTE: If any library files are returned, this is a finding."${BLD}
cci5="CCI-001499"
stigid5="RHEL-08-010340"
severity5="CAT II"
ruleid5="SV-230261r627750_rule"
vulnid5="V-230261"

title6a="RHEL 8 library files must be group-owned by root or a system account."
title6b="Checking with: find -L /lib /lib64 /usr/lib /usr/lib64 ! -group root -exec ls -l {} \;"
title6c="Expecting: ${YLO}Nothing returned
           NOTE: If any system wide shared library file is returned and is not group-owned by a required system account, this is a finding."${BLD}
cci6="CCI-001499"
stigid6="RHEL-08-010350"
severity6="CAT II"
ruleid6="SV-230262r627750_rule"
vulnid6="V-230262"

title7a=" RHEL 8 must prevent the installation of software, patches, service packs, device drivers, or operating system components from a repository without verification they have been digitally signed using a certificate that is issued by a Certificate Authority (CA) that is recognized and approved by the organization."
title7b="Checking with: egrep '^\[.*\]|gpgcheck' /etc/yum.repos.d/*.repo"
title7c="Expecting: ${YLO}
           /etc/yum.repos.d/appstream.repo:[appstream]
           /etc/yum.repos.d/appstream.repo:gpgcheck=1
           /etc/yum.repos.d/baseos.repo:[baseos]
           /etc/yum.repos.d/baseos.repo:gpgcheck=1
           NOTE: If "gpgcheck" is not set to "1", or if options are missing or commented out, ask the System Administrator how the certificates for patches and other operating system components are verified.
           NOTE: If there is no process to validate certificates that is approved by the organization, this is a finding."${BLD}
cci7="CCI-001749"
stigid7="RHEL-08-010370"
severity7="CAT I"
ruleid7="SV-230264r627750_rule"
vulnid7="V-230264"

title8a="RHEL 8 must prevent the installation of software, patches, service packs, device drivers, or operating system components of local packages without verification they have been digitally signed using a certificate that is issued by a Certificate Authority (CA) that is recognized and approved by the organization."
title8b="Checking with: grep -i localpkg_gpgcheck /etc/dnf/dnf.conf"
title8c="Expecting: ${YLO}localpkg_gpgcheck =True
           NOTE: If "localpkg_gpgcheck" is not set to either \"1\", \"True\", or \"yes\", commented out, or is missing from \"/etc/dnf/dnf.conf\", this is a finding."${BLD}
cci8="CCI-001749"
stigid8="RHEL-08-010371"
severity8="CAT I"
ruleid8="SV-230265r627750_rule"
vulnid8="V-230265"

title9a="RHEL 8 must prevent the loading of a new kernel for later execution."
title9b="Checking with:
           a. sysctl kernel.kexec_load_disabled
	   b. grep -r kernel.kexec_load_disabled /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf /etc/sysctl.d/*.conf"
title9c="Expecting: ${YLO}
           a. kernel.kexec_load_disabled = 1
	   b. /etc/sysctl.d/99-sysctl.conf:kernel.kexec_load_disabled = 1
           NOTE: a. If \"kernel.kexec_load_disabled\" is not set to \"1\" or is missing, this is a finding.
	   NOTE: b. If \"kernel.kexec_load_disabled\" is not set to \"1\", is missing or commented out, this is a finding."${BLD}
cci9="CCI-001749"
stigid9="RHEL-08-010372"
severity9="CAT II"
ruleid9="SV-230266r818816_rule"
vulnid9="V-230266"

title10a="RHEL 8 library directories must have mode 755 or less permissive."
title10b="Checking with: find /lib /lib64 /usr/lib /usr/lib64 -perm /022 -type d -exec stat -c \"%n %a\" '{}' \;"
title10c="Expecting: ${YLO}Nothing returned
           NOTE: If any system-wide shared library directories are found to be group-writable or world-writable, this is a finding."${BLD}
cci10="CCI-001499"
stigid10="RHEL-08-010331"
severity10="CAT II"
ruleid10="SV-251707r809345_rule"
vulnid10="V-251707"

title11a="RHEL 8 library directories must be owned by root."
title11b="Checking with: find -L /lib /lib64 /usr/lib /usr/lib64 ! -user root -type d -exec stat -c \"%n %U\" {} \;"
title11c="Expecting: ${YLO}Nothing returned
           NOTE: If any library files are returned, this is a finding."${BLD}
cci11="CCI-001499"
stigid11="RHEL-08-010341"
severity11="CAT II"
ruleid11="SV-251708r810012_rule"
vulnid11="V-251708"

title12a="RHEL 8 library directories must be group-owned by root."
title12b="Checking with: find -L /lib /lib64 /usr/lib /usr/lib64 ! -group root -type d -exec stat -c \"%n %G\" {} \;"
title12c="Expecting: ${YLO}Nothing returned
           NOTE: If any library files are returned, this is a finding."${BLD}
cci12="CCI-001499"
stigid12="RHEL-08-010351"
severity12="CAT II"
ruleid12="SV-251709r810014_rule"
vulnid12="V-251709"

title13a="RHEL 8 must ensure cryptographic verification of vendor software packages."
title13b="Checking with:
           a. rpm -q --queryformat \"%{SUMMARY}\" gpg-pubkey | grep -i \"red hat\".
	   b. gpg -q --keyid-format short --with-fingerprint /etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release"
title13c="Expecting ${YLO}
           a. gpg(Red Hat, Inc. (release key 2) <security@redhat.com>)
	   a. gpg(Red Hat, Inc. (auxiliary key) <security@redhat.com>)
	   b. (\"pub\" and \"uid\" info for gpg keys returned in a.)
	   NOTE: If Red Hat GPG keys \"release key 2\" and \"auxiliary key 2\" are not installed, this is a finding.
	   NOTE: The \"auxiliary key 2\" appears as \"auxiliary key\" on a RHEL 8 system.
${BLD}"
cci13="CCI-001749"
stigid13="RHEL-08-010019"
severity13="CAT II"
ruleid13="SV-256973r902752_rule"
vulnid13="V-256973"

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

dir1arr=("/bin" "/sbin" "/usr/bin" "/usr/sbin" "/usr/local/bin" "/usr/local/sbin")

fail=0

datetime="$(date +%FT%H:%M:%S)"

for dir in ${dir1arr[@]}
do
  if [[ -d $dir ]]
  then
    writeable="$(find -L $dir -perm /022 -exec ls -l {} \;)"
    if [[ $writeable ]]
    then
      fail=1
      for file in ${writeable[@]}
      do
        echo -e "${NORMAL}RESULT:    ${RED}$file${NORMAL}"
      done
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}$dir not found${NORMAL}"
  fi
done

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
  echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${GRN}PASSED, RHEL 8 system commands are mode 755 or less permissive.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${RED}FAILED, RHEL 8 system commands are not mode 755 or less permissive.${NORMAL}"
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

dir2arr=("/bin" "/sbin" "/usr/bin" "/usr/sbin" "/usr/local/bin" "/usr/local/sbin")

fail=0

datetime="$(date +%FT%H:%M:%S)"

for dir in ${dir2arr[@]}
do
  if [[ -d $dir ]]
  then
    owner="$(find -L $dir ! -user root -exec ls -l {} \;)"
    if [[ $owner ]]
    then
      fail=1
      for file in ${owner[@]}
      do
        echo -e "${NORMAL}RESULT:    ${RED}$file${NORMAL}"
      done
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}$dir not found${NORMAL}"
  fi
done

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
  echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${GRN}PASSED, RHEL 8 system commands are owned by root.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${RED}FAILED, RHEL 8 system commands are not owned by root.${NORMAL}"
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

dir3arr=("/bin" "/sbin" "/usr/bin" "/usr/sbin" "/usr/local/bin" "/usr/local/sbin")

fail=0

datetime="$(date +%FT%H:%M:%S)"

for dir in ${dir3arr[@]}
do
  if [[ -d $dir ]]
  then
    owner="$(find -L $dir ! -group root -exec ls -l {} \;)"
    if [[ $owner ]]
    then
      fail=1
      for file in ${owner[@]}
      do
        echo -e "${NORMAL}RESULT:    ${RED}$file${NORMAL}"
      done
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}$dir not found${NORMAL}"
  fi
done

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
  echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${GRN}PASSED, RHEL 8 system commands are group-owned by root.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${RED}FAILED, RHEL 8 system commands are not group-owned by root.${NORMAL}"
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

dir4arr=("/lib" "/lib64" "/usr/lib" "/usr/lib64")

fail=0

datetime="$(date +%FT%H:%M:%S)"

for dir in ${dir4arr[@]}
do
  if [[ -d $dir ]]
  then
    writeable="$(find -L $dir -perm /022 -type f -exec ls -l {} \;)"
    if [[ $writeable ]]
    then
      fail=1
      for file in ${writeable[@]}
      do
        echo -e "${NORMAL}RESULT:    ${RED}$file${NORMAL}"
      done
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}$dir not found${NORMAL}"
  fi
done

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
  echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${GRN}PASSED, RHEL 8 library files are mode 755 or less permissive.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${RED}FAILED, RHEL 8 library files are not mode 755 or less permissive.${NORMAL}"
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

dir5arr=("/lib" "/lib64" "/usr/lib" "/usr/lib64")

fail=0

datetime="$(date +%FT%H:%M:%S)"

for dir in ${dir5arr[@]}
do
  if [[ -d $dir ]]
  then
    owner="$(find -L $dir ! -user root -exec ls -l {} \;)"
    if [[ $owner ]]
    then
      fail=1
      for file in ${owner[@]}
      do
        echo -e "${NORMAL}RESULT:    ${RED}$file${NORMAL}"
      done
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}$dir not found${NORMAL}"
  fi
done

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
  echo -e "${NORMAL}$hostname, $severity5, $controlid, $stigid5, $ruleid5, $cci5, $datetime, ${GRN}PASSED, RHEL 8 library files are owned by root.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity5, $controlid, $stigid5, $ruleid5, $cci5, $datetime, ${RED}FAILED, RHEL 8 library files are not owned by root.${NORMAL}"
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

dir6arr=("/lib" "/lib64" "/usr/lib" "/usr/lib64")

fail=0

datetime="$(date +%FT%H:%M:%S)"

for dir in ${dir6arr[@]}
do
  if [[ -d $dir ]]
  then
    owner="$(find -L $dir ! -group root -exec ls -l {} \; | sed 's|\.\.\/||g' 2>/dev/null)"
    if [[ $owner ]]
    then
      fail=1
      for file in ${owner[@]}
      do
	if [[ ${file:0:1} == "l" ]]
	then
	  file="$(echo $file | awk -F ">" '{print $2}' | sed 's/ //g' 2>/dev/null)"
	  file="$(ls -l /$file)"
	  echo -e "${NORMAL}RESULT:    ${RED}$file${NORMAL}"
	else
          echo -e "${NORMAL}RESULT:    ${RED}$file${NORMAL}"
	fi
      done
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}$dir not found${NORMAL}"
  fi
done

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
  echo -e "${NORMAL}$hostname, $severity6, $controlid, $stigid6, $ruleid6, $cci6, $datetime, ${GRN}PASSED, RHEL 8 library files are group-owned by root.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity6, $controlid, $stigid6, $ruleid6, $cci6, $datetime, ${CYN}VERIFY, RHEL 8 library files are not group-owned by root. Verify groups are a required system account.${NORMAL}"
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

dir7="/etc/yum.repos.d"

fail=0

datetime="$(date +%FT%H:%M:%S)"

if [[ $dir7 ]]
then
  gpgcheck="$(egrep '^\[.*\]|gpgcheck' $dir7/*.repo | grep -v "^#")"  
  if [[ $gpgcheck ]]
  then
    for line in ${gpgcheck[@]}
    do
      path="$(echo $line | awk -F: '{print $1}')"
      repo="$(echo $line | awk -F: '{print $2}')"
      if [[ ${repo:0:1} == "[" ]]
      then
	echo -e "${NORMAL}RESULT:    $line${NORMAL}"
      elif [[ $repo =~ "gpgcheck" ]]
      then 
        signed="$(echo $repo | awk -F= '{print $2}')"
        if (( $signed == 1 ))
        then
          echo -e "${NORMAL}RESULT:    $line${NORMAL}"
	else
	  echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
	  fail=1
	fi
      fi
    done
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}\"gpgcheck\" not defined in $dir7${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity7, $controlid, $stigid7, $ruleid7, $cci7, $datetime, ${GRN}PASSED, YUM verifies the signature of packages from a repository prior to install${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity7, $controlid, $stigid7, $ruleid7, $cci7, $datetime, ${RED}FAILED, YUM does not verify the signature of packages from a repository prior to install${NORMAL}"
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

file8="/etc/dnf/dnf.conf"

fail=1

datetime="$(date +%FT%H:%M:%S)"

if [[ $file8 ]]
then
  signed="$(grep -i localpkg_gpgcheck $file8 | grep -v "^#")"
  signedval="$(echo $signed | awk -F= '{print toupper($2)}' | sed 's/ //g')"
  if [[ $signedval == "1" || $signedval == "YES" || $signedval == "TRUE" ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}$signed${NORMAL}"
    fail=0
  else
    echo -e "${NORMAL}RESULT:    ${RED}$signed${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}$file8 not found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity8, $controlid, $stigid8, $ruleid8, $cci8, $datetime, ${GRN}PASSED, YUM is configured to perform a signature check on local packages.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity8, $controlid, $stigid8, $ruleid8, $cci8, $datetime, ${GRN}PASSED, YUM is not configured to perform a signature check on local packages.${NORMAL}"
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

dir9arr=("/run/sysctl.d" "/usr/local/lib/sysctl.d" "/usr/lib/sysctl.d" "/lib/sysctl.d/" "/etc/sysctl.d")
file9="/etc/sysctl.conf"

fail=0

datetime="$(date +%FT%H:%M:%S)"

disabled="$(sysctl kernel.kexec_load_disabled)"
if [[ $disabled ]]
then
  value="$(echo $disabled | awk -F= '{print $2}' | sed 's/ //g')"
  if [[ $value == 1 ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}a. $disabled${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}a. $disabled${NORMAL}"
    fail=1
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}a. \"kernel.kexec_load_disabled\" not defined in sysctl${NORMAL}"
fi

for dir in ${dir9arr[@]}
do
  disabled=$NULL
  disabled="$(grep -r kernel.kexec_load_disabled 2>/dev/null $dir/*.conf | grep -v ":#")"
  if [[ $disabled ]]
  then
    for line in ${disabled[@]}
    do
      path="$(echo $line | awk -F: '{print $1}')"
      value="$(echo $line| awk -F= '{print $2}' | sed 's/ //g')"
      if [[ $value == 1 ]]
      then
        echo -e "${NORMAL}RESULT:    ${BLD}b. $line${NORMAL}"
      else
	echo -e "${NORMAL}RESULT:    ${RED}b. $line${NORMAL}"
	fail=1
      fi
    done
  fi
done


if [[ -f $file9 ]]
then
  disabled=$NULL
  disabled="$(grep -r kernel.kexec_load_disabled 2>/dev/null $file9 | grep -v "^#")"
  if [[ $disabled != $NULL ]]
  then
    value="$(echo $disabled | awk -F= '{print $2}' | sed 's/ //g')"
    if [[ $value == 1 ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}b. $file9:$disabled${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${RED}b. $file9:$disabled${NORMAL}"
      fail=1
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}\"kernel.kexec_load_disabled\" is not defined in $file9${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}$file9 not found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity9, $controlid, $stigid9, $ruleid9, $cci9, $datetime, ${GRN}PASSED, RHEL 8 prevents the loading of a new kernel for later execution.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity9, $controlid, $stigid9, $ruleid9, $cci9, $datetime, ${RED}FAILED, RHEL 8 does not prevent the loading of a new kernel for later execution.${NORMAL}"
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

dir10arr=("/lib" "/lib64" "/usr/lib" "/usr/lib64")

fail=0

datetime="$(date +%FT%H:%M:%S)"

for dir in ${dir10arr[@]}
do
  if [[ -d $dir ]]
  then
    writeable="$(find -L $dir -perm /022 -type d -exec stat "%n %a" '{}' \;)"
    if [[ $writeable ]]
    then
      fail=1
      for file in ${writeable[@]}
      do
        echo -e "${NORMAL}RESULT:    ${RED}$file${NORMAL}"
      done
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}$dir not found${NORMAL}"
  fi
done

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
  echo -e "${NORMAL}$hostname, $severity10, $controlid, $stigid10, $ruleid10, $cci10, $datetime, ${GRN}PASSED, RHEL 8 library files are mode 755 or less permissive.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity10, $controlid, $stigid10, $ruleid10, $cci10, $datetime, ${RED}FAILED, RHEL 8 library files are not mode 755 or less permissive.${NORMAL}"
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

dir11arr=("/lib" "/lib64" "/usr/lib" "/usr/lib64")

fail=0

datetime="$(date +%FT%H:%M:%S)"

for dir in ${dir11arr[@]}
do
  if [[ -d $dir ]]
  then
    owner="$(find -L $dir ! -user root -type d -exec stat -c "%n %U" '{}' \;)"
    if [[ $owner ]]
    then
      fail=1
      for file in ${owner[@]}
      do
        echo -e "${NORMAL}RESULT:    ${RED}$file${NORMAL}"
      done
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}$dir not found${NORMAL}"
  fi
done

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
  echo -e "${NORMAL}$hostname, $severity11, $controlid, $stigid11, $ruleid11, $cci11, $datetime, ${GRN}PASSED, RHEL 8 library directories are owned by root.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity11, $controlid, $stigid11, $ruleid11, $cci11, $datetime, ${RED}FAILED, RHEL 8 library directories are not owned by root.${NORMAL}"
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

dir12arr=("/lib" "/lib64" "/usr/lib" "/usr/lib64")

fail=0

datetime="$(date +%FT%H:%M:%S)"

for dir in ${dir12arr[@]}
do
  if [[ -d $dir ]]
  then
    owner="$(find -L $dir ! -group root -type d -exec stat -c "%n %G" '{}' \;)"
    if [[ $owner ]]
    then
      fail=1
      for file in ${owner[@]}
      do
        echo -e "${NORMAL}RESULT:    ${RED}$file${NORMAL}"
      done
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}$dir not found${NORMAL}"
  fi
done

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
  echo -e "${NORMAL}$hostname, $severity12, $controlid, $stigid12, $ruleid12, $cci12, $datetime, ${GRN}PASSED, RHEL 8 library directories are group-owned by root.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity12, $controlid, $stigid12, $ruleid12, $cci12, $datetime, ${RED}FAILED, RHEL 8 library directories are not group-owned by root.${NORMAL}"
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

dir13="/etc/pki/rpm-gpg"

fail=1

datetime="$(date +%FT%H:%M:%S)"

if [[ -d $dir13 ]]
then
  gpgpubkeys="$(rpm -q --queryformat "%{SUMMARY}\n" gpg-pubkey | grep -i "red hat" 2>/dev/null)"

  if [[ $gpgpubkeys ]]
  then
    for key in ${gpgpubkeys[@]}
    do
      echo -e "${NORMAL}RESULT:    ${BLD}a. $key${NORMAL}"
      fail=0
    done
  else
    echo -e "${NORMAL}RESULT:    ${RED}a. Nothing returned${NORMAL}"
  fi

  fingerprints="$(gpg -q --keyid-format short --with-fingerprint /etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release 2>/dev/null)"
  if [[ $fingerprints ]]
  then
    for line in ${fingerprints[@]}
    do
      echo -e "${NORMAL}RESULT:    ${BLD}b. $line${NORMAL}"
    done
  else
    echo -e "${NORMAL}RESULT:    ${RED}b. No GPG key fingerprints found${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}$dir13 not found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity13, $controlid, $stigid13, $ruleid13, $cci13, $datetime, ${GRN}PASSED, Red Hat package-signing keys are properly installed on the system.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity13, $controlid, $stigid13, $ruleid13, $cci13, $datetime, ${RED}FAILED, Red Hat package-signing keys are not properly installed on the system.${NORMAL}"
fi

exit
