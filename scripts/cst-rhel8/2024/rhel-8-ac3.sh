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

stig="Red Hat Enterprise Linux 8 Security Technical Implementation Guide :: Version 1, Release: 13 Benchmark Date: 24 Jan 2024"

hostname="$(uname -n)"

if [[ -f /etc/redhat-release ]]
then
   os="$(cat /etc/redhat-release)"
else
   os="OS not defined"
fi

prog="$(basename $0)"

controlid="AC-3 Access Enforcement"

title1a="RHEL 8 operating systems booted with United Extensible Firmware Interface (UEFI) must require authentication upon booting into single-user mode and maintenance."
title1b="Checking with 'grep -iw grub2_password /boot/efi/EFI/redhat/grub.cfg'."
title1c="Expecting:${YLO}GRUB2_PASSWORD=grub.pbkdf2.sha512.[password_hash]${BLD}
           NOTE: ${YLO}If the grub superusers password does not begin with \"grub.pbkdf2.sha512\", this is a finding.${BLD}
           NOTE: ${YLO}For systems that use BIOS, this is Not Applicable."${BLD}
cci1="CCI-000213"
stigid1="RHEL-08-010140"
severity1="CAT I"
ruleid1="SV-230234r743922_rule"
vulnid1="V-230234"

title2a="RHEL 8 operating systems booted with a BIOS must require authentication upon booting into single-user and maintenance modes."
title2b="Checking with 'grep -iw grub2_password /boot/grub2/user.cfg'."
title2c="Expecting: ${YLO}GRUB2_PASSWORD=grub.pbkdf2.sha512.[password_hash]${BLD}
           NOTE: ${YLO}If the grub superusers password does not begin with \"grub.pbkdf2.sha512\", this is a finding.${BLD}
	   NOTE: ${YLO}For systems that use UEFI, this is Not Applicable."${BLD}
cci2="CCI-000213"
stigid2="RHEL-08-010150"
severity2="CAT I"
ruleid2="SV-230235r743925_rule"
vulnid2="V-230235"

title3a="RHEL 8 operating systems must require authentication upon booting into rescue mode."
title3b="Checking with 'grep sulogin-shell /usr/lib/systemd/system/rescue.service'."
title3c="Expecting: ${YLO}ExecStart=-/usr/lib/systemd/systemd-sulogin-shell rescue${BLD}
           NOTE: ${YLO}If the \"ExecStart\" line is configured for anything other than \"/usr/lib/systemd/systemd-sulogin-shell rescue\", commented out, or missing, this is a finding."${BLD}
cci3="CCI-000213"
stigid3="RHEL-08-010151"
severity3="CAT II"
ruleid3="SV-230236r743928_rule"
vulnid3="V-230236"

title4a="RHEL 8 must enable kernel parameters to enforce discretionary access control on symlinks."
title4b="Checking with:
           a. 'sysctl fs.protected_symlinks'
	   b. 'grep -r fs.protected_symlinks /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf /etc/sysctl.d/*.conf"
title4c="Expecting: ${YLO}fs.protected_symlinks = 1${BLD}
           NOTE: ${YLO}If \"fs.protected_symlinks\" is not set to \"1\" or is missing, this is a finding.${BLD}"
cci4="CCI-002165"
stigid4="RHEL-08-010373"
severity4="CAT II"
ruleid4="SV-230267r858751_rule"
vulnid4="V-230267"

title5a="RHEL 8 must enable kernel parameters to enforce discretionary access control on hardlinks."
title5b="Checking with:
           a. 'sysctl fs.protected_hardlinks'
	   b. 'grep -r fs.protected_hardlinks /etc/sysctl.d/*.conf"
title5c="Expecting: ${YLO}fs.protected_hardlinks = 1${BLD}
           NOTE: ${YLO}If \"fs.protected_hardlinks\" is not set to \"1\" or is missing, this is a finding.${BLD}
	   NOTE: ${YLO}If the configuration file does not begin with \"99-\", this is a finding."${BLD}
cci5="CCI-002165"
stigid5="RHEL-08-010374"
severity5="CAT II"
ruleid5="SV-230268r858754_rule"
vulnid5="V-230268"

title6a="RHEL 8 operating systems booted with United Extensible Firmware Interface (UEFI) must require a unique superusers name upon booting into single-user mode and maintenance."
title6b="Checking with 'grep -iw \"superusers\" /boot/efi/EFI/redhat/grub.cfg'."
title6c="Expecting: 
           ${YLO}set superusers=\"[someuniquestringhere]\"${BLD}
           NOTE: ${YLO}If \"superusers\" is identical to any OS account name or is missing a name, this is a finding.${BLD}
           NOTE: ${YLO}For systems that use BIOS, this is Not Applicable."${BLD}
cci6="CCI-000213"
stigid6="RHEL-08-010141"
severity6="CAT II"
ruleid6="SV-244521r792982_rule"
vulnid6="V-244521"

title7a="RHEL 8 operating systems booted with a BIOS must require a unique superusers name upon booting into single-user mode and maintenance."
title7b="Checking with 'grep -iw \"superusers\" /boot/grub2/grub.cfg'."
title7c="Expecting:
           ${YLO}set superusers=\"[someuniquestringhere]\"${BLD}
	   ${YLO}export superusers${BLD}
           NOTE: ${YLO}If \"superusers\" is identical to any OS account name or is missing a name, this is a finding.${BLD}
           NOTE: ${YLO}For systems that use UEFI, this is Not Applicable."${BLD}
cci7="CCI-000213"
stigid7="RHEL-08-010149"
severity7="CAT II"
ruleid7="SV-244522r792984_rule"
vulnid7="V-244522"

title8a="RHEL 8 operating systems must require authentication upon booting into emergency mode."
title8b="Checking with 'grep sulogin-shell /usr/lib/systemd/system/emergency.service'."
title8c="Expecting: ${YLO}ExecStart=-/usr/lib/systemd/systemd-sulogin-shell emergency${BLD}
           NOTE: ${YLO}If the \"ExecStart\" line is configured for anything other than \"/usr/lib/systemd/systemd-sulogin-shell emergency\", commented out, or missing, this is a finding."{BLD}
cci8="CCI-000213"
stigid8="RHEL-08-010152"
severity8="CAT II"
ruleid8="SV-244523r743818_rule"
vulnid8="V-244523"

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

file1="/boot/efi/EFI/redhat/user.cfg"

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

if [[ -d /sys/firmware/efi ]]
then
   echo -e "${NORMAL}RESULT:    ${BLD}The system uses UEFI${NORMAL}"
   firmware='UEFI'
else
   echo -e "${NORMAL}RESULT:    ${BLD}The system uses BIOS${NORMAL}"
   firmware='BIOS'
fi

if [[ $firmware == 'UEFI' ]]
then
  if [[ -f $file1 ]]
  then
    efigrubpw="$(grep -iw grub2_password $file1 | sed -e 's/^[[:space:]]*//')"
    if [[ $efigrubpw ]]
    then
      for pw in ${efigrubpw[@]}
      do
        if [[ $pw =~ 'grub.pbkdf2.sha512' ]]
        then
          echo -e "${NORMAL}RESULT:    ${BLD}$pw${NORMAL}"
          echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${GRN}PASSED, An encrypted grub superusers password is set.${NORMAL}"
        else
          echo -e "${NORMAL}RESULT:    ${RED}$pw${NORMAL}"
          echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${RED}FAILED, An encrypted grub superusers password is not set.${NORMAL}"
        fi
      done
    else
      echo -e "${NORMAL}RESULT:    ${RED}nothing found${NORMAL}"
      echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${RED}FAILED, An encrypted grub superusers password is not set${NORMAL}"
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}$file1 not found${NORMAL}"
    echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${RED}FAILED, An encrypted grub superusers password is not set${NORMAL}"
  fi
else
    echo -e "${NORMAL}RESULT:    ${BLD}UEFI firmware was not found${NORMAL}"
    echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${GRN}N/A, UEFI GRUB 2 Password: UEFI firmware was not found.${NORMAL}"
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

file2="/boot/grub2/user.cfg"

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

if [[ -d /sys/firmware/efi ]]
then
   echo -e "${NORMAL}RESULT:    ${BLD}The system uses UEFI${NORMAL}"
   firmware='UEFI'
else
   echo -e "${NORMAL}RESULT:    ${BLD}The system uses BIOS${NORMAL}"
   firmware='BIOS'
fi

if [[ $firmware == 'BIOS' ]]
then
  if [[ -f $file2 ]]
  then
    biosgrubpw="$(grep -iw grub2_password $file2 | sed -e 's/^[[:space:]]*//')"
    if [[ $biosgrubpw ]]
    then
      for pw in ${biosgrubpw[@]}
      do
        if [[ $pw =~ 'grub.pbkdf2.sha512' ]]
        then
          echo -e "${NORMAL}RESULT:    ${BLD}grub.pbkdf2.sha512.10000.[password hash omitted]${NORMAL}"
          echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${GRN}PASSED, An encrypted grub superusers password is set.${NORMAL}"
        else
          echo -e "${NORMAL}RESULT:    ${RED}password not begin with 'grub.pbkdf2.sha512'$pw${NORMAL}"
          echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${RED}FAILED, An encrypted grub superusers password is not set.${NORMAL}"
        fi
      done
    else
      echo -e "${NORMAL}RESULT:    ${RED}nothing found${NORMAL}"
      echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${RED}FAILED, An encrypted grub superusers password is not set${NORMAL}"
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}$file2 not found${NORMAL}"
    echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${RED}FAILED, An encrypted grub superusers password is not set${NORMAL}"
  fi
else
    echo -e "${NORMAL}RESULT:    ${BLD}BIOS firmware was not found${NORMAL}"
    echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${GRN}N/A, BIOS firmware was not found.${NORMAL}"
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

file3="/usr/lib/systemd/system/rescue.service"
fail=1

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file3 ]]
then

   execstart="$(grep sulogin-shell $file3)"

   if [[ $execstart ]]
   then
      for line in ${execstart[@]}
      do
         if [[ $line =~ 'systemd-sulogin-shell rescue' ]]
         then
            echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
            fail=0
         else
            echo -e "${NORMAL}RESULT:    $line${NORMAL}"
         fi
      done
      if (( $fail == 0 ))
      then
         echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${GRN}PASSED, The system requires authentication for rescue mode${NORMAL}"
      else
         echo -e "${NORMAL}RESULT:    ${RED}Missing '/usr/sbin/sulogin'${NORMAL}"
         echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${RED}FAILED, The system does not require authentication for rescue mode.${NORMAL}"
      fi
   else
      echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
      echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${RED}FAILED, The system does not require authentication for rescue mode.${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${RED}$file3 not found${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${RED}FAILED, The system does not require authentication for rescue mode.${NORMAL}"
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
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 4:    ${BLD}$title4a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title4b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title4c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity4${NORMAL}"

IFS='
'
file4="/etc/sysctl.d/*.conf"

fail=1

fsprotect1="$(sysctl fs.protected_symlinks)"
fsprotect2="$(grep -r fs.protected_symlinks $file4 2>/dev/null | grep -v (':#' | '^#Per ')"
fsp1=0
fsp2=0

datetime="$(date +%FT%H:%M:%S)"

if [[ $fsprotect1 ]]
then
  fsp1val="$(echo $fsprotect1 | awk -F= '{print $2/ //}')"
  if [[ $fsp1val == '1' ]]
  then
    fsp1=1
    echo -e "${NORMAL}RESULT:    ${BLD}a. $fsprotect1${NORMAL}"
    if [[ $fsprotect2 ]]
    then
      fsp2val="$(echo $fsprotect2 | awk -F= '{print $2/ //}')"
      fsp2filename="$(echo $fsprotect2 | awk -F: '{print $1}' | awk -F"/" '{print $4}' | cut -c -3)"
      if [[ $fsp2filename != "99-" ]]
      then
	fail=2
      fi
      if [[ $fsp2val == "1" ]]
      then
	fsp2=1
	echo -e "${NORMAL}RESULT:    ${BLD}b. $fsprotect2${NORMAL}"
      else
	echo -e "${NORMAL}RESULT:    ${RED}b. $fsprotect2${NORMAL}"
      fi
    else
      echo -e "${NORMAL}RESULT:    ${RED}b. \"fs.protected_symlinks\" is not defined in $file4 files${NORMAL}"
      if [[ $fsp1 == 1 ]]
      then
	fail=2 
      fi
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}a. $fsprotect1${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}\"fs.protected_symlinks\" is not defined in sysctl files${NORMAL}"
fi

if [[ $fsp1 == 1 && $fsp2 == 1 ]]
then
  fail=0
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${GRN}PASSED, RHEL 8 is configured to enable DAC on symlinks${NORMAL}"
elif [[ $fail == 2 ]]
then
  echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${RED}FAILED, RHEL 8 is configured to enable DAC on symlinks but the file it's configured in does not begin with '99-'.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${RED}FAILED, RHEL 8 is not configured to enable DAC on symlinks${NORMAL}"
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
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 5:    ${BLD}$title5a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title5b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title5c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity5${NORMAL}"

IFS='
'
file5="/etc/sysctl.d/*.conf"

fail=1

fsprotect1="$(sysctl fs.protected_hardlinks)"
fsprotect2="$(grep -r fs.protected_hardlinks $file5 2>/dev/null | grep -v (':#' | '^#Per'))"
fsp1=0
fsp2=0

datetime="$(date +%FT%H:%M:%S)"

if [[ $fsprotect1 ]]
then
  fsp1val="$(echo $fsprotect1 | awk -F= '{print $2/ //}')"
  if [[ $fsp1val == '1' ]]
  then
    fsp1=1
    echo -e "${NORMAL}RESULT:    ${BLD}a. $fsprotect1${NORMAL}"
    if [[ $fsprotect2 ]]
    then
      fsp2val="$(echo $fsprotect2 | awk -F= '{print $2/ //}')"
      fsp2filename="$(echo $fsprotect2 | awk -F: '{print $1}' | awk -F"/" '{print $4}' | cut -c -3)"
      if [[ $fsp2filename != "99-" ]]
      then
	fail=2
      fi
      if [[ $fsp2val == "1" ]]
      then
	fsp2=1
	echo -e "${NORMAL}RESULT:    ${BLD}b. $fsprotect2${NORMAL}"
      else
	echo -e "${NORMAL}RESULT:    ${RED}b. $fsprotect2${NORMAL}"
      fi
    else
      echo -e "${NORMAL}RESULT:    ${RED}b. \"fs.protected_hardlinks\" is not defined in $file5 files${NORMAL}"
      if [[ $fsp1 == 1 ]]
      then
	fail=2 
      fi
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}a. $fsprotect1${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}\"fs.protected_hardlinks\" is not defined in sysctl files${NORMAL}"
fi

if [[ $fsp1 == 1 && $fsp2 == 1 ]]
then
  fail=0
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity5, $controlid, $stigid5, $ruleid5, $cci5, $datetime, ${GRN}PASSED, RHEL 8 is configured to enable DAC on hardlinks${NORMAL}"
elif [[ $fail == 2 ]]
then
  echo -e "${NORMAL}$hostname, $severity5, $controlid, $stigid5, $ruleid5, $cci5, $datetime, ${RED}FAILED, RHEL 8 is configured to enable DAC on hardlinks but the file it's configured in does not begin with '99-'.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity5, $controlid, $stigid5, $ruleid5, $cci5, $datetime, ${RED}FAILED, RHEL 8 is not configured to enable DAC on hardlinks${NORMAL}"
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

file6a="/boot/efi/EFI/redhat/grub.cfg"
file6b="/etc/passwd"
fail=1

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
  if [[ -f $file6a ]]
  then
    grubsu="$(cat $file6a | grep 'set superusers' | awk '{print $2}' | awk -F= '{print $2}')"
    if [[ $grubsu ]]
    then
      isunique="$(grep $grubsu $file6b)"
      if [[ $isunique != "" ]]
      then
        echo -e "${NORMAL}RESULT:    ${RED}Superusers is set to a non-unique name${NORMAL}"
      else
	echo -e "${NORMAL}RESULT:    ${BLD}Superusers is set to a unique name${NORMAL}"
	fail=0
      fi
    else
      echo -e "${NORMAL}RESULT:    ${RED}Superusers is not defined in $file6a${NORMAL}"
      fail=1
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}$file6a not found${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${BLD}UEFI firmware not found${NORMAL}"
  fail=2
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity6, $controlid, $stigid6, $ruleid6, $cci6, $datetime, ${GRN}PASSED, A unique name is set as the \"superusers\" account${NORMAL}"
elif [[ $fail == 2 ]]
then
  echo -e "${NORMAL}$hostname, $severity6, $controlid, $stigid6, $ruleid6, $cci6, $datetime, ${GRN}N/A, The system uses BIOS${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity6, $controlid, $stigid6, $ruleid6, $cci6, $datetime, ${RED}FAILED, A unique name is not set as the \"superusers\" account${NORMAL}"
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

file7a="/boot/grub2/grub.cfg"
file7b="/etc/passwd"
fail=1

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
  if [[ -f $file7a ]]
  then
    grubsu="$(cat $file7a | grep 'set superusers' | grep -v "^#" | awk '{print $2}' | awk -F= '{print $2}' | tr -d '"')"
    if [[ $grubsu ]]
    then
      isunique="$(grep $grubsu $file7b)"
      if [[ $isunique != "" ]]
      then
        echo -e "${NORMAL}RESULT:    ${RED}Superusers is set to a non-unique name${NORMAL}"
      else
	echo -e "${NORMAL}RESULT:    ${BLD}Superusers is set to a unique name${NORMAL}"
	fail=0
      fi
    else
      echo -e "${NORMAL}RESULT:    ${RED}Superusers is not defined in $file7${NORMAL}"
      fail=1
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}$file7a not found${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${BLD}UEFI firmware not found${NORMAL}"
  fail=2
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity7, $controlid, $stigid7, $ruleid7, $cci7, $datetime, ${GRN}PASSED, A unique name is set as the \"superusers\" account${NORMAL}"
elif [[ $fail == 2 ]]
then
  echo -e "${NORMAL}$hostname, $severity7, $controlid, $stigid7, $ruleid7, $cci7, $datetime, ${GRN}N/A, The system uses BIOS${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity7, $controlid, $stigid7, $ruleid7, $cci7, $datetime, ${RED}FAILED, A unique name is not set as the \"superusers\" account${NORMAL}"
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

file8="/usr/lib/systemd/system/emergency.service"
fail=1

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file8 ]]
then

   execstart="$(grep sulogin-shell $file8)"

   if [[ $execstart ]]
   then
      for line in ${execstart[@]}
      do
         if [[ $line =~ 'systemd-sulogin-shell emergency' ]]
         then
            echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
            fail=0
         else
            echo -e "${NORMAL}RESULT:    $line${NORMAL}"
         fi
      done
      if (( $fail == 0 ))
      then
         echo -e "${NORMAL}$hostname, $severity8, $controlid, $stigid8, $ruleid8, $cci8, $datetime, ${GRN}PASSED, The system requires authentication for emergency mode${NORMAL}"
      else
         echo -e "${NORMAL}RESULT:    ${RED}Missing '/usr/sbin/sulogin'${NORMAL}"
         echo -e "${NORMAL}$hostname, $severity8, $controlid, $stigid8, $ruleid8, $cci8, $datetime, ${RED}FAILED, The system does not require authentication for emergency mode.${NORMAL}"
      fi
   else
      echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
      echo -e "${NORMAL}$hostname, $severity8, $controlid, $stigid8, $ruleid8, $cci8, $datetime, ${RED}FAILED, The system does not require authentication for emergency mode.${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${RED}$file8 not found${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity8, $controlid, $stigid8, $ruleid8, $cci8, $datetime, ${RED}FAILED, The system does not require authentication for emergency mode.${NORMAL}"
fi

exit

