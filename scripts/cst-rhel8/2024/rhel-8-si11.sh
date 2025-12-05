#! /bin/bash

# SI-11 Error Handling

# CONTROL: The information system:
# a. Generates error messages that provide  informationnecessaryfor corrective actions without
#    revealinginformation that could be exploited by adversaries; and
# b. Reveals error messages only to [Assignment: organization-defined personnel or  roles].

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

controlid="SI-11 Error Handling"

title1a="The RHEL 8 /var/log/messages file must have mode 0640 or less permissive."
title1b="Checking with: stat -c \"%a %n\" /var/log/messages"
title1c="Expecting: ${YLO}640 /var/log/messages${BLD}
           NOTE: ${YLO}If a value of "0640" or less permissive is not returned, this is a finding."${BLD}
cci1="CCI-001314"
stigid1="RHEL-08-010210"
severity1="CAT II"
ruleid1="SV-230245r627750_rule"
vulnid1="V-230245"

title2a="The RHEL 8 /var/log/messages file must be owned by root."
title2b="Checking with: stat -c \"%U\" /var/log/messages"
title2c="Expecting: ${YLO}root${BLD}
           NOTE: ${YLO}If \"root\" is not returned as a result, this is a finding."${BLD}
cci2="CCI-001314"
stigid2="RHEL-08-010220"
severity2="CAT II"
ruleid2="SV-230246r627750_rule"
vulnid2="V-230246"

title3a="The RHEL 8 /var/log/messages file must be group-owned by root."
title3b="Checking with: stat -c \"%G\" /var/log/messages"
title3c="Expecting: ${YLO}root${BLD}
           NOTE: ${YLO}If \"root\" is not returned as a result, this is a finding."${BLD}
cci3="CCI-001314"
stigid3="RHEL-08-010230"
severity3="CAT II"
ruleid3="SV-230247r627750_rule"
vulnid31="V-230247"

title4a="The RHEL 8 /var/log directory must have mode 0755 or less permissive."
title4b="Checking with: stat -c \"%a %n\" /var/log"
title4c="Expecting: ${YLO}755${BLD}
           NOTE: ${YLO}If a value of "0755" or less permissive is not returned, this is a finding."${BLD}
cci4="CCI-001314"
stigid4="RHEL-08-010240"
severity4="CAT II"
ruleid4="SV-230248r627750_rule"
vulnid4="V-230248"

title5a="The RHEL 8 /var/log directory must be owned by root."
title5b="Checking with: stat -c \"%U\" /var/log"
title5c="Expecting: ${YLO}root${BLD}
           NOTE: ${YLO}If \"root\" is not returned as a result, this is a finding."${BLD}
cci5="CCI-001314"
stigid5="RHEL-08-010250"
severity5="CAT II"
ruleid5="SV-230249r627750_rule"
vulnid51="V-230249"

title6a="The RHEL 8 /var/log directory must be group-owned by root."
title6b="Checking with: stat -c \"%G\" /var/log"${BLD}
title6c="Expecting: ${YLO}root${BLD}
           NOTE: ${YLO}If \"root\" is not returned as a result, this is a finding."${BLD}
cci6="CCI-001314"
stigid6="RHEL-08-010260"
severity6="CAT II"
ruleid6="SV-230250r627750_rule"
vulnid6="V-230250"

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

file1="/var/log/messages"

fail=1

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file1 ]]
then
  stat="$(stat -c "%a %n" $file1 | grep $file1)"
  if [[ $stat ]]
  then
    mode="$(echo $stat | awk '{print $1}')"
    if (( ${mode:0:1} <= 6 &&
	  ${mode:1:1} <= 4 &&
	  ${mode:2:1} == 0
       ))
    then
      echo -e "${NORMAL}RESULT:    ${BLD}$stat${NORMAL}"
      fail=0
    else
      echo -e "${NORMAL}RESULT:    ${RED}$stat${NORMAL}"
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}$file1 not found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${GRN}PASSED, The RHEL 8 /var/log/messages file has mode 0640 or less permissive.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${RED}FAILED, The RHEL 8 /var/log/messages file is not mode 0640 or less permissive.${NORMAL}"
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

file2="/var/log/messages"

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file2 ]]
then
  stat="$(stat -c "%U" $file2)"
  if [[ $stat ]]
  then
    owner="$(echo $stat)"
    if [[ $owner == "root" ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}$stat${NORMAL}"
      fail=0
    else
      echo -e "${NORMAL}RESULT:    ${RED}$stat${NORMAL}"
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}$file2 not found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${GRN}PASSED, The RHEL 8 /var/log/messages file is owned by root.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${RED}FAILED, The RHEL 8 /var/log/messages file is not owned by root.${NORMAL}"
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

file3="/var/log/messages"

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file3 ]]
then
  stat="$(stat -c "%G" $file3)"
  if [[ $stat ]]
  then
    group="$(echo $stat)"
    if [[ $group == "root" ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}$stat${NORMAL}"
      fail=0
    else
      echo -e "${NORMAL}RESULT:    ${RED}$stat${NORMAL}"
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}$file3 not found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${GRN}PASSED, The RHEL 8 /var/log/messages file is group-owned by root.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${RED}FAILED, The RHEL 8 /var/log/messages file is not group-owned by root.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid4${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid4${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid4${NORMAL}"
echo -e "${NORMAL}CCI:       $cci1${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 4:    ${BLD}$title4a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title4b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title4c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity4${NORMAL}"

IFS='
'

dir4="/var/log"

fail=1

datetime="$(date +%FT%H:%M:%S)"

if [[ -d $dir4 ]]
then
  stat="$(stat -c "%a %n" $dir4)"
  if [[ $stat ]]
  then
    mode="$(echo $stat | awk '{print $1}')"
    if (( ${mode:0:1} <= 7 &&
	  ${mode:1:1} <= 5 &&
	  ${mode:2:1} <= 5
       ))
    then
      echo -e "${NORMAL}RESULT:    ${BLD}$mode${NORMAL}"
      fail=0
    else
      echo -e "${NORMAL}RESULT:    ${RED}$mode${NORMAL}"
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}$file4 not found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${GRN}PASSED, The RHEL 8 /var/log directory has mode 0755 or less permissive.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${RED}FAILED, The RHEL 8 /var/log directory is not mode 0755 or less permissive.${NORMAL}"
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

dir5="/var/log"

datetime="$(date +%FT%H:%M:%S)"

if [[ -d $dir5 ]]
then
  stat="$(stat -c "%U" $dir5)"
  if [[ $stat ]]
  then
    owner="$(echo $stat)"
    if [[ $owner == "root" ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}$stat${NORMAL}"
      fail=0
    else
      echo -e "${NORMAL}RESULT:    ${RED}$stat${NORMAL}"
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}$dir5 not found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity5, $controlid, $stigid5, $ruleid5, $cci5, $datetime, ${GRN}PASSED, The RHEL 8 /var/log directory is owned by root.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity5, $controlid, $stigid5, $ruleid5, $cci5, $datetime, ${RED}FAILED, The RHEL 8 /var/log directory is not owned by root.${NORMAL}"
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

dir6="/var/log"

datetime="$(date +%FT%H:%M:%S)"

if [[ -d $dir6 ]]
then
  stat="$(stat -c "%G" $dir6)"
  if [[ $stat ]]
  then
    group="$(echo $stat)"
    if [[ $group == "root" ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}$stat${NORMAL}"
      fail=0
    else
      echo -e "${NORMAL}RESULT:    ${RED}$stat${NORMAL}"
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}$dir6 not found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity6, $controlid, $stigid6, $ruleid6, $cci6, $datetime, ${GRN}PASSED, The RHEL 8 /var/log directory is group-owned by root.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity6, $controlid, $stigid6, $ruleid6, $cci6, $datetime, ${RED}FAILED, The RHEL 8 /var/log directory is not group-owned by root.${NORMAL}"
fi

exit
