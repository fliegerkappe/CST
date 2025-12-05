#! /bin/bash

# AC-6 Least Privilege

# Control: The organization employs the principle of least privilege, allowing only authorized
# accesses for users (or processes acting on behalf of users) which are necessary to accomplish
# assigned tasks in accordance with organizational missions and business functions.

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

controlid="AC-6 Least Privilege"

title1a="The systemd Ctrl-Alt-Delete burst key sequence in RHEL 9 must be disabled."
title1b="Checking with: grep -i ctrl /etc/systemd/system.conf"
title1c="Expecting: ${YLO}CtrlAltDelBurstAction=none
           NOTE: If the \"CtrlAltDelBurstAction\" is not set to \"none\", is commented out, or is missing, this is a finding."${BLD}
cci1="CCI-002235"
stigid1="RHEL-09-211045"
severity1="CAT I"
ruleid1="SV-257784r1044832"
vulnid1="V-257784"

title2a="The x86 Ctrl-Alt-Delete key sequence must be disabled on RHEL 9."
title2b="Checking with: systemctl status ctrl-alt-del.target"
title2c="Expecting: ${YLO}
           ctrl-alt-del.target
           Loaded: masked (Reason: Unit ctrl-alt-del.target is masked.)
           Active: inactive (dead)
           NOTE: If the \"ctrl-alt-del.target\" is loaded and not masked, this is a finding."${BLD}
cci2="CCI-002235"
stigid2="RHEL-09-211050"
severity2="CAT I"
ruleid2="SV-257785r1044833"
vulnid2="V-257785"

title3a="RHEL 9 debug-shell systemd service must be disabled."
title3b="Checking with: systemctl status debug-shell.service"
title3c="Expecting: ${YLO}
           debug-shell.service
           Loaded: masked (Reason: Unit debug-shell.service is masked.)
           Active: inactive (dead)
           NOTE: If the \"debug-shell.service\" is loaded and not masked, this is a finding."${BLD}
cci3="CCI-002235"
stigid3="RHEL-09-211055"
severity3="CAT II"
ruleid3="SV-257786r1044834"
vulnid3="V-257786"

title4a="RHEL 9 must enable kernel parameters to enforce discretionary access control on hardlinks."
title4b="Checking with: sysctl fs.protected_hardlinks"
title4c="Expecting: fs.protected_hardlinks = 1
           NOTE: If \"fs.protected_hardlinks\" is not set to \"1\" or is missing, this is a finding."${BLD}
cci4="CCI-002165 CCI-002235"
stigid4="RHEL-09-213030"
severity4="CAT II"
ruleid4="SV-257801r1106279"
vulnid4="V-257801"

title5a="RHEL 9 must enable kernel parameters to enforce discretionary access control on symlinks."
title5b="Checking with: sysctl fs.protected_symlinks"
title5c="Expecting: ${YLO}fs.protected_symlinks = 1
           NOTE: If \"fs.protected_symlinks\" is not set to \"1\" or is missing, this is a finding."${BLD}
cci5="CCI-002165 CCI-002235"
stigid5="RHEL-09-213035"
severity5="CAT II"
ruleid5="SV-257802r1106282"
vulnid5="V-257802"

title6a="RHEL 9 must have the sudo package installed."
title6b="Checking with: dnf list --installed sudo"
title6c="Expecting: ${YLO}(example) sudo.x86_64          1.9.5p2-7.el9
           NOTE: If the "sudo" package is not installed, this is a finding."${BLD}
cci6="CCI-002235"
stigid6="RHEL-09-432010"
severity6="CAT II"
ruleid6="SV-258083r1045168"
vulnid6="V-258083"

title7a="RHEL 9 must audit uses of the "execve" system call."
title7b="Checking with: auditctl -l | grep execve "
title7c="Expecting: ${YLO}
           -a always,exit -S arch=b32 -S execve -C uid!=euid -F euid=0 -F key=execpriv
           -a always,exit -S arch=b64 -S execve -C uid!=euid -F euid=0 -F key=execpriv
           -a always,exit -S arch=b32 -S execve -C gid!=egid -F egid=0 -F key=execpriv
           -a always,exit -S arch=b64 -S execve -C gid!=egid -F egid=0 -F key=execpriv
           NOTE: If the command does not return all lines, or the lines are commented out, this is a finding."${BLD}
cci7="CCI-002233 CCI-002234"
stigid7="RHEL-09-654010"
severity7="CAT II"
ruleid7="SV-258176r1106366"
vulnid7="V-258176"

title8a="RHEL 9 must elevate the SELinux context when an administrator calls the sudo command."
title8b="Checking with: grep -r sysadm_r /etc/sudoers /etc/sudoers.d"
title8c="Expecting: ${YLO}%{designated_group_or_user_name} ALL=(ALL) TYPE=sysadm_t ROLE=sysadm_r ALL
           NOTE: If conflicting results are returned, this is a finding."${BLD}
cci8="CCI-002235"
stigid8="RHEL-09-431016"
severity8="CAT II"
ruleid8="SV-272496r1082184"
vulnid8="V-272496"

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

fail=1

datetime="$(date +%FT%H:%M:%S)"

cad="$(grep -i ctrl /etc/systemd/system.conf | grep -v "#")"

if [[ $cad ]]
then
  cadval="$(echo $cad | awk -F= '{print $2}')"
  if [[ $cadval == "none" ]]
  then
    fail=0
    echo -e "${NORMAL}RESULT:    ${BLD}$cad${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}$cad${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${GRN}PASSED, The systemd Ctrl-Alt-Delete burst key sequence in RHEL 9 is disabled.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${RED}FAILED, The systemd Ctrl-Alt-Delete burst key sequence in RHEL 9 is not disabled.${NORMAL}"
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

status="$(systemctl status ctrl-alt-del.target | grep -v "#"  | sed -e 's/.*ctrl-alt-del.target$/ctrl-alt-del.target/' | sed -e 's/^[ \t]*//')"

if [[ $status ]]
then
  for line in ${status[@]}
  do
    if ! [[ $line =~ "ctrl-alt-del.target" ||
	    $line =~ "Loaded: masked" ||
            $line =~ "Active: inactive (dead)"
         ]]
    then
      fail=1
      echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${GRN}PASSED, The x86 Ctrl-Alt-Delete key sequence is disabled.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${RED}FAILED, The x86 Ctrl-Alt-Delete key sequence is not disabled.${NORMAL}"
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

fail=0

datetime="$(date +%FT%H:%M:%S)"

status="$(systemctl status debug-shell.service | grep -v "#"  | sed -e 's/.*debug-shell.service$/debug-shell.service/' | sed -e 's/^[ \t]*//')"

if [[ $status ]]
then
  for line in ${status[@]}
  do
    if ! [[ $line =~ "debug-shell.service" ||
            $line =~ "Loaded: masked" ||
            $line =~ "Active: inactive (dead)"
         ]]
    then
      fail=1
      echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${GRN}PASSED, The RHEL 9 debug-shell systemd service is disabled.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${RED}FAILED, The RHEL 9 debug-shell systemd service is not disabled.${NORMAL}"
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

datetime="$(date +%FT%H:%M:%S)"

echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${CYN}VERIFY, (See AC-3 Access Enforcement: V-257801)${NORMAL}" 

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

echo -e "${NORMAL}$hostname, $severity5, $controlid, $stigid5, $ruleid5, $cci5, $datetime, ${CYN}VERIFY, (See AC-3 Access Enforcement: V-257802)${NORMAL}"

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

isinstalled="$(dnf list --installed 2>&1 sudo | grep -Ev 'Updating|Installed')"

if [[ $isinstalled ]]
then
  fail=0
  echo -e "${NORMAL}RESULT:    ${BLD}$isinstalled${NORMAL}"
  echo -e "${NORMAL}$hostname, $severity6, $controlid, $stigid6, $ruleid6, $cci6, $datetime, ${GRN}PASSED, The RHEL 9 sudo package is installed.${NORMAL}"
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
  echo -e "${NORMAL}$hostname, $severity6, $controlid, $stigid6, $ruleid6, $cci6, $datetime, ${RED}FAILED, The RHEL 9 sudo package is not installed.${NORMAL}"
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

rules="$(auditctl -l | grep execve)"

if [[ $rules ]]
then
  for line in ${rules[@]}
  do
    if [[ $line =~ '-a always,exit' ]] 
    then
      if ! [[ ( $line =~ '-C gid!=egid' || $line =~ '-F egid=0' ||
	        $line =~ '=C uid!=egid' || $line =~ '-F euid=0') &&
		$line =~ '-F key=execpriv'
           ]]
      then
        echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
        fail=1
      else
        echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
      fi
    else
      echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity7, $controlid, $stigid7, $ruleid7, $cci7, $datetime, ${GRN}PASSED, RHEL 9 audits uses of the "execve" system call correctly.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity7, $controlid, $stigid7, $ruleid7, $cci7, $datetime, ${RED}FAILED, RHEL 9 does not audit uses of the "execve" system call correctly.${NORMAL}"
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

fail=0

datetime="$(date +%FT%H:%M:%S)"

admrules="$(grep -r sysadm_r /etc/sudoers /etc/sudoers.d)"

if [[ $admrules ]]
then
  size=${#admrules[@]}
  for rule in ${admrules[@]}
  do
    echo -e "${NORMAL}RESULT:    ${BLD}$rule${NORMAL}"
  done
fi

if [[ $size == 1 ]]
then
  echo -e "${NORMAL}$hostname, $severity8, $controlid, $stigid8, $ruleid8, $cci8, $datetime, ${GRN}PASSED, RHEL 9 elevates the SELinux context when an administrator calls the sudo command.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity8, $controlid, $stigid8, $ruleid8, $cci8, $datetime, ${CYN}VERIFY, Verify that there are no conficting configurations for SELinux context rules.${NORMAL}"
fi

exit
