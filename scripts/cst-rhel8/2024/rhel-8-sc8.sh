#! /bin/bash
RHEL-08-040160
# SC-8 Transmission Confidentiality and Integrity
#
# CONTROL: The information system protects the [Selection (one or more): confidentiality; integrity]
# of transmitted information.

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

controlid="SC-8 Transmission Confidentiality and Integrity"

title1a="All RHEL 8 networked systems must have and implement SSH to protect the confidentiality and integrity of transmitted and received information, as well as information during preparation for transmission."
title1b="Checking with 'systemctl status sshd."
title1c="Expecting: i${YLO}
           sshd.service - OpenSSH server daemon
           Loaded: loaded (/usr/lib/systemd/system/sshd.service; enabled)
           Active: active (running) since Tue 2015-11-17 15:17:22 EST; 4 weeks 0 days ago
           Main PID: 1348 (sshd)
           CGroup: /system.slice/sshd.service
           1053 /usr/sbin/sshd -D
           NOTE: If \"sshd\" does not show a status of \"active\" and \"running\", this is a finding."
cci1="CCI-002418"
stigid1="RHEL-08-040160"
severity1="CAT II"
ruleid1="SV-230526r744032_rule"
vulnid1="V-230526"

title2a="All RHEL 8 networked systems must have SSH installed."
title2b="Checking with 'yum list installed openssh-server"
title2c="Expecting:${YLO}openssh-server.x86_64                 8.0p1-5.el8          @anaconda
           NOTE: If the \"SSH server\" package is not installed, this is a finding."
cci2="CCI-002418"
stigid2="RHEL-08-040159"
severity2="CAT II"
ruleid2="SV-244549r743896_rule"
vulnid2="V-244549"

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

cmd1="$(command -v systemctl)"
fail=0

datetime="$(date +%FT%H:%M:%S)"

if [[ $cmd1 ]]
then
   sshdstat="$($cmd1 status sshd)"
   if [[ $sshdstat ]]
   then
      for line in ${sshdstat[@]}
      do
         #name="$(echo $line | awk -F. '{print $1}')"
         if [[ $line =~ 'enabled' || $line =~ '(running)' ]]
         then
            echo -e "${NORMAL}RESULT:    ${GRN}$line${NORMAL}"
         elif [[ $line =~ 'Active' && ! $line =~ '(running)' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
         else
            echo -e "${NORMAL}RESULT:    $line${NORMAL}"
         fi
      done
   fi
   if (( $fail == 0 ))
   then
      echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${GRN}PASSED, SSH is loaded and active${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${RED}FAILED, SSH is not loaded and active${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${RED}$cmd1 not found${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${RED}FAILED, The \"systemctl\" command was not found${NORMAL}"
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

isinstalled="$(yum list installed openssh-server | grep openssh-server)"

datetime="$(date +%FT%H:%M:%S)"

if [[ $isinstalled ]]
then
  echo -e "${NORMAL}RESULT:    ${BLD}$isinstalled${NORMAL}"
  fail=0
else
  echo -e "${NORMAL}RESULT:    ${RED}The \"openssh-server\" package is not installed${NORMAL}"
fi
if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${GRN}PASSED, SSH is installed${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${RED}FAILED, SSH is not installed.${NORMAL}"
fi

exit
