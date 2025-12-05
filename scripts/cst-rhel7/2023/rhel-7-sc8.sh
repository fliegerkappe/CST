#! /bin/bash

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

stig="Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Version 3, Release: 10 Benchmark Date: 26 Jan 2023"

hostname="$(uname -n)"

if [[ -f /etc/redhat-release ]]
then
   os="$(cat /etc/redhat-release)"
else
   os="OS not defined"
fi

prog="$(basename $0)"

controlid="SC-8 Transmission Confidentiality and Integrity"

title1a="The Red Hat Enterprise Linux operating system must be configured so that all networked systems have SSH installed."
title1b="Checking with 'yum list installed ssh'"
title1c="Expecting:${YLO}
           libssh.x86_64                                        0.9.6-3.el8                                @anaconda
           libssh-config.noarch                                 0.9.6-3.el8                                @anaconda
           openssh.x86_64                                       8.0p1-13.el8                               @anaconda
           openssh-clients.x86_64                               8.0p1-13.el8                               @anaconda
           openssh-server.x86_64                                8.0p1-13.el8                               @anaconda
           Note: If the \"SSH server\" package is not installed, this is a finding."
cci1="CCI-002418"
stigid1="RHEL-07-040300"
severity1="CAT II"
ruleid1="SV-204585r603261_rule"
vulnid1="V-204585"

title2a="The Red Hat Enterprise Linux operating system must be configured so that all networked systems use SSH for confidentiality and integrity of transmitted and received information as well as information during preparation for transmission."
title2b="Checking with 'systemctl status sshd'."
title2c="Expecting:${YLO}
           sshd.service - OpenSSH server daemon
             Loaded: loaded (/usr/lib/systemd/system/sshd.service; enabled)
             Active: active (running) since Tue 2015-11-17 15:17:22 EST; 4 weeks 0 days ago
           Note: If \"sshd\" does not show a status of \"active\" and \"running\", this is a finding."${BLD}
cci2="CCI-002418"
stigid2="RHEL-07-040310"
severity2="CAT II"
ruleid2="SV-204586r603261_rule"
vulnid2="V-204586"

title3a="The Red Hat Enterprise Linux operating system must be configured so that all wireless network adapters are disabled."
title3b="Checking with 'nmci device'."
title3c="Expecting:${YLO}
           DEVICE TYPE STATE
           eth0 ethernet connected
           wlp3s0 wifi disconnected
           lo loopback unmanaged
           Note: If a wireless interface is configured and its use on the system is not documented with the Information System Security Officer (ISSO), this is a finding."${YLO}
cci3="CCI-002418"
stigid3="RHEL-07-041010"
severity3="CAT II"
ruleid3="SV-204634r603261_rule"
vulnid3="V-204634"

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

fail=1

sshpkgs="$(yum list installed \*ssh\*)"

if [[ $sshpkgs ]]
then
   for pkg in ${sshpkgs[@]}
   do
      name="$(echo $pkg | awk '{print $1}')"
      if [[ $name =~ 'server' ]]
      then
         echo -e "${NORMAL}RESULT:    ${BLD}$pkg${NORMAL}"
	 fail=0
      else
         echo -e "${NORMAL}RESULT:    $pkg${NORMAL}"
      fi
   done
else
   echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
   echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${GRN}PASSED, SSH packages are installed${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${RED}FAILED, SSH packages are missing or not installed.${NORMAL}"
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

cmd2="$(command -v systemctl)"
fail=1

if [[ $cmd2 ]]
then
   sshdstat="$($cmd2 status sshd)"
   if [[ $sshdstat ]]
   then
      for line in ${sshdstat[@]}
      do
         if [[ $line =~ 'Active' && $line =~ '(running)' ]]
         then
            echo -e "${NORMAL}RESULT:    ${GRN}$line${NORMAL}"
	    fail=0
         else
            echo -e "${NORMAL}RESULT:    $line${NORMAL}"
         fi
      done
   fi
else
   echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
   echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${GRN}PASSED, The SSH daemon is loaded and running${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${RED}FAILED, The SSH Daemon is not running${NORMAL}"
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

echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${CYN}VERIFY, (See AC-18 Wireless Access: V-204634)${NORMAL}"

exit
