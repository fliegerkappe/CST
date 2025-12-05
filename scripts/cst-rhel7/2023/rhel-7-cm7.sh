#! /bin/bash

# CM-7 Least Functionality
#
# CONTROL: The organization:
# a. Configures the information system to provide only essential capabilities; and
# b. Prohibits or restricts the use of the following functions, ports, protocols,
#    and/or services: [Assignment: organization-defined prohibited or restricted
#    functions, ports, protocols, and/or services].

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

controlid="CM-7 Least Functionality"

title1a="The Red Hat Enterprise Linux operating system must not have the rsh-server package installed."
title1b="Checking with 'yum list installed rsh-server'."
title1c="Expecting:${YLO}
           Nothing returned.
           Note: If the rsh-server package is installed, this is a finding."${BLD}
cci1="CCI-000381"
stigid1="RHEL-07-020000"
severity1="CAT I"
ruleid1="SV-204442r603261_rule"
vulnid1="V-204442"

title2a="The Red Hat Enterprise Linux operating system must not have the ypserv package installed."
title2b="Checking with 'yum list installed ypserv'."
title2c="Expecting:${YLO}
           Nothing returned.
           Note: If the \"ypserv\" package is installed, this is a finding."${BLD}
cci2="CCI-000381"
stigid2="RHEL-07-020010"
severity2="CAT I"
ruleid2="SV-204443r603261_rule"
vulnid2="V-204443"

title3a="The Red Hat Enterprise Linux operating system must mount /dev/shm with secure options."
title3b="Checking with
           a. 'cat /etc/fstab | grep /dev/shm'
           b. 'mount | grep /dev/shm'"
title3c="Expecting:${YLO}
           a. tmpfs /dev/shm tmpfs defaults,nodev,nosuid,noexec 0 0${YLO}
           b. tmpfs on /dev/shm type tmpfs (rw,nodev,nosuid,noexec,seclabel)
           Note: If results are returned and the \"nodev\", \"nosuid\", or \"noexec\" options are missing, this is a finding.
           Note: If /dev/shm is mounted without secure options \"nodev\", \"nosuid\", and \"noexec\", this is a finding."${BLD}
cci3="CCI-001764"
stigid3="RHEL-07-021022"
severity3="CAT III"
ruleid3="SV-204486r603261_rule"
vulnid3="V-204486"

title4a="The Red Hat Enterprise Linux operating system must not have the telnet-server package installed."
title4b="Checking with
           'yum list installed telnet-server'."
title4c="Expecting:${YLO}
           Nothing returned.
           Note: If the telnet-server package is installed, this is a finding."${YLO}
cci4="CCI-000381"
stigid4="RHEL-07-021710"
severity4="CAT I"
ruleid4="SV-204502r603261_rule"
vulnid4="V-204502"

title5a="The Red Hat Enterprise Linux operating system must be configured to prohibit or restrict the use of functions, ports, protocols, and/or services, as defined in the Ports, Protocols, and Services Management Component Local Service Assessment (PPSM CLSA) and vulnerability assessments"
title5b="Checking with 'firewall-cmd --list-all'."
title5c="Expecting:$YLO}
           public \(default, active\) 
             interfaces: enp0s3 
             sources: 
             services: dhcpv6-client dns http https ldaps rpc-bind ssh 
             ports: 
             masquerade: no 
             forward-ports: 
             icmp-blocks: 
             rich rules:
           Note: Ask the System Administrator for the site or program PPSM CLSA. Verify the services allowed by the firewall match the PPSM CLSA. If there are additional ports, protocols, or services that are not in the PPSM CLSA, or there are ports, protocols, or services that are prohibited by the PPSM Category Assurance List (CAL), this is a finding."${BLD}
cci5="CCI-000382"
stigid5="RHEL-07-040100"
severity5="CAT II"
ruleid5="SV-204577r603261_rule"
vulnid5="V-204577"

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

isinstalled="$(yum list installed rsh-server 2>/dev/null | grep rsh-server)"

if [[ $isinstalled ]]
then
   for pkg in ${isinstalled[@]}
   do
      echo -e "${NORMAL}RESULT:    ${RED}$pkg${NORMAL}"
      fail=1
   done
else
   echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
fi
if [[ $fail == 0 ]]
then
   echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${GRN}PASSED, The 'rsh-server' package is not installed${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${RED}FAILED, The 'rsh-server' package is installed${NORMAL}"
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

fail=0

isinstalled="$(yum list installed ypserv 2>/dev/null | grep ypserv)"

if [[ $isinstalled ]]
then
   for pkg in ${isinstalled[@]}
   do
      echo -e "${NORMAL}RESULT:    ${RED}$pkg${NORMAL}"
      fail=1
   done
else
   echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
fi
if [[ $fail == 0 ]]
then
   echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${GRN}PASSED, The 'ypserv' package is not installed${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${RED}FAILED, The 'ypserv' package is installed${NORMAL}"
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

file3="/etc/fstab"
fail=0

shm1="$(cat $file3 | grep /dev/shm)"
shm2="$(mount | grep /dev/shm)"

if [[ $shm1 ]]
then
   for line in ${shm1[@]}
   do
      if ! [[ $line =~ 'nodev'  ||
              $line =~ 'nosuid' ||
              $line =~ 'noexec'
           ]]
      then
         echo -e "${NORMAL}RESULT:    ${RED}a. $line${NORMAL}"
         fail=1
      else
         echo -e "${NORMAL}RESULT:    ${BLD}a. $line${NORMAL}"
      fi
   done
else
   echo -e "${NORMAL}RESULT:    /dev/shm is not listed in $file3${NORMAL}"
fi

if [[ $shm2 ]]
then
   for line in ${shm2[@]}
   do
      if ! [[ $line =~ 'nodev'  ||
              $line =~ 'nosuid' ||
              $line =~ 'noexec'
           ]]
      then
         echo -e "${NORMAL}RESULT:    ${RED}b. $line${NORMAL}"
         fail=1
      else
         echo -e "${NORMAL}RESULT:    ${BLD}b. $line${NORMAL}"
      fi
   done
else
   echo -e "${NORMAL}RESULT:    /dev/shm is not listed as a mount point${NORMAL}"
fi

if [[ $fail == 0 ]]
then
   echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${GRN}PASSED, The operating system mounts /dev/shm with secure options.${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${RED}FAILED, The operating system does not mount /dev/shm with secure options.${NORMAL}"
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

fail=0

isinstalled="$(yum list installed telnet-server 2>/dev/null | grep telnet-server)"

if [[ $isinstalled ]]
then
   for pkg in ${isinstalled[@]}
   do
      echo -e "${NORMAL}RESULT:    ${RED}$pkg${NORMAL}"
      fail=1
   done
else
   echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
fi
if [[ $fail == 0 ]]
then
   echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${GRN}PASSED, The 'telnet-server' package is not installed${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${RED}FAILED, The 'telnet-server' package is installed${NORMAL}"
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

fwcmd="$(command -v firewall-cmd)"

if [[ $fwcmd ]]
then
   fwsvcs="$($fwcmd --list-all 2>/dev/null)"
   if [[ $fwsvcs ]]
   then
      for line in ${fwsvcs[@]}
      do
         if [[ $line =~ 'public' && $line =~ 'active' ]] ||
            [[ $line =~ 'services' ]]
         then
            echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
         else
            echo -e "${NORMAL}RESULT:    $line${NORMAL}"
         fi
      done
      echo -e "${NORMAL}$hostname, $severity5, $controlid, $stigid5, $ruleid5, $cci5, $datetime, ${CYN}VERIFY, Firewall Services (PPSM CLSA): Ask the System Administrator for the site or program PPSM CLSA. Verify the services allowed match the site PPSM CLSA.${NORMAL}"
   else
      echo -e "${NORMAL}RESULT:    ${CYN}Nothing returned${NORMAL}"
      echo -e "${NORMAL}$hostname, $severity5, $controlid, $stigid5, $ruleid5, $cci5, $datetime, ${CYN}VERIFY, Firewall Services (PPSM CLSA): No services listed${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity5, $controlid, $stigid5, $ruleid5, $cci5, $datetime, ${RED}FAILED, The firewall-cmd command was not found${NORMAL}"
fi

exit
