#! /bin/bash

# AC-12 Session Termination

# CONTROL: The information system automatically terminates a user session after
# [Assignment: organization-defined conditions or trigger events requiring session disconnect].

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

controlid="AC-12 Session Termination"

title1a="The Red Hat Enterprise Linux operating system must be configured so that all network connections associated with a communication session are terminated at the end of the session or after 10 minutes of inactivity from the user at a command prompt, except to fulfill documented and validated mission requirements."
title1b="Checking with grep -irw tmout /etc/profile /etc/bashrc /etc/profile.d/*"
title1c="Expecting: ${YLO}etc/profile.d/tmout.sh:declare -xr TMOUT=900
           Note: If \"TMOUT\" is not set to \"900\" or less to enforce session termination after inactivity, this is a finding.
	   Note: If conflicting results are returned, this is a finding.${BLD}"
cci1="CCI-001133"
stigid1="RHEL-07-040160"
severity1="CAT II"
ruleid1="SV-204579r646844_rule"
vulnid1="V-204579"

title2a="The Red Hat Enterprise Linux operating system must be configured so that all network connections associated with SSH traffic are terminated at the end of the session or after 10 minutes of inactivity, except to fulfill documented and validated mission requirements."
title2b="Checking with ${YLO}'grep -iw clientaliveinterval /etc/ssh/sshd_config'."
title2c="Expecting: ${YLO}ClientAliveInterval 600
           Note: If \"ClientAliveInterval\" is not configu/mnt/shared/CST/reports/cst-rhel8_2023-02-25-1633-full.txtred, commented out, or has a value of \"0\", this is a finding.
           Note: If \"ClientAliveInterval\" has a value that is greater than \"600\" and is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding.${BLD}"
cci2="CCI-001133"
stigid2="RHEL-07-040320"
severity2="CAT II"
ruleid2="SV-204587r603261_rule"
vulnid2="V-204587"

title3a="The Red Hat Enterprise Linux operating system must be configured so that all network connections associated with SSH traffic terminate after a period of inactivity."
title3b="Checking with 'grep -iw clientalivecountmax /etc/ssh/sshd_config'."
title3c="Expecting: ${YLO}ClientAliveCountMax 0
           Note: If \"ClientAliveCountMax\" is not set to \"0\", this is a finding.${BLD}"
cci3="CCI-001133"
stigid3="RHEL-07-040340"
severity3="CAT II"
ruleid3="SV-204589r603261_rule"
vulnid3="V-204589"

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

dir1="/etc/profile.d"
file1a="/etc/profile"
file1b="/etc/bashrc"

tmoutvaltmp=0

fail=0

tmout="$(grep -irw tmout $file1a $file1b $dir1/* | grep -v '^#')"

if [[ $tmout ]]
then
  for line in ${tmout[@]}
  do
    if [[ $line =~ "=" ]]
    then
      tmoutval="$(echo $line | awk -F= '{print $2}' | awk '{print $1}')"
      if (( $tmoutvaltmp == 0 ))
      then
	tmoutvaltmp=$tmoutval
        if (( $tmoutval <= 900 ))
        then
          echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
        else
          echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
          fail=1
        fi
      elif (( $tmoutval == $tmoutvaltmp ))
      then
	echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
      else
        echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
	fail=2
      fi
    else
      echo -e "${NORMAL}RESULT:    $line${NORMAL}"
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${BLD}TMOUT is not defined in either $file1a, $file1b, or $dir1/*${NORMAL}"
  fail=1
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${GRN}PASSED, TMOUT - All network connections associated with a communication session are terminated at the end of the session or after 10 minutes of inactivity from the user at a command prompt except to fulfill documented and validated mission requirements.${NORMAL}"
elif [[ $fail == 2 ]]
then
  echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${RED}FAIlED, TMOUT - Conflicting results returned.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${RED}FAILED, TMOUT - All network connections associated with a communication session are not terminated at the end of the session or after 10 minutes of inactivity from the user at a command prompt except to fulfill documented and validated mission requirements.${NORMAL}"
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

file2="/etc/ssh/sshd_config"
fail=1

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file2 ]]
then
   calive="$(grep -iw clientaliveinterval $file2)"
   if [[ $calive ]]
   then
      for line in ${calive[@]}
      do
         caliveval="$(echo $line | awk '{print $2}')"
         if (( $caliveval <= 600 )) && [[ ${line:1} != '#' && $caliveval != 0 ]]
         then
            echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
            fail=0
         else
            echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
         fi
      done
   else
      echo -e "${NORMAL}RESULT:    ${BLD}ClientAliveInterval is not defined in $file2${NORMAL}"
   fi

   if [[ $fail == 0 ]]
   then
      echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${GRN}PASSED, ClientAliveInterval - All network connections associated with SSH traffic are terminate at the end of the session or after 10 minutes of inactivity except to fulfill documented and validated mission requirements.${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${RED}FAILED, ClientAliveInterval - All network connections associated with SSH traffic are not terminate at the end of the session or after 10 minutes of inactivity except to fulfill documented and validated mission requirements..${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${RED}$file2 not found${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${RED}FAILED, $file2 not found${NORMAL}"
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

file3="/etc/ssh/sshd_config"
fail=1

if [[ -f $file3 ]]
then
  countmax="$(grep -i clientalivecountmax $file3)"
  if [[ $countmax ]]
  then
    for line in ${countmax[@]}
    do
      if [[ ${line:1} != '#' ]]
      then
        countmaxval="$(echo $line | awk '{print $2}')"
        if (( $countmaxval == 0 ))
        then
          echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
          fail=0
        else
          echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
        fi
      else
        echo -e "${NORMAL}RESULT:    $line${NORMAL}"
      fi
    done
  else
    echo -e "${NORMAL}RESULT:    ${RED}\"clentalivecountmax\" is not defined in $file3.{NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}$file3 not found.{NORMAL}"	
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${GRN}PASSED, ClientAliveCountMax - All network connections associated with SSH traffic are terminate after a period of inactivity.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${RED}FAILED, ClientAliveCountMax - All network connections associated with SSH traffic are not terminate after a period of inactivity.${NORMAL}"
fi

exit


