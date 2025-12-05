#! /bin/bash

# AU-8 Time Stamps

# CONTROL: The information system:
# a. Uses internal system clocks to generate time stamps for audit records; and
# b. Records time stamps for audit records that can be mapped to Coordinated Universal Time (UTC)
#    or Greenwich Mean Time (GMT) and meets [Assignment: organization-defined granularity of time
#    measurement].

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

controlid="AU-8 Time Stamps"

title1a="RHEL 9 must have the chrony package installed."
title1b="Checking with: dnf list --installed chrony"
title1c="Expecting: ${YLO}chrony.x86_64          4.1-3.el9
           NOTE: If the \"chrony\" package is not installed, this is a finding."${BLD}
cci1="CCI-004923 CCI-001891"
stigid1="RHEL-09-252010"
severity1="CAT II"
ruleid1="SV-257943r1045001"
vulnid1="V-257943"

title2a="RHEL 9 chronyd service must be enabled."
title2b="Checking with: systemctl is-active chronyd"
title2c="Expecting: ${YLO}active
           NOTE: If the chronyd service is not active, this is a finding."${BLD}
cci2="CCI-004923 CCI-001891"
stigid2="RHEL-09-252015"
severity2="CAT II"
ruleid2="SV-257944r1038944"
vulnid2="V-257944"

title3a="RHEL 9 must securely compare internal information system clocks at least every 24 hours with a server synchronized to an authoritative time source, such as the United States Naval Observatory (USNO) time servers, or a time server designated for the appropriate DoD network (NIPRNet/SIPRNet), and/or the Global Positioning System (GPS)."
title3b="Checking with:
	   a. grep maxpoll /etc/chrony.conf
	   b. chronyc sources"
title3c="Expecting: ${YLO}
           a. server 0.us.pool.ntp.mil iburst maxpoll 16
	   b. MS Name/IP address         Stratum Poll Reach LastRx Last sample               
           b. ===============================================================================
           b. ^+ ntp.maxhost.io                2   8   377   304  -1928us[-1908us] +/-   49ms
           b. ^+ 173.249.203.227               2   8   377    53   -916us[ -916us] +/-   32ms
           b. ^+ nyc3.us.ntp.li                2   8   377    47   -434us[ -434us] +/-   32ms
           b. ^* pool-96-231-54-40.washdc>     1   8   377   182  +1736us[+1747us] +/-   31ms
	   NOTE: The above list is an example of unclassified public autoritative time sources.
	   NOTE: If the \"maxpoll\" option is set to a number greater than 16 or the line is commented out, this is a finding.
	   NOTE: If the parameter \"server\" is not set or is not set to an authoritative DoD time source, this is a finding.
	   NOTE: If the \"MS\" column of the chronyc output does not contain a \"^+\" or \"*+\", this is a finding."${BLD}
cci3="CCI-001890 CCI-004923 CCI-004926 CCI-001891 CCI-002046"
stigid3="RHEL-09-252020"
severity3="CAT II"
ruleid3="SV-257945r1038944"
vulnid3="V-257945"

title4a="RHEL 9 audit package must be installed."
title4b="Checking with: dnf list --installed audit"
title4c="Expecting: ${YLO}audit-3.0.7-101.el9_0.2.x86_64
           NOTE: If the \"audit\" package is not installed, this is a finding."${BLD}
cci4="CCI-000130 CCI-000131 CCI-000132 CCI-000133 CCI-000134 CCI-000135 CCI-000154 CCI-000158 CCI-000159 CCI-000169 CCI-000172 CCI-001464 CCI-001487 CCI-003938 CCI-001875 CCI-001876 CCI-001877 CCI-001878 CCI-001879 CCI-001880 CCI-001881 CCI-001882 CCI-001889 CCI-001914 CCI-002884 CCI-001814"
stigid4="RHEL-09-653010"
severity4="CAT II"
ruleid4="SV-258151r1045298"
vulnid4="V-258151"

title5a="RHEL 9 audit service must be enabled."
title5b="Checking with: systemctl status auditd.service"
title5c="Expecting: ${YLO}
auditd.service - Security Auditing Service
Loaded:loaded (/usr/lib/systemd/system/auditd.service; enabled; vendor preset: enabled)
Active: active (running) since Tues 2022-05-24 12:56:56 EST; 4 weeks 0 days ago
NOTE: If the audit service is not \"active\" and \"running\", this is a finding."${BLD}
cci5="CCI-000130 CCI-000131 CCI-000132 CCI-000133 CCI-000134 CCI-000135 CCI-000154 CCI-000158 CCI-000169 CCI-000172 CCI-001464 CCI-001487 CCI-003938 CCI-001875 CCI-001876 CCI-001877 CCI-001878 CCI-001879 CCI-001880 CCI-001881 CCI-001882 CCI-001889 CCI-001914 CCI-002884 CCI-004188 CCI-001814"
stigid5="RHEL-09-653015"
severity5="CAT II"
ruleid5="SV-258152r1015127"
vulnid5="V-258152"

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

isinstalled="$(dnf list --installed 2>&1 chrony | grep -Ev 'Updating|Installed')"

if [[ $isinstalled ]]
then
  for line in ${isinstalled[@]}
  do
    if [[ $line =~ "chrony" ]]
    then
      fail=0
      echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${GRN}PASSED, RHEL 9 has the chrony package installed.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${RED}FAILED, RHEL 9 does not have the chrony package installed.${NORMAL}"
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

datetime="$(date +%FT%H:%M:%S)"

isactive="$(systemctl is-active chronyd)"

if [[ $isactive ]]
then
  if [[ $isactive == "active" ]]
  then
    fail=0
    echo -e "${NORMAL}RESULT:    ${BLD}$isactive${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}$isactive${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${GRN}PASSED, The RHEL 9 chronyd service is enabled.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${RED}FAILED, The RHEL 9 chronyd service is not enabled.${NORMAL}"
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

maxpoll="$(grep maxpoll /etc/chrony.conf)"

if [[ $maxpoll ]]
then
  for line in ${maxpoll[@]}
  do
    value="$(echo $line | awk '{print $NF}')"
    if (( $value <= 16 && $value >= 1 )) && [[ ${line:0:1} != "#" ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}a. $line${NORMAL}"
      server="$(grep -Ei 'server|pool' /etc/chrony.conf | grep -v "^#")"
      if [[ $server ]]
      then
	for svr in ${server[@]}
        do
	  if command -v chronyc &>/dev/null
	  then
	    tracking="$(chronyc sources 2>/dev/null)"
	    if [[ $tracking ]]
	    then
              for src in ${tracking[@]}
	      do
		stat="$(echo $src | awk '{print $1}')"
		if [[ $stat =~ '=|#|~|?|x' ]]
		then
		  echo -e "${NORMAL}RESULT:    ${RED}b. $src${NORMAL}"
		else
		  echo -e "${NORMAL}RESULT:    ${BLD}b. $src${NORMAL}"
		  fail=0
		fi
              done
	    else
              echo -e "${NORMAL}RESULT:    ${BLD}b. Nothing returned${NORMAL}"
	    fi
	  else
	    echo -e "${NORMAL}RESULT:    ${CYN}b. Command \"chronyc\" does not exist. Unable to obtain ntp sync status.${NORMAL}"
	    fail=2
	  fi
	done
      else
	echo -e "${NORMAL}RESULT:    ${RED}b. Nothing returned${NORMAL}"
      fi
    else
      echo -e "${NORMAL}RESULT:    ${RED}a. Nothing returned${NORMAL}"
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${RED}a. Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${GRN}PASSED, RHEL 9 securely compares internal information system clocks at least every 24 hours.${NORMAL}"
elif [[ $fail == 2 ]]
then
	echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${CYN}VERIFY, Have the system administrator (SA) or ISSO verify that the information system securely compares internal clocks to authoritative time servers at least every 24 hours.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${RED}FAILED, RHEL 9 does not securely compare internal information system clocks at least every 24 hours.${NORMAL}"
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

echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${CYN}VERIFY, (See AU-12 Audit Generation: V-258151)${NORMAL}"

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

echo -e "${NORMAL}$hostname, $severity5, $controlid, $stigid5, $ruleid5, $cci5, $datetime, ${CYN}VERIFY, (See AU-12 Audit Generation: V-258152)${NORMAL}"

exit

