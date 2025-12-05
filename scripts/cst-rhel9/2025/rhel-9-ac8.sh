#! /bin/bash

# AC-8 System Use Notification
#
# CONTROL: 
# a. Display [Assignment: organization-defined system use notification message or banner] to users
#    before granting access to the system that provides privacy and security notices consistent with
#    applicable laws, executive orders, directives, regulations, policies, standards, and guidelines
#    and state that: 
#    1. Users are accessing a U.S. Government system; 
#    2. System usage may be monitored, recorded, and subject to audit; 
#    3. Unauthorized use of the system is prohibited and subject to criminal and civil penalties; and 
#    4. Use of the system indicates consent to monitoring and recording; 
# b. Retain the notification message or banner on the screen until users acknowledge the usage conditions
#    and take explicit actions to log on to or further access the system; and 
# c. For publicly accessible systems: 
#    1. Display system use information [Assignment: organization-defined conditions], before granting
#       further access to the publicly accessible system; 
#    2. Display references, if any, to monitoring, recording, or auditing that are consistent with
#       privacy accommodations for such systems that generally prohibit those activities; and 
#    3. Include a description of the authorized uses of the system. 

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

controlid="AC-8 System Use Notification"

title1a="RHEL 9 must display the Standard Mandatory DOD Notice and Consent Banner before granting local or remote access to the system via a command line user logon."
title1b="Checking with: cat /etc/issue"
title1c="Expecting: ${YLO}
\"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent to the following conditions:

-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.

-At any time, the USG may inspect and seize data stored on this IS.

-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.

-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.

-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details.\"

           NOTE: System use notifications are required only for access via login interfaces with human users and are not required when such human interfaces do not exist.

           NOTE: If the banner text does not match the Standard Mandatory DOD Notice and Consent Banner exactly, or the line is commented out, this is a finding."${BLD}
cci1="CCI-000048 CCI-001384 CCI-001385 CCI-001386 CCI-001387 CCI-001388"
stigid1="RHEL-09-211020"
severity1="CAT II"
ruleid1="SV-257779r958390"
vulnid1="V-257779"

title2a="RHEL 9 must display the Standard Mandatory DOD Notice and Consent Banner before granting local or remote access to the system via a SSH logon."
title2b="Checking with: /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print \$4}' | tr -d '\\\\r' | tr '\\\\n' ' ' | sudo grep -iH '^\s*banner'"
title2c="Expecting: ${YLO}/etc/ssh/sshd_config.d/80-bannerPointer.conf:Banner /etc/issue
           NOTE: If the line is commented out, this is a finding.
	   NOTE: This file may be named differently or be in a different location if using a version of SSH that is provided by a third-party vendor"${BLD}
cci2="CCI-000048 CCI-001384 CCI-001385 CCI-001386 CCI-001387 CCI-001388"
stigid2="RHEL-09-255025"
severity2="CAT II"
ruleid2="SV-257981r1101970"
vulnid2="V-257981"

title3a="RHEL 9 must display the Standard Mandatory DOD Notice and Consent Banner before granting local or remote access to the system via a graphical user logon."
title3b="Checking with: gsettings get org.gnome.login-screen banner-message-enable"
title3c="Expecting: ${YLO}true
           NOTE: This requirement assumes the use of the RHEL 9 default graphical user interface, the GNOME desktop environment. If the system does not have any graphical user interface installed, this requirement is Not Applicable."${BLD}
cci3="CCI-000048 CCI-001384 CCI-001385 CCI-001386 CCI-001387 CCI-001388"
stigid3="RHEL-09-271010"
severity3="CAT II"
ruleid3="SV-258012r1014855"
vulnid3="V-258012"

title4a="RHEL 9 must prevent a user from overriding the banner-message-enable setting for the graphical user interface."
title4b="Checkin with: gsettings writable org.gnome.login-screen banner-message-enable"
title4c="Expecting: ${YLO}false
           NOTE: If \"banner-message-enable\" is writable or the result is \"true\", this is a finding.
	   NOTE: This requirement assumes the use of the RHEL 9 default graphical user interface, the GNOME desktop environment. If the system does not have any graphical user interface installed, this requirement is Not Applicable.
	   NOTE: For U.S. Government systems, system use notifications are required only for access via login interfaces with human users and are not required when such human interfaces do not exist."${BLD}
cci4="CCI-000048 CCI-001384 CCI-001385 CCI-001386 CCI-001387 CCI-001388"
stigid4="RHEL-09-271015"
severity4="CAT II"
ruleid4="SV-258013r1045082"
vulnid4="V-258013"

title5a="RHEL 9 must display the Standard Mandatory DOD Notice and Consent Banner before granting local or remote access to the system via a graphical user logon."
title5b="Checking with:  gsettings get org.gnome.login-screen banner-message-text"
title5c="Expecting: ${YLO}
banner-message-text=
'You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.\\nBy using this IS (which includes any device attached to this IS), you consent to the following conditions:\\n-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.\\n-At any time, the USG may inspect and seize data stored on this IS.\\n-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.\\n-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.\\n-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details. '

           NOTE: The "\\\\n" characters are for formatting only. They will not be displayed on the graphical interface.
           NOTE: If the banner does not match the Standard Mandatory DOD Notice and Consent Banner exactly, this is a finding."${BLD}
cci5="CCI-000048"
stigid5="RHEL-09-171011"
severity5="CAT II"
ruleid5="SV-270174r1044831"
vulnid5="V-270174"

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

file1="/etc/issue"
file2="/mnt/shared/cst/files/issue"

fail=1

datetime="$(date +%FT%H:%M:%S)"

badmatch="$(cmp -l $file1 $file2)"

if ! [[ $badmatch ]]
then
  fail=0
  echo -e "${NORMAL}RESULT:    ${BLD}\"/etc/issue\" is an exact DoD banner match.${NORMAL}"
else
  echo -e "${NORMAL}RESULT:    ${RED}\"/etc/issue\" is not an exact DoD banner match.${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${GRN}PASSED, RHEL 9 displays the Standard Mandatory DoD Notice and Consent Banner before granting local or remote access to the system via a command line user logon.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${RED}FAILED, RHEL 9 does not display the Standard Mandatory DoD Notice and Consent Banner before granting local or remote access to the system via a command line user logon.${NORMAL}"
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

bannerpath="$(/usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | sudo grep -iH '^\s*banner')"

if [[ $bannerpath ]]
then
  cfg="$(echo $bannerpath | awk -F: '{print $1}')"
  file="$(echo $bannerpath | awk -F: '{print $2}')"
  if ! [[ ${file:0:1} == "#" ]]
  then
    fail=0
    echo -e "${NORMAL}RESULT:    ${BLD}$bannerpath${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}$bannerpath${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${GRN}PASSED, RHEL 9 displays the Standard Mandatory DOD Notice and Consent Banner before granting local or remote access to the system via a SSH logon.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${RED}FAILED, RHEL 9 does not display the Standard Mandatory DOD Notice and Consent Banner before granting local or remote access to the system via a SSH logon.${NORMAL}"
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

isenabled="$(gsettings get org.gnome.login-screen banner-message-enable)"

gnomeinstalled="$(rpm -qa | grep gnome | egrep '(desktop|session)')"

if [[ $gnomeinstalled ]]
then
  if [[ $isenabled ]]
  then
    if [[ $isenabled == "true" ]]
    then
      fail=0
      echo -e "${NORMAL}RESULT:    ${BLD}$isenabled${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${RED}$isenabled${NORMAL}"
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
  fi

  if [[ $fail == 0 ]]
  then
    echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${GRN}PASSED, RHEL 9 displays the Standard Mandatory DOD Notice and Consent Banner before granting local or remote access to the system via a graphical user logon.${NORMAL}"
  else
    echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${RED}FAILED, RHEL 9 does not display the Standard Mandatory DOD Notice and Consent Banner before granting local or remote access to the system via a graphical user logon.${NORMAL}"
  fi
else
  echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${GRN}N/A, RHEL 9 does not have a graphical user interface (GUI) installed. This requirement is Not Applicable.${NORMAL}"
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

fail=1

datetime="$(date +%FT%H:%M:%S)"

isenabled="$(gsettings writable org.gnome.login-screen banner-message-enable)"

gnomeinstalled="$(rpm -qa | grep gnome | egrep '(desktop|session)')"

if [[ $gnomeinstalled ]]
then
  if [[ $isenabled ]]
  then
    if [[ $isenabled == "false" ]]
    then
      fail=0
      echo -e "${NORMAL}RESULT:    ${BLD}$isenabled${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${RED}$isenabled${NORMAL}"
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
  fi

  if [[ $fail == 0 ]]
  then
    echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${GRN}PASSED, RHEL 9 displays the Standard Mandatory DOD Notice and Consent Banner before granting local or remote access to the system via a graphical user logon.${NORMAL}"
  else
    echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${RED}FAILED, RHEL 9 does not display the Standard Mandatory DOD Notice and Consent Banner before granting local or remote access to the system via a graphical user logon.${NORMAL}"
  fi
else
  echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${GRN}N/A, RHEL 9 does not have a graphical user interface (GUI) installed. This requirement is Not Applicable.${NORMAL}"
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

#file1="/etc/dconf/db/local.d/01-banner-message"
file1="/etc/dconf/db/distro.d/00-security-settings"
file2="/mnt/shared/cst/files/01-banner-message"

gnomeinstalled="$(rpm -qa | grep gnome | egrep '(desktop|session)')"

if [[ $gnomeinstalled ]]
then
  if [[ -f $file1 && -f $file2 ]]
  then
    mybanner1="$(cat 2>/dev/null $file1 | awk -F= '{print $2}' | awk -F'\n' '{print $1}' | sed -e s/true$//)"
    mybanner2="$(cat 2>/dev/null $file2 | sed -e s/^.*=//)"
    isenabled="$(gsettings get org.gnome.login-screen banner-message-text)"
    if [[ $isenabled ]]
    then
      badmatch="$(cmp -l 2>/dev/null $file1 $file2)"
      echo $isenabled
      if ! [[ $badmatch ]]
      then
        fail=0
        echo -e "${NORMAL}RESULT:    ${BLD}$file1 is an exact DoD banner match.${NORMAL}"
      else
        echo -e "${NORMAL}RESULT:    ${RED}$file1 is not an exact DoD banner match.${NORMAL}"
      fi
    else
      echo -e "${NORMAL}RESULT:    ${RED}The graphical login screen banner is not enabled${NORMAL}"
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}The graphical login screen banner does not exist${NORMAL}"
  fi
  if [[ $fail == 0 ]]
  then
    echo -e "${NORMAL}$hostname, $severity5, $controlid, $stigid5, $ruleid5, $cci5, $datetime, ${GRN}PASSED, RHEL 9 displays the Standard Mandatory DoD Notice and Consent Banner before granting local or remote access to the system via a graphical user logon.${NORMAL}"
  else
    echo -e "${NORMAL}$hostname, $severity5, $controlid, $stigid5, $ruleid5, $cci5, $datetime, ${RED}FAILED, RHEL 9 does not display the Standard Mandatory DoD Notice and Consent Banner before granting local or remote access to the system via a graphical user logon.${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${BLD}The Gnome package is not installed${NORMAL}"
  echo -e "${NORMAL}$hostname, $severity5, $controlid, $stigid5, $ruleid5, $cci5, $datetime, ${GRN}N/A, The RHEL 9 Gnome graphical user interface (GUI) package is not installed. This is Not Applicable.${NORMAL}"
fi


exit
