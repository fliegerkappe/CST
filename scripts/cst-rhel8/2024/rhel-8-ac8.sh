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

controlid="AC-8 System Use Notification"

title1a="RHEL 8 must display the Standard Mandatory DoD Notice and Consent Banner before granting local or remote access to the system via a ssh logon."
title1b="Checking with: 'grep -i banner /etc/ssh/sshd_config'."
title1c="Expecting: ${YLO}banner /etc/issue
           NOTE: If the line is commented out, this is a finding."${BLD}
cci1="CCI-000048"
stigid1="RHEL-08-010040"
severity1="CAT II"
ruleid1="SV-230225r627750_rule"
vulnid1="V-230225"

title2a="RHEL 8 must display the Standard Mandatory DoD Notice and Consent Banner before granting local or remote access to the system via a graphical user logon."
title2b="Checking with: 'grep -ir banner-message-text /etc/dconf/db/*'."
title2c="Expecting: ${YLO}
banner-message-text=
'You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.\\\nBy using this IS (which includes any device attached to this IS), you consent to the following conditions:\\\n-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.\\\n-At any time, the USG may inspect and seize data stored on this IS.\\\n-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.\\\n-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.\\\n-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details. '

           NOTE: This requirement assumes the use of the RHEL 8 default graphical user interface, Gnome Shell. If the system does not have any graphical user interface installed, this requirement is Not Applicable.
           NOTE: The \"\\\n\" characters are for formatting only. They will not be displayed on the graphical interface.
           NOTE: If the banner does not match the Standard Mandatory DoD Notice and Consent Banner exactly, this is a finding.
	   NOTE:  This requirement assumes the use of the RHEL 8 default graphical user interface, Gnome Shell. If the system does not have any graphical user interface installed, this requirement is Not Applicable."${BLD}
cci2="CCI-000048"
stigid2="RHEL-08-010050"
severity2="CAT II"
ruleid2="SV-230226r743916_rule"
vulnid2="V-230226"

title3a="RHEL 8 must display the Standard Mandatory DoD Notice and Consent Banner before granting local or remote access to the system via a command line user logon."
title3b="Checking with: 'cat /etc/issue'."
title3c="Expecting: ${YLO}
“You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent to the following conditions:

-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.

-At any time, the USG may inspect and seize data stored on this IS.

-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.

-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.

-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details.”
NOTE: If the banner text does not match the Standard Mandatory DoD Notice and Consent Banner exactly, this is a finding."${BLD}
cci3="CCI-000048"
stigid3="RHEL-08-010060"
severity3="CAT II"
ruleid3="SV-230227r627750_rule"
vulnid3="V-230227"

title4a="RHEL 8 must display a banner before granting local or remote access to the system via a graphical user logon."
title4b="Checking with: 'grep banner-message-enable /etc/dconf/db/local.d/*'."
title4c="Expecting: ${YLO}banner-message-enable=true
           NOTE: If \"banner-message-enable\" is set to \"false\" or is missing, this is a finding."${BLD}
cci4="CCI-000048"
stigid4="RHEL-08-010049"
severity4="CAT II"
ruleid4="SV-244519r743806_rule"
vulnid4="V-244519"

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid1${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid1${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid1${NORMAL}"
echo -e "${NORMAL}CCI:       $cci1${NORMAL}"
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 1:    ${BLD}$title1a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title1b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title1c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity1${NORMAL}"

IFS='
'

file1="/etc/ssh/sshd_config"
bannerssh="/mnt/shared/cst/files/issue"

fail=1

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file1 ]]
then
  banner="$(grep -i banner $file1 | grep -v "^#")"
  bannerfile="$(echo $banner | grep -v "^#" | awk '{print $2}')"
  if [[ -f $bannerfile ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}$banner${NORMAL}"
    if cmp -s "$bannerssh" "$bannerfile" 
    then
      echo -e "${NORMAL}RESULT:    ${BLD}$bannerfile matches the DoD Banner.${NORMAL}"
      fail=0
    else
      echo -e "${NORMAL}RESULT:    ${RED}$bannerfile does not match the DoD Banner.${NORMAL}"
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}$bannerfile not found${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}$file1 not found.${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${GRN}PASSED, RHEL 8 displays the Standard Mandatory DoD Notice and Consent Banner before granting local or remote access to the system via a ssh logon.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${RED}FAILED, RHEL 8 does not display the Standard Mandatory DoD Notice and Consent Banner before granting local or remote access to the system via a ssh logon.${NORMAL}"
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
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 2:    ${BLD}$title2a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title2b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title2c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity2${NORMAL}"

IFS='
'

dir2="/etc/dconf/db/gdm.d"
gui="$(yum list installed | grep gnome | grep -E 'desktop|shell')"
bannergui="$(cat /mnt/shared/cst/files/banner-gui | awk -F= '{print $2}')"

fail=1

datetime="$(date +%FT%H:%M:%S)"

if [[ $gui ]]
then
  echo -e "${NORMAL}RESULT:    ${BLD}The GNOME graphical user interface is installed.${NORMAL}"
  if [[ -d $dir2 ]]
  then
    bannerfile="$(grep -r banner-message-text $dir2/* | awk -F= '{print $1}' | awk -F":" '{print $1}' | grep -v lock 2>/dev/null)"
    bannertext="$(cat $bannerfile | awk -F= '{print $2}')"
    if [[ -f $bannerfile ]]
    then

      echo

      echo "DoD banner:"
      echo $bannergui

      echo

      echo "Local banner:"
      echo $bannertext

      echo

      if [[ "$bannergui" == "$bannertext" ]]
      then
        echo -e "${NORMAL}RESULT:    ${BLD}The GUI banner matches the DoD Banner.${NORMAL}"
        fail=0
      else
        echo -e "${NORMAL}RESULT:    ${RED}The GUI banner does not match the DoD Banner.${NORMAL}"
      fi
    else
      echo -e "${NORMAL}RESULT:    ${RED}The GUI banner file was not found${NORMAL}"
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}$file2 not found.${NORMAL}"
  fi

  if [[ $fail == 0 ]]
  then
    echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${GRN}PASSED, RHEL 8 displays the Standard Mandatory DoD Notice and Consent Banner before granting local or remote access to the system via a graphical user logon.${NORMAL}"
  else
    echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${RED}FAILED, RHEL 8 does not display the Standard Mandatory DoD Notice and Consent Banner before granting local or remote access to the system via a graphical user logon.${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${BLD}The GNOME graphical user interface is not installed${NORMAL}"
  echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${GRN}N/A, Only applies to systems with a graphical user interface installed.${NORMAL}"
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
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 3:    ${BLD}$title3a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title3b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title3c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity3${NORMAL}"

IFS='
'

file3="/etc/issue"
bannercl="/mnt/shared/cst/files/issue"

fail=1

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file3 ]]
then
  bannerfile="$(cat $bannercl)"
  bannertext="$(cat $file3)"

  echo

  echo "DoD banner:"
  echo $bannerfile

  echo

  echo "Local banner:"
  echo $bannertext

  echo

  if [[ "$bannerfile" == "$bannertext" ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}The local command line login banner matches the DoD Banner.${NORMAL}"
    fail=0
  else
    echo -e "${NORMAL}RESULT:    ${RED}The local command line login banner does not match the DoD Banner.${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}$file3 not found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${GRN}PASSED, RHEL 8 displays the Standard Mandatory DoD Notice and Consent Banner before granting local or remote access to the system via a command line user logon.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${RED}FAILED, RHEL 8 does not display the Standard Mandatory DoD Notice and Consent Banner before granting local or remote access to the system via a command line user logon.${NORMAL}"
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

dir4="/etc/dconf/db"

fail=1

datetime="$(date +%FT%H:%M:%S)"

if [[ -e $dir4 ]]
then
  enabled="$(grep -r banner-message-enable $dir4/* | grep -v "Binary" | grep -v "locks")"
  if [[ $enabled ]]
  then
    enabledval="$(echo $enabled | awk -F= '{print $2}')"
    if [[ $enabledval == "true" ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}$enabled${NORMAL}"
      fail=0
    else
      echo -e "${NORMAL}RESULT:    ${RED}$enabled${NORMAL}"
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}\"banner-message-enable\" not defined in $dir4/*.${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}$dir4 not found.${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${GRN}PASSED, RHEL 8 displays the Standard Mandatory DoD Notice and Consent Banner before granting local or remote access to the system via a graphical user logon.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${RED}FAILED, RHEL 8 does not display the Standard Mandatory DoD Notice and Consent Banner before granting local or remote access to the system via a graphical user logon.${NORMAL}"
fi

exit
