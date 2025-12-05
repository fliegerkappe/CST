#! /bin/bash

# AC-8 System Use Notification
#
# CONTROL: The information system:
# a. Displays to users [Assignment: organization-defined system use notification message
#    or banner] before granting access to the system that provides privacy and security notices
#    consistent with applicable federal laws, Executive Orders, directives, policies, regulations,
#    standards, and guidance and states that:
#    1. Users are accessing a U.S. Government information system;
#    2. Information system usage may be monitored, recorded, and subject to audit;
#    3. Unauthorized use of the information system is prohibited and subject to criminal and civil
#       penalties; and
#    4. Use of the information system indicates consent to monitoring and recording;
# b. Retains the notification message or banner on the screen until users acknowledge the usage
#    conditions and take explicit actions to log on to or further access the information system; and
# c. For publicly accessible systems:
#    1. Displays system use information [Assignment: organization-defined conditions], before
#       granting further access;
#    2. Displays references, if any, to monitoring, recording, or auditing that are consistent
#       with privacy accommodations for such systems that generally prohibit those activities; and
# 3. Includes a description of the authorized uses of the system.

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

controlid="AC-8 System Use Notification"

title1a="The Red Hat Enterprise Linux operating system must display the Standard Mandatory DoD Notice and Consent Banner before granting local or remote access to the system via a graphical user logon."
title1b="Checking with 'grep banner-message-enable /etc/dconf/db/local.d/*'."
title1c="Expecting: ${YLO}banner-message-enable = true and banner is DoD Standard
           Note: If GNOME is not installed, this in Not Applicable.
           Note: If \"banner-message-enable\" is set to \"false\" or is missing, this is a finding."${BLD}
cci1="CCI-000048"
stigid1="RHEL-07-010030"
severity1="CAT II"
ruleid1="SV-204393r603261_rule"
vulnid1="V-204393"

title2a="The Red Hat Enterprise Linux operating system must display the approved Standard Mandatory DoD Notice and Consent Banner before granting local or remote access to the system via a graphical user logon."
title2b="Checking with 'grep banner-message-enable /etc/dconf/db/local.d/(config file)."
title2c="Expecting: ${YLO}banner-message-enable = true and banner is DoD Standard
           Note: If GNOME is not installed, this is Not Applicable.
           Note: The \"\n \" characters are for formatting only. They will not be displayed on the GUI.
           Note: If the banner does not match the approved Standard Mandatory DoD Notice and Consent Banner, this is a finding."${BLD}
cci2="CCI-000048"
stigid2="RHEL-07-010040"
severity2="CAT II"
ruleid2="SV-204394r603261_rule"
vulnid2="V-204394"

title3a="The Red Hat Enterprise Linux operating system must display the Standard Mandatory DoD Notice and Consent Banner before granting local or remote access to the system via a command line user logon."
title3b="Checking with 'more /etc/issue'."
title3c="Expecting: ${YLO}The Standard Mandatory DoD Notice and Consent Banner is displayed.
           Note: If the operating system does not display a graphical logon banner or the banner does not match the Standard Mandatory DoD Notice and Consent Banner, this is a finding.
           Note: If the text in the \"/etc/issue\" file does not match the Standard Mandatory DoD Notice and Consent Banner, this is a finding."${BLD}
cci3="CCI-000048"
stigid3="RHEL-07-010050"
severity3="CAT II"
ruleid3="SV-204395r603261_rule"
vulnid3="V-204395"

title4a="The Red Hat Enterprise Linux operating system must display the Standard Mandatory DoD Notice and Consent Banner immediately prior to, or as part of, remote access logon prompts."
title4b="Checking with with 'grep -i banner /etc/ssh/sshd_config'."
title4c="Expecting: ${YLO}banner /etc/issue
           Note: If the line is commented out, this is a finding.
           Note: If the text in the file does not match the Standard Mandatory DoD Notice and Consent Banner, this is a finding."${BLD}
cci4="CCI-000048"
stigid4="RHEL-07-040170"
severity4="CAT II"
ruleid4="SV-204580r603261_rule"
vulnid4="V-204580"

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

dir1="/etc/dconf/db"
fail=0

dodbanner="You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.\n\nBy using this IS (which includes any device attached to this IS), you consent to the following conditions:\n\n-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.\n\n-At any time, the USG may inspect and seize data stored on this IS.\n\n-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.\n\n-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.\n\n-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."

gnomeinstalled="$(rpm -qa | grep gnome | egrep '(desktop|session)')"

if [[ $gnomeinstalled ]]
then
   if [[ -d $dir1 ]]
   then
      for rpm in ${gnomeinstalled[@]}
      do
         echo -e "${NORMAL}RESULT:       ${NORMAL}$rpm${NORMAL}"
      done

      file1="$(grep -ilR '^banner-message-enable=' $dir1/*)"

      if [[ $file1 ]]
      then

         echo -e "${NORMAL}RESULT:    The system-wide graphical user logon banner settings are defined in:${NORMAL}"

         for file in ${file1[@]}
         do
            echo -e "${NORMAL}RESULT:       ${NORMAL}$file${NORMAL}"
            enabled="$(grep banner-message-enable $file)"
            bannertxt="$(grep banner-message-text $file | sed -e 's/\"//g' | sed -e 's/^banner-message-text=//')"
            if [[ $enabled ]]
            then
            echo -e "${NORMAL}RESULT:    ${BLD}$enabled${NORMAL}"
               enabledval="$(echo $enabled | awk -F= '{print $2}' | sed -e 's/^[[:space:]]*//')"
               if [[ $enabledval == 'true' ]]
               then
                  if [[ $bannertxt ]]
                  then

                     echo
                     echo -e "${NORMAL}Local Login Banner -----------------------------------------${NORMAL}"
                     echo -e "${NORMAL}$bannertxt${NORMAL}"
                     echo

                     dodbannerwc="$(echo $dodbanner | wc -m)"
                     lclbannerwc="$(echo $bannertxt | wc -m)"

                     if (( $dodbannerwc != $lclbannerwc ))
                     then
                        echo -e "${NORMAL}RESULT:    ${BLD}The login banner does not match the DoD Banner${NORMAL}"
                        fail=4
                     else
                        echo -e "${NORMAL}RESULT:    ${BLD}The login banner matches the DoD Banner${NORMAL}"
                     fi
                  else
                     echo -e "${NORMAL}RESULT:    ${BLD}Banner text not found${NORMAL}"
                     fail=3
                  fi
               else
                  echo -e "${NORMAL}RESULT:    ${BLD}The logon banner is not enabled${NORMAL}"
                  fail=2
               fi
            else
               echo -e "${NORMAL}RESULT:    ${BLD}banner-message-enable is not configured in $dir1/$file${NORMAL}"
               fail=1
            fi
         done
      else
         echo -e "${NORMAL}RESULT:    ${BLD}banner-message-enable is not configured in $dir1${NORMAL}"
         fail=1
      fi

      if [[ $fail == 0 ]]
      then
         echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${GRN}PASSED, The operating system displays the Standard Mandatory DoD Notice and Consent Banner before granting local orremote access to the system via a graphical user logon.${NORMAL}"
      else
         echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${RED}FAILED, The operating system does not display the Standard Mandatory DoD Notice and Consent Banner before granting local or remote access to the system via a graphical user logon.${NORMAL}"
      fi
   else
      echo -e "${NORMAL}RESULT:    ${BLD}$dir1 not found${NORMAL}"
      echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${RED}FAILED, $dir1 not found${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${BLD}GNOME server and client RPMs not found${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${GRN}N/A, Not Applicable - GNOME is not installed${NORMAL}"
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

dir2="/etc/dconf/db"
fail=0

dodbanner="You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.\n\nBy using this IS (which includes any device attached to this IS), you consent to the following conditions:\n\n-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.\n\n-At any time, the USG may inspect and seize data stored on this IS.\n\n-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.\n\n-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.\n\n-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."

gnomeinstalled="$(rpm -qa | grep gnome | egrep '(desktop|session)')"

if [[ $gnomeinstalled ]]
then
   if [[ -d $dir2 ]]
   then
      for rpm in ${gnomeinstalled[@]}
      do
         echo -e "${NORMAL}RESULT:       ${NORMAL}$rpm${NORMAL}"
      done

      file2="$(grep -ilR '^banner-message-enable=' $dir2/*)"

      if [[ $file2 ]]
      then

         echo -e "${NORMAL}RESULT:    The system-wide graphical user logon banner settings are defined in:${NORMAL}"

         for file in ${file2[@]}
         do
            echo -e "${NORMAL}RESULT:       ${NORMAL}$file${NORMAL}"
            enabled="$(grep banner-message-enable $file)"
            bannertxt="$(grep banner-message-text $file | sed -e 's/\"//g' | sed -e 's/^banner-message-text=//')"
            if [[ $enabled ]]
            then
            echo -e "${NORMAL}RESULT:    ${BLD}$enabled${NORMAL}"
               enabledval="$(echo $enabled | awk -F= '{print $2}' | sed -e 's/^[[:space:]]*//')"
               if [[ $enabledval == 'true' ]]
               then
                  if [[ $bannertxt ]]
                  then

                     echo
                     echo -e "${NORMAL}Local Login Banner -----------------------------------------${NORMAL}"
                     echo -e "${NORMAL}$bannertxt${NORMAL}"
                     echo

                     dodbannerwc="$(echo $dodbanner | wc -m)"
                     lclbannerwc="$(echo $bannertxt | wc -m)"

                     if (( $dodbannerwc != $lclbannerwc ))
                     then
                        echo -e "${NORMAL}RESULT:    ${BLD}The login banner does not match the DoD Banner${NORMAL}"
                        fail=4
                     else
                        echo -e "${NORMAL}RESULT:    ${BLD}The login banner matches the DoD Banner${NORMAL}"
                     fi
                  else
                     echo -e "${NORMAL}RESULT:    ${BLD}Banner text not found${NORMAL}"
                     fail=3
                  fi
               else
                  echo -e "${NORMAL}RESULT:    ${BLD}The logon banner is not enabled${NORMAL}"
                  fail=2
               fi
            else
               echo -e "${NORMAL}RESULT:    ${BLD}banner-message-enable is not configured in $dir1/$file${NORMAL}"
               fail=1
            fi
         done
      else
         echo -e "${NORMAL}RESULT:    ${BLD}banner-message-enable is not configured in $dir1${NORMAL}"
         fail=1
      fi

      if [[ $fail == 0 ]]
      then
         echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${GRN}PASSED, The operating system displays the Standard Mandatory DoD Notice and Consent Banner before granting local or remote access to the system via a graphical user logon.${NORMAL}"
      else
         echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${RED}FAILED, The operating system does not display the Standard Mandatory DoD Notice and Consent Banner before granting local or remote access to the system via a graphical user logon.${NORMAL}"
      fi
   else
      echo -e "${NORMAL}RESULT:    ${BLD}$dir2 not found${NORMAL}"
      echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${RED}FAILED, $dir2 not found${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${BLD}GNOME server and client RPMs not found${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${GRN}N/A, Not Applicable - GNOME is not installed${NORMAL}"
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

file3="/etc/issue"

dodbanner=null

dodbanner="You are accessing a U.S. Government (USG) Information System (IS) that is  provided for USG-authorized use only. By using this IS (which includes any  device attached to this IS), you consent to the following conditions: -The USG routinely intercepts and monitors communications on this IS for  purposes including, but not limited to, penetration testing, COMSEC monitoring,  network operations and defense, personnel misconduct (PM), law enforcement  (LE), and counterintelligence (CI) investigations. -At any time, the USG may inspect and seize data stored on this IS. -Communications using, or data stored on, this IS are not private, are subject  to routine monitoring, interception, and search, and may be disclosed or used  for any USG-authorized purpose. -This IS includes security measures (e.g., authentication and access controls)  to protect USG interests--not for your personal benefit or privacy. -Notwithstanding the above, using this IS does not constitute consent to PM, LE  or CI investigative searching or monitoring of the content of privileged  communications, or work product, related to personal representation or services  by attorneys, psychotherapists, or clergy, and their assistants. Such  communications and work product are private and confidential. See User  Agreement for details."

if [[ -f $file3 ]]
then
   lclbanner="$(cat $file3)"
   lclbannertxt="$(echo $lclbanner | sed 's/\r$//g')"

   if [[ $lclbanner ]]
   then

      echo -e "${NORMAL}SSH Login Banner -------------------------------------------${NORMAL}"
      echo -e "${NORMAL}$lclbanner${NORMAL}"
      echo -e "${NORMAL}------------------------------------------------------------${NORMAL}"

      dodbannerwc="$(echo $dodbanner | wc -m)"
      lclbannerwc="$(echo $lclbannertxt | wc -m)"

      if (( $lclbannerwc == $dodbannerwc )) && [[ $lclbanner =~ 'psychotherapists' ]]
      then
         echo -e "${NORMAL}RESULT:    ${BLD}The SSH login banner matches the DoD Banner${NORMAL}"
         echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${GRN}PASSED, Command Line DoD Banner: The system displays the Standard Mandatory DoD Notice and Consent Banner before granting local or remote access to the system via a command line user logon.${NORMAL}"
      else
         echo -e "${NORMAL}RESULT:    ${BLD}The SSH login banner does not match the DoD Banner${NORMAL}"
         echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${RED}FAILED, Command Line DoD Banner: The system does not display the Standard Mandatory DoD Notice and Consent Banner before granting local or remote access to the system via a command line user logon.${NORMAL}"
      fi
   else
      echo -e "${NORMAL}RESULT:    ${BLD}The SSH login banner is blank${NORMAL}"
      echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${RED}FAILED, Command Line DoD Banner: The command line login banner is blank${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${BLD}$file3 not found${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${RED}FAILED, Command Line DoD Banner: $file3 not found${NORMAL}"
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

file4="/etc/ssh/sshd_config"

dodbanner=null

dodbanner="You are accessing a U.S. Government (USG) Information System (IS) that is  provided for USG-authorized use only. By using this IS (which includes any  device attached to this IS), you consent to the following conditions: -The USG routinely intercepts and monitors communications on this IS for  purposes including, but not limited to, penetration testing, COMSEC monitoring,  network operations and defense, personnel misconduct (PM), law enforcement  (LE), and counterintelligence (CI) investigations. -At any time, the USG may inspect and seize data stored on this IS. -Communications using, or data stored on, this IS are not private, are subject  to routine monitoring, interception, and search, and may be disclosed or used  for any USG-authorized purpose. -This IS includes security measures (e.g., authentication and access controls)  to protect USG interests--not for your personal benefit or privacy. -Notwithstanding the above, using this IS does not constitute consent to PM, LE  or CI investigative searching or monitoring of the content of privileged  communications, or work product, related to personal representation or services  by attorneys, psychotherapists, or clergy, and their assistants. Such  communications and work product are private and confidential. See User  Agreement for details."

if [[ -f $file4 ]]
then
   sshbannerpath="$(grep -i ^banner $file4)"
   if [[ $sshbannerpath ]]
   then
      sshbannerfile="$(echo $sshbannerpath | awk '{print $2}')"
      if [[ $sshbannerfile ]]
      then
         echo -e "${NORMAL}RESULT:    ${BLD}SSH login banner: $sshbannerfile${NORMAL}"
         lclbanner="$(cat $sshbannerfile | sed 's/\r$//g')"

         if [[ $lclbanner ]]
         then

            echo -e "${NORMAL}SSH Login Banner -------------------------------------------${NORMAL}"
            echo -e "${NORMAL}$lclbanner${NORMAL}"
            echo -e "${NORMAL}------------------------------------------------------------${NORMAL}"

            dodbannerwc="$(echo $dodbanner | wc -m)"
            lclbannerwc="$(echo $lclbanner | wc -m)"

            if (( $lclbannerwc == $dodbannerwc )) && [[ $lclbanner =~ 'psychotherapists' ]]
            then
               echo -e "${NORMAL}RESULT:    ${BLD}The SSH login banner matches the DoD Banner${NORMAL}"
               echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${GRN}PASSED, SSH DoD Banner: The SSH login banner is $sshbannerfile and matches the DoD Banner${NORMAL}"
            else
               echo -e "${NORMAL}RESULT:    ${BLD}The SSH login banner does not match the DoD Banner${NORMAL}"
               echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${RED}FAILED, SSH DoD Banner: The SSH login banner is $sshbannerfile and does not match the DoD Banner${NORMAL}"
            fi
         else
            echo -e "${NORMAL}RESULT:    ${BLD}The SSH login banner file is blank${NORMAL}"
            echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${RED}FAILED, SSH DoD Banner: The SSH login banner $sshbannerfile is blank${NORMAL}"
         fi
      else
         echo -e "${NORMAL}RESULT:    ${BLD}The SSH login banner file is not defined in $file4${NORMAL}"
         echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${RED}FAILED, SSH DoD Banner: The SSH login banner file is not defined in $file4${NORMAL}"
      fi
   else
      echo -e "${NORMAL}RESULT:    ${BLD}The SSH login banner is not defined in $file4${NORMAL}"
      echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${RED}FAILED, SSH DoD Banner: The SSH login banner is not defined in $file4${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${BLD}$file4 not found${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${RED}FAILED, SSH DoD Banner: $file4 not found${NORMAL}"
fi

exit

