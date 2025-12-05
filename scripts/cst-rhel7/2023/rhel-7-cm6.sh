#! /bin/bash

# CM-6 Configuration Settings
#
# CONTROL: The organization:
# a. Establishes and documents configuration settings for information technology products
#    employed within the information system using [Assignment: organization-defined security
#    configuration checklists] that reflect the most restrictive mode consistent with operational
#    requirements;
# b. Implements the configuration settings;
# c. Identifies, documents, and approves any deviations from established configuration settings for
#    [Assignment: organization-defined information system components] based on [Assignment:
#    organization-defined operational requirements]; and
# d. Monitors and controls changes to the configuration settings in accordance with organizational
#    policies and procedures.

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

controlid="CM-6 Configuration Settings"

title1a="The Red Hat Enterprise Linux operating system must not have accounts configured with blank or null passwords."
title1b="Checking with 'grep nullok /etc/pam.d/system-auth /etc/pam.d/password-auth'"
title1c="Expecting:${YLO}
           Nothing returned
           Note: If this produces any output, it may be possible to log on with accounts with empty passwords.
           Note: If null passwords can be used, this is a finding."${BLD}
cci1="CCI-000366"
stigid1="RHEL-07-010290"
severity1="CAT I"
ruleid1="SV-204424r809187_rule"
vulnid1="V-204424"

title2a="The Red Hat Enterprise Linux operating system must be configured so that the delay between logon prompts following a failed console logon attempt is at least four seconds."
title2b="Checking with 'grep -i fail_delay /etc/login.defs'."
title2c="Expecting:${YLO}
           FAIL_DELAY 4
           Note: If the value of \"FAIL_DELAY\" is not set to \"4\" or greater, or the line is commented out, this is a finding."${BLD}
cci2="CCI-000366"
stigid2="RHEL-07-010430"
severity2="CAT II"
ruleid2="SV-204431r603261_rule"
vulnid2="V-204431"

title3a="The Red Hat Enterprise Linux operating system must not allow an unattended or automatic logon to the system via a graphical user interface."
title3b="Checking with 'grep -i automaticloginenable /etc/gdm/custom.conf."
title3c="Expecting:${YLO}
           AutomaticLoginEnable=false
           Note: If the system does not have GNOME installed, this requirement is Not Applicable."
cci3="CCI-000366"
stigid3="RHEL-07-010440"
severity3="CAT I"
ruleid3="SV-204432r603261_rule"
vulnid3="V-204432"

title4a="The Red Hat Enterprise Linux operating system must not allow an unrestricted logon to the system."
title4b="Checking with 'grep -i timedloginenable /etc/gdm/custom.conf."
title4c="Expecting: ${YLO}
           TimedLoginEnable=false
           Note: If the system does not have GNOME installed, this requirement is Not Applicable.
           Note: If the value of \"TimedLoginEnable\" is not set to \"false\", this is a finding."${BLD}
cci4="CCI-000366"
stigid4="RHEL-07-010450"
severity4="CAT I"
ruleid4="SV-204433r603261_rule"
vulnid4="V-204433"

title5a="The Red Hat Enterprise Linux operating system must not allow users to override SSH environment variables."
title5b="Checking with 'grep -i permituserenvironment /etc/ssh/sshd_config'."
title5c="Expecting:${YLO}
           PermitUserEnvironment no
           Note: If the \"PermitUserEnvironment\" keyword is not set to \"no\", is missing, or is commented out, this is a finding.${BLD}"
cci5="CCI-000366"
stigid5="RHEL-07-010460"
severity5="CAT II"
ruleid5="SV-204434r603261_rule"
vulnid5="V-204434"

title6a="The Red Hat Enterprise Linux operating system must not allow a non-certificate trusted host SSH logon to the system."
title6b="Checking with 'grep -i hostbasedauthentication /etc/ssh/sshd_config'."
title6c="Expecting:${YLO}
           HostbasedAuthentication no
           Note: If the \"HostbasedAuthentication\" keyword is not set to \"no\", is missing, or is commented out, this is a finding."${BLD}
cci6="CCI-000366"
stigid6="RHEL-07-010470"
severity6="CAT II"
ruleid6="SV-204435r603261_rule"
vulnid6="V-204435"

title7a="The Red Hat Enterprise Linux operating system must be configured to disable USB mass storage."
title7b="Checking with
           a. 'grep -r usb-storage /etc/modprobe.d/* | grep -i \"/bin/true\" | grep -v \"^#\"'
           b. 'grep usb-storage /etc/modprobe.d/* | grep -i \"blacklist\" | grep -v \"^#\"'"
title7c="Expecting:${YLO}
           a. install usb-storage /bin/true
           b. blacklist usb-storage
           Note a: Verify the operating system disables the ability to use USB mass storage devices.
           Note b: If the command does not return any output, or the line is commented out, and use of USB Storage is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding."${BLD}
cci7="CCI-000366"
stigid7="RHEL-07-020100"
severity7="CAT II"
ruleid7="SV-204449r603261_rule"
vulnid7="V-204449"

title8a="The Red Hat Enterprise Linux operating system must disable the file system automounter unless required."
title8b="Checking with 'systemctl status autofs'."
title8c="Expecting:${YLO}
           autofs.service - Automounts filesystems on demand
              Loaded: loaded (/usr/lib/systemd/system/autofs.service; disabled)
              Active: inactive (dead)
           Note: If the \"autofs\" status is set to \"active\" and is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding."${BLD}
cci8="CCI-000366"
stigid8="RHEL-07-020110"
severity8="CAT II"
ruleid8="SV-204451r603261_rule"
vulnid8="V-204451"

title9a="The Red Hat Enterprise Linux operating system must be configured so that the x86 Ctrl-Alt-Delete key sequence is disabled."
title9b="Checking with 'systemctl status ctrl-alt-del.target'."
title9c="Expecting:${YLO}
           ctrl-alt-del.target
           Loaded: masked (/dev/null; bad)
           Active: inactive (dead)
           Note: If the ctrl.alt.del.target is not masked, this is a finding. 
           Note: If the ctrl.alt.del.target is active, this is a finding."${BLD}
cci9="CCI-000366"
stigid9="RHEL-07-020230"
severity9="CAT I"
ruleid9="SV-204455r833106_rule"
vulnid9="V-204455"

title10a="The Red Hat Enterprise Linux operating system must be configured so that the x86 Ctrl-Alt-Delete key sequence is disabled in the GUI."
title10b="Checking with: grep -ir logout /etc/dconf/*"
title10c="Expecting: logout=''
           Note: If \"logout\" is not set to use two single quotations, or is missing, this is a finding.
           Note: If GNOME is not installed, this is Not Applicable."
cci10="CCI-000366"
stigid10="RHEL-07-020231"
severity10="CAT I"
ruleid10="SV-204456r603261_rule"
vulnid10="V-204456"

title11a="The Red Hat Enterprise Linux operating system must define default permissions for all authenticated users in such a way that the user can only read and modify their own files."
title11b="Checking with 'grep -i ^umask /etc/login.defs'."
title11c="Expecting:${YLO}
           UMASK	077
           Note: If the value for the \"UMASK\" parameter is not \"077\", or the \"UMASK\" parameter is missing or is commented out, this is a finding."${BLD}
cci11="CCI-000366"
stigid11="RHEL-07-020240"
severity11="CAT II"
ruleid11="SV-204457r603261_rule"
vulnid11="V-204457"

title12a="The Red Hat Enterprise Linux operating system must be a vendor supported release."
title12b="Checking with 'cat /etc/redhat-release'."
title12c="Expecting:${YLO}
           Red Hat Enterprise Linux Server release 7.9 (Maipo) (or newer)
           Note: Current End of Extended Update Support for RHEL 7.6 is 31 May 2021.
           Note: Current End of Extended Update Support for RHEL 7.7 is 30 August 2021.
           Note: Current End of Maintenance Support for RHEL 7.9 is 30 June 2024.
           Note: If the release is not supported by the vendor, this is a finding."
cci12="CCI-000366"
stigid12="RHEL-07-020250"
severity12="CAT I"
ruleid12="SV-204458r744100_rule"
vulnid12="V-204458"

title13a="The Red Hat Enterprise Linux operating system security patches and updates must be installed and up to date."
title13b="Checking with 'yum history list | more'."
title13c="Expecting:${YLO}
           Package updates are performed within program requirements.
           Note: If package updates have not been performed on the system within the timeframe that the site/program documentation requires, this is a finding."${BLD}
cci13="CCI-000366"
stigid13="RHEL-07-020260"
severity13="CAT II"
ruleid13="SV-204459r603261_rule"
vulnid13="V-204459"

title14a="The Red Hat Enterprise Linux operating system must not have unnecessary accounts."
title14b="Checking with 'more/etc/passwd'." 
title14c="Expecting:${YLO}
           Have the ISSO verify all accounts.
           Note: If the accounts on the system do not match the provided documentation, or accounts that do not support an authorized system function are present, this is a finding."${BLD}
cci14="CCI-000366"
stigid14="RHEL-07-020270"
severity14="CAT II"
ruleid14="SV-204460r603261_rule"
vulnid14="V-204460"

title15a="The Red Hat Enterprise Linux operating system must be configured so that the root account must be the only account having unrestricted access to the system."
title15b="Checking with 'awk -F: '(\$3 == \"0\") {print \$1}' /etc/passwd'."
title15c="Expecting:${YLO}
           Only the 'root' account has a UID of '0'.
           Note: If any accounts other than root have a UID of \"0\", this is a finding."${BLD}
cci15="CCI 000366"
stigid15="RHEL-07-020310"
severity15="CAT I"
ruleid15="SV-204462r603261_rule"
vulnid15="V-204462"

title16a="The Red Hat Enterprise Linux operating system must be configured so that all local interactive user accounts, upon creation, are assigned a home directory."
title16b="Checking with 'grep -i ^create_home /etc/login.defs'."
title16c="Expecting: ${YLO}
           CREATE_HOME yes
           Note: If the value for \"CREATE_HOME\" parameter is not set to \"yes\", the line is missing, or the line is commented out, this is a finding."
cci16="CCI-000366"
stigid16="RHEL-07-020610"
severity16="CAT II"
ruleid16="SV-204466r603261_rule"
vulnid16="V-204466"

title17a="The Red Hat Enterprise Linux operating system must be configured so that all local interactive user home directories are defined in the /etc/passwd file."
title17b="Checking with 
           a. 'awk -F: '(\$3>=1000)&&(\$7 !~ /nologin/){print \$1, \$3, \$6}' /etc/passwd'
           b. 'pwck -r'."
title17c="Expecting:${YLO}
           All local interactive user home directories defined in the /etc/passwd file exist.
           Note: This may miss interactive users that have been assigned a privileged UID. Evidence of interactive use may be obtained from a number of log files containing system logon information.
           Note: If any home directories referenced in \"/etc/passwd\" are returned as not defined, this is a finding."${BLD}
cci17="CCI-000366"
stigid17="RHEL-07-020620"
severity17="CAT II"
ruleid17="SV-204467r603826_rule"
vulnid17="V-204467"

title18a="The Red Hat Enterprise Linux operating system must be configured so that all local interactive user home directories have mode 0750 or less permissive."
title18b="Checking with 'ls -ld \$(awk -F: '(\$3>=1000)&&(\$7 !~ /nologin/){print \$6}' /etc/passwd)'."
title18c="Expecting:${YLO}
           -rwxr-x--- 1 smithj users 18 Mar 5 17:06 /home/smithj
           Note: If home directories referenced in \"/etc/passwd\" do not have a mode of \"0750\" or less permissive, this is a finding."${BLD}
cci18="CCI-000366"
stigid18="RHEL-07-020630"
severity18="CAT II"
ruleid18="SV-204468r603828_rule"
vulnid18="V-204468"

title19a="The Red Hat Enterprise Linux operating system must be configured so that all local interactive user home directories are owned by their respective users."
title19b="Checking with 'ls -ld \$(awk -F: '(\$3>=1000)&&(\$7 !~ /nologin/){print \$6}' /etc/passwd)'."
title19c="Expecting:${YLO}
           -rwxr-x--- 1 smithj users 18 Mar 5 17:06 /home/smithj
           Note: If any home directories referenced in \"/etc/passwd\" are not owned by the interactive user, this is a finding."${BLD}
cci19="CCI-000366"
stigid19="RHEL-07-020640"
severity19="CAT II"
ruleid19="SV-204469r603830_rule"
vulnid19="V-204469"

title20a="The Red Hat Enterprise Linux operating system must be configured so that all local interactive user home directories are group-owned by the home directory owners primary group."
title30b="Checking with 
           a. 'ls -ld \$(awk -F: '(\$3>=1000)&&(\$7 !~ /nologin/){print \$6}' /etc/passwd)'.
           b. 'grep \$(grep smithj /etc/passwd | awk -F: '{print \$4}') /etc/group'
           Note: If the user home directory referenced in \"/etc/passwd\" is not group-owned by that user's primary GID, this is a finding."${BLD}
title20c="Expecting:${YLO}
           -rwxr-x--- 1 smithj users 13 Apr 1 04:20 /home/smithj
           Note: If the user home directory referenced in \"/etc/passwd\" is not group-owned by that user's primary GID, this is a finding."
cci20="CCI-000366"
stigid20="RHEL-07-020650"
severity20="CAT II"
ruleid20="SV-204470r744102_rule"
vulnid20="V-204470"

title21a="The Red Hat Enterprise Linux operating system must be configured so that all files and directories contained in local interactive user home directories have a valid owner."
title21b="Checking with 'ls -ilR /home/smithj'."
title21c="Expecting:${YLO}
           -rw-r--r-- 1 smithj smithj 18 Mar 5 17:06 file1
           -rw-r--r-- 1 smithj smithj 193 Mar 5 17:06 file2
           -rw-r--r-- 1 smithj smithj 231 Mar 5 17:06 file3
           Note: If any files are found without an owner, this is a finding."
cci21="CCI-000366"
stigid21="RHEL-07-020660"
severity21="CAT II"
ruleid21="SV-204471r744105_rule"
vulnid21="V-204471"

title22a="The Red Hat Enterprise Linux operating system must be configured so that all files and directories contained in local interactive user home directories are group-owned by a group of which the home directory owner is a member."
title22b="Checking with 'ls -llR /<home directory>/<users home directory>/'."
title22c="Expecting:i${YLO}
           -rw-r--r-- 1 smithj smithj 18 Mar 5 17:06 file1
           -rw-r--r-- 1 smithj smithj 193 Mar 5 17:06 file2
           -rw-r--r-- 1 smithj sa 231 Mar 5 17:06 file3
           Note: If the user is not a member of a group that group owns file(s) in a local interactive user's home directory, this is a finding."${BLD}
cci22="CCI-000366"
stigid22="RHEL-07-020670"
severity22="CAT II"
ruleid22="SV-204472r603261_rule"
vulnid22="V-204472"

title23a="The Red Hat Enterprise Linux operating system must be configured so that all files and directories contained in local interactive user home directories have a mode of 0750 or less permissive."
title23b="Checking with 'ls -ilR /<home directory>/<users home directory>/'."
title23c="Expecting:${YLO}
           -rw-r--r-- 1 smithj smithj 18 Mar 5 17:06 file1
           -rw-r--r-- 1 smithj smithj 193 Mar 5 17:06 file2
           -rw-r--r-- 1 smithj sa 231 Mar 5 17:06 file3
           Note: If any files are found with a mode more permissive than \"0750\", this is a finding."${BLD}
cci23="CCI-000366"
stigid23="RHEL-07-020680"
severity23="CAT II"
ruleid23="SV-204473r603261_rule"
vulnid23="V-204473"

title24a="The Red Hat Enterprise Linux operating system must be configured so that all local initialization files for interactive users are owned by the home directory user or root."
title24b="Checking with
           a. awk -F: '(\$3>=1000)&&(\$7 !~ /nologin/){print \$1, \$3, \$6}' /etc/passwd
           b. 'ls -al /home/smithj/.[^.]* | more'."
title24c="Expecting:${YLO}
           -rwxr-xr-x 1 smithj users 896 Mar 10 2011 .profile
           -rwxr-xr-x 1 smithj users 497 Jan 6 2007 .login
           -rwxr-xr-x 1 smithj users 886 Jan 6 2007 .something
           Note: This may miss interactive users that have been assigned a privileged User Identifier (UID). Evidence of interactive use may be obtained from a number of log files containing system logon information.
           Note: If all local interactive user's initialization files are not owned by that user or root, this is a finding."${BLD}
cci24="CCI-000366"
stigid24="RHEL-07-020690"
severity24="CAT II"
ruleid24="SV-204474r603834_rule"
vulnid24="V-204474"

title25a="The Red Hat Enterprise Linux operating system must be configured so that all local initialization files for local interactive users are group-owned by the users primary group or root."
title25b="Checking with 'ls -al /home/smithj/.*'."
title25c="Expecting:${YLO}
           -rwxr-xr-x 1 smithj users 896 Mar 10 2011 .profile
           -rwxr-xr-x 1 smithj users 497 Jan 6 2007 .login
           -rwxr-xr-x 1 smithj users 886 Jan 6 2007 .something
           Note: This may miss interactive users that have been assigned a privileged User Identifier (UID). Evidence of interactive use may be obtained from a number of log files containing system logon information.
           Note: If all local interactive user's initialization files are not group-owned by that user or root, this is a finding."${BLD}
cci25="CCI-000366"
stigid25="RHEL-07-020700"
severity25="CAT II"
ruleid25="SV-204475r603836_rule"
vulnid25="V-204475"

title26a="The Red Hat Enterprise Linux operating system must be configured so that all local initialization files have mode 0740 or less permissive."
title26b="Checking with 'ls -al /home/smithj/.[^.]*'."
title26c="Expecting:${YLO}
           -rwxr-xr-x 1 smithj users 896 Mar 10 2011 .profile
           -rwxr-xr-x 1 smithj users 497 Jan 6 2007 .login
           -rwxr-xr-x 1 smithj users 886 Jan 6 2007 .something
           Note: If any local initialization files have a mode more permissive than \"0740\", this is a finding."${BLD}
cci26="CCI-000366"
stigid26="RHEL-07-020710"
severity26="CAT II"
ruleid26="SV-204476r603261_rule"
vulnid26="V-204476"

title27a="The Red Hat Enterprise Linux operating system must be configured so that all local interactive user initialization files executable search paths contain only paths that resolve to the users home directory."
title27b="Checking with 'grep -i path /home/smithj/.*'."
title27c="Expecting:${YLO}
           /home/smithj/.bash_profile:PATH=\$PATH:\$HOME/.local/bin:\$HOME/bin
           /home/smithj/.bash_profile:export PATH
            or   /root/.bash_profile:PATH=\$PATH:\$HOME/bin
           /root/.bash_profile:export PATH
           Note: If any local interactive user initialization files have executable search path statements that include directories outside of their home directory, this is a finding."${BLD}
cci27="CCI-000366"
stigid27="RHEL-07-020720"
severity27="CAT II"
ruleid27="SV-204477r792828_rule"
vulnid27="V-204477"

title28a="The Red Hat Enterprise Linux operating system must be configured so that local initialization files do not execute world-writable programs."
title28b="Checking with
           a. 'find / -xdev -perm -002 -type f -exec ls -ld {} \;'
           b. 'grep <file> /home/*/.*"
title28c="Expecting:${YLO}
           No world-writable initialization files found
           Note: If any local initialization files are found to reference world-writable files, this is a finding."${BLD}
cci28="CCI-000366"
stigid28="RHEL-07-020730"
severity28="CAT II"
ruleid28="SV-204478r603261_rule"
vulnid28="V-204478"

title29a="The Red Hat Enterprise Linux operating system must be configured so that all system device files are correctly labeled to prevent unauthorized modification."
title29b="Checking with
           a. 'find /dev -context *:device_t:* \( -type c -o -type b \) -printf \"%p %Z\"'
           b. 'find /dev -context *:unlabeled_t:* \( -type c -o -type b \) -printf \"%p %Z\"'."
title29c="Expecting:${YLO}
           Nothing returned (/dev/vmci is an exception for VMs)
           Note: If there is output from either of these commands, other than already noted, this is a finding."${BLD}
cci29="CCI-000368"
stigid29="RHEL-07-020900"
severity29="CAT II"
ruleid29="SV-204479r603261_rule"
vulnid29="V-204479"

title30a="The Red Hat Enterprise Linux operating system must be configured so that file systems containing user home directories are mounted to prevent files with the setuid and setgid bit set from being executed."
title30b="Checking with
           a. 'awk -F: '(\$3>=1000)&&(\$7 !~ /nologin/){print \$1, \$3, \$6}' /etc/passwd
           b. 'cat /etc/fstab' to check the file systems that are mounted at boot time"
title30c="Expecting:${YLO}
           All mounted file systems refering to user home directories are mounted 'nosuid'.
           Note: Expects local interactive user home directories to be on a file system specifically for home directories."${BLD}
cci30="CCI-000366"
stigid30="RHEL-07-021000"
severity30="CAT II"
ruleid30="SV-204480r603838_rule"
vulnid30="V-204480"

title31a="The Red Hat Enterprise Linux operating system must prevent files with the setuid and setgid bit set from being executed on file systems that are used with removable media."
title31b="Checking with 'more /etc/fstab'"
title31c="Expecting:${YLO} Nothing returned, or removable media file systems that have the 'nosuid' option set.
           Note: If a file system found in \"/etc/fstab\" refers to removable media and it does not have the \"nosuid\" option set, this is a finding."${BLD}
cci31="CCI-000366"
stigid31="RHEL-07-021010"
severity31="CAT II"
ruleid31="SV-204481r603261_rule"
vulnid31="V-204481"

title32a="The Red Hat Enterprise Linux operating system must prevent files with the setuid and setgid bit set from being executed on file systems that are being imported via Network File System (NFS)." 
title32b="Checking with
           a. 'more /etc/fstab | grep nfs'
           b. 'mount | grep nfs | grep nosuid'."
title32c="Expecting:${YLO} 
           No NFS mounts found, or no NFS mount without the 'nosuid' option set.
           Note: If a file system found in \"/etc/fstab\" refers to NFS and it does not have the \"nosuid\" option set, this is a finding.${BLD}"
cci32="CCI-000366"
stigid32="RHEL-07-021020"
severity32="CAT II"
ruleid32="SV-204482r603261_rule"
vulnid32="V-204482"

title33a="The Red Hat Enterprise Linux operating system must prevent binary files from being executed on file systems that are being imported via Network File System (NFS)."
title33b="Checking with
           a. 'more /etc/fstab | grep nfs'
           b. 'mount | grep nfs | grep noexec'"
title33c="Expecting:${YLO}
           No NFS mounts found, or NFS mounts without the 'noexec' option set.
           Note: If a file system found in \"/etc/fstab\" refers to NFS and it does not have the \"nosuid\" option set, this is a finding.${BLD}"
cci33="CCI-000366"
stigid33="RHEL-07-021021"
severity33="CAT II"
ruleid33="SV-204483r603261_rule"
vulnid33="V-204483"

title34a="The Red Hat Enterprise Linux operating system must be configured so that all world-writable directories are group-owned by root, sys, bin, or an application group."
title34b="Checking with 'find [PART] -xdev -type d -perm -0002 -gid +999 -print'."
title34c="Expecting:${YLO}
           Nothing returned
           Note: If there is output, this is a finding."${BLD}
cci34="CCI-000366"
stigid34="RHEL-07-021030"
severity34="CAT II"
ruleid34="SV-204487r744106_rule"
vulnid34="V-204487"

title35a="The Red Hat Enterprise Linux operating system must set the umask value to 077 for all local interactive user accounts."
title35b="Checking with
           a. 'awk -F: '(\$3>=1000)&&(\$7 !~ /nologin/){print \$1, \$3, \$6}' /etc/passwd'
           b. 'grep -ir ^umask /<user's home> | grep -v '.bash_history'"
title35c="Expecting:${YLO}
           Nothing returned - (check /etc/login.defs for 'UMASK 077')
           Note: If any local interactive user initialization files are found to have a umask statement that has a value less restrictive than \"077\", this is a finding."${BLD}
cci35="CCI-000368"
stigid35="RHEL-07-021040"
severity35="CAT II"
ruleid35="SV-204488r603261_rule"
vulnid35="V-204488"

title36a="The Red Hat Enterprise Linux operating system must have cron logging implemented."
title36b="Checking with 'grep cron /etc/rsyslog.conf /etc/rsyslog.d/*.conf'."
title36c="Expecting:${YLO}
           cron.* /var/log/cron.log
           Note: If \"rsyslog\" is not logging messages for the cron facility or all facilities, this is a finding.${BLD}"
cci36="CCI-000366"
stigid36="RHEL-07-021100"
severity36="CAT II"
ruleid36="SV-204489r744109_rule"
vulnid36="V-204489"

title37a="The Red Hat Enterprise Linux operating system must be configured so that the cron.allow file, if it exists, is owned by root."
title37b="Checking with 'ls -al /etc/cron.allow'."
title37c="Expecting:${YLO}
           If it exists, cron.allow is owned by root.
           Note: If the \"cron.allow\" file exists and has a owner other than root, this is a finding."${BLD}
cci37="CCI-000366"
stigid37="RHEL-07-021110"
severity37="CAT II"
ruleid37="SV-204490r603261_rule"
vulnid37="V-204490"

title38a="The Red Hat Enterprise Linux operating system must be configured so that the cron.allow file, if it exists, is group-owned by root."
title38b="Checking with 'ls -al /etc/cron.allow'."
title38c="Expecting:${YLO}
           If it exists, cron.allow is group-owned by root.
           Note: If the \"cron.allow\" file exists and has a group-owner other than root, this is a finding."${BLD}
cci38="CCI-000366"
stigid38="RHEL-07-021120"
severity38="CAT II"
ruleid38="SV-204491r603261_rule"
vulnid38="V-204491"

title39a="The Red Hat Enterprise Linux operating system must disable Kernel core dumps unless needed."
title39b="Checking with 'systemctl status kdump.service'."
title39c="Expecting:${YLO}
           Kernel core dumps are disabled unless needed (and documented with the ISSO)
           if active:
           kdump.service - Crash recovery kernel arming 
             Loaded: loaded (/usr/lib/systemd/system/kdump.service; enabled) 
             Active: active (exited) since Wed 2015-08-26 13:08:09 EDT; 43min ago 
           Main PID: 1130 (code=exited, status=0/SUCCESS) 
           kernel arming.
           Note: If the service is active and is not documented, this is a finding."${BLD}
cci39="CCI-000366"
stigid39="RHEL-07-021300"
severity39="CAT II"
ruleid39="SV-204492r603261_rule"
vulnid39="V-204491"

title40a="The Red Hat Enterprise Linux operating system must be configured so that a separate file system is used for user home directories (such as /home or an equivalent)."
title40b="Checking with 'awk -F: '(\$3>=1000)&&(\$7 !~ /nologin/){print \$1, \$3, \$6, \$7}' /etc/passwd)'"
title40c="Expecting:${YLO}
           A separate file system is used for user home directories.
           Note: If a separate entry for the file system/partition that contains the non-privileged interactive users' home directories does not exist, this is a finding."${BLD}
cci40="CCI-000366"
stigid40="RHEL-07-021310"
severity40="CAT III"
ruleid40="SV-204493r603840_rule"
vulnid40="V-204493"

title41a="The Red Hat Enterprise Linux operating system must use a separate file system for /var."
title41b="Checking with 'grep /var /etc/fstab'."
title41c="Expecting:${YLO}
           A separage partition exists for /var.
           Note: If a separate entry for \"/var\" is not in use, this is a finding."${BLD}
cci41="CCI-000366"
stigid41="RHEL-07-021320"
severity41="CAT III"
ruleid41="SV-204494r603261_rule"
vulnid41="V-204494"

title42a="The Red Hat Enterprise Linux operating system must use a separate file system for the system audit data path."
title42b="Checking with 'grep /var/log/audit /etc/fstab'."
title42c="Expecting:${YLO}
           A separate file system for the system audit data path exists.
           Note: If no result is returned, or the operating system is not configured to have \"/var/log/audit\" on a separate file system, this is a finding."${BLD}
cci42="CCI-000366"
stigid42="RHEL-07-021330"
severity42="CAT III"
ruleid42="SV-204495r603261_rule"
vulnid42="V-204495"

title43a="The Red Hat Enterprise Linux operating system must use a separate file system for /tmp (or equivalent)."
title43b="Checking with 'systemctl is-enabled tmp.mount')."
title43c="Expecting:${YLO}
           A separate file system is used for /tmp.
           Note: If the \"tmp.mount\" service is not enabled, or the \"/tmp\" directory is not defined in the fstab with a device and mount point, this is a finding."${BLD}
cci43="CCI-000366"
stigid43="RHEL-07-021340"
severity43="CAT III"
ruleid43="SV-204496r603261_rule"
vulnid43="V-204496"

title44a="The Red Hat Enterprise Linux operating system must be configured so that the file integrity tool is configured to verify Access Control Lists (ACLs)."
title44b="Checking with
           a. 'rpm -qa | grep  aide'
           b. 'find / -name aide.conf'
           c. 'grep +acl aide.conf'
           d. 'grep '^/' aide.conf'
           e. 'grep '^!/' aide.conf'"
title44c="Expecting:i${YLO}
           a. the installed AIDE package
           b. the location of the aide.conf file
           c. aliases that include the 'acl' rule
           d. files and directories that AIDE should scan
           e. files and directories that AIDE should not scan
           Note: If the \"acl\" rule is not being used on all uncommented selection lines in the \"/etc/aide.conf\" file, or ACLs are not being checked by another file integrity tool, this is a finding.
           Note: If there are no directories listed to be scanned, this is a finding"${BLD}
cci44="CCI-000366"
stigid44="RHEL-07-021600"
severity44="CAT III"
ruleid44="SV-204498r603261_rule"
vulnid44="V-204498"

title45a="The Red Hat Enterprise Linux operating system must be configured so that the file integrity tool is configured to verify extended attributes."
title45b="Checking with
           a. 'rpm -qa | grep  aide'
           b. 'find / -name aide.conf'
           c. 'grep +xattrs aide.conf'
           d. 'grep '^/' aide.conf'
           e. 'grep '^!/' aide.conf'"
title45c="Expecting:${YLO}
           a. the installed AIDE package
           b. the location of the aide.conf file
           c. aliases that include the 'xattrs' rule
           d. files and directories that AIDE should scan
           e. files and directories that AIDE should not scan
           Note: If the \"xattrs\" rule is not being used on all uncommented selection lines in the \"/etc/aide.conf\" file, or extended attributes are not being checked by another file integrity tool, this is a finding."${BLD}
cci45="CCI-000366"
stigid45="RHEL-07-021610"
severity45="CAT III"
ruleid45="SV-204499r603261_rule"
vulnid45="V-204499"

title46a="The Red Hat Enterprise Linux operating system must use a file integrity tool that is configured to use FIPS 140-2 approved cryptographic hashes for validating file contents and directories."
title46b="Checking with
           a. 'rpm -qa | grep  aide'
           b. 'find / -name aide.conf'
           c. 'grep +sha512 aide.conf'
           d. 'grep '^/' aide.conf'
           e. 'grep '^!/' aide.conf'"
title46c="Expecting:${YLO}
           a. the installed AIDE package
           b. the location of the aide.conf file
           c. aliases that include the 'sha512' rule
           d. files and directories that AIDE should scan
           e. files and directories that AIDE should not scan
           Note: If the \"sha512\" rule is not being used on all uncommented selection lines in the \"/etc/aide.conf\" file, or another file integrity tool is not using FIPS 140-2 approved cryptographic hashes for validating file contents and directories, this is a finding."${BLD}
cci46="CCI-000366"
stigid46="RHEL-07-021620"
severity46="CAT II"
ruleid46="SV-204500r792831_rule"
vulnid46="V-204500"

title47a="The Red Hat Enterprise Linux operating system must not allow removable media to be used as the boot loader unless approved."
title47b="Checking with
           a. 'find / -name grub.cfg'
           b. 'grep -cw menuentry /boot/grub2/grub.cfg
           c. 'grep set root /boot/grub2/grub.cfg'."
title47c="Expecting:${YLO}
           a. /boot/grub2/grub.cfg (for systems that use BIOS)
             or /boot/efi/EFI/redhat/grub.cfg (for systems that use UEFI)
           b. menuentry 1 (depending on your configuration, there could be more)
           c. set root=(hd0,1) (depending on your configuration, there could  be more)
           Note: If the system is using an alternate boot loader on removable media, and documentation does not exist approving the alternate configuration, this is a finding."${BLD}
cci47="CCI-000368"
stigid47="RHEL-07-021700"
severity47="CAT II"
ruleid47="SV-204501r603261_rule"
vulnid47="V-204501"

title48a="The Red Hat Enterprise Linux operating system must send rsyslog output to a log aggregation server."
title48b="Checking with 'grep @ /etc/rsyslog.conf /etc/rsyslog.d/*.conf'."
title48c="Expecting:${YLO}
           *.* @@logagg.site.mil
           Note: If there are no lines in the \"/etc/rsyslog.conf\" or \"/etc/rsyslog.d/*.conf\" files that contain the \"@\" or \"@@\" symbol(s), and the lines with the correct symbol(s) to send output to another system do not cover all \"rsyslog\" output, ask the System Administrator to indicate how the audit logs are off-loaded to a different system or media.
           Note: If the lines are commented out or there is no evidence that the audit logs are being sent to another system, this is a finding."${BLD}
cci48="CCI-000366"
stigid48="RHEL-07-031000"
severity48="CAT II"
ruleid48="SV-204574r603261_rule"
vulnid48="V-204574"

title49a="The Red Hat Enterprise Linux operating system must be configured so that the rsyslog daemon does not accept log messages from other servers unless the server is being used for log aggregation."
title49b="Checking with
           a. 'grep imtcp /etc/rsyslog.conf'
           b. 'grep imudp /etc/rsyslog.conf'
           c. 'grep imrelp /etc/rsyslog.conf'"
title49c="Expecting:${YLO}
           a. \$ModLoad imtcp
           b. \$ModLoad imudp
           c. \$ModLoad imrelp
           Note: If any of the listed modules are being loaded in the \"/etc/rsyslog.conf\" file, ask to see the documentation for the system being used for log aggregation.
           Note: If the documentation does not exist, or does not specify the server as a log aggregation system, this is a finding."${BLD}
cci49="CCI-000318"
stigid49="RHEL-07-031010"
severity49="CAT II"
ruleid49="SV-204575r603261_rule"
vulnid49="V-204575"

title50a="The Red Hat Enterprise Linux 7 operating system must implement DoD-approved encryption to protect the confidentiality of SSH connections"
title50b="Checking with
           a. 'grep -i ^ciphers /etc/ssh/sshd_config'
           b. 'cat /proc/sys/crypto/fips_enabled'"
title50c="Expecting:${YLO}
           a. fips_enabled = 1
           b. only FIPS 140-2 cryptographic algorithms are authorized.
           Note: If any ciphers other than \"aes256-ctr\", \"aes192-ctr\", or \"aes128-ctr\" are listed, the order differs from the example above, the \"Ciphers\" keyword is missing, or the returned line is commented out, this is a finding.${BLD}"
cci50="CCI-000068"
stigid50="RHEL-07-040110"
severity50="CAT II"
ruleid50="SV-204578r744116_rule"
vulnid50="V-204578"

title51a="The Red Hat Enterprise Linux operating system must implement virtual address space randomization."
title51b="Checking with
           a. 'grep -r kernel.randomize_va_space /run/sysctl.d/* /etc/sysctl.d/* /usr/local/lib/sysctl.d/* /usr/lib/sysctl.d/* /lib/sysctl.d/* /etc/sysctl.conf 2> /dev/null'
           b. '/sbin/sysctl -a | grep kernel.randomize_va_space'."
title51c="Expecting:${YLO}
           kernel.randomize_va_space = 2
           Note: If \"kernel.randomize_va_space\" is not configured in the /etc/sysctl.conf file or in the /etc/sysctl.d/ directory, is commented out or does not have a value of \"2\", this is a finding."${BLD}
cci51="CCI-000366"
stigid51="RHEL-07-040201"
severity51="CAT II"
ruleid51="SV-204584r603261_rule"
vulnid51="V-204584"

title52a="The Red Hat Enterprise Linux operating system must be configured so that the SSH daemon does not allow authentication using RSA rhosts authentication."
title52b="Checking with 'grep ^RhostsRSAAuthentication /etc/ssh/sshd_config'."
title52c="Expecting:${YLO}
           RhostsRSAAuthentication no
           Note: If the release is 7.4 or newer this requirement is Not Applicable.
           Note: If the value is returned as \"yes\", the returned line is commented out, or no output is returned, this is a finding."${BLD}
cci52="CCI-000366"
stigid52="RHEL-07-040330"
severity52="CAT II"
ruleid52="SV-204588r603261_rule"
vulnid52="V-204588"

title53a="The Red Hat Enterprise Linux operating system must be configured so that the SSH daemon does not allow authentication using rhosts authentication."
title53b="Checking with
           'grep -i ignorerhosts /etc/ssh/sshd_config'."
title53c="Expecting:${YLO}
           IgnoreRhosts yes.
           Note: If the value is returned as \"no\", the returned line is commented out, or no output is returned, this is a finding."${BLD}
cci53="CCI-000366"
stigid53="RHEL-07-040350"
severity53="CAT II"
ruleid53="SV-204590r603261_rule"
vulnid53="V-204590"

title54a="The Red Hat Enterprise Linux operating system must not permit direct logons to the root account using remote access via SSH."
title54b="Checking with 'grep -i permitrootlogin' /etc/ssh/sshd_config'."
title54c="Expecting:${YLO}
           PermitRootLogin no
           Note: If the \"PermitRootLogin\" keyword is set to \"yes\", is missing, or is commented out, this is a finding."${BLD}
cci54="CCI-000366"
stigid54="RHEL-07-040370"
severity54="CAT II"
ruleid54="SV-204592r603261_rule"
vulnid54="V-204592"

title55a="The Red Hat Enterprise Linux operating system must be configured so that the SSH daemon does not allow authentication using known hosts authentication."
title55b="Checking with 'grep -i ignoreuserknownhosts /etc/ssh/sshd_config'."
title55c="Expecting:${YLO}
           IgnoreUserKnownHosts yes
           Note: If the value is returned as \"no\", the returned line is commented out, or no output is returned, this is a finding."${BLD}
cci55="CCI-000366"
stigid55="RHEL-07-040380"
severity55="CAT II"
ruleid55="SV-204593r603261_rule"
vulnid55="V-204593"

title56a="The Red Hat Enterprise Linux operating system must be configured so that the SSH daemon is configured to only use the SSHv2 protocol."
title56b="Checking with
           a. 'cat /etc/redhat-release'
           b. 'grep ^Protocol /etc/ssh/sshd_config'."
title56c="Expecting:${YLO}
           a. (a supported version of Red Hat)
           b. Protocol 2 or OpenSSH_7 or later
           Note: If the release is 7.4 or newer this requirement is Not Applicable. 
           Note: If any protocol line other than \"Protocol 2\" is uncommented, this is a finding."${BLD}
cci56="CCI-000366"
stigid56="RHEL-07-040390"
severity56="CAT I"
ruleid56="SV-204594r603261_rule"
vulnid56="V-204594"

title57a="The Red Hat Enterprise Linux operating system must be configured so that the SSH public host key files have mode 0644 or less permissive."
title57b="Checking with 'find /etc/ssh -name '*.pub' -exec ls -lL {} \\;'."
title57c="Expecting:${YLO}
           644 or less
           Note: If any file has a mode more permissive than \"0644\", this is a finding."{BLD}
cci57="CCI-000366"
stigid57="RHEL-07-040410"
severity57="CAT II"
ruleid57="SV-204596r603261_rule"
vulnid57="V-204596"

title58a="The Red Hat Enterprise Linux operating system must be configured so that the SSH private host key files have mode 0640 or less permissive."
title58b="Checking with 'find / -name \'*ssh_host*key\' | xargs ls -lL."
title58c="Expecting:${YLO}
           640 or less
           Note: If any file has a mode more permissive than \"0640\", this is a finding."${BLD}
cci58="CCI-000366"
stigid58="RHEL-07-040420"
severity58="CAT II"
ruleid58="SV-204597r792834_rule"
vulnid58="V-204597"

title59a="The Red Hat Enterprise Linux operating system must be configured so that the SSH daemon does not permit Generic Security Service Application Program Interface (GSSAPI) authentication unless needed."
title59b="Checking with 'grep -i gssapiauth /etc/ssh/sshd_config'."
title59c="Expecting:${YLO}
           GSSAPIAuthentication no
           Note: If the \"GSSAPIAuthentication\" keyword is missing, is set to \"yes\" and is not documented with the Information System Security Officer (ISSO), or the returned line is commented out, this is a finding.
           Note: If GSSAPI authentication is required, it must be documented, to include the location of the configuration file, with the ISSO."${BLD}
cci59="CCI-000368"
stigid59="RHEL-07-040430"
severity59="CAT II"
ruleid59="SV-204598r603261_rule"
vulnid59="V-204598"

title60a="The Red Hat Enterprise Linux operating system must be configured so that the SSH daemon does not permit Kerberos authentication unless needed."
title60b="Checking with 'grep -i kerberosauth /etc/ssh/sshd_config'."
title60c="Expecting:${YLO}
           KerberosAuthentication no
           Note: If the \"KerberosAuthentication\" keyword is missing, or is set to \"yes\" and is not documented with the Information System Security Officer (ISSO), or the returned line is commented out, this is a finding."${BLD}
cci60="CCI-000318"
stigid60="RHEL-07-040440"
severity60="CAT II"
ruleid60="SV-204599r603261_rule"
vulnid60="V-204599"

title61a="The Red Hat Enterprise Linux operating system must be configured so that the SSH daemon performs strict mode checking of home directory configuration files."
title61b="Checking with 'grep -i strictmodes /etc/ssh/sshd_config'."
title61c="Expecting:${YLO}
           StrictModes yes
           Note: If \"StrictModes\" is set to \"no\", is missing, or the returned line is commented out, this is a finding."${BLD}
cci61="CCI-000366"
stigid61="RHEL-07-040450"
severity61="CAT II"
ruleid61="SV-204600r603261_rule"
vulnid61="V-204600"

title62a="The Red Hat Enterprise Linux operating system must be configured so that the SSH daemon uses privilege separation."
title62b="Checking with 'grep -i usepriv /etc/ssh/sshd_config'."
title62c="Expecting:${YLO}
           UsePrivilegeSeparation sandbox
           Note: If the \"UsePrivilegeSeparation\" keyword is set to \"no\", is missing, or the returned line is commented out, this is a finding."${BLD}
cci62="CCI-000366"
stigid62="RHEL-07-040460"
severity62="CAT II"
ruleid62="SV-204601r603261_rule"
vulnid62="V-204601"

title63a="The Red Hat Enterprise Linux operating system must be configured so that the SSH daemon does not allow compression or only allows compression after successful authentication."
title63b="Checking with 'grep -i compression /etc/ssh/sshd_config'."
title63c="Expecting:${YLO}
           Compression delayed
           Note: If the \"Compression\" keyword is set to \"yes\", is missing, or the returned line is commented out, this is a finding."${BLD}
cci63="CCI-000366"
stigid63="RHEL-07-040470"
severity63="CAT II"
ruleid63="SV-204602r603261_rule"
vulnid63="V-204602"

title64a="The Red Hat Enterprise Linux operating system must enable an application firewall, if available."
title64b="Checking with 'yum list installed firewalld'."
title64c="Expecting:${YLO}
           firewalld-0.3.9-11.el7.noarch.rpm or newer
           Note: If an application firewall is not installed, this is a finding.
           Note: If \"firewalld\" does not show a status of \"loaded\" and \"active\", this is a finding.
           Note: If \"firewalld\" does not show a state of \"running\", this is a finding."${BLD}
cci64="CCI-000366"
stigid64="RHEL-07-040520"
severity64="CAT II"
ruleid64="SV-204604r603261_rule"
vulnid64="V-204604"

title65a="The Red Hat Enterprise Linux operating system must not contain .shosts files."
title65b="Checking with 'find / -name '*.shosts'"
title65c="Expecting:${YLO}
           Nothing returned
           Note: If any \".shosts\" files are found on the system, this is a finding."${BLD}
cci65="CCI-000366"
stigid65="RHEL-07-040540"
severity65="CAT I"
ruleid65="SV-204606r603261_rule"
vulnid65="V-204606"

title66a="The Red Hat Enterprise Linux operating system must not contain shosts.equiv files."
title66b="Checking with 'find / -name shosts.equiv'."
title66c="Expecting:${YLO}
           Nothing returned
           Note: If any \"shosts.equiv\" files are found on the system, this is a finding."${BLD}
cci66="CCI-000366"
stigid66="RHEL-07-040550"
severity66="CAT I"
ruleid66="SV-204607r603261_rule"
vulnid66="V-204607"

title67a="For Red Hat Enterprise Linux operating systems using DNS resolution, at least two name servers must be configured."
title67b="Checking with
           a. 'grep hosts /etc/nsswitch.conf'
           b. 'ls -al /etc/resolv.conf'
           c. 'grep nameserver /etc/resolv.conf'."
title67c="Expecting: ${YLO}
           a. hosts: files dns
           b. -rw-r--r-- 1 root root 0 Aug 19 08:31 resolv.conf
           c. two name servers (DNS used).
           Note: If local host authentication is being used and the \"/etc/resolv.conf\" file is not empty, this is a finding.
           Note: If less than two lines are returned that are not commented out, this is a finding."${BLD}
cci67="CCI-000366"
stigid67="RHEL-07-040600"
severity67="CAT III"
ruleid67="SV-204608r603261_rule"
vulnid67="V-204608"

title68a="The Red Hat Enterprise Linux operating system must not forward Internet Protocol version 4 (IPv4) source-routed packets."
title68b="Checking with
           a. 'grep -r net.ipv4.conf.all.accept_source_route /run/sysctl.d/* /etc/sysctl.d/* /usr/local/lib/sysctl.d/* /usr/lib/sysctl.d/* /lib/sysctl.d/* /etc/sysctl.conf 2> /dev/null'
           b. '/sbin/sysctl -a | grep net.ipv4.conf.all.accept_source_route'"
title68c="Expecting:${YLO}
           a. net.ipv4.conf.all.accept_source_route = 0
           b. net.ipv4.conf.all.accept_source_route = 0
           Note: If \"net.ipv4.conf.all.accept_source_route\" is not configured in the /etc/sysctl.conf file or in the /etc/sysctl.d/ directory, is commented out, or does not have a value of \"0\", this is a finding.${BLD}
           Note: If the returned line does not have a value of \"0\", this is a finding."
cci68="CCI-000366"
stigid68="RHEL-07-040610"
severity68="CAT II"
ruleid68="SV-204609r603261_rule"
vulnid68="V-204609"

title69a="The Red Hat Enterprise Linux operating system must use a reverse-path filter for IPv4 network traffic when possible on all interfaces."
title69b="Checking with
           a.'grep -r net.ipv4.conf.all.rp_filter /run/sysctl.d/* /etc/sysctl.d/* /usr/local/lib/sysctl.d/* /usr/lib/sysctl.d/* /lib/sysctl.d/* /etc/sysctl.conf 2> /dev/null'
           b. /sbin/sysctl -a | grep net.ipv4.conf.all.rp_filter"
title69c="Expecting:${YLO}
           a. net.ipv4.conf.all.rp_filter = 1
           b. net.ipv4.conf.all.rp_filter = 1
           Note: If \"net.ipv4.conf.all.rp_filter\" is not configured in the /etc/sysctl.conf file or in the /etc/sysctl.d/ directory, is commented out, or does not have a value of \"1\", this is a finding."${BLD}
cci69="CCI-000366"
stigid69="RHEL-07-040611"
severity69="CAT II"
ruleid69="SV-204610r603261_rule"
vulnid69="V-204610"

title70a="The Red Hat Enterprise Linux operating system must use a reverse-path filter for IPv4 network traffic when possible by default."
title70b="Checking with
           a. '# grep net.ipv4.conf.default.rp_filter /etc/sysctl.conf /usr/lib/sysctl.d/* /etc/sysctl.d/*'.
           b. '# /sbin/sysctl -a | grep net.ipv4.conf.default.rp_filter'."
title70c="Expecting:${YLO}
           a. net.ipv4.conf.default.rp_filter = 1
           b. net.ipv4.conf.default.rp_filter = 1
           Note: If \"net.ipv4.conf.default.rp_filter\" is not configured in the /etc/sysctl.conf file or in the /etc/sysctl.d/ directory, is commented out, or does not have a value of \"1\", this is a finding."${BLD}
cci70="CCI-000366"
stigid70="RHEL-07-040612"
severity70="CAT II"
ruleid70="SV-204611r603261_rule"
vulnid70="V-204611"

title71a="The Red Hat Enterprise Linux operating system must not forward Internet Protocol version 4 (IPv4) source-routed packets by default."
title71b="Checking with
           a. 'grep -r net.ipv4.conf.default.accept_source_route /run/sysctl.d/* /etc/sysctl.d/* /usr/local/lib/sysctl.d/* /usr/lib/sysctl.d/* /lib/sysctl.d/* /etc/sysctl.conf 2> /dev/null'."
title71c="Expecting:${YLO}
           a. net.ipv4.conf.default.accept_source_route = 0
           b. net.ipv4.conf.default.accept_source_route = 0
           Note: If \"net.ipv4.conf.default.accept_source_route\" is not configured in the /etc/sysctl.conf file or in the /etc/sysctl.d/ directory, is commented out, or does not have a value of \"0\", this is a finding.
           Note: If the returned line does not have a value of \"0\", this is a finding."${BLD}
cci71="CCI-000366"
stigid71="RHEL-07-040620"
severity71="CAT II"
ruleid71="SV-204612r603261_rule"
vulnid71="V-204612"

title72a="The Red Hat Enterprise Linux operating system must not respond to Internet Protocol version 4 (IPv4) Internet Control Message Protocol (ICMP) echoes sent to a broadcast address."
title72b="Checking with
           a. 'grep ^net.ipv4.icmp /etc/sysctl.conf | grep ignore_broadcasts'.
           b. '/sbin/sysctl -a | grep net.ipv4.icmp_echo_ignore_broadcasts'."
title72c="Expecting:${YLO}
           a. net.ipv4.icmp_echo_ignore_broadcasts = 1
           b. net.ipv4.icmp_echo_ignore_broadcasts = 1
           Note: If \"net.ipv4.icmp_echo_ignore_broadcasts\" is not configured in the /etc/sysctl.conf file or in the /etc/sysctl.d/ directory, is commented out, or does not have a value of \"1\", this is a finding.
           Note: If the returned line does not have a value of \"1\", this is a finding."${BLD}
cci72="CCI-000366"
stigid72="RHEL-07-040630"
severity72="CAT II"
ruleid72="SV-204613r603261_rule"
vulnid72="V-204613"

title73a="The Red Hat Enterprise Linux operating system must prevent Internet Protocol version 4 (IPv4) Internet Control Message Protocol (ICMP) redirect messages from being accepted."
title73b="Checking with
           a. 'grep -r net.ipv4.conf.default.accept_redirects /run/sysctl.d/* /etc/sysctl.d/* /usr/local/lib/sysctl.d/* /usr/lib/sysctl.d/* /lib/sysctl.d/* /etc/sysctl.conf 2> /dev/null'.
           b. '/sbin/sysctl -a | grep net.ipv4.conf.default.accept_redirects"
title73c="Expecting:${YLO}
           a. net.ipv4.conf.default.accept_redirects = 0
           b. net.ipv4.conf.default.accept_redirects = 0
           Note: If \"net.ipv4.conf.default.accept_redirects\" is not configured in the /etc/sysctl.conf file or in the /etc/sysctl.d/ directory, is commented out, or does not have a value of \"0\", this is a finding.
           Note: If the returned line does not have a value of \"0\", this is a finding."${BLD}
cci73="CCI-000366"
stigid73="RHEL-07-040640"
severity73="CAT II"
ruleid73="SV-204614r603261_rule"
vulnid73="V-204614"

title74a="The Red Hat Enterprise Linux operating system must ignore Internet Protocol version 4 (IPv4) Internet Control Message Protocol (ICMP) redirect messages."
title74b="Checking with
           a. 'grep -r net.ipv4.conf.all.accept_redirects /run/sysctl.d/* /etc/sysctl.d/* /usr/local/lib/sysctl.d/* /usr/lib/sysctl.d/* /lib/sysctl.d/* /etc/sysctl.conf 2> /dev/null'.
           b. '/sbin/sysctl -a | grep net.ipv4.conf.all.accept_redirects"
title74c="Expecting:${YLO}
           a. net.ipv4.conf.all.accept_redirects = 0
           b. net.ipv4.conf.all.accept_redirects = 0
           Note: If \"net.ipv4.conf.all.accept_redirects\" is not configured in the /etc/sysctl.conf file or in the /etc/sysctl.d/ directory, is commented out, or does not have a value of \"0\", this is a finding.
           Note: If the returned line does not have a value of \"0\", this is a finding."${BLD}
cci74="CCI-000366"
stigid74="RHEL-07-040641"
severity74="CAT II"
ruleid74="SV-204615r603261_rule"
vulnid74="V-204615"

title77a="Network interfaces configured on the Red Hat Enterprise Linux operating system must not be in promiscuous mode."
title77b="Checking with 'ip link | grep -i promisc'."
title77c="Expecting: Nothing returned
           Note: If network interfaces are found on the system in promiscuous mode and their use has not been approved by the ISSO and documented, this is a finding."
cci77="CCI-000366"
stigid77="RHEL-07-040670"
severity77="CAT II"
ruleid77="SV-204618r603261_rule"
vulnid77="V-204618"

title75a="The Red Hat Enterprise Linux operating system must not allow interfaces to perform Internet Protocol version 4 (IPv4) Internet Control Message Protocol (ICMP) redirects by default."
title75b="Checking with
           a. 'grep -r net.ipv4.conf.default.send_redirects /run/sysctl.d/* /etc/sysctl.d/* /usr/local/lib/sysctl.d/* /usr/lib/sysctl.d/* /lib/sysctl.d/* /etc/sysctl.conf 2> /dev/null'.
           b. '/sbin/sysctl -a | grep net.ipv4.conf.default.send_redirects"
title75c="Expecting:${YLO}
           a. net.ipv4.conf.default.send_redirects = 0
           b. net.ipv4.conf.default.send_redirects = 0
           Note: If \"net.ipv4.conf.default.send_redirects\" is not configured in the \"/etc/sysctl.conf\" file or in the /etc/sysctl.d/ directory, is commented out or does not have a value of \"0\", this is a finding.
           Note: If the returned line does not have a value of \"0\", this is a finding."${BLD}
cci75="CCI-000366"
stigid75="RHEL-07-040650"
severity75="CAT II"
ruleid75="SV-204616r603261_rule"
vulnid75="V-204616"

title76a="The Red Hat Enterprise Linux operating system must not send Internet Protocol version 4 (IPv4) Internet Control Message Protocol (ICMP) redirects."
title76b="Checking with
           a. 'grep -r net.ipv4.conf.all.send_redirects /run/sysctl.d/* /etc/sysctl.d/* /usr/local/lib/sysctl.d/* /usr/lib/sysctl.d/* /lib/sysctl.d/* /etc/sysctl.conf 2> /dev/null
'.
           b. '/sbin/sysctl -a | grep net.ipv4.conf.all.send_redirects'."
title76c="Expecting:${YLO}
           a. net.ipv4.conf.all.send_redirects = 0
           b. net.ipv4.conf.all.send_redirects = 0
           Note: If \"net.ipv4.conf.all.send_redirects\" is not configured in the /etc/sysctl.conf file or in the /etc/sysctl.d/ directory, is commented out or does not have a value of \"0\", this is a finding.
           Note: If the returned line does not have a value of \"0\", this is a finding."${BLD}
cci76="CCI-000366"
stigid76="RHEL-07-040660"
severity76="CAT II"
ruleid76="SV-204617r603261_rule"
vulnid76="V-204617"

title77a="Network interfaces configured on the Red Hat Enterprise Linux operating system must not be in promiscuous mode."
title77b="Checking with 'ip link | grep -i promisc'."
title77c="Expecting:${YLO}
           Nothing returned
           Note: If network interfaces are found on the system in promiscuous mode and their use has not been approved by the ISSO and documented, this is a finding."${BLD}
cci77="CCI-000366"
stigid77="RHEL-07-040670"
severity77="CAT II"
ruleid77="SV-204618r603261_rule"
vulnid77="V-204618"

title78a="The Red Hat Enterprise Linux operating system must be configured to prevent unrestricted mail relaying."
title78b="Checking with
           a. 'yum list installed postfix'
           b. 'systemctl status postfix'
           c. 'postconf -n smtpd_client_restrictions'."
title78c="Expecting:${YLO}
           a. Nothing returned
           b. ● postfix.service - Postfix Mail Transport Agent
                  Loaded: loaded (/usr/lib/systemd/system/postfix.service; enabled; vendor preset: disabled)
                  Active: inactive (dead) since Sat 2023-04-01 08:05:13 MDT; 5s ago

           c. smtpd_client_restrictions = permit_mynetworks, reject
           Note: If postfix is not installed, this is Not Applicable.
           Note: If the \"postfix.service\" is not running, this is Not Applicable.
           Note: If the \"smtpd_client_restrictions\" parameter contains any entries other than \"permit_mynetworks\" and \"reject\", this is a finding."${BLD}
cci78="CCI-000366"
stigid78="RHEL-07-040680"
severity78="CAT II"
ruleid78="SV-204619r603261_rule"
vulnid78="V-204619"

title79a="The Red Hat Enterprise Linux operating system must not have a File Transfer Protocol (FTP) server package installed unless needed."
title79b="Checking with 'yum list installed vsftpd'."
title79c="Expecting:${YLO}
           Nothing returned.
           Note: If \"vsftpd\" is installed and is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding."${BLD}
cci79="CCI-000366"
stigid79="RHEL-07-040690"
severity79="CAT I"
ruleid79="SV-204620r603261_rule"
vulnid79="V-204620"

title80a="The Red Hat Enterprise Linux operating system must not have a File Transfer Protocol (FTP) server package installed unless needed."
title80b="Checking with 'yum list installed tftp-server'."
title80c="Expecting:${YLO}
           Nothing returned.
           Note: If \"tftp-server\" is installed and is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding."${BLD}
cci80="CCI-000366"
stigid80="RHEL-07-040690"
severity80="CAT I"
ruleid80="SV-204621r603261_rule"
vulnid80="V-204621"

title81a="The Red Hat Enterprise Linux operating system must be configured so that remote X connections are disabled except to fulfill documented and validated mission requirements."
title81b="Checking with 'grep -i x11forwarding /etc/ssh/sshd_config | grep -v \"^#\"'"
title81c="Expecting:${YLO}
           X11Forwarding no
           Note: If the \"X11Forwarding\" keyword is set to \"yes\" and is not documented with the Information System Security Officer (ISSO) as an operational requirement or is missing, this is a finding."${BLD}
cci81="CCI-000366"
stigid81="RHEL-07-040710"
severity81="CAT II"
ruleid81="SV-204622r603849_rule"
vulnid81="V-204622"

title82a="The Red Hat Enterprise Linux operating system must not have a File Transfer Protocol (FTP) server package installed unless needed."
title82b="Checking with
           a. 'yum list installed tftp-server'
           b. 'grep server_args /etc/xinetd.d/tftp'"
title82c="Expecting:${YLO}
           Nothing returned. But if it is,
           a. tftp-server.x86_64 x.x-x.el7 rhel-7-server-rpms
           b. server_args = -s /var/lib/tftpboot
           Note: If a TFTP server is not installed, this is Not Applicable.
           Note: If \"tftp-server\" is installed and is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding.
           Note: If the \"server_args\" line does not have a \"-s\" option and a subdirectory is not assigned, this is a finding."${BLD}
cci82="CCI-000366"
stigid82="RHEL-07-040690"
severity82="CAT I"
ruleid82="SV-204623r603261_rule"
vulnid82="V-204623"

title83a="The Red Hat Enterprise Linux operating system must not have a graphical display manager installed unless approved."
title83b="Checking with
           a. 'rpm -qa | grep xorg | grep server'
           b. 'systemctl get-default'"
title83c="Expecting:${YLO}
           a. xorg-x11-server-Xorg-1.20.4-22.el7_9.x86_64
              xorg-x11-server-utils-7.7-20.el7.x86_64
              xorg-x11-server-common-1.20.4-22.el7_9.x86_64
           b. multi-user.target
           Note: If GNOME or a graphical user interface is not installed, this is Not Applicable.
           Note: If the use of X Windows on the system is not documented with the Information System Security Officer (ISSO), this is a finding."
cci83="CCI-000366"
stigid83="RHEL-07-040730"
severity83="CAT II"
ruleid83="SV-204624r646847_rule"
vulnid83="V-204624"

title84a="The Red Hat Enterprise Linux operating system must not be performing packet forwarding unless the system is a router."
title84b="Checking with
           a. 'grep -r net.ipv4.ip_forward /run/sysctl.d/* /etc/sysctl.d/* /usr/local/lib/sysctl.d/* /usr/lib/sysctl.d/* /lib/sysctl.d/* /etc/sysctl.conf 2> /dev/nul'.
           b. '/sbin/sysctl -a | grep net.ipv4.ip_forward'"
title84c="Expecting:${YLO}
           a. net.ipv4.ip_forward = 0
           b. net.ipv4.ip_forward = 0
           Note: If \"net.ipv4.ip_forward\" is not configured in the /etc/sysctl.conf file or in the /etc/sysctl.d/ directory, is commented out, or does not have a value of \"0\", this is a finding.
           Note: If IP forwarding value is \"1\" and the system is hosting any application, database, or web servers, this is a finding."${BLD}
cci84="CCI-000366"
stigid84="RHEL-07-040740"
severity84="CAT II"
ruleid84="SV-204625r603261_rule"
vulnid84="V-204625"

title85a="The Red Hat Enterprise Linux operating system must be configured so that the Network File System (NFS) is configured to use RPCSEC_GSS."
title85b="Checking with 'cat /etc/fstab | grep nfs'."
title85c="Expecting:${YLO}
           192.168.21.5:/mnt/export /data1 nfs4 rw,sync ,soft,sec=krb5:krb5i:krb5p'.
           Note: If the system is mounting file systems via NFS and has the sec option without the \"krb5:krb5i:krb5p\" settings, the \"sec\" option has the \"sys\" setting, or the \"sec\" option is missing, this is a finding."${BLD}
cci85="CCI-000366"
stigid85="RHEL-07-040750"
severity85="CAT II"
ruleid85="SV-204626r603261_rule"
vulnid85="V-204626"

title86a="SNMP community strings on the Red Hat Enterprise Linux operating system must be changed from the default."
title86b="Checking with
           a. 'ls -al /etc/snmp/snmpd.conf'
           b. 'grep public /etc/snmp/snmpd.conf
           c. 'grep private /etc/snmp/snmpd.conf"
title86c="Expecting:${YLO}
           a. -rw-------   1 root root      52640 Mar 12 11:08 snmpd.conf
           b. Nothing found
           c. Nothing found
           Note: If the file does not exist, this is Not Applicable.
           Note: If either of these commands returns any output, this is a finding."${BLD}
cci86="CCI-000366"
stigid86="RHEL-07-040800"
severity86="CAT I"
ruleid86="SV-204627r603261_rule"
vulnid86="V-204627"

title87a="The Red Hat Enterprise Linux operating system access control program must be configured to grant or deny system access to specific hosts and services."
title87b="Checking with
           a. 'systemctl status firewalld'
           b. 'firewall-cmd --get-default-zone'
           c. 'firewall-cmd --list-all --zone=public'
           d. 'ls -al /etc/hosts.allow'
           e. 'ls -al /etc/hosts.deny"
title87c="Expecting:${YLO}
           a. firewalld.service - firewalld - dynamic firewall daemon
                Loaded: loaded (/usr/lib/systemd/system/firewalld.service; enabled)
                Active: active (running) since Sun 2014-04-20 14:06:46 BST; 30s ago
           b. public
           c. public (active)
                target: default
                icmp-block-inversion: no
                interfaces: enp0s3
                sources: 
                services: dhcpv6-client ssh
                ports: 
                protocols: 
                masquerade: no
                forward-ports: 
                source-ports: 
                icmp-blocks: 
                rich rules:
           d. -rw-r--r--. 1 root root 370 Jun  7  2013 /etc/hosts.allow
           e. -rw-r--r--. 1 root root 460 Jun  7  2013 /etc/hosts.deny
           Note: Use the zone assigned to your LAN interface.
           Note: If \"firewalld\" and \"tcpwrappers\" are not installed, configured, and active, ask the SA if another access control program (such as iptables) is installed and active. Ask the SA to show that the running configuration grants or denies access to specific hosts or services.
           Note: If \"firewalld\" is active and is not configured to grant access to specific hosts or \"tcpwrappers\" is not configured to grant or deny access to specific hosts, this is a finding."${BLD}
cci87="CCI-000366"
stigid87="RHEL-07-040810"
severity87="CAT II"
ruleid87="SV-204628r603261_rule"
vulnid87="V-204628"

title88a="The Red Hat Enterprise Linux operating system must not have unauthorized IP tunnels configured."
title88b="Checking with
           a. 'yum list installed | grep libreswan'
           b. 'systemctl status ipsec'
           c. 'grep -iw conn /etc/ipsec.conf /etc/ipsec.d/*.conf'"
title88c="Expecting:${YLO}
           a. openswan-2.6.32-27.el6.x86_64 (or libreswan.x86_64)
           b. ipsec.service - Internet Key Exchange (IKE) Protocol Daemon for IPsec
                Loaded: loaded (/usr/lib/systemd/system/ipsec.service; disabled)
                Active: inactive (dead)
           c. Nothing found
           Note: If there are indications that a \"conn\" parameter is configured for a tunnel, ask the System Administrator if the tunnel is documented with the ISSO.
           Note: If \"libreswan\" is installed, \"IPsec\" is active, and an undocumented tunnel is active, this is a finding."${BLD}
cci88="CCI-000366"
stigid88="RHEL-07-040820"
severity88="CAT II"
ruleid88="SV-204629r603261_rule"
vulnid88="V-204629"

title89a="The Red Hat Enterprise Linux operating system must not forward IPv6 source-routed packets."
title89b="Checking with
           a. 'grep -r net.ipv6.conf.all.accept_source_route /run/sysctl.d/* /etc/sysctl.d/* /usr/local/lib/sysctl.d/* /usr/lib/sysctl.d/* /lib/sysctl.d/* /etc/sysctl.conf 2> /dev/null'
           b. '/sbin/sysctl -a | grep net.ipv6.conf.all.accept_source_route'"
title89c="Expecting:${YLO}
           a. net.ipv6.conf.all.accept_source_route = 0
           b. net.ipv6.conf.all.accept_source_route = 0
           Note: If \"net.ipv6.conf.all.accept_source_route\" is not configured in the /etc/sysctl.conf file or in the /etc/sysctl.d/ directory, is commented out or does not have a value of \"0\", this is a finding.
           Note: If the returned lines do not have a value of \"0\", this is a finding."${BLD}
cci89="CCI-000366"
stigid89="RHEL-07-040830"
severity89="CAT II"
ruleid89="SV-204630r603261_rule"
vulnid89="V-204630"

title90a="The Red Hat Enterprise Linux operating system must implement the Endpoint Security for Linux Threat Prevention tool."
title90b="Checking with
           a. 'rpm -qa | grep -i mcafeetp'
           b. 'ps -ef | grep -i mfetpd'"
title90c="Expecting:
           a. (the mcafeetp rpm)
           b. (the mcafeetp daemon is running)
           Note: If the \"mcafeetp\" package is not installed, this is a finding.
           Note: If the daemon is not running, this is a finding."${BLD}
cci90="CCI-001263"
stigid90="RHEL-07-020019"
severity90="CAT II"
ruleid90="SV-214800r854323_rule"
vulnid90="V-214800"

title91a="The Red Hat Enterprise Linux operating system must use a virus scan program."
title91b="Checking with: (using clamav as an example)
           a. yum list installed clamav
           b. crontab -l | grep clam
           c. grep -ir clam /etc/cron.daily
           d. grep -w clamscan /var/log/cron
           e. tail var/log/clamav/clamscan.log (check scan.log config)"
title91c="Expecting:${YLO}
           a. clamav.x86_64         0.103.8-3.el7              @epel
           b. 15,4,*,*,0 /bin/clamscan -r /home --move=/tmp/quar --log=/var/log/clamav/clamscan.log --infected & --quiet
           c. Get the name of the script and the command that cron.daily runs
           d. /etc/cron.daily/50-clamscan.sh:clamscan -r /home --move=/tmp/quar --log=/var/log/clamav/clamscan.log --infected & --quiet (for example)
           e. Evidence that the daily scan is logging
           Note: If there is no anti-virus solution installed on the system, this is a finding."${BLD}
cci91="CCI-000366"
stigid91="RHEL-07-032000"
severity91="CAT I"
ruleid91="SV-214801r603261_rule"
vulnid91="V-214801"

title92a="The Red Hat Enterprise Linux operating system must disable the graphical user interface automounter unless required."
title92b="Checking with:
           a. 'grep -ir automount /etc/dconf*/*'
           b. 'cat /etc/dconf/db/local.d/locks/00-No-Automount"
title92c="Expecting:${YLO}
           a. automount=false
              automount-open=false
              autorun-never=true
           b. /org/gnome/desktop/media-handling/automount
              /org/gnome/desktop/media-handling/automount-open
              /org/gnome/desktop/media-handling/autorun-never
           Note: If the output does not match the example, this is a finding."${BLD}
cci92="CCI-000366"
stigid92="RHEL-07-020111"
severity92="CAT II"
ruleid92="SV-219059r603261_rule"
vulnid92="V-219059"

title93a="The Red Hat Enterprise Linux operating system must be configured so that all world-writable directories are owned by root, sys, bin, or an application user."
title93b="Checking with
           'find [PART] -xdev -type d -perm -0002 -uid +999 -print'"
title93c="Expecting:${YLO}
           Nothing returned
           Note: If there is output, this is a finding."${BLD}
cci93="CCI-000366"
stigid93="RHEL-07-021031"
severity93="CAT II"
ruleid93="SV-228563r744119_rule"
vulnid93="V-228563"

title94a="The Red Hat Enterprise Linux operating system SSH daemon must prevent remote hosts from connecting to the proxy display."
title94b="Checking with:
           'grep -i x11uselocalhost /etc/ssh/sshd_config'"
title94c="Expecting:${YLO}
           X11UseLocalhost yes
           Note: If the \"X11UseLocalhost\" keyword is set to \"no\", is missing, or is commented out, this is a finding."${BLD}
cci94="CCI-000366"
stigid94="RHEL-07-040711"
severity94="CAT II"
ruleid94="SV-233307r603301_rule"
vulnid94="V-233307"

title95a="The Red Hat Enterprise Linux operating system must restrict privilege elevation to authorized personnel."
title95b="Checking with:
           grep -iw 'ALL' /etc/sudoers /etc/sudoers.d/*"
title95c="Expecting"${YLO}
cci95="CCI-000366"
stigid95="RHEL-07-010341"
severity95="CAT II"
ruleid95="SV-237633r646850_rule"
vulnid95="V-237633"

title96a="The Red Hat Enterprise Linux operating system must not have accounts configured with blank or null passwords."
title96b="Checking with:
           awk -F: '!\$2 {print \$1}' /etc/shadow"
title96c="Expecting:${YLO}
           Nothing returned
           Note: If the command returns any results, this is a finding."${BLD}
cci96="CCI-000366"
stigid96="RHEL-07-010291"
severity96="CAT I"
ruleid96="SV-251702r809220_rule"
vulnid96="V-251702"

title97a="The Red Hat Enterprise Linux operating system must specify the default "include" directory for the /etc/sudoers file."
title97b="Checking with:
           grep include /etc/sudoers"
title97c="Expecting:${YLO}
           #includedir /etc/sudoers.d
           Note: If the results are not "/etc/sudoers.d" or additional files or directories are specified, this is a finding."${BLD}
cci97="CCI-000366"
stigid97="RHEL-07-010339"
severity97="CAT II"
ruleid97="SV-251703r833183_rule"
vulnid97="V-251703"

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

file1a="/etc/shadow"
file1arr=('/etc/pam.d/system-auth' '/etc/pam.d/password-auth')
fail=0

if [[ -f $file1a ]]
then
   isnull="$(awk -F":" '($2 == "") {print $1 ":" $2 ":"}' $file1a)"
   if [[ $isnull ]]
   then
      for acct in ${isnull[@]}
      do
         fail=1
         echo -e "${NORMAL}RESULT:    ${RED}The '$acct' account has a blank password in $file1a${NORMAL}"
      done
   else
      echo -e "${NORMAL}RESULT:    ${BLD}There are no accounts with blank or null passwords in $file1a${NORMAL}"
   fi
   for file in ${file1arr[@]}
   do
      if [[ -f $file ]]
      then
         nullok="$(grep nullok $file)"
         if [[ $nullok ]]
         then
            fail=2
            for line in ${nullok[@]}
            do
               echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
            done
         else
            echo -e "${NORMAL}RESULT:    ${BLD}\"nullok\" was not found in $file${NORMAL}"
         fi
      else
         echo -e "${NORMAL}RESULT:    ${RED}$file not found${NORMAL}"
      fi
   done

   if [[ $fail == 1 ]]
   then
      echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${RED}FAILED, Blank or Null Passwords: Accounts with blank or null passwords found${NORMAL}"
   elif [[ $fail == 2 ]]
   then
       echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${RED}FAILED, Blank or Null Passwords (nullok): Accounts with blank or null passwords are possible${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${GRN}PASSED, Blank or Null Passwords: No blank passwords found or allowed${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${BLD}$file1a was not found${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${RED}FAILED, Blank or Null Passwords: $file1a not found${NORMAL}"
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

file2="/etc/login.defs"

if [[ -f $file2 ]]
then
   delay="$(grep -i 'fail_delay' $file2 | grep -v '^#')"
   if [[ $delay ]]
   then
      echo -e "${NORMAL}RESULT:    ${BLD}$delay${NORMAL}"
      delaytime="$(echo $delay | awk '{print $2}')"
      if (( $delaytime >= 4 ))
      then
         echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${GRN}PASSED, FAIL_DELAY - The delay between logon prompts following a failed console logon is $delaytime seconds${NORMAL}"
      else
         echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${RED}FAILED, FAIL_DELAY - The delay between logon prompts following a failed console logon is $delaytime seconds${NORMAL}"
      fi
   else
      echo -e "${NORMAL}RESULT:    ${RED}'FAIL_DELAY' is not defined in $file2${NORMAL}"
      echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${RED}FAILED, FAIL_DELAY - The delay between logon prompts following a failed console logon is not defined${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${RED}$file2 was not found${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${RED}FAILED, $file2 was not found${NORMAL}"
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

file3="/etc/gdm/custom.conf"
fail=1

if [[ -f $file3 ]]
then # (Gnome is installed)
   autologin="$(grep -i automaticloginenable $file3)"
   if [[ $autologin ]]
   then
      autologinval="$(echo $autologin | awk -F'= ' '{print tolower($2)}')"
      if [[ ${autologin:0:1} != '#' && $autologinval == 'false' ]]
      then
         echo -e "${NORMAL}RESULT:    ${BLD}$autologin${NORMAL}"
         fail=0
      else
         echo -e "${NORMAL}RESULT:    ${RED}$autologin${NORMAL}"
      fi
   else
      echo -e "${NORMAL}RESULT:    ${RED}AutomaticLoginEnable was not defined in $file3${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${BLD}GNOME is not installed${NORMAL}"
   fail=2
fi

if [[ $fail == 0 ]]
then
   echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${GRN}PASSED, Unattended Logons: Unattended or automatic logins are not allowed${NORMAL}"
elif [[ $fail == 2 ]]
then
   echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${GRN}N/A, Unattended Logons: Not Applicable: GNOME is not installed${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${RED}FAILED, Unattended Logons: Unattended or automatic logins are allowed${NORMAL}"
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

file4="/etc/gdm/custom.conf"
fail=1

if [[ -f $file4 ]]
then # (Gnome is installed)
   timedlogin="$(grep -i ^timedloginenable $file4)"
   if [[ $timedlogin ]]
   then
      timedloginval="$(echo $timedlogin | awk -F'= ' '{print tolower($2)}')"
      if [[ ${timedlogin:0:1} != '#' && $timedloginval == 'false' ]]
      then
         echo -e "${NORMAL}RESULT:    ${BLD}$timedlogin${NORMAL}"
         fail=0
      else
         echo -e "${NORMAL}RESULT:    ${RED}$timedlogin${NORMAL}"
      fi
   else
      echo -e "${NORMAL}RESULT:    ${RED}TimedLoginEnable was not defined in $file4${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${RED}GNOME is not installed${NORMAL}"
   fail=2
fi

if [[ $fail == 0 ]]
then
   echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${GRN}PASSED, Unrestricted Logons: Unrestricted logins are not allowed${NORMAL}"
elif [[ $fail == 2 ]]
then
   echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${GRN}N/A, Unrestricted Logons: Not Applicable - GNOME is not installed${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${RED}FAILED, Unrestricted Logons: Unrestricted logins are allowed${NORMAL}"
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

file5="/etc/ssh/sshd_config"
fail=1

if [[ -f $file5 ]]
then
   userenv="$(grep -i '^permituserenvironment' $file5)"
   if [[ $userenv ]]
   then
      userenval="$(echo $userenv | awk '{print $2}')"
      if [[ $userenval == 'no' ]]
      then
         echo -e "${NORMAL}RESULT:    ${BLD}$userenv${NORMAL}"
         fail=0
      else
         echo -e "${NORMAL}RESULT:    ${RED}$userenv${NORMAL}"
      fi
   else
      echo -e "${NORMAL}RESULT:    ${RED}PermitUserEnvironment was not defined in $file5${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${RED}$file5 was not found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
   echo -e "${NORMAL}$hostname, $severity5, $controlid, $stigid5, $ruleid5, $cci5, $datetime, ${GRN}PASSED, SSH Override: Users are not allowed to override environment variables to the SSH daemon${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity5, $controlid, $stigid5, $ruleid5, $cci5, $datetime, ${RED}FAILED, SSH Override: Users are allowed to override environment variables to the SSH daemon${NORMAL}"
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

datetime="$(date +%FT%H:%M:%S)"

file6="/etc/ssh/sshd_config"
fail=1

if [[ -f $file6 ]]
then
   hauth="$(grep -i '^hostbasedauthentication' $file6)"
   if [[ $hauth ]]
   then
      hauthval="$(echo $hauth | awk '{print $2}')"
      if [[ $hauthval == 'no' ]]
      then
         echo -e "${NORMAL}RESULT:    ${BLD}$hauth${NORMAL}"
         fail=0
      else
         echo -e "${NORMAL}RESULT:    ${RED}$hauth${NORMAL}"
      fi
   else
      echo -e "${NORMAL}RESULT:    ${BLD}HostbasedAuthentication was not defined in $file6${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${BLD}$file6 was not found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
   echo -e "${NORMAL}$hostname, $severity6, $controlid, $stigid6, $ruleid6, $cci6, $datetime, ${GRN}PASSED, SSH Logon: Non-certificate trusted hosts are not allowed SSH logon to the system${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity6, $controlid, $stigid6, $ruleid6, $cci6, $datetime, ${RED}FAILED, SSH Logon: Non-certificate trusted hosts are allowed SSH logon to the system${NORMAL}"
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

datetime="$(date +%FT%H:%M:%S)"

dir7="/etc/modprobe.d"
fail=1

if [[ -d $dir7 ]]
then
   installusb="$(grep -r usb-storage $dir7/* | grep -i '/bin/true' | grep -v '^#')"
   if [[ $installusb ]]
   then
      for line in ${installusb[@]}
      do
        echo -e "${NORMAL}RESULT:    ${BLD}$installusb${NORMAL}"
      done
      blacklist="$(grep usb-storage $dir7/* | grep -i 'blacklist' | grep -v '^#')"
      if [[ $blacklist ]]
      then
         for line in ${blacklist[@]}
         do
            echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
            fail=0
         done
      else
         echo -e "${NORMAL}RESULT:    ${RED}\"blacklist usb-storage\" not found in $dir7/*${NORMAL}"
      fi
   else
      echo  -e "${NORMAL}RESULT:    ${BLD}\"usb-storage\" not found in $dir7/*${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    $dir7 not found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
   echo -e "${NORMAL}$hostname, $severity7, $controlid, $stigid7, $ruleid7, $cci7, $datetime, ${GRN}PASSED, USB Blacklist: USB mass storage is blacklisted.${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity7, $controlid, $stigid7, $ruleid7, $cci7, $datetime, ${RED}FAILED, USB Blacklist: USB mass storage is not blacklisted.${NORMAL}"
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

datetime="$(date +%FT%H:%M:%S)"

isinstalled="$(rpm -qa | grep ^autofs)"
fail=0

if [[ $isinstalled ]]
then
   statusv="$(systemctl status autofs)"
   if [[ $statusv ]]
   then
      for line in ${statusv[@]}
      do
         if [[ $line =~ 'Loaded' && $line =~ 'disabled' ]]
         then
            echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
         elif [[ $line =~ 'Loaded' && $line =~ 'enabled' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
            fail=1
         elif [[ $line =~ 'Active' && $line =~ 'dead' ]]
         then
            echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
         elif [[ $line =~ 'Active' && $line =~ 'running' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
            fail=1
         else
            echo -e "${NORMAL}RESULT:    $line${NORMAL}"
         fi
      done
   else
      echo -e "${NORMAL}RESULT:    ${RED}$statusv${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${BLD}The autofs rpm is not installed${NORMAL}" 
fi
   
if [[ $fail == 0 ]]
then
   echo -e "${NORMAL}$hostname, $severity8, $controlid, $stigid8, $ruleid8, $cci8, $datetime, ${GRN}PASSED, The file system automounter is either not installed or is disabled${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity8, $controlid, $stigid8, $ruleid8, $cci8, $datetime, ${RED}FAILED, The file system automounter is not disabled${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid9${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid9${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid9${NORMAL}"
echo -e "${NORMAL}CCI:       $cci9${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 9:    ${BLD}$title9a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title9b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title9c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity9${NORMAL}"

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

fail=0

statusv="$(systemctl status ctrl-alt-del.target)"
if [[ $statusv ]]
then
   for line in ${statusv[@]}
   do
      if [[ $line =~ 'Loaded' && $line =~ 'masked' ]]
      then
         echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
      elif [[ $line =~ 'Loaded' && !$line =~ 'masked' ]]
      then
         echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
         fail=1
      elif [[ $line =~ 'Active' && $line =~ 'dead' ]]
      then
         echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
      elif [[ $line =~ 'Active' && ! $line =~ 'dead' ]]
      then
         echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
         fail=1
      else
         echo -e "${NORMAL}RESULT:    $line${NORMAL}"
      fi
   done
else
   echo -e "${NORMAL}RESULT:    ${RED}$statusv${NORMAL}"
fi

if [[ $fail == 0 ]]
then
   echo -e "${NORMAL}$hostname, $severity9, $controlid, $stigid9, $ruleid9, $cci9, $datetime, ${GRN}PASSED, The operating system is not configured to reboot the system when Ctrl-Alt-Delete is pressed.${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity9, $controlid, $stigid9, $ruleid9, $cci9, $datetime, ${RED}FAILED, The operating system is configured to reboot the system when Ctrl-Alt-Delete is pressed.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid10${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid10${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid10${NORMAL}"
echo -e "${NORMAL}CCI:       $cci10${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 10:   ${BLD}$title10a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title10b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title10c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity10${NORMAL}"

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

fail=1

file10="/etc/gdm/custom.conf"
dir10="/etc/dconf"

if [[ -f $file10 ]]
then # (Gnome is installed)

   cad="$(grep -ir 'logout' $dir10)"

   if [[ $cad ]]
   then
      for line in ${cad[@]}
      do
         if [[ $line =~ "logout = ''" ]]
         then
            echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
            fail=0
         else
            echo -e "${NORMAL}RESULT:    $line${NORMAL}"
         fi
      done
   else
      echo -e "${NORMAL}RESULT:    ${RED}\"logout\" not defined in $dir10${NORMAL}"
   fi

   if [[ $fail == 0 ]]
   then
      echo -e "${NORMAL}$hostname, $severity10, $controlid, $stigid10, $ruleid10, $cci10, $datetime, ${GRN}PASSED, Ctrl-Alt-Delete - The Red Hat Enterprise Linux operating system is configured so that the x86 Ctrl-Alt-Delete key sequence is disabled in the GUI.${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity10, $controlid, $stigid10, $ruleid10, $cci10, $datetime, ${RED}FAILED, Ctrl-Alt-Delete - The Red Hat Enterprise Linux operating system isnot configured so that the x86 Ctrl-Alt-Delete key sequence is disabled in the GUI.${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${BLD}The GNOME GUI is not installed${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity10, $controlid, $stigid10, $ruleid10, $cci10, $datetime, ${GRN}N/A, Ctrl-Alt-Delete - Not Applicable: GNOME is not installed.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid11${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid11${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid11${NORMAL}"
echo -e "${NORMAL}CCI:       $cci11${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 11:   ${BLD}$title11a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title11b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title11c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity11${NORMAL}"

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

file11="/etc/login.defs"
fail=0

if [[ -f $file11 ]]
then
   umaskset="$(grep -i ^umask $file11)"
   if [[ $umaskset ]]
   then
      umaskval="$(echo $umaskset | awk '{print $2}')"
      if (( $umaskval == '077' ))
      then
         echo -e "${NORMAL}RESULT:    ${BLD}$umaskset${NORMAL}"
      else
         echo -e "${NORMAL}RESULT:    ${BLD}$umaskset${NORMAL}"
         fail=1
      fi
   else
      echo -e "${NORMAL}RESULT:    ${BLD}'UMASK' was not found${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${BLD}$file11 was not found${NORMAL}"
   umaskval="not defined"
fi

if [[ $fail == 0 ]]
then
   echo -e "${NORMAL}$hostname, $severity11, $controlid, $stigid11, $ruleid11, $cci11, $datetime, ${GRN}PASSED, The default UMASK is $umaskval${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity11, $controlid, $stigid11, $ruleid11, $cci11, $datetime, ${RED}FAILED, The default UMASK is $umaskval${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid12${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid12${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid12${NORMAL}"
echo -e "${NORMAL}CCI:       $cci12${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 12:   ${BLD}$title12a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title12b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title12c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity12${NORMAL}"

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

file12="/etc/redhat-release"
fail=1

if [[ -f $file12 ]]
then

   osmake="$(echo $os | awk '{print $1}')"

   case $osmake in
      'Red')
          release="$(echo $os | awk '{print $7}')"
          ;;
      'CentOS')
          release="$(echo $os | awk '{print $4}')"
          ;;
   esac

   major="$(echo $release | awk -F. '{print $1}')"
   minor="$(echo $release | awk -F. '{print $2}')"

   if (( $major < 7 || ( $major == 7 && $minor >= 9 ) ))
   then
      echo -e "${NORMAL}RESULT:    ${BLD}$os${NORMAL}"
      fail=0
   else
      echo -e "${NORMAL}RESULT:    ${RED}$os${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${RED}$file12 not found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
   echo -e "${NORMAL}$hostname, $severity12, $controlid, $stigid12, $ruleid12, $cci12, $datetime, ${GRN}PASSED, The operating system is a vendor supported release.${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity12, $controlid, $stigid12, $ruleid12, $cci12, $datetime, ${RED}FAILED, The operating system is not a vendor supported release.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid13${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid13${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid13${NORMAL}"
echo -e "${NORMAL}CCI:       $cci13${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 13:   ${BLD}$title13a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title13b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title13c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity13${NORMAL}"

IFS='
' 

datetime="$(date +%FT%H:%M:%S)"

yumhistory="$(yum history)"

if [[ $yumhistory ]]
then
   for line in ${yumhistory[@]}
   do
      echo -e "${NORMAL}RESULT:    $line${NORMAL}"
   done
else
   echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
   fail=1
fi

if [[ $fail == 0 ]]
then
   echo -e "${NORMAL}$hostname, $severity13, $controlid, $stigid13, $ruleid13, $cci13, $datetime, ${CYN}VERIFY, Verify the operating system security patches and updates are applied at a frequency determined by the site or Program Management Office (PMO). ${NORMAL}"
else
   echo -e  "${NORMAL}$hostname, $severity13, $controlid, $stigid13, $ruleid13, $cci13, $datetime, ${RED}FAILED, YUM history returned nothing. The operating system security patches and updates are not applied at a frequency determined by the site or Program Management Office (PMO).${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid14${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid14${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid14${NORMAL}"
echo -e "${NORMAL}CCI:       $cci14${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 14:   ${BLD}$title14a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title14b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title14c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity14${NORMAL}"

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

file14="/etc/shadow"
fail=0

if [[ -f $file14 ]]
then
   sysapps="$(awk -F: '($2 == "*" || $2 == "!!" || $2 == ".") {print $1}' $file14)"
   usrs="$(awk -F: '($2 != "*" && $2 != "!!" && $2 != ".") {print $1}' $file14)"

   echo
   echo "system/application accounts:"
   echo "------------------------------------------------"
   if [[ $sysapps ]]
   then
      for name in ${sysapps[@]}
      do
         if [[ $name == "games" ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}$name${NORMAL}"
         else
            echo -e "${NORMAL}RESULT:    $name${NORMAL}"
         fi
      done
   else
      echo -e "${NORMAL}RESULT:    ${RED}No system/application accounts found${NORMAL}"
      fail=1
   fi

   echo
   echo "interactive user accounts:"
   echo "------------------------------------------------"
   if [[ $usrs ]]
   then
      for name in ${usrs[@]}
      do
         echo -e "${NORMAL}RESULT:    $name${NORMAL}"
      done
   else
      echo -e "${NORMAL}RESULT:    ${RED}No user accounts found${NORMAL}"
      fail=1
   fi
else
   echo -e "${NORMAL}RESULT:    ${BLD}$file14 was not found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
   echo -e "${NORMAL}$hostname, $severity14, $controlid, $stigid14, $ruleid14, $cci14, $datetime, ${CYN}VERIFY, Valid Accounts: Have the ISSO verify all accounts are valid.${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity14, $controlid, $stigid14, $ruleid14, $cci14, $datetime, ${RED}FAILED, Valid Accounts: No interactive user accounts were found.${NORMAL}"
fi
 
echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid15${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid15${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid15${NORMAL}"
echo -e "${NORMAL}CCI:       $cci15${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 15:   ${BLD}$title15a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title15b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title15c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity15${NORMAL}"

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

file15="/etc/passwd"

accts=($(awk -F: '($3 == "0") {print}' $file15))

if [[ $accts ]] && [[ ${#accts[@]} > 0 ]]
then
   fail=2
   for acct in ${accts[@]}
   do
      user="$(echo $acct | awk -F: '{print $1}')"
      if [[ $user == 'root' ]]
      then
         fail=0
         echo -e "${NORMAL}RESULT:    ${BLD}$acct${NORMAL}"
      else
         fail=1
         echo -e "${NORMAL}RESULT:    ${RED}$acct${NORMAL}"
      fi
   done
fi

if [[ $fail == 0 ]]
then
   echo -e "${NORMAL}$hostname, $severity15, $controlid, $stigid15, $ruleid15, $cci15, $datetime, ${GRN}PASSED, 'root' is the only account having unrestricted access.${NORMAL}"
elif [[ $fail == 1 ]]
then
   echo -e "${NORMAL}$hostname, $severity15, $controlid, $stigid15, $ruleid15, $cci15, $datetime, ${RED}FAILED, 'root' is not the only account having unrestricted access.${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity15, $controlid, $stigid15, $ruleid15, $cci15, $datetime, ${RED}FAILED, There are no accounts with unrestricted access.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid16${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid16${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid16${NORMAL}"
echo -e "${NORMAL}CCI:       $cci16${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 16:   ${BLD}$title16a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title16b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title16c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity16${NORMAL}"

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

file16="/etc/login.defs"
fail=1

if [[ -f $file16 ]]
then
   createhome="$(grep -i ^create_home $file16)"
   if [[ $createhome ]]
   then
      createhomeval="$(echo $createhome | awk '{print $2}')"
      if [[ $createhomeval == 'yes' ]]
      then
         echo -e "${NORMAL}RESULT:    ${BLD}$createhome${NORMAL}"
         fail=0
      else
         echo -e "${NORMAL}RESULT:    ${BLD}$createhome${NORMAL}"
      fi
   else
      echo -e "${NORMAL}RESULT:    ${BLD}CREATE_HOME was not defined in $file16${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${BLD}$file16 was not found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
   echo -e "${NORMAL}$hostname, $severity16, $controlid, $stigid16, $ruleid16, $cci16, $datetime, ${GRN}PASSED, All local interactive user accounts upon creation are assigned a home directory${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity16, $controlid, $stigid16, $ruleid16, $cci16, $datetime, ${RED}FAILED, All local interactive user accounts upon creation are not assigned a home directory${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid17${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid17${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid17${NORMAL}"
echo -e "${NORMAL}CCI:       $cci17${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 17:   ${BLD}$title17a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title17b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title17c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity17${NORMAL}"

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

file17="/etc/passwd"
cmd="$(command -v pwck)"
fail=0

if [[ -f $file17 ]]
then
   useraccts="$(awk -F: '($3>=1000)&&($7 !~ /nologin/){print $1, $3, $6}' $file17)"
   if [[ $cmd ]]
   then
      nohomelist="$($cmd -r)"
      if [[ $nohomelist ]]
      then
         for user in ${useraccts[@]}
         do
            found=0
            username="$(echo $user | awk '{print $1}')"
            userhome="$(echo $user | awk '{print $3}')"
            for nohome in ${nohomelist[@]}
            do
               if [[ $nohome =~ $username ]]
               then
                  fail=1
                  found=1
               fi
            done
            if [[ $found == 0 ]]
            then
               if [[ -d $userhome ]]
               then
                  echo -e "${NORMAL}RESULT:    ${BLD}$username has a home directory defined in $file17 and the directory exists.${NORMAL}"
               else
                  echo -e "${NORMAL}RESULT:    ${BLD}$username has a home directory defined in $file17 but the directory does not exist.${NORMAL}"
                  fail=1
               fi
            else
               echo -e "${NORMAL}RESULT:    ${RED}$username does not have a home directory defined in $file17${NORMAL}"
               fail=1
            fi
         done
      else
         echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
      fi
   else
      echo -e "${NORMAL}RESULT:    ${RED}The command \"pwck\" was not found${NORMAL}"
      fail=1
   fi
else
   echo -e "${NORMAL}RESULT:    ${RED}Couldn't find $file17${NORMAL}"
fi

if [[ $fail == 0 ]]
then
   echo -e "${NORMAL}$hostname, $severity17, $controlid, $stigid17, $ruleid17, $cci17, $datetime, ${GRN}PASSED, Valid Home Directories - All local interactive user accounts have valid home directories assigned in $file17 and the directories exist.${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity17, $controlid, $stigid17, $ruleid17, $cci17, $datetime, ${GRN}FAILED, All local interactive user accounts either do not have valid home directories assigned in $file17, or the directories do not all exist.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid18${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid18${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid18${NORMAL}"
echo -e "${NORMAL}CCI:       $cci18${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 18:   ${BLD}$title18a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title18b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title18c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity18${NORMAL}"

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

file18="/etc/passwd"
fail=0

if [[ -f $file18 ]]
then
   useraccts="$(ls -ld $(awk -F: '($3>=1000)&&($7 !~ /nologin/){print $6}' $file18))"
   if [[ $useraccts ]]
   then
      for user in ${useraccts[@]}
      do
         homedir="$(echo $user | awk '{print $9}')"
         mode="$(stat -c %a $homedir)"
         if (( ${mode:0:1} <= 7 &&
               ${mode:1:1} <= 5 &&
               ${mode:2:1} == 0
            )) 
         then
            echo -e "${NORMAL}RESULT:    ${BLD}$user${NORMAL}"
         else
            echo -e "${NORMAL}RESULT:    ${RED}$user${NORMAL}"
            fail=1
         fi
      done
   else
      echo -e "${NORMAL}RESULT:    No interactive user accounts found${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${RED}$file18 not found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
   echo -e "${NORMAL}$hostname, $severity18, $controlid, $stigid18, $ruleid18, $cci18, $datetime, ${GRN}PASSED, All local interactive user account home directories are mode 0750 or less permissive.${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity18, $controlid, $stigid18, $ruleid18, $cci18, $datetime, ${RED}FAILED, All local interactive user account home directories are not mode 0750 or less permissive.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid19${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid19${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid19${NORMAL}"
echo -e "${NORMAL}CCI:       $cci19${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 19:   ${BLD}$title19a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title19b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title19c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity19${NORMAL}"

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

file19="/etc/passwd"
fail=0

if [[ -f $file19 ]]
then
#   usraccts="$(ls -ld $(awk -F: '($3>=1000)&&($7 !~ /nologin/){print $6}' $file19))"
   usraccts="$(awk -F: '($3>=1000)&&($7 !~ /nologin/){print $1, $6}' $file19)"
   if [[ $usraccts ]]
   then
      for account in ${usraccts[@]}
      do
         homedir="$(echo $account | awk '{print $2}')"
         user="$(echo $account | awk '{print $1}')"
         owner="$(ls -ld $homedir | awk '{print $3}')"
         if [[ $user == $owner ]]
         then
            echo -e "${NORMAL}RESULT:    ${BLD}$account${NORMAL}"
         else
            echo -e "${NORMAL}RESULT:    ${RED}$account${NORMAL}"
            fail=1
         fi
      done
   else
      echo -e "${NORMAL}RESULT:    No local interactive user accounts found${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${RED}$file19 not found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
   echo -e "${NORMAL}$hostname, $severity19, $controlid, $stigid19, $ruleid19, $cci19, $datetime, ${GRN}PASSED, Home Directory Owner - All local interactive user home directories are owned by their respective users.${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity19, $controlid, $stigid19, $ruleid19, $cci19, $datetime, ${RED}FAILED, Home Directory Owner - All local interactive user home directories are not owned by their respective users..${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid20${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid20${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid20${NORMAL}"
echo -e "${NORMAL}CCI:       $cci20${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 20:   ${BLD}$title20a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title30b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title20c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity20${NORMAL}"

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

file20a="/etc/passwd"
file20b="/etc/shadow"
fail=0

if [[ -f $file20a && -f $file20b ]]
then
   usraccts="$(awk -F: '($2 != "*" && $2 != "!!") {print $1}' $file20b)"
   for account in ${usraccts[@]}
   do
      usracct="$(grep $account $file20a)"
      homedir="$(echo $usracct | awk -F: '{print $6}')"
      if [[ -d $homedir ]]
      then
         hdirperm="$(ls -ld $homedir)"
         gowner="$(ls -ld $homedir | awk '{print $4}')"
         prigrp="$(groups $account | awk '{print $3}')"
         if [[ $gowner == $prigrp ]]
         then
            echo -e "${NORMAL}RESULT:    ${BLD}$hdirperm${NORMAL}"
         else
            echo -e "${NORMAL}RESULT:    ${RED}$hdirperm ($account's primary group is '$prigrp')${NORMAL}"
            fail=1
         fi
      else
         echo -e "${NORMAL}RESULT:    $homedir does not exist${NORMAL}"
      fi
   done

   if [[ $fail == 0 ]]
   then
      echo -e "${NORMAL}$hostname, $severity20, $controlid, $stigid20, $ruleid20, $cci20, $datetime, ${GRN}PASSED, Home Directory Group-Owner - All local interactive user home directories are group-owned by their respective users.${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity20, $controlid, $stigid20, $ruleid20, $cci20, $datetime, ${RED}FAILED, Home Directory Group-Owner - All local interactive user home directories are not group-owned by their respective users..${NORMAL}"
   fi
else
   echo -e "${NORMAL}$hostname, $severity20, $controlid, $stigid20, $ruleid20, $cci20, $datetime, ${RED}FAILED, Home Directory Group-Owner - $file20a and $file20b were not found.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid21${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid21${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid21${NORMAL}"
echo -e "${NORMAL}CCI:       $cci21${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 21:   ${BLD}$title21a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title21b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title21c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity21${NORMAL}"

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

file21a="/etc/passwd"
file21b="/etc/shadow"
fail=0

if [[ -f $file21a && -f $file21b ]]
then
   usraccts="$(awk -F: '($2 != "*" && $2 != "!!") {print $1}' $file21b)"
   for account in ${usraccts[@]}
   do
      echo -e "${NORMAL}RESULT:    $account------------------------------------${NORMAL}"
      usracct="$(grep $account $file21a)"
      homedir="$(echo $usracct | awk -F: '{print $6}')"
      if [[ -d $homedir ]]
      then
         hdirperm="$(ls -ld $homedir)"
         owner="$(ls -ld $homedir | awk '{print $3}')"
         subtree="$(ls -ilR $homedir | grep -v 'total' | grep -v '/')"
         if [[ $subtree ]]
         then
            for line in ${subtree[@]}
            do
               if [[ $line != "" ]]
               then
                  subowner="$(echo $line | awk '{print $4}')"
                  if [[ $subowner != $owner && ! $subowner =~ $useraccts ]]
                  then
                     echo -e "${NORMAL}RESULT:    ${RED}$line does not have a valid owner${NORMAL}"
                     fail=1
                  fi
               fi
            done
         else
            echo -e "${NORMAL}RESULT:    ${RED}No subfiles and folders found under $homedir${NORMAL}"
            fail=1
         fi
         if [[ $fail == 0 ]]
         then
            echo -e "${NORMAL}RESULT:    ${BLD}All subfiles and folders for $homedir have a valid owner${NORMAL}"
         fi
      else
         echo -e "${NORMAL}RESULT:    $homedir does not exist${NORMAL}"
      fi
   done
   if [[ $fail == 0 ]]
   then
      echo -e "${NORMAL}$hostname, $severity21, $controlid, $stigid21, $ruleid21, $cci21, $datetime, ${GRN}PASSED, Subfiles and Folders Owner - All subfiles and folders in local interactive user home directories have a valid owner.${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity21, $controlid, $stigid21, $ruleid21, $cci21, $datetime, ${RED}FAILED, Subfiles and Folders Owner - All subfiles and folders in local interactive user home directories do not have a valid owner.${NORMAL}"
   fi
else
   echo -e "${NORMAL}$hostname, $severity21, $controlid, $stigid21, $ruleid21, $cci21, $datetime, ${RED}FAILED, Sub Subfiles and Folders Owner - $file21a and $file21b were not found.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid22${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid22${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid22${NORMAL}"
echo -e "${NORMAL}CCI:       $cci22${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 22:   ${BLD}$title22a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title22b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title22c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity22${NORMAL}"

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

file22a="/etc/passwd"
file22b="/etc/shadow"
fail=0

if [[ -f $file22a && -f $file22b ]]
then
   usraccts="$(awk -F: '($2 != "*" && $2 != "!!") {print $1}' $file22b)"
   for account in ${usraccts[@]}
   do
      usracct="$(grep $account $file22a)"
      homedir="$(echo $usracct | awk -F: '{print $6}')"
      IFS=' ' ismemberof="$(groups $account | awk -F: '{print $2}' | sed -e 's/ //')" IFS=$'\n'
      echo
      echo -e "${NORMAL}RESULT:    ${BLD}$account's groups: $ismemberof${NORMAL}"
      echo "------------------------------------------------------------------"
      if [[ -d $homedir ]]
      then
         hdirperm="$(ls -ld $homedir)"
         gowner="$(ls -ld $homedir | awk '{print $4}')"
         IFS=' ' ismemberof="$(groups $account | awk -F: '{print $2}' | sed -e 's/ //')" IFS=$'\n'
         subtree="$(ls -ilR $homedir | grep -v 'total' | grep -v '^/')"
         if [[ $subtree ]]
         then
            for line in ${subtree[@]}
            do
               if [[ $line != "" ]]
               then
                  subgowner="$(echo $line | awk '{print $5}')"
                  if [[ ! $ismemberof =~ $subgowner ]]
                  then
                     echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
                     fail=1
#                  else
#                     echo -e "${NORMAL}RESULT:    $line${NORMAL}"
                  fi
               fi
            done
         else
            echo -e "${NORMAL}RESULT:    ${RED}No subfiles and folders found under $homedir${NORMAL}"
            fail=1
         fi
         if [[ $fail == 0 ]]
         then
            echo -e "${NORMAL}RESULT:    ${BLD}All subfiles and folders for $homedir are group-owned by one of $account's groups${NORMAL}"
         else
            echo -e "${NORMAL}RESULT:    ${BLD}All subfiles and folders for $homedir are not group-owned by one of $account's groups${NORMAL}"
         fi
      else
         echo -e "${NORMAL}RESULT:    $homedir does not exist${NORMAL}"
      fi
   done
   if [[ $fail == 0 ]]
   then
      echo -e "${NORMAL}$hostname, $severity22, $controlid, $stigid22, $ruleid22, $cci22, $datetime, ${GRN}PASSED, Subfiles and Folders Group-Owner - All files and directories contained in local interactive user home directories are group-owned by a group of which the home directory owner is a member.${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity22, $controlid, $stigid22, $ruleid22, $cci22, $datetime, ${RED}FAILED, Subfiles and Folders Group-Owner - All files and directories contained in local interactive user home directories are not group-owned by a group of which the home directory owner is a member.${NORMAL}"
   fi
else
   echo -e "${NORMAL}$hostname, $severity22, $controlid, $stigid22, $ruleid22, $cci22, $datetime, ${RED}FAILED, Sub Subfiles and Folders Group-Owner - $file22a and $file22b were not found.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid23${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid23${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid23${NORMAL}"
echo -e "${NORMAL}CCI:       $cci23${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 23:   ${BLD}$title23a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title23b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title23c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity23${NORMAL}"

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

file23a="/etc/passwd"
file23b="/etc/shadow"
userfail=0
fail=0


if [[ -f $file23a && -f $file23b ]]
then
   usraccts="$(awk -F: '($2 != "*" && $2 != "!!") {print $1}' $file23b)"
   for account in ${usraccts[@]}
   do
      userfail=0
      echo
      echo -e "${NORMAL}RESULT:    ${BLD}$account's home directory subfiles and folders${NORMAL}"
      echo "------------------------------------------------------------------"
      usracct="$(grep $account $file23a)"
      homedir="$(echo $usracct | awk -F: '{print $6}')"
      if [[ -d $homedir ]]
      then
         hdirperm="$(ls -ld $homedir)"
         gowner="$(ls -ld $homedir | awk '{print $4}')"
         subtree="$(ls -ilR $homedir | grep -v 'total')"
         if [[ $subtree ]]
         then
            for line in ${subtree[@]}
            do
               if [[ $line == '/'* ]]
               then
                  path="$(echo $line | sed -e 's/:$//')"
               fi
               if [[ $line != "" && ! $line =~ '/' ]]
               then
                  target="$(echo $line | awk '{print $10}')"
                  mode="$(stat -c %a $path/$target)"
                  if (( ${mode:1:1} > 5 ||
                        ${mode:2:1} > 0
                     ))
                  then
                     echo -e "${NORMAL}RESULT:    ${BLD}$line ${RED}(mode: $mode)${NORMAL}"
                     userfail=1
                     fail=1
#                  else
#                     echo -e "${NORMAL}RESULT:    $line (mode: $mode)${NORMAL}"
                  fi
               fi
            done
         else
            echo -e "${NORMAL}RESULT:    ${RED}No subfiles and folders found under $homedir${NORMAL}"
         fi

         if (( $userfail == 0 ))
         then
            echo -e "${NORMAL}RESULT:    ${BLD}All subfiles and folders for $homedir are mode 750 or less.${NORMAL}"
         else
            echo -e "${NORMAL}RESULT:    ${RED}All subfiles and folders for $homedir are not mode 750 or less${NORMAL}"
         fi
      else
         echo -e "${NORMAL}RESULT:    $homedir does not exist${NORMAL}"
      fi
   done
   if [[ $fail == 0 ]]
   then
      echo -e "${NORMAL}$hostname, $severity23, $controlid, $stigid23, $ruleid23, $cci23, $datetime, ${GRN}PASSED, Subfiles and Folders Permissions - All files and directories contained in local interactive user home directories are mode 750 or less.${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity23, $controlid, $stigid23, $ruleid23, $cci23, $datetime, ${RED}FAILED, Subfiles and Folders Permissions - All files and directories contained in local interactive user home directories are not mode 750 or less.${NORMAL}"
   fi
else
   echo -e "${NORMAL}$hostname, $severity23, $controlid, $stigid23, $ruleid23, $cci23, $datetime, ${RED}FAILED, Sub Subfiles and Folders Permissions - $file23a and $file23b were not found.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid24${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid24${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid24${NORMAL}"
echo -e "${NORMAL}CCI:       $cci24${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 24:   ${BLD}$title24a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title24b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title24c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity25${NORMAL}"

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

file24="/etc/passwd"
fail=0

if [[ -f $file24 ]]
then
   usraccts="$(awk -F: '($3>=1000)&&($7 !~ /nologin/){print $1, $3, $6}' $file24)"
   for account in ${usraccts[@]}
   do
      userfail=0
      user="$(echo $account | awk '{print $1}')"
      usracct="$(grep ^$user $file24)"
      homedir="$(echo $usracct | awk -F: '{print $6}')"
      echo
      echo -e "${NORMAL}RESULT:    ${BLD}$user's home directory is $homedir${NORMAL}"
      echo -e "${NORMAL}RESULT:    ${BLD}$user's initialization files${NORMAL}"
      echo "------------------------------------------------------------------"
      if [[ -d $homedir ]]
      then
         initfiles="$(ls -al $homedir/.[^.]*)"
         if [[ $initfiles ]]
         then
            for file in ${initfiles[@]}
            do
               if [[ $file =~ $homedir && ${file:0:1} == '-' ]]
               then
                  owner="$(echo $file | awk '{print $3}')"
                  if [[ $owner == $user || $owner == 'root' ]]
                  then
                     echo -e "${NORMAL}RESULT:    $file${NORMAL}"
                  else
                     echo -e "${NORMAL}RESULT:    ${RED}$file${NORMAL}"
                     userfail=1
                     fail=1
                  fi
               fi
            done
         else
            echo -e "${NORMAL}RESULT:    ${RED}No initialization files found in $homedir${NORMAL}"
         fi
         if [[ $userfail == 0 ]] 
         then
            echo -e "${NORMAL}RESULT:    ${BLD}All initialization files in $homedir are owned by either $owner or root.${NORMAL}"
         else
            echo -e "${NORMAL}RESULT:    ${RED}All initialization files in $homedir are not owned by either $account or root${NORMAL}"
         fi
      else
         echo -e "${NORMAL}RESULT:    $homedir does not exist${NORMAL}"
      fi
   done
   if [[ $fail == 0 ]]
   then
      echo -e "${NORMAL}$hostname, $severity24, $controlid, $stigid24, $ruleid24, $cci24, $datetime, ${GRN}PASSED, Initialization File Owner - All initialization files are owned by by either the home directory user or root${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity24, $controlid, $stigid24, $ruleid24, $cci24, $datetime, ${RED}FAILED, Initialization File Owner - All initialization files are owned by by either the home directory user or root${NORMAL}"
   fi
else
   echo -e "${NORMAL}$hostname, $severity24, $controlid, $stigid24, $ruleid24, $cci24, $datetime, ${RED}FAILED, Initialization File Owner - $file24 not found.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid25${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid25${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid25${NORMAL}"
echo -e "${NORMAL}CCI:       $cci25${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 25:   ${BLD}$title25a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title25b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title25c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity25${NORMAL}"

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

file25="/etc/passwd"
fail=0

if [[ -f $file25 ]]
then
   usraccts="$(awk -F: '($4>=1000)&&($7 !~ /nologin/){print $1, $4, $6}' $file25)"
   for account in ${usraccts[@]}
   do
      userfail=0
      user="$(echo $account | awk '{print $1}')"
      usracct="$(grep ^$user $file25)"
      homedir="$(echo $usracct | awk -F: '{print $6}')"
      gid="$(id $user)"
      prigid="$(id $user | awk '{print $2}' | cut -d "=" -f2 | cut -d "(" -f1)"
      prigidname="$(id $user | awk '{print $1}' | cut -d "(" -f2 | cut -d ")" -f1)"
      echo
      echo -e "${NORMAL}RESULT:    ${BLD}$user's home directory is $homedir${NORMAL}"
      echo -e "${NORMAL}RESULT:    ${BLD}$user's ID: $gid${NORMAL}"
      echo "------------------------------------------------------------------"
      if [[ -d $homedir ]]
      then
         initfiles="$(ls -al $homedir/.[^.]*)"
         if [[ $initfiles ]]
         then
            for file in ${initfiles[@]}
            do
               if [[ $file =~ $homedir && ${file:0:1} == '-' ]]
               then
                  gowner="$(echo $file | awk '{print $4}')"
                  if [[ $gowner == $prigid || $gowner == $prigidname ]]
                  then
                     echo -e "${NORMAL}RESULT:    $file${NORMAL}"
                  else
                     echo -e "${NORMAL}RESULT:    ${RED}$file${NORMAL}"
                     userfail=1
                     fail=1
                  fi
               fi
            done
         else
            echo -e "${NORMAL}RESULT:    ${RED}No initialization files found in $homedir${NORMAL}"
         fi
         if [[ $userfail == 0 ]] 
         then
            echo -e "${NORMAL}RESULT:    ${BLD}All initialization files in $homedir are group-owned by either $owner's primary group or root.${NORMAL}"
         else
            echo -e "${NORMAL}RESULT:    ${RED}All initialization files in $homedir are not group-owned by either $account's primary group or root.${NORMAL}"
         fi
      else
         echo -e "${NORMAL}RESULT:    $homedir does not exist${NORMAL}"
      fi
   done
   if [[ $fail == 0 ]]
   then
      echo -e "${NORMAL}$hostname, $severity25, $controlid, $stigid25, $ruleid25, $cci25, $datetime, ${GRN}PASSED, Initialization File Group-Owner - All initialization files are group-owned by by the user's primary group or root.${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity25, $controlid, $stigid25, $ruleid25, $cci25, $datetime, ${RED}FAILED, Initialization File Group-Owner - All initialization files are not group-owned by the user's primary group or root.${NORMAL}"
   fi
else
   echo -e "${NORMAL}$hostname, $severity25, $controlid, $stigid25, $ruleid25, $cci25, $datetime, ${RED}FAILED, Initialization File Group-Owner - $file25 not found.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid26${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid26${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid26${NORMAL}"
echo -e "${NORMAL}CCI:       $cci26${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 26:   ${BLD}$title26a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title26b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title26c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity26${NORMAL}"

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

file26="/etc/passwd"
fail=0

if [[ -f $file26 ]]
then
   usraccts="$(awk -F: '($4>=1000)&&($7 !~ /nologin/){print $1, $4, $6}' $file26)"
   for account in ${usraccts[@]}
   do
      userfail=0
      user="$(echo $account | awk '{print $1}')"
      usracct="$(grep ^$user $file26)"
      homedir="$(echo $usracct | awk -F: '{print $6}')"
      echo
      echo -e "${NORMAL}RESULT:    ${BLD}$user's home directory is $homedir${NORMAL}"
      echo "------------------------------------------------------------------"
      if [[ -d $homedir ]]
      then
         initfiles="$(ls -al $homedir/.[^.]*)"
         if [[ $initfiles ]]
         then
            for file in ${initfiles[@]}
            do
               if [[ $file =~ $homedir && ${file:0:1} == '-' ]]
               then
                  filename="$(echo $file | awk '{print $9}')"
                  mode="$(stat -c %a $filename)"
                  if (( ${mode:1:1} > 4 ||
                        ${mode:2:1} > 0
                     ))
                  then
                     echo -e "${NORMAL}RESULT:    ${BLD}$file ${RED}(mode: $mode)${NORMAL}"
                     userfail=1
                     fail=1
#                  else
#                     echo -e "${NORMAL}RESULT:    $file (mode: $mode)${NORMAL}"
                  fi
               fi
            done
         else
            echo -e "${NORMAL}RESULT:    ${RED}No initialization files found in $homedir${NORMAL}"
         fi
         if [[ $userfail == 0 ]] 
         then
            echo -e "${NORMAL}RESULT:    ${BLD}All initialization files in $homedir are mode 0740 or less permissive${NORMAL}"
         else
            echo -e "${NORMAL}RESULT:    ${RED}All initialization files in $homedir are not mode 0740 or less permissive${NORMAL}"
         fi
      else
         echo -e "${NORMAL}RESULT:    $homedir does not exist${NORMAL}"
      fi
   done
   if [[ $fail == 0 ]]
   then
      echo -e "${NORMAL}$hostname, $severity26, $controlid, $stigid26, $ruleid26, $cci26, $datetime, ${GRN}PASSED, Initialization File Permissions - All initialization files are mode 0740 or less permissive${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity26, $controlid, $stigid26, $ruleid26, $cci26, $datetime, ${RED}FAILED, Initialization File Permissions - All initialization files are not mode 0740 or less permissive${NORMAL}"
   fi
else
   echo -e "${NORMAL}$hostname, $severity26, $controlid, $stigid26, $ruleid26, $cci26, $datetime, ${RED}FAILED, Initialization File Group-Owner - $file26 not found.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid27${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid27${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid27${NORMAL}"
echo -e "${NORMAL}CCI:       $cci27${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 27:   ${BLD}$title27a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title27b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title27c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity27${NORMAL}"

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

file27a="/etc/passwd"
file27b="/etc/shadow"
fail=0

if [[ -f $file27a && -f $file27b ]]
then
   usraccts="$(awk -F: '($2 != "*" && $2 != "!!") {print $1}' $file27b)"
   for account in ${usraccts[@]}
   do
      userfail=0
      usracct="$(grep $account $file27a)"
      homedir="$(echo $usracct | awk -F: '{print $6}')"
      echo
      echo -e "${NORMAL}RESULT:    ${BLD}$account${NORMAL}"
      echo "------------------------------------------------------------------"
      if [[ -d $homedir ]]
      then
         initfiles="$(ls -al $homedir/.[^.]*)"
         if [[ $initfiles ]]
         then
            for line in ${initfiles[@]}
            do
               #echo -e "${NORMAL}RESULT:    $line${NORMAL}"
               if [[ $line =~ $homedir && ${line:0:1} == '-' &&
                   ! ($line =~ ".viminfo" || $line =~ '.bash_history')
                  ]]
               then
                  file="$(echo $line | awk '{print $9}')"
                  expath="$(grep -i \$HOME $file)"
                  if [[ $expath ]]
                  then
                     for path in ${expath[@]}
                     do
                        if [[ $path =~ "PATH" && $path =~ "HOME" ]]
                        then
                           echo -e "${NORMAL}RESULT:    ${CYN}$file:${BLD}$path${NORMAL}"
                        else
                           echo -e "${NORMAL}RESULT:    ${RED}$file:$path${NORMAL}"
                           userfail=1
                           fail=1
                        fi
                     done
                  fi
               fi
            done
         else
            echo -e "${NORMAL}RESULT:    ${RED}No initialization files found.${NORMAL}"
         fi
      else
         echo -e "${NORMAL}RESULT:    ${RED}$homedir not found..${NORMAL}"
         fail==1
      fi
   done
else
   echo -e "${NORMAL}RESULT:    ${RED}$file27a and/or $file27b not found.${NORMAL}" 
fi

if [[ $fail == 0 ]]
then
   echo -e "${NORMAL}$hostname, $severity27, $controlid, $stigid27, $ruleid27, $cci27, $datetime, ${GRN}PASSED, Initialization File Path - All initialization file paths resolve to the user's home directory${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity27, $controlid, $stigid27, $ruleid27, $cci27, $datetime, ${RED}FAILED, Initialization File Path - All initialization file paths do not reslolve to the user's home directory${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid28${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid28${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid28${NORMAL}"
echo -e "${NORMAL}CCI:       $cci28${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 28:   ${BLD}$title28a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title28b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title28c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity28${NORMAL}"

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

file28="/etc/passwd"
fail=0

wldwrt="$(find / -type d -name '(mnt|pcap)' -prune -type f \( -perm -0002 \) 2>/dev/null -exec ls -ld {} \;)" 

homedirs="$(cat $file28 | awk -F: '{print $1, $6}')"
if [[ $wldwrt ]]
then
   for file in ${wldwrt[@]}
   do
      if [[ -f $file ]]
      then
         fname="$(echo $file | awk '{print $9}')"
         for line in ${homedirs[@]}
         do
            user="$(echo $line | awk '{print $1}')"
            home="$(echo $line | awk '{print $2)')"
            isrefd="$(grep $fname $home/$user/.* 2>&1)"
            if [[ $isrefd ]]
            then
               for ref in ${isrefd[@]}
               do
                  if [[ ! $ref =~ 'Is a directory' ]]
                  then
                     echo -e "${NORMAL}RESULT:    ${RED}$file${NORMAL}"
                     fail=1
                  fi
               done
            else
               echo -e "${NORMAL}RESULT:    nothing found in $home/$user${NORMAL}"
            fi
         done
      fi
   done
   wldwrt=null
else
   echo  -e "${NORMAL}RESULT:    ${BLD}No world-writable files found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
   echo -e "${NORMAL}$hostname, $severity28, $controlid, $stigid28, $ruleid28, $cci28, $datetime, ${GRN}PASSED, Local initialization files do not execute world-writable programs.${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity28, $controlid, $stigid28, $ruleid28, $cci28, $datetime, ${RED}FAILED, Local initialization files execute world-writable programs.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid29${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid29${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid29${NORMAL}"
echo -e "${NORMAL}CCI:       $cci29${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 29:   ${BLD}$title29a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title29b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title29c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity29${NORMAL}"

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

fail=0

isenabled="$(getenforce)"

if [[ $isenabled == 'Enforcing' ]]
then
   echo -e "${NORMAL}RESULT:    ${BLD}$isenabled${NORMAL}"

   labeled="$(find /dev -context *:device_t:* \( -type c -o -type b \) -printf "%p %Z\n")"
   unlabeled="$(find /dev -context *:unlabeled_t:* \( -type c -o -type b \) -printf "%p %Z\n")"

   if [[ $labeled ]]
   then
      echo -e "${NORMAL}RESULT:    a. ${RED}$labeled${NORMAL}"
      fail=1
   else
      echo -e "${NORMAL}RESULT:    a. Nothing returned for '-context *:device_t:*'${NORMAL}"
   fi
   if [[ $unlabeled ]]
   then
      echo -e "${NORMAL}RESULT:    b. ${RED}$unlabeled${NORMAL}"
      fail=1
   else
      echo -e "${NORMAL}RESULT:    b. Nothing returned for '-context *:unlabeled_t:*'${NORMAL}"
   fi
   if [[ $fail == 0 ]]
   then
      echo -e "${NORMAL}$hostname, $severity29, $controlid, $stigid29, $ruleid29, $cci29, $datetime, ${GRN}PASSED, All system device files are correctly labeled to prevent unauthorized modification.${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity29, $controlid, $stigid29, $ruleid29, $cci29, $datetime, ${RED}FAILED, All system device files are not correctly labeled to prevent unauthorized modification.${NORMAL}"
   fi

else
   echo -e "${NORMAL}RESULT:    ${RED}SELinux is not running${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity29, $controlid, $stigid29, $ruleid29, $cci29, $datetime, ${RED}FAILED, All system device files are not correctly labeled to prevent unauthorized modification.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid30${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid30${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid30${NORMAL}"
echo -e "${NORMAL}CCI:       $cci30${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 30:   ${BLD}$title30a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title30b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title30c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity30${NORMAL}"

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

file30a="/etc/passwd"
file30b="/etc/fstab"
fail=0

if [[ -f $file30a ]]
then
   fsmnts="$(cat $file30b | grep -v '^#')"
   if [[ $fsmnts ]]
   then
      echo "File System Mounts:--------------------------------------------------------"
      for mnt in ${fsmnts[@]}
      do
         echo  -e "${NORMAL}RESULT:    $mnt${NORMAL}"
      done
      echo "---------------------------------------------------------------------------"
   fi
   hdirlist="$(cut -d: -f 1,3,6 $file30a | egrep ':[1-4][0-9]{3}')"
   if [[ $hdirlist ]]
   then
      for account in ${hdirlist[@]}
      do
         hdir="/$(echo $account | awk -F: '{print $3}' | awk -F/ '{print $2}')"
         echo -e "${NORMAL}RESULT:    $account: (looking for the $hdir file system)${NORMAL}"
         if [[ -d $hdir ]]
         then
            hdirmnt="$(grep $hdir $file30b)"
            if [[ $hdirmnt ]]
            then
               if [[ $hdirmnt =~ 'nosuid' ]]
               then
                  echo -e "${NORMAL}RESULT:    ${BLD}$hdirmnt${NORMAL}"
               else
                  echo -e "${NORMAL}RESULT:    ${RED}$hdirmnt${NORMAL}"
                  fail=1
               fi 
            else
               echo -e "${NORMAL}RESULT:    ${RED}A separate file system does not exist for $hdir${NORMAL}"
               fail=1
            fi
         else
            echo -e "${NORMAL}RESULT:    ${RED}$hdir not found${NORMAL}"
            fail=1
         fi
      done
   else
      echo -e "${NORMAL}RESULT:    Nothing returned${NORMAL}"
   fi
   if [[ $fail == 0 ]]
   then
      echo -e "${NORMAL}$hostname, $severity30, $controlid, $stigid30, $ruleid30, $cci30, $datetime, ${GRN}PASSED, File systems that contain user home directories are mounted to prevent files with the setuid and setgid bit set from being executed.${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity30, $controlid, $stigid30, $ruleid30, $cci30, $datetime, ${RED}FAILED, File systems that contain user home directories are not mounted to prevent files with the setuid and setgid bit set from being executed.${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${RED}$file30 not found${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity30, $controlid, $stigid30, $ruleid30, $cci30, $datetime, ${RED}FAILED, File System Mount (nosuid) - $file30 not found${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid31${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid31${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid31${NORMAL}"
echo -e "${NORMAL}CCI:       $cci31${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 31:   ${BLD}$title31a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title31b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title31c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity31${NORMAL}"

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

file31="/etc/fstab"
fail=0

if [[ -f $file31 ]]
then
   fsmnts="$(cat $file31 | grep -v '^#')"
   if [[ $fsmnts ]]
   then
      echo "File System Mounts:--------------------------------------------------------"
      for mnt in ${fsmnts[@]}
      do
         if [[ ($mnt =~ 'cdrom' || $mnt =~ 'media' ||
                $mnt =~ 'usb' || $mnt =~ 'flash') && ! $mnt =~ 'nosuid' 
            ]]
        then
            echo  -e "${NORMAL}RESULT:    ${RED}$mnt${NORMAL}"
            fail=1
         elif [[ ($mnt =~ 'cdrom' || $mnt =~ 'media' ||
                  $mnt =~ 'usb' || $mnt =~ 'flash') && $mnt =~ 'nosuid' 
              ]]
         then
            echo  -e "${NORMAL}RESULT:    ${BLD}$mnt${NORMAL}"
         else
            echo  -e "${NORMAL}RESULT:    $mnt${NORMAL}"
         fi
     done
      echo "---------------------------------------------------------------------------"
   fi

   if [[ $fail == 0 ]]
   then
      echo -e "${NORMAL}$hostname, $severity31, $controlid, $stigid31, $ruleid31, $cci31, $datetime, ${GRN}PASSED, Removable Media Mounts (nosuid) - There are no removable media mounts listed in $file31${NORMAL}"
   elif [[ $fail == 0 ]]
   then
      echo -e "${NORMAL}$hostname, $severity31, $controlid, $stigid31, $ruleid31, $cci31, $datetime, ${GRN}PASSED, Removable Media Mounts (nosuid) - File systems that are used with removable media are mounted to prevent files with the setuid and setgid bit set from being executed.${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity31, $controlid, $stigid31, $ruleid31, $cci31, $datetime, ${RED}FAILED, Removable Media Mounts (nosuid) -  File systems that are used with removable media are not mounted to prevent files with the setuid and setgid bit set from being executed.${NORMAL}"
   fi

else
   echo -e "${NORMAL}RESULT:    ${RED}$file31 not found${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity31, $controlid, $stigid31, $ruleid31, $cci31, $datetime, ${RED}FAILED, Removable Media Mount (nosuid) - $file31 not found${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid32${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid32${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid32${NORMAL}"
echo -e "${NORMAL}CCI:       $cci32${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 32:   ${BLD}$title32a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title32b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title32c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity32${NORMAL}"

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

file32="/etc/fstab"
fail=0

if [[ -f $file32 ]]
then
   nfsmnts="$(grep nfs $file32 2>/dev/null | grep nfs)"
   if [[ $nfsmnts ]]
   then
      for mnt in ${nfsmnts[@]}
      do
         if [[ $mnt =~ 'nosuid' ]]
         then
            echo -e "${NORMAL}RESULT:    ${BLD}a. $mnt${NORMAL}"
         else
            echo -e "${NORMAL}RESULT:    ${RED}a. $mnt${NORMAL}"
            fail=1
         fi
      done
      mnttab="$(mount | grep nfs | grep nosuid )"
      if [[ $mnttab ]]
      then
         for tab in ${mnttab[@]}
         do
            if ! [[ $tab =~ nosuid ]]
            then
               echo -e "${NORMAL}RESULT:    ${RED}b. $fs${NORMAL}"
               fail=1
            else
               echo -e "${NORMAL}RESULT:    ${BLD}b. $fs${NORMAL}"
            fi
         done
      else
        echo -e "${NORMAL}RESULT:    ${BLD}b. Nothing returned${NORMAL}"
      fi        
   else
      echo -e "${NORMAL}RESULT:    ${BLD}'a. Nothing returned - exiting.${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${RED}$file32 not found${NORMAL}"
   fail=1
fi
        
if [[ $fail == 0 ]]
then
   echo -e "${NORMAL}$hostname, $severity32, $controlid, $stigid32, $ruleid32, $cci32, $datetime, ${GRN}PASSED, NFS mounts either do not exist or are set to prevent files with the setuid and setgid bit set from being executed${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity32, $controlid, $stigid32, $ruleid32, $cci32, $datetime, ${RED}FAILED, NFS mounts do not prevent files with the setuid and setgid bit set from being executed${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid33${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid33${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid33${NORMAL}"
echo -e "${NORMAL}CCI:       $cci33${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 33:   ${BLD}$title33a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title33b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title33c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity33${NORMAL}"

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

file33="/etc/fstab"
nfs="false"
fail=0

if [[ -f $file33 ]]
then
   nfsmnts="$(grep nfs $file33 2>/dev/null | grep nfs)"
   if [[ $nfsmnts ]]
   then
      for mnt in ${nfsmnts[@]}
      do
         if [[ $mnt =~ 'noexec' ]]
         then
            echo -e "${NORMAL}RESULT:    ${BLD}a. $mnt${NORMAL}"
         else
            echo -e "${NORMAL}RESULT:    ${RED}a. $mnt${NORMAL}"
            fail=1
         fi
      done
      mnttab="$(mount | grep nfs | grep noexec )"
      if [[ $mnttab ]]
      then
         for tab in ${mnttab[@]}
         do
            if ! [[ $tab =~ noexec ]]
            then
               echo -e "${NORMAL}RESULT:    ${RED}b. $fs${NORMAL}"
               fail=1
            else
               echo -e "${NORMAL}RESULT:    ${BLD}b. $fs${NORMAL}"
            fi
         done
      else
        echo -e "${NORMAL}RESULT:    ${BLD}b. Nothing returned${NORMAL}"
      fi        
   else
      echo -e "${NORMAL}RESULT:    ${BLD}'a. Nothing returned - exiting.${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${RED}$file33 not found${NORMAL}"
   fail=1
fi

if [[ $fail == 0 ]]
then
   echo -e "${NORMAL}$hostname, $severity33, $controlid, $stigid33, $ruleid33, $cci33, $datetime, ${GRN}PASSED,  NFS Mount NOEXEC: NFS mounts either do not exist or are set to prevent binary files being executed from the mount.${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity33, $controlid, $stigid33, $ruleid33, $cci33, $datetime, ${RED}FAILED, NFS Mount NOEXEC: NFS mounts do not prevent binary files from being executed${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid34${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid34${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid34${NORMAL}"
echo -e "${NORMAL}CCI:       $cci34${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 34:   ${BLD}$title34a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title34b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title34c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity34${NORMAL}"

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

fsys="$(df -hl | awk '{print $6}' 2>/dev/null | grep -v 'Mounted')"

for fs in ${fsys[@]}
do
	wrdir="$(find $fs -type d -name '(mnt|pcap)' -prune 2>/dev/null -xdev -o -type d -perm -0002 -gid +999 -print)"
   if ! [[ $wrdir ]]
   then
      echo -e "${NORMAL}RESULT:    ${CYN}$fs:${BLD}Nothing returned.${NORMAL}"
   else
      for line in ${wrdir[@]}
      do
         echo -e "${NORMAL}RESULT:    ${CYN}$fs:${RED}$line${NORMAL}"
         fail=1
      done
   fi
done

if [[ $fail == 0 ]]
then
   echo -e "${NORMAL}$hostname, $severity34, $controlid, $stigid34, $ruleid34, $cci34, $datetime, ${GRN}PASSED, All world-writable directories are group-owned by either root sys bin or an application group${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity34, $controlid, $stigid34, $ruleid34, $cci34, $datetime, ${RED}FAILED, World-writable directories have unauthorized group owners${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid35${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid35${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid35${NORMAL}"
echo -e "${NORMAL}CCI:       $cci35${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 35:   ${BLD}$title35a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title35b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title35c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity35${NORMAL}"

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

file35="/etc/passwd"
fail=0

if [[ -f $file35 ]]
then
   usraccts="$(awk -F: '($4>=1000)&&($7 !~ /nologin/){print $1, $4, $6}' $file35)"
   if [[ $usraccts ]]
   then
      for user in ${usraccts[@]}
      do
         username="$(echo $user | awk '{print $1}')"
         homedir="$(echo $user | awk '{print $3}')"
         echo
         echo -e "${NORMAL}RESULT:    ${BLD}$username's initialization files${NORMAL}"
         echo "------------------------------------------------------------------"
         if [[ -d $homedir ]]
         then
            initfiles="$(ls -al $homedir/.[^.]* | grep $homedir | grep -v '^/' | grep -v '.bash_history' | awk '{print $9}')"
            if [[ $initfiles ]]
            then
               for file in ${initfiles[@]}
               do
                  umask="$(grep -ir ^umask $file)"
                  if [[ $umask ]]
                  then
                     umaskval="$(echo $umask | awk '{print $2}')"
                     if [[ $umaskval ]]
                     then
                        if (( ${umaskval:1:1} < 7 ||
                              ${umaskval:2:1} < 7
                           ))
                        then
                           echo -e "${NORMAL}RESULT:    ${CYN}$file:${RED}$umask${NORMAL}"
                           fail=1
                        else
                           echo -e "${NORMAL}RESULT:    ${CYN}$file:${GRN}$umask${NORMAL}"
                        fi
                     fi
                  else
                     echo -e "${NORMAL}RESULT:    ${CYN}$file:${BLD}No reference to UMASK found${NORMAL}"
                  fi
               done
            else
               echo -e "${NORMAL}RESULT:    ${RED}No initialization files found in $homedir${NORMAL}"
            fi
         else
            echo -e "${NORMAL}RESULT:    ${RED}$homedir is not a directory${NORMAL}"
         fi
      done
   else
      echo -e "${NORMAL}RESULT:    No interactive user accounts found in $file35${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${RED}$file35 not found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
   echo -e "${NORMAL}$hostname, $severity35, $controlid, $stigid35, $ruleid35, $cci35, $datetime, ${GRN}PASSED, There are no local interactive user initialization files that set UMASK to a mode less permissive than 077${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity35, $controlid, $stigid35, $ruleid35, $cci35, $datetime, ${RED}FAILED, There are local interactive user initialization files that set UMASK to a mode less permissive than 077${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid36${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid36${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid36${NORMAL}"
echo -e "${NORMAL}CCI:       $cci36${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 36:   ${BLD}$title36a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title36b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title36c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity36${NORMAL}"

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

file36arr=('/etc/rsyslog.conf' '/etc/rsyslog.d/*.conf')
fail=1

for file in ${file36arr[@]}
do
   if [[ -f $file ]]
   then
      croncfgs="$(grep cron $file)"
      if [[ $croncfgs ]]
      then
         for cfg in ${croncfgs[@]}
         do
            if [[ $cfg =~ 'cron.*' && $cfg =~ '/var/log/cron' ]]
            then
               echo -e "${NORMAL}RESULT:    ${CYN}$file:${BLD}$cfg${NORMAL}"
               fail=0
            else
               echo -e "${NORMAL}RESULT:    $file:$cfg${NORMAL}"
            fi
         done
       else
          echo -e "${NORMAL}RESULT:    $file:No cron log configs found${NORMAL}"
       fi
   else
      echo -e "${NORMAL}RESULT:    ${RED}$file not found${NORMAL}"
   fi
done

if [[ $fail == 0 ]]
then
   echo -e "${NORMAL}$hostname, $severity36, $controlid, $stigid36, $ruleid36, $cci36, $datetime, ${GRN}PASSED, Cron logging is implemented.${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity36, $controlid, $stigid36, $ruleid36, $cci36, $datetime, ${RED}FAILED, Cron logging is not implemented.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid37${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid37${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid37${NORMAL}"
echo -e "${NORMAL}CCI:       $cci37${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 37:   ${BLD}$title37a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title37b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title37c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity37${NORMAL}"

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

file37="/etc/cron.allow"
fail=0

if [[ -f $file37 ]]
then
   fperm="$(ls -l /etc | grep cron.allow)"
   if [[ $fperm ]]
   then
      for line in ${fperm[@]}
      do
         fowner="$(echo $line | awk '{print $3}')"
         if [[ $fowner == 'root' ]]
         then
            echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
         else
            echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
            fail=1
         fi
      done
   fi
else
   echo -e "${NORMAL}RESULT:    ${BLD}$file37 was not found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
   echo -e "${NORMAL}$hostname, $severity37, $controlid, $stigid37, $ruleid37, $cci37, $datetime, ${GRN}PASSED, cron.allow is owned by root.${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity37, $controlid, $stigid37, $ruleid37, $cci37, $datetime, ${RED}FAILED, cron.allow is not owned by root.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid38${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid38${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid38${NORMAL}"
echo -e "${NORMAL}CCI:       $cci38${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 38:   ${BLD}$title38a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title38b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title38c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity38${NORMAL}"

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

file38="/etc/cron.allow"

if [[ -f $file38 ]]
then
   fperm="$(ls -l /etc | grep cron.allow)"
   if [[ $fperm ]]
   then
      for line in ${fperm[@]}
      do
         fgowner="$(echo $line | awk '{print $4}')"
         if [[ $fowner == 'root' ]]
         then
            echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
         else
            echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
            fail=1
         fi
      done
   fi
else
   echo -e "${NORMAL}RESULT:    ${BLD}$file38 was not found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
   echo -e "${NORMAL}$hostname, $severity38, $controlid, $stigid38, $ruleid38, $cci38, $datetime, ${GRN}PASSED, cron.allow is group-owned by root.${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity38, $controlid, $stigid38, $ruleid38, $cci38, $datetime, ${RED}FAILED, cron.allow is not group-owned by root.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid39${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid39${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid39${NORMAL}"
echo -e "${NORMAL}CCI:       $cci39${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 39:   ${BLD}$title39a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title39b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title39c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity39${NORMAL}"

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

fail=0

kdump="$(systemctl status kdump.service)"
if [[ $kdump ]]
then
   for line in ${kdump[@]}
   do
      if [[ $line =~ 'service; enabled' || $line =~ 'Active: active' ]]
      then
         echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
         fail=1
      else
         echo -e "${NORMAL}RESULT:    $line${NORMAL}"
      fi
   done
else
   echo -e "${NORMAL}RESULT:    ${BLD}The kdump service was not found${NORMAL}"
fi
if [[ $fail == 0 ]]
then
   echo -e "${NORMAL}$hostname, $severity39, $controlid, $stigid39, $ruleid39, $cci39, $datetime, ${GRN}PASSED, Kernel Core Dump - The kdump service is disabled${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity39, $controlid, $stigid39, $ruleid39, $cci39, $datetime, ${CYN}VERIFY, Kernel Core Dump - The kdump service is not disabled. Verify with the ISSO.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid40${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid40${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid40${NORMAL}"
echo -e "${NORMAL}CCI:       $cci40${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 40:   ${BLD}$title40a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title40b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title40c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity40${NORMAL}"

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

file40="/etc/passwd"
fail=0
usrfail=1

IFS='
'
usraccts="$(awk -F: '($3>=1000)&&($7 !~ /nologin/){print $1, $3, $6, $7}' $file40)"

fsys="$(df -hl)"

for fs in ${fsys[@]}
do
   echo $fs
done
echo "-----------------------------------------------------"

if [[ $usraccts ]]
then
   for usr in ${usraccts[@]}
   do
      usr="$(echo $usr | awk -F: '{print $1}')"
      usrname="$(echo $user | awk '{print $1}')"
      homedir="$(echo $usr | awk '{print $3}')"
      for fs in ${fsys[@]}
      do
         fsmnt="$(echo $fs | awk '{print $6}')"
         hdpath="$(dirname $homedir)"
         if [[ $hdpath == $fsmnt ]]
         then
            usrfail=0
            echo -e "${NORMAL}RESULT:    $usrname's home directory is ${BLD}$fsmnt${NORMAL}"
         fi
      done
      if [[ $usrfail == 1 ]]
      then
         fail=1
         echo -e "${NORMAL}RESULT:    ${RED}$usrname's home directory is not on a separate file system${NORMAL}"
      fi
   done
   if [[ $fail == 1 ]]
   then
      echo -e "${NORMAL}$hostname, $severity40, $controlid, $stigid40, $ruleid40, $cci40, $datetime, ${RED}FAILED, A separate file system is not used for all user home directories${NORMAL}"
   else
      echo -e "${NORMAL}RESULT:    ${BLD}A separate file system is used for all user home directories${NORMAL}"
      echo -e "${NORMAL}$hostname, $severity40, $controlid, $stigid40, $ruleid40, $cci40, $datetime, ${GRN}PASSED, A separate file system is used for all user home directories${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${BLD}No local interactive user accounts were found${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity40, $controlid, $stigid40, $ruleid40, $cci40, $datetime, ${CYN}VERIFY, No local interactive user accounts were found${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid41${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid41${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid41${NORMAL}"
echo -e "${NORMAL}CCI:       $cci41${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 41:   ${BLD}$title41a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title41b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title41c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity41${NORMAL}"

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

file41="/etc/fstab"
fail=1

if [[ -f $file41 ]]
then
   fsys="$(df -hl)"
   for fs in ${fsys[@]}
   do
      echo $fs
   done
   echo "-----------------------------------------------------"
   for fs in ${fsys[@]}
   do
      mnt="$(echo $fs | awk '{print $6}')"
      if [[ $mnt == '/var' ]]
      then
         fail=0
         echo -e "${NORMAL}RESULT:    ${BLD}$fs${NORMAL}"
      fi
   done

   if [[ $fail == 1 ]]
   then
      echo -e "${NORMAL}RESULT:    ${BLD}A separate file system for \"/var\" was not found${NORMAL}"
      echo -e "${NORMAL}$hostname, $severity41, $controlid, $stigid41, $ruleid41, $cci41, $datetime, ${RED}FAILED, Separate /VAR File System: A separate file system for \"/var\" does not exist${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity41, $controlid, $stigid41, $ruleid41, $cci41, $datetime, ${GRN}PASSED, Separate /VAR File System: A separate file system for \"/var\" exists${NORMAL}"
   fi
else
   echo -e "${NORMAL}$hostname, $severity41, $controlid, $stigid41, $ruleid41, $cci41, $datetime, ${RED}FAILED, Separate /VAR File System: $file40 not found${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid42${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid42${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid42${NORMAL}"
echo -e "${NORMAL}CCI:       $cci42${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 42:   ${BLD}$title42a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title42b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title42c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity42${NORMAL}"

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

file42="/etc/fstab"
fail=1

if [[ -f $file42 ]]
then
   fsys="$(df -hl) | grep -v '^find'"
   for fs in ${fsys[@]}
   do
      echo $fs
   done
   echo "-----------------------------------------------------"
   cfgpath="$(find /etc -xdev -noleaf -name auditd.conf)"
   for line in ${cfgpath[@]}
   do
      if [[ ! $line =~ 'find' ]]
      then
         cfgfile=$line
      fi
   done
   logpath="$(grep ^log_file $cfgfile | awk -F= '{print $2}' | sed -r 's/( )+//g')"
   logpartition="$(dirname $logpath)"
   echo -e "${NORMAL}RESULT:    Logs are in: $logpath"

   for fs in ${fsys[@]}
   do
      partition="$(echo $fs | awk '{print $6}')"
      if [[ $partition == $logpartition ]]
      then
         fail=0
         echo -e "${NORMAL}RESULT:    ${BLD}$fs${NORMAL}"
      fi
   done

   if [[ $fail == 1 ]]
   then
      echo -e "${NORMAL}RESULT:    ${BLD}A separate file system for \"$logpartition\" was not found${NORMAL}"
      echo -e "${NORMAL}$hostname, $severity42, $controlid, $stigid42, $ruleid42, $cci42, $datetime, ${RED}FAILED, Separate Log Partition: A separate file system for \"$logpartition\" does not exist${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity42, $controlid, $stigid42, $ruleid42, $cci42, $datetime, ${GRN}PASSED, Separate Log Partition: A separate file system for \"$logpartition\" exists${NORMAL}"
   fi
else
   echo -e "${NORMAL}$hostname, $severity42, $controlid, $stigid42, $ruleid42, $cci42, $datetime,${RED}FAILED, Separate Log Partition: $file41 not found${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid43${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid43${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid43${NORMAL}"
echo -e "${NORMAL}CCI:       $cci43${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 43:   ${BLD}$title43a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title43b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title43c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity43${NORMAL}"

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

file43="/etc/fstab"
mntfound=0
fail=1

if [[ -f $file43 ]]
then
   fsys="$(df -hl)"
   for fs in ${fsys[@]}
   do
      echo $fs
   done
   echo "-----------------------------------------------------"

   for fs in ${fsys[@]}
   do
      partition="$(echo $fs | awk '{print $6}')"
      if [[ $partition == "/tmp" ]]
      then
         echo -e "${NORMAL}RESULT:    ${BLD}$fs${NORMAL}"
         mntfound=1
      fi
   done

   tmpmnt="$(systemctl is-enabled tmp.mount)"
   if [[ $tmpmnt == enabled ]]
   then
      echo -e "${NORMAL}RESULT:    ${BLD}The tmp.mount service is $tmpmnt${NORMAL}"
      fail=0
   else
      echo -e "${NORMAL}RESULT:    ${RED}The tmp.mount service is $tmpmnt${NORMAL}"
      if [[ $mntfound == 1 ]]
      then
         fail=0
      fi
   fi

   if [[ $fail == 0 ]]
   then
      echo -e "${NORMAL}$hostname, $severity43, $controlid, $stigid43, $ruleid43, $cci43, $datetime, ${GRN}PASSED, Separate /TMP File System: A separate file system for \"/tmp\" exists${NORMAL}"
   else
      echo -e "${NORMAL}RESULT:    ${BLD}A separate file system for \"/tmp\" was not found${NORMAL}"
      echo -e "${NORMAL}$hostname, $severity43, $controlid, $stigid43, $ruleid43, $cci43, $datetime, ${RED}FAILED, Separate /TMP File System: A separate file system for \"/tmp\" does not exist${NORMAL}"
   fi
else
   echo -e "${NORMAL}$hostname, $severity43, $controlid, $stigid43, $ruleid43, $cci43, $datetime, ${RED}FAILED, Separate /TMP File System: $file42 not found${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid44${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid44${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid44${NORMAL}"
echo -e "${NORMAL}CCI:       $cci44${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 44:   ${BLD}$title44a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title44b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title44c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity44${NORMAL}"

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

file44="aide.conf"
rulenamearr=""
fail=0

isinstalled="$(rpm -qa | grep aide)"

if [[ $isinstalled ]]
then
   echo -e "${NORMAL}RESULT:    ${BLD}a. $isinstalled${NORMAL}"
   conf="$(find / -type d -name '(mnt|pcap)' -prune -xdev -noleaf -o -name $file44)"
   if [[ $conf ]]
   then
      echo -e "${NORMAL}RESULT:    ${BLD}b. $conf${NORMAL}"
      rules="$(cat $conf | grep -v '^#')"
      aclrule="$(grep -i '+acl' $conf | grep -v '^#')"
      include="$(grep -i '^/' $conf)"
      exclude="$(grep -i '^!/' $conf)"
      if [[ $aclrule ]]
      then
         for rule in ${aclrule[@]}
         do
            echo -e "${NORMAL}RESULT:    ${BLD}c. $rule${NORMAL}"
            rulename="$(echo $rule | awk '{print $1}')"
            rulenamearr+=("$rulename")
         done
         if [[ $include ]]
         then
            for rule in ${include[@]}
            do
               hasrule=""
               for rulename in ${rulenamearr[@]}
               do
                  hasrule="$(echo $rule | grep -w $rulename)"
                  if [[ $hasrule ]]
                  then
                     echo -e "${NORMAL}RESULT:    ${BLD}d. $rule${NORMAL}"
                     break
                  fi
               done
               if [[ ! $hasrule ]]
               then
                  echo -e "${NORMAL}RESULT:    ${BLD}d. $rule is missing the \"acl\" rule${NORMAL}"
                  fail=2
               fi
            done
         else
            echo -e "${NORMAL}RESULT:    ${RED}d. No files or directories are scanned${NORMAL}"
            fail=2
         fi
         if [[ $exclude ]]
         then
            for rule in ${exclude[@]}
            do
               echo -e "${NORMAL}RESULT:    ${BLD}e. $rule${NORMAL}"
            done
         else
            echo -e "${NORMAL}RESULT:    ${RED}e. No files or directories are excluded from scans${NORMAL}"
            fail=2
         fi
      else
         echo -e "${NORMAL}RESULT:    ${RED}c. No \"acl\" rules found${NORMAL}"
         fail=2
      fi
   else
      echo -e "${NORMAL}RESULT:    ${RED}b. \"$file44\" not found - exiting${NORMAL}"
      fail=2
   fi
else
   echo -e "${NORMAL}RESULT:    ${RED}a. AIDE is not instaled - exiting${NORMAL}"
   fail=1
fi

if [[ $fail == 0 ]]
then
   echo -e "${NORMAL}$hostname, $severity44, $controlid, $stigid44, $ruleid44, $cci44, $datetime, ${CYN}VERIFY, File Integrity: AIDE is installed and the \"acl\" rule is applied. Have the ISSO verify all security relevant files and directories are being scanned.${NORMAL}"
elif (( $fail == 1 ))
then
   echo -e "${NORMAL}$hostname, $severity44, $controlid, $stigid44, $ruleid44, $cci44, $datetime, ${CYN}VERIFY, File Integrity: AIDE is not installed. Have the ISSO verify whether another tool is used.${NORMAL}"
elif (( $fail == 2 ))
then
   echo -e "${NORMAL}$hostname, $severity44, $controlid, $stigid44, $ruleid44, $cci44, $datetime, ${RED}FAILED, File Integrity: AIDE is installed but the \"acl\" rule is not applied.${NORMAL}" 
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid45${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid45${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid45${NORMAL}"
echo -e "${NORMAL}CCI:       $cci45${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 45:   ${BLD}$title45a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title45b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title45c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity45${NORMAL}"

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

file45="aide.conf"
rulenamearr=""
fail=0

isinstalled="$(rpm -qa | grep aide)"

if [[ $isinstalled ]]
then
   echo -e "${NORMAL}RESULT:    ${BLD}a. $isinstalled${NORMAL}"
   conf="$(find / -type d -name '(mnt|pcap)' -prune -o -type f -name $file45 2>/dev/null)"
   if [[ $conf ]]
   then
      echo -e "${NORMAL}RESULT:    ${BLD}b. $conf${NORMAL}"
      rules="$(cat $conf | grep -v '^#')"
      xattrsrule="$(grep -i '+xattrs' $conf | grep -v '^#')"
      include="$(grep -i '^/' $conf)"
      exclude="$(grep -i '^!/' $conf)"
      if [[ $xattrsrule ]]
      then
         for rule in ${xattrsrule[@]}
         do
            echo -e "${NORMAL}RESULT:    ${BLD}c. $rule${NORMAL}"
            rulename="$(echo $rule | awk '{print $1}')"
            rulenamearr+=("$rulename")
         done
         if [[ $include ]]
         then
            for rule in ${include[@]}
            do
               hasrule=""
               for rulename in ${rulenamearr[@]}
               do
                  hasrule="$(echo $rule | grep -w $rulename)"
                  if [[ $hasrule ]]
                  then
                     echo -e "${NORMAL}RESULT:    ${BLD}d. $rule${NORMAL}"
                     break
                  fi
               done
               if [[ ! $hasrule ]]
               then
                  echo -e "${NORMAL}RESULT:    ${BLD}d. $rule is missing the \"xattrs\" rule${NORMAL}"
                  fail=2
               fi
            done
         else
            echo -e "${NORMAL}RESULT:    ${RED}d. No files or directories are scanned${NORMAL}"
            fail=2
         fi
         if [[ $exclude ]]
         then
            for rule in ${exclude[@]}
            do
               echo -e "${NORMAL}RESULT:    ${BLD}e. $rule${NORMAL}"
            done
         else
            echo -e "${NORMAL}RESULT:    ${RED}e. No files or directories are excluded from scans${NORMAL}"
            fail=2
         fi
      else
         echo -e "${NORMAL}RESULT:    ${RED}c. No \"xattrs\" rules found${NORMAL}"
         fail=2
      fi
   else
      echo -e "${NORMAL}RESULT:    ${RED}b. \"$file45\" not found - exiting${NORMAL}"
      fail=2
  fi
else
   echo -e "${NORMAL}RESULT:    ${RED}a. AIDE is not instaled - exiting${NORMAL}"
   fail=1
fi

if [[ $fail == 0 ]]
then
   echo -e "${NORMAL}$hostname, $severity45, $controlid, $stigid45, $ruleid45, $cci45, $datetime, ${CYN}VERIFY, File Integrity: AIDE is installed and the \"xattrs\" rule is applied. Have the ISSO verify all security relevant files and directories are being scanned.${NORMAL}"
elif (( $fail == 1 ))
then
   echo -e "${NORMAL}$hostname, $severity45, $controlid, $stigid45, $ruleid45, $cci45, $datetime, ${CYN}VERIFY, File Integrity: AIDE is not installed. Have the ISSO verify whether another tool is used.${NORMAL}"
elif (( $fail == 2 ))
then
   echo -e "${NORMAL}$hostname, $severity45, $controlid, $stigid45, $ruleid45, $cci45, $datetime, ${RED}FAILED, File Integrity: AIDE is installed but the \"xattrs\" rule is not applied.${NORMAL}" 
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid46${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid46${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid46${NORMAL}"
echo -e "${NORMAL}CCI:       $cci46${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 46:   ${BLD}$title46a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title46b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title46c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity46${NORMAL}"

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

file46="aide.conf"
rulenamearr=""
fail=0

isinstalled="$(rpm -qa | grep aide)"

if [[ $isinstalled ]]
then
   echo -e "${NORMAL}RESULT:    ${BLD}a. $isinstalled${NORMAL}"
   conf="$(find / -type d -name '(mnt|pcap)' -prune -name $file46 2>/dev/null)"
   if [[ $conf ]]
   then
      echo -e "${NORMAL}RESULT:    ${BLD}b. $conf${NORMAL}"
      rules="$(cat $conf | grep -v '^#')"
      sha512rule="$(grep -i '+sha512' $conf | grep -v '^#')"
      include="$(grep -i '^/' $conf)"
      exclude="$(grep -i '^!/' $conf)"
      if [[ $sha512rule ]]
      then
         for rule in ${sha512rule[@]}
         do
            echo -e "${NORMAL}RESULT:    ${BLD}c. $rule${NORMAL}"
            rulename="$(echo $rule | awk '{print $1}')"
            rulenamearr+=("$rulename")
         done
         if [[ $include ]]
         then
            for rule in ${include[@]}
            do
               hasrule=""
               for rulename in ${rulenamearr[@]}
               do
                  hasrule="$(echo $rule | grep -w $rulename)"
                  if [[ $hasrule ]]
                  then
                     echo -e "${NORMAL}RESULT:    ${BLD}d. $rule${NORMAL}"
                     break
                  fi
               done
               if [[ ! $hasrule ]]
               then
                  echo -e "${NORMAL}RESULT:    ${BLD}d. $rule is missing the \"sha512\" rule${NORMAL}"
                  fail=2
               fi
            done
         else
            echo -e "${NORMAL}RESULT:    ${RED}d. No files or directories are scanned${NORMAL}"
            fail=2
         fi
         if [[ $exclude ]]
         then
            for rule in ${exclude[@]}
            do
               echo -e "${NORMAL}RESULT:    ${BLD}e. $rule${NORMAL}"
            done
         else
            echo -e "${NORMAL}RESULT:    ${RED}e. No files or directories are excluded from scans${NORMAL}"
            fail=2
         fi
      else
         echo -e "${NORMAL}RESULT:    ${RED}c. No \"sha512\" rules found${NORMAL}"
         fail=2
      fi
   else
      echo -e "${NORMAL}RESULT:    ${RED}b. \"$file46\" not found - exiting${NORMAL}"
      fail=2
  fi
else
   echo -e "${NORMAL}RESULT:    ${RED}a. AIDE is not instaled - exiting${NORMAL}"
   fail=1
fi

if [[ $fail == 0 ]]
then
   echo -e "${NORMAL}$hostname, $severity46, $controlid, $stigid46, $ruleid46, $cci46, $datetime, ${CYN}VERIFY, File Integrity: AIDE is installed and the \"sha512\" rule is applied. Have the ISSO verify all security relevant files and directories are being scanned.${NORMAL}"
elif (( $fail == 1 ))
then
   echo -e "${NORMAL}$hostname, $severity46, $controlid, $stigid46, $ruleid46, $cci46, $datetime, ${CYN}VERIFY, File Integrity: AIDE is not installed. Have the ISSO verify whether another tool is used.${NORMAL}"
elif (( $fail == 2 ))
then
   echo -e "${NORMAL}$hostname, $severity46, $controlid, $stigid46, $ruleid46, $cci46, $datetime, ${RED}FAILED, File Integrity: AIDE is installed but the \"sha512\" rule is not applied.${NORMAL}" 
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid47${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid47${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid47${NORMAL}"
echo -e "${NORMAL}CCI:       $cci47${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 47:   ${BLD}$title47a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title47b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title47c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity47${NORMAL}"

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

file47arr=('/boot/grub2/grub.cfg' '/boot/efi/EFI/redhat/grub.cfg')
fail=0
found=0

grubloader="$(find / -type d -name '(mnt|pcap)' -prune -o -type f -name 'grub.cfg' 2>/dev/null)"

if [[ $grubloader ]]
then
   for gldr in ${grubloader[@]}
   do
      if [[ ! $file47arr =~ $gldr ]]
      then
         echo -e "${NORMAL}RESULT:    ${RED}a. $gldr${NORMAL}"
         fail=2
      else
         echo -e "${NORMAL}RESULT:    ${BLD}a. $gldr${NORMAL}"
         menuentry="$(grep -cw menuentry $grubloader)"
         rootsets="$(grep 'set root' $grubloader | sed 's/^[[:space:]]*//')"
         echo -e "${NORMAL}RESULT:    ${BLD}b. menuentry $menuentry${NORMAL}"
         if [[ $rootsets ]]
         then
            for rset in ${rootsets[@]}
            do
               if [[ $rset =~ 'hd0' ]]
               then
                  echo -e "${NORMAL}RESULT:    ${BLD}c. $rset${NORMAL}"
               else
                  echo -e "${NORMAL}RESULT:    ${RED}c. $rset${NORMAL}"
                  fail=1
               fi
            done
         else
            fail=1
         fi
      fi
   done
else
   echo -e "${NORMAL}RESULT:    ${RED}\"grub.cfg\" not found${NORMAL}"
   fail=1
fi
         
if (( $fail == 0  ))
then
   echo -e "${NORMAL}$hostname, $severity47, $controlid, $stigid47, $ruleid47, $cci47, $datetime, ${GRN}PASSED, GRUB Boot Loader: The system is configured to use hd0 as the boot loader device.${NORMAL}"
elif (( $fail == 2 ))
then
   echo -e "${NORMAL}$hostname, $severity47, $controlid, $stigid47, $ruleid47, $cci47, $datetime, ${RED}VERIFY, GRUB Boot Loader: \"grub.cfg\" was found in a location other than \"/boot/grub2\" and \"/boot/efi/EFI/redhat\". Ask the System Administrator if there is documentation signed by the ISSO to approve the use of removable media as a boot loader.${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity47, $controlid, $stigid47, $ruleid47, $cci47, $datetime, ${RED}FAILED, GRUB Boot Loader: The system is not configured to use hd0 as the boot loader device.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid48${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid48${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid48${NORMAL}"
echo -e "${NORMAL}CCI:       $cci48${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 48:   ${BLD}$title48a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title48b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title48c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity48${NORMAL}"

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

file48arr=('/etc/rsyslog.conf' '/etc/rsyslog.d/*.conf')
fail=1

for file in ${file48arr[@]}
do
   if [[ -f $file ]]
   then
      logagg="$(grep @ $file)"
      if [[ $logagg ]]
      then
         for line in ${logagg[@]}
         do
            if [[ ${line:0:1} != '#' ]]
            then
               if [[ $line =~ '*.*' && $line =~ '@@' ]]
               then
                  echo -e "${NORMAL}RESULT:    ${CYN}$file:${GRN}$line${NORMAL}"
                  fail=0
               else
                  echo -e "${NORMAL}RESULT:    $file:$line${NORMAL}"
               fi
            else
               echo -e "${NORMAL}RESULT:    $file:$line${NORMAL}"
            fi
         done
      else
         echo -e "${NORMAL}RESULT:    $file:Nothing found${NORMAL}"
      fi
   else
      echo -e "${NORMAL}RESULT:    ${RED}$file not found${NORMAL}"
   fi
done

if [[ $fail == 0 ]]
then
   echo -e "${NORMAL}$hostname, $severity48, $controlid, $stigid48, $ruleid48, $cci48, $datetime, ${CYN}VERIFY, RSYSLOG Aggrigation: Ask the System Administrator to verify that the identified log collector is a valid destination (nslookup, ping, etc.).${NORMAL}"
else
   echo -e "${NORMAL}RESULT:    ${RED}Rsyslog off-loading is not configured${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity48, $controlid, $stigid48, $ruleid48, $cci48, $datetime, ${RED}FAILED, RSYSLOG Aggrigation: RSYSLOG output is not sent to a remote system${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid49${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid49${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid49${NORMAL}"
echo -e "${NORMAL}CCI:       $cci49${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 49:   ${BLD}$title49a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title49b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title49c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity49${NORMAL}"

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

file49="/etc/rsyslog.conf"
imarr=('imtcp' 'imudp' 'imrelp')
fail=0

if [[ -f $file49 ]]
then
   for im in ${imarr[@]}
   do
      improto="$(grep $im $file49)"
      if [[ $improto ]]
      then
         echo -e "${NORMAL}RESULT:    ${CYN}$improto${NORMAL}"
         if [[ ${improto:0:1} == '#' ]]
         then
            echo -e "${NORMAL}RESULT:    The '$improto' module is not loaded${NORMAL}"
         else
            echo -e "${NORMAL}RESULT:    The '$improto' module is loaded${NORMAL}"
            fail=1
         fi
      else
         echo -e "${NORMAL}RESULT:    'ModLoad $im' is not identified in $file49${NORMAL}"
      fi
   done
else
   echo -e "${NORMAL}RESULT:    ${BLD}$file49 not found${NORMAL}"
fi

if (( $fail == 0 ))
then
   echo -e "${NORMAL}$hostname, $severity49, $controlid, $stigid49, $ruleid49, $cci49, $datetime, ${CYN}VERIFY, RSYSLOG Log Aggregation: Have the ISSO verify that the system is not being used as a log aggregation server${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity49, $controlid, $stigid49, $ruleid49, $cci49, $datetime, ${CYN}VERIFY, RSYSLOG Log Aggregation: Have the ISSO verify that the system is being used as a log aggregation server${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity49, $controlid, $stigid49, $ruleid49, $cci49, $datetime, ${CYN}VERIFY, RSYSLOG Log Aggregation: Have the ISSO verify that the log aggregation server is valid${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid50${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid50${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid50${NORMAL}"
echo -e "${NORMAL}CCI:       $cci50${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 50:   ${BLD}$title50a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title50b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title50c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity50${NORMAL}"

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

file50a="/proc/sys/crypto/fips_enabled"
file50b="/etc/ssh/sshd_config"

fipsciphers=("aes256-ctr" "aes192-ctr" "aes128-ctr")
aes128=0
aes192=0
aes256=0
badorder=0
fail=0


if [[ -f $file50a ]]
then
   fipsenabled="$(cat $file50a)"
   if (( $fipsenabled == 1 ))
   then
      echo -e "${NORMAL}RESULT:    ${BLD}fips_enabled = $fipsenabled${NORMAL}"      
      if [[ -f $file50b ]]
      then
         ciphers="$(grep ^Ciphers $file50b)"
         ciphers="$(echo $ciphers | sed 's/^Ciphers* *//')"
         IFS=',' read -a cipherarray <<< $ciphers
         if (( ${#cipherarray[@]} > 0 ))
         then
            echo -e "${NORMAL}RESULT:    ${BLD}$ciphers${NORMAL}"      
            for cipher in ${cipherarray[@]}
            do
               case $cipher in
               'aes128-ctr')
                  (( aes128++ ))
                  if [[ $aes128 > $aes192 || $aes128 > $aes256 ]]
                  then
                     badorder=1
                  fi
                  ;;
               'aes192-ctr')
                  (( aes192++ ))
                  if [[ $aes192 > $aes256 || $aes192 < $aes128 ]]
                  then
                     badorder=1
                  fi
                  ;;
               'aes256-ctr')
                  (( aes256++ ))
                  if [[ $aes256 < $aes192 || $aes256 < $aes128 ]]
                  then
                     badorder=1
                  fi
               esac
               if ! [[ "${fipsciphers[@]}" =~ "${cipher}" ]]
               then
                  fail=3
                  echo -e "${NORMAL}RESULT:    ${RED}$cipher is not FIPS 140-2 authorized${NORMAL}"
               fi
            done
            if [[ $badorder == 1 ]]
            then
               echo -e "${NORMAL}RESULT:    ${RED}FIPS 140-2 authorized ciphers are out of order${NORMAL}"
            fi
         fi
      else
         fail=2
      fi
   else
      fail=1
      echo -e "${NORMAL}RESULT:    ${BLD}FIPS is not enabled in $file50a${NORMAL}"
   fi

   if [[ $fail == 0 ]]
   then
   echo -e "${NORMAL}$hostname, $severity50, $controlid, $stigid50, $ruleid50, $cci50, $datetime, ${GRN}PASSED, FIPS Ciphers: FIPS is enabled and only FIPS 140-2 approved cryptographic algorithms are authorized for SSH commucation${NORMAL}"
   elif (( $fail == 1 ))
   then
      echo -e "${NORMAL}$hostname, $severity50, $controlid, $stigid50, $ruleid50, $cci50, $datetime, ${RED}FAILED, FIPS Ciphers: FIPS is not enabled in $file50a. The system cannot implement FIPS 140-2 authorized cryptographic algorithms and hashes.${NORMAL}"
   elif (( $fail == 2 ))
   then
      echo -e "${NORMAL}$hostname, $severity50, $controlid, $stigid50, $ruleid50, $cci50, $datetime, ${RED}FAILED, FIPS Ciphers: $file50b was not found${NORMAL}"
   elif (( $fail == 3 || $badorder == 1 ))
   then
      echo -e "${NORMAL}$hostname, $severity50, $controlid, $stigid50, $ruleid50, $cci50, $datetime, ${RED}FAILED, FIPS Ciphers: FIPS 140-2 approved ciphers are out of order, and at least one cryptographic algorithm that is not FIPS 140-2 authorized was found.${NORMAL}"
   elif (( $fail == 3 && $badorder == 0 ))
   then
      echo -e "${NORMAL}$hostname, $severity50, $controlid, $stigid50, $ruleid50, $cci50, $datetime, ${RED}FAILED, At least one cryptographic algorithm that is not FIPS 140-2 authorized was found.${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${BLD}$file50a was not found${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity50, $controlid, $stigid50, $ruleid50, $cci50, $datetime, ${RED}FAILED, FIPS Ciphers: $file50a was not found${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid51${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid51${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid51${NORMAL}"
echo -e "${NORMAL}CCI:       $cci51${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 51:   ${BLD}$title51a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title51b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title51c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity51${NORMAL}"

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

randspace1="$(grep -r 'kernel.randomize_va_space' /run/sysctl.d/* /etc/sysctl.d/* /usr/local/lib/sysctl.d/* usr/lib/sysctl.d/* lib/sysctl.d/* /etc/sysctl.conf 2>/dev/null)"

fail=0

if [[ $randspace1 ]]
then
   for line in ${randspace1[@]}
   do
      if [[ ${line:0:1} == "/" ]] 
      then
         filename="$(echo $line | awk -F: '{print $1}')"
         randspace="$(echo $line | awk -F: '{print $2}')"
         if [[ ${randspace:0:1} == "#" ]]
         then
            echo -e "${NORMAL}RESULT:    $file:$randspace${NORMAL}"
         else
            randspaceval="$(echo $randspace | awk -F'= ' '{print $2}')"
            if [[ $randspaceval == 2 ]]
            then
               echo -e "${NORMAL}RESULT:    ${CYN}$filename:${BLD}$randspace${NORMAL}"
            else
               echo -e "${NORMAL}RESULT:    ${CYN}$filename:${RED}$randspace${NORMAL}"
               fail=1
            fi
         fi
      else
         echo -e "${NORMAL}RESULT:    $line${NORMAL}"
      fi
   done
fi

if [[ $fail == 0 ]]
then
   echo -e "${NORMAL}$hostname, $severity51, $controlid, $stigid51, $ruleid51, $cci51, $datetime, ${GRN}PASSED, Virtual address space randomization is implemented${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity51, $controlid, $stigid51, $ruleid51, $cci51, $datetime, ${RED}FAILED, Virtual address space randomization is not properly implemented${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid52${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid52${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid52${NORMAL}"
echo -e "${NORMAL}CCI:       $cci52${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 52:   ${BLD}$title52a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title52b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title52c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity52${NORMAL}"

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

file52="/etc/ssh/sshd_config"

if [[ -f $file52 ]]
then

   osmake="$(echo $os | awk '{print $1}')"

   case $osmake in
      'Red')
          release="$(echo $os | awk '{print $7}')"
          ;;
      'CentOS')
          release="$(echo $os | awk '{print $4}')"
          ;;
   esac

   minver="7.4"

   major="$(echo $release | awk -F. '{print $1}')"
   minor="$(echo $release | awk -F. '{print $2}')"

   if (( $major > 7 || ( $major == 7 && $minor >= 4 ) ))
   then
      echo -e "${NORMAL}RESULT:    ${BLD}$os${NORMAL}"
      echo -e "${NORMAL}$hostname, $severity52, $controlid, $stigid52, $ruleid52, $cci52, $datetime, ${GRN}N/A, SSH RSA Rhost Authentication: Not Applicable: The Linux operating system is at least version $minver.${NORMAL}"
   else
      rsarhost="$(grep ^RhostsRSAAuthentication $file52)"
      if [[ $rsarhost ]]
      then
         rsarhostval="$(echo $rsarhost | awk '{print $2}')"
         if [[ $rsarhostval == 'no' ]]
         then
            echo -e "${NORMAL}RESULT:    ${BLD}$rsarhost${NORMAL}"
            echo -e "${NORMAL}$hostname, $severity52, $controlid, $stigid52, $ruleid52, $cci52, $datetime, ${GRN}PASSED, The SSH daemon does not allow RSA rhosts authentication${NORMAL}"
         else
            echo -e "${NORMAL}RESULT:    ${RED}$rsarhost${NORMAL}"
            echo -e "${NORMAL}$hostname, $severity52, $controlid, $stigid52, $ruleid52, $cci52, $datetime, ${RED}FAILED, The SSH daemon allows RSA rhosts authentication${NORMAL}"
         fi
      else
         echo -e "${NORMAL}RESULT:    ${BLD}RhostsRSAAuthentication is not defined in $file52${NORMAL}"
         echo -e "${NORMAL}$hostname, $severity52, $controlid, $stigid52, $ruleid52, $cci52, $datetime, ${RED}FAILED, RhostsRSAAuthentication is not defined in $file52${NORMAL}"
      fi
   fi
else
   echo -e "${NORMAL}RESULT:    ${BLD}$file52 was not found${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity52, $controlid, $stigid52, $ruleid52, ${RED}FAILED, SSH RSA Rhost Authentication: $file52 was not found${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid53${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid53${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid531${NORMAL}"
echo -e "${NORMAL}CCI:       $cci53${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 53:   ${BLD}$title53a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title53b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title53c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity53${NORMAL}"

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

file53="/etc/ssh/sshd_config"
fail=1

if [[ -f $file53 ]]
then
   ignorehost="$(grep -i ignorehost $file53)"
   if [[ $ignorehost ]]
   then
      for line in ${ignorehost[@]}
      do
         ignorerhostval="$(echo $line | awk '{print $2}')"
         if [[ $ignorerhostval == 'yes' && ${ignorehost:0:1} != '#' ]]
         then
            echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
            fail=0
         else
            echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
         fi
      done
   else
      echo -e "${NORMAL}RESULT:    ${RED}IgnoreRhosts is not defined in $file53${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${BLD}$file53 was not found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
   echo -e "${NORMAL}$hostname, $severity53, $controlid, $stigid53, $ruleid53, $cci53, $datetime, ${GRN}PASSED, SSH Ignore Rhosts: The SSH daemon does not allow authentication using rhosts authentication${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity53, $controlid, $stigid53, $ruleid53, $cci53, $datetime, ${RED}FAILED, SSH Ignore Rhosts: The SSH daemon allows authentication using rhosts authentication${NORMAL}"
fi

echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid54${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid54${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid54${NORMAL}"
echo -e "${NORMAL}CCI:       $cci54${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 54:   ${BLD}$title54a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title54b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title54c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity54${NORMAL}"

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

file54="/etc/ssh/sshd_config"
fail=1

if [[ -f $file54 ]]
then
   rootlogin="$(grep -i permitrootlogin $file54)"
   if [[ $rootlogin ]]
   then
      for line in ${rootlogin[@]}
      do
         rootloginval="$(echo $line | awk '{print $2}')"
         if [[ $rootloginval == 'no' && ${rootlogin:0:1} != '#' ]]
         then
            echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
            fail=0
         else
            echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
         fi
      done
   else
      echo -e "${NORMAL}RESULT:    ${BLD}PermitRootLogin is not defined in $file54${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${BLD}$file54 was not found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
   echo -e "${NORMAL}$hostname, $severity54, $controlid, $stigid54, $ruleid54, $cci54, $datetime, ${GRN}PASSED, SSH Root Login: The system does not permit direct logons to the root account using remote access via SSH${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity54, $controlid, $stigid54, $ruleid54, $cci54, $datetime, ${RED}FAILED, SSH Root Login: The system permits direct logons to the root account using remote access via SSH${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid55${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid55${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid55${NORMAL}"
echo -e "${NORMAL}CCI:       $cci55${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 55:   ${BLD}$title55a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title55b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title55c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity55${NORMAL}"

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

file55="/etc/ssh/sshd_config"
fail=1

if [[ -f $file55 ]]
then
   knownhost="$(grep -i ignoreuserknownhosts $file55)"
   if [[ $knownhost ]]
   then
      for line in ${knownhost[@]}
      do
         knownhostval="$(echo $line | awk '{print $2}')"
         if [[ $knownhostval == 'yes' && ${line:0:1} != '#' ]]
         then
            echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
            fail=0
         else
            echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
         fi
      done
   else
      echo -e "${NORMAL}RESULT:    ${BLD}IgnoreUserKnownHosts is not defined in $file55${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${BLD}$file55 was not found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
   echo -e "${NORMAL}$hostname, $severity55, $controlid, $stigid55, $ruleid55, $cci55, $datetime, ${GRN}PASSED, IgnoreUserKnownHosts: The system does not allow authentication using known host authentication.${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity55, $controlid, $stigid55, $ruleid55, $cci55, $datetime, ${RED}FAILED, IgnoreUserKnownHosts: The system allows authentication using known host authentication.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid56${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid56${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid56${NORMAL}"
echo -e "${NORMAL}CCI:       $cci56${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 56:   ${BLD}$title56a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title56b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title56c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity56${NORMAL}"

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

file56="/etc/ssh/sshd_config"
fail=1

if [[ -f $file56 ]]
then

   osmake="$(echo $os | awk '{print $1}')"

   case $osmake in
      'Red')
          release="$(echo $os | awk '{print $7}')"
          ;;
      'CentOS')
          release="$(echo $os | awk '{print $4}')"
          ;;
   esac

   minver="7.4"

   major="$(echo $release | awk -F. '{print $1}')"
   minor="$(echo $release | awk -F. '{print $2}')"

   if (( $major > 7 || ( $major == 7 && $minor >= 4 ) ))
   then
      echo -e "${NORMAL}RESULT:    ${BLD}$os${NORMAL}"
      echo -e "${NORMAL}$hostname, $severity56, $controlid, $stigid56, $ruleid56, $cci56, $datetime, ${GRN}N/A, SSHv2 Protocol: Not Applicable: The Linux operating system is at least version $minver.${NORMAL}"
   else
      sshproto="$(grep -i protocol $file56)"
      if [[ $sshproto ]]
      then
         sshprotover="$(echo $sshproto | awk '{print $2}')"
         if (( $sshprotover == 2 ))
         then
            echo -e "${NORMAL}RESULT:    ${BLD}$sshproto${NORMAL}"
            echo -e "${NORMAL}$hostname, $severity56, $controlid, $stigid56, $ruleid56, $cci56, $datetime, ${GRN}PASSED, SSHv2 Protocol: The SSH daemon is configured to only use the SSHv2 protocol${NORMAL}"
         else
            echo -e "${NORMAL}RESULT:    ${RED}$sshproto${NORMAL}"
            echo -e "${NORMAL}$hostname, $severity56, $controlid, $stigid56, $ruleid56, $cci56, $datetime, ${RED}FAILED, SSHv2 Protocol: The SSH daemon is not configured to only use the SSHv2 protocol${NORMAL}"
         fi
      fi
   fi
else
   echo -e "${NORMAL}RESULT:    ${RED}$file56 not found${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity56, $controlid, $stigid56, $ruleid56, $cci56, $datetime, ${RED}FAILED, SSHv2 Protocol: $file56 not found${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid57${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid57${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid57${NORMAL}"
echo -e "${NORMAL}CCI:       $cci57${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 57:   ${BLD}$title57a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title57b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title57c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity57${NORMAL}"

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

dir57="/etc/ssh"
fail=0

if [[ -d $dir57 ]]
then
   pubhostkeyfiles="$(find $dir57 -name '*.pub' 2>/dev/null -exec ls -lL {} \;)"
   if [[ $pubhostkeyfiles ]]
   then
      for file in ${pubhostkeyfiles[@]}
      do
         filename="$(echo $file | awk '{print $9}')"
         mode="$(stat -c %a $filename)"
         if (( ${mode:0:1} > 6 ||
               ${mode:1:1} > 4 ||
               ${mode:2:1} > 4
            ))
         then
            echo -e "${NORMAL}RESULT:    ${RED}$file (mode: $mode)${NORMAL}"
            fail=1
         else
            echo -e "${NORMAL}RESULT:    ${BLD}$file (mode: $mode)${NORMAL}"
         fi
      done
   else
      echo -e "${NORMAL}RESULT:    ${RED}No public host key files found in $dir57${NORMAL}"
      fail=1
   fi
else
   echo -e "${NORMAL}RESULT:    ${BLD}$dir57 not found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
   echo -e "${NORMAL}$hostname, $severity57, $controlid, $stigid57, $ruleid57, $cci57, $datetime, ${GRN}PASSED, SSH Public Host Key Permissions: Public host keys are mode 644 or less permissive${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity57, $controlid, $stigid57, $ruleid57, $cci57, $datetime, ${RED}FAILED, SSH Public Host Key Permissions: Public host keys are not mode 644 or less permissive${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid58${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid58${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid58${NORMAL}"
echo -e "${NORMAL}CCI:       $cci58${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 58:   ${BLD}$title58a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title58b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title58c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity58${NORMAL}"

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

dir58="/etc/ssh"
fail=0

if [[ -d $dir58 ]]
then
   privhostkeyfiles="$(find $dir58 -name '*.pub' -exec ls -lL {} \;)"
   if [[ $privhostkeyfiles ]]
   then
      for file in ${privhostkeyfiles[@]}
      do
         filename="$(echo $file | awk '{print $9}')"
         mode="$(stat -c %a $filename)"
         if (( ${mode:0:1} > 6 ||
               ${mode:1:1} > 4 ||
               ${mode:2:1} > 0
            ))
         then
            echo -e "${NORMAL}RESULT:    ${RED}$file (mode: $mode)${NORMAL}"
            fail=1
         else
            echo -e "${NORMAL}RESULT:    ${BLD}$file (mode: $mode)${NORMAL}"
         fi
      done
   else
      echo -e "${NORMAL}RESULT:    ${BLD}No private host key files found in $dir58${NORMAL}"
      fail=1
   fi
else
   echo -e "${NORMAL}RESULT:    ${BLD}$dir58 not found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
   echo -e "${NORMAL}$hostname, $severity58, $controlid, $stigid58, $ruleid58, $cci58, $datetime, ${GRN}PASSED, SSH Private Host Key Permissions: Private host keys are mode 640 or less permissive${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity58, $controlid, $stigid58, $ruleid58, $cci58, $datetime, ${RED}FAILED, SSH Private Host Key Permissions: Private host keys are not mode 640 or less permissive${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid59${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid59${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid59${NORMAL}"
echo -e "${NORMAL}CCI:       $cci59${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 59:   ${BLD}$title59a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title59b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title59c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity59${NORMAL}"

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

file59="/etc/ssh/sshd_config"
fail=1

if [[ -f $file59 ]]
then
   gssapiauth="$(grep -i gssapiauth $file59)"
   if [[ $gssapiauth ]]
   then
      gssapiauthval="$(echo $gssapiauth | awk '{print $2}')"
      if [[ $gssapiauthval == 'no' ]]
      then
         echo -e "${NORMAL}RESULT:    ${BLD}$gssapiauth${NORMAL}"
         fail=0
      else
         echo -e "${NORMAL}RESULT:    ${RED}$gssapiauth${NORMAL}"
      fi
   else
      echo -e "${NORMAL}RESULT:    ${BLD}GSSAPIAuthentication is not defined in $file58${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${BLD}$file58 was not found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
   echo -e "${NORMAL}$hostname, $severity59, $controlid, $stigid59, $ruleid59, $cci59, $datetime, ${GRN}PASSED, SSH GSSAPI Authentication: The SSH daemon does not allow GSSAPI authentication${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity59, $controlid, $stigid59, $ruleid59, $cci59, $datetime, ${RED}FAILED, SSH GSSAPI Authentication: The SSH daemon allows GSSAPI authentication${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid60${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid60${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid60${NORMAL}"
echo -e "${NORMAL}CCI:       $cci60${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 60:   ${BLD}$title60a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title60b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title60c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity60${NORMAL}"

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

file60="/etc/ssh/sshd_config"
fail=1

if [[ -f $file60 ]]
then
   kerberosauth="$(grep -i kerberosauth $file60)"
   if [[ $kerberosauth ]]
   then
      for line in ${kerberosauth{@]}
      do
         kerberosauthval="$(echo $kerberosauth | awk '{print $2}')"
         if [[ $kerberosauthval == 'no' && ${kerberosauth:0:1} != '#' ]]
         then
            echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
            fail=0
         else
            echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
         fi
      done
   else
      echo -e "${NORMAL}RESULT:    ${BLD}KerberosAuthentication is not defined in $file60${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${BLD}$file59 was not found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
   echo -e "${NORMAL}$hostname, $severity60, $controlid, $stigid60, $ruleid60, $cci60, $datetime, ${GRN}PASSED, SSH Kerberos Authentication: The SSH daemon does not allow Kerberos authentication${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity60, $controlid, $stigid60, $ruleid60, $cci60, $datetime, ${CYN}VERIFY, SSH Kerberos Authentication: Ask the System Administrator or ISSO to show documentation stating Kerberos authentication is needed for SSH authentication. If none can be produced this is a finding.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid61${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid61${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid61${NORMAL}"
echo -e "${NORMAL}CCI:       $cci61${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 61:   ${BLD}$title61a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title61b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title61c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity61${NORMAL}"

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

file61="/etc/ssh/sshd_config"
fail=1

if [[ -f $file61 ]]
then
   strictmodes="$(grep -i strictmodes $file61)"
   if [[ $strictmodes ]]
   then
      for line in ${strictmodes[@]}
      do
         strictmodesval="$(echo $strictmodes | awk '{print $2}')"
         if [[ $strictmodesval == 'yes' && ${line:0:1} != '#' ]]
         then
            echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
            fail=0
         else
            echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
         fi
      done
   else
      echo -e "${NORMAL}RESULT:    ${BLD}StrictModes is not defined in $file61${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${BLD}$file61 was not found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
   echo -e "${NORMAL}$hostname, $severity61, $controlid, $stigid61, $ruleid61, $cci61, $datetime, ${GRN}PASSED, SSH StrictModes: The SSH daemon performs strict mode checking of home directory configuration files.${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity61, $controlid, $stigid61, $ruleid61, $cci61, $datetime, ${RED}FAILED, The SSH daemon does not perform strict mode checking of home directory configuration files.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid62${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid62${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid62${NORMAL}"
echo -e "${NORMAL}CCI:       $cci62${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 62:   ${BLD}$title62a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title62b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title62c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity62${NORMAL}"

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

file62="/etc/ssh/sshd_config"
fail=1

if [[ -f $file62 ]]
then
   privsep="$(grep -i usepriv $file62)"
   if [[ $privsep ]]
   then
      for line in ${privsep[@]}
      do
         privsepval="$(echo $privsep | awk '{print $2}')"
         if [[ $privsepval == 'sandbox' ]]
         then
            echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
            fail=0
         else
            echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
         fi
      done
   else
      echo -e "${NORMAL}RESULT:    ${BLD}UsePrivilegeSeparation is not defined in $file62${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${BLD}$file62 was not found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
   echo -e "${NORMAL}$hostname, $severity62, $controlid, $stigid62, $ruleid62, $cci62, $datetime, ${GRN}PASSED, SSH Privilege Separation: The SSH daemon uses privilege separation${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity62, $controlid, $stigid62, $ruleid62, $cci62, $datetime, ${RED}FAILED, SSH Privilege Separation: The SSH daemon does use privilege separation${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid63${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid63${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid63${NORMAL}"
echo -e "${NORMAL}CCI:       $cci63${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 63:   ${BLD}$title63a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title63b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title63c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity63${NORMAL}"

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

file63="/etc/ssh/sshd_config"
fail=1

if [[ -f $file63 ]]
then
   compression="$(grep -i compression $file63)"
   if [[ $compression ]]
   then
      for line in ${compression[@]}
      do
         compressionval="$(echo $compression | awk '{print $2}')"
         if [[ ( $compressionval == 'no' || $compressionval == 'delayed' ) &&
               ! ${line:0:1} == '#'
            ]]
         then
            echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
            fail=0
         elif [[ $compressionval == 'yes' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
         else
            echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
         fi
      done
   else
      echo -e "${NORMAL}RESULT:    ${RED}\"Compression\" is not defined in $file63${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${RED}$file63 was not found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
   echo -e "${NORMAL}$hostname, $severity63, $controlid, $stigid63, $ruleid63, $cci63, $datetime, ${GRN}PASSED, SSH Compression: The SSH daemon does not allow compression before successful authentication${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity63, $controlid, $stigid63, $ruleid63, $cci63, $datetime, ${RED}FAILED, SSH Compression: The SSH daemon allows compression before successful authentication${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid64${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid64${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid64${NORMAL}"
echo -e "${NORMAL}CCI:       $cci64${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 64:   ${BLD}$title64a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title64b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title64c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity64${NORMAL}"

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

fwrpm="$(yum list installed firewalld | grep firewalld)"

fail=1

if [[ $fwrpm ]]
then
   for pkg in ${fwrpm[@]}
   do
      echo -e "${NORMAL}RESULT:    ${BLD}$pkg${NORMAL}"
   done
   fwdstate="$(systemctl status firewalld)"
   if [[ $fwdstate ]]
   then
      for line in ${fwdstate[@]}
      do
         if [[ $line =~ 'Active' && $line =~ 'running' ]]
         then
            echo -e "${NORMAL}RESULT:    ${GRN}$line${NORMAL}"
            fail=0
         elif [[ $line =~ 'Active' && $line =~ 'dead' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
         else
            echo -e "${NORMAL}RESULT:    $line${NORMAL}"
         fi
      done
   fi
   fwstat="$(firewall-cmd --state 2>/dev/null)"
   if [[ $fwstat ]]
   then
      if [[ $fwstat =~ 'running' ]]
      then
         echo -e "${NORMAL}RESULT:    ${BLD}\"firewall-cmd --state\" returned: ${GRN}$fwstat${NORMAL}"
         fail=0
      else
         echo -e "${NORMAL}RESULT:    ${RED}$fwstat${NORMAL}"
      fi
   else
      echo -e "${NORMAL}RESULT:    ${RED}Firewalld is not running${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${RED}The firewalld RPM is not installed${NORMAL}"
fi 

if [[ $fail == 0 ]]
then
   echo -e "${NORMAL}$hostname, $severity64, $controlid, $stigid64, $ruleid64, $cci64, $datetime, ${GRN}PASSED, (Firewall) The operating system enables an application firewall${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity64, $controlid, $stigid64, $ruleid64, $cci64, $datetime, ${RED}FAILED, (Firewall) An application firewall is not running or was not found${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid65${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid65${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid65${NORMAL}"
echo -e "${NORMAL}CCI:       $cci65${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 65:   ${BLD}$title65a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title65b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title65c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity65${NORMAL}"

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

shosts="$(find / -type d -name '(mnt|pcap)' -prune -o -type f -name '*.shosts' 2>/dev/null)"
fail=0

if [[ $shosts ]]
then
   for file in ${shosts[@]}
   do
      if [[ $file =~ ".shosts" ]]
      then
         echo -e "${NORMAL}RESULT:    ${RED}$file${NORMAL}"
         fail=1
      fi
   done
fi

if [[ $fail == 1 ]]
then
   echo -e "${NORMAL}$hostname, $severity65, $controlid, $stigid65, $ruleid65, $cci65, $datetime, ${RED}FAILED, Host-based authentication files (*.shosts) found${NORMAL}"
else
   echo -e "${NORMAL}RESULT:    ${BLD}No Host-based authentication files (*.shosts) found${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity65, $controlid, $stigid65, $ruleid65, $cci65, $datetime, ${GRN}PASSED, No host-based authentication files (*.shosts) found${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid66${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid66${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid66${NORMAL}"
echo -e "${NORMAL}CCI:       $cci66${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 66:   ${BLD}$title66a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title66b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title66c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity66${NORMAL}"

IFS='
'

datetime="$(date +%FT%H:%M:%S)"
fail=0

shostsequiv="$(find / -type d -name '(mnt|pcap)' -prune -o -name 'shosts.equiv' 2>/dev/null)"

if [[ $shostsequiv ]]
then
   for file in ${shostsequiv[@]}
   do
      if [[ $file =~ "shosts.equiv" ]]
      then
         echo -e "${NORMAL}RESULT:    ${RED}$file${NORMAL}"
         fail=1
      fi
   done
fi

if [[ $fail == 1 ]]
then
   echo -e "${NORMAL}$hostname, $severity66, $controlid, $stigid66, $ruleid66, $cci66, $datetime, ${RED}FAILED, Host-based authentication files (shosts.equiv) found${NORMAL}"
else
   echo -e "${NORMAL}RESULT:    ${BLD}No Host-based authentication files (shosts.equiv) found${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity66, $controlid, $stigid66, $ruleid66, $cci66, $datetime, ${GRN}PASSED, No host-based authentication files (shosts.equiv) found${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid67${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid67${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid67${NORMAL}"
echo -e "${NORMAL}CCI:       $cci67${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 67:   ${BLD}$title67a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title67b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title67c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity67${NORMAL}"

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

file67a="/etc/nsswitch.conf"
file67b="/etc/resolv.conf"

nsvrcnt=0
usesdns=0
fail=1

nameservice="$(grep hosts $file67a | grep -v '^#')"
if [[ $nameservice =~ 'dns' ]]
then
   echo -e "${NORMAL}RESULT:    ${BLD}a. $nameservice${NORMAL}"
   usesdns=1
else
   echo -e "${NORMAL}RESULT:    ${BLD}a. $nameservice ${CYN}(dns is not used)${NORMAL}"
fi

if [[ -f $file67b ]]
then
   conf="$(ls -al $file67b)"
   echo -e "${NORMAL}RESULT:    ${BLD}b. $conf${NORMAL}"
   fsize="$(echo $conf | awk '{print $5}')"
   if [[ $fsize > 0 && $usesdns == 0 ]]
   then
      echo -e "${NORMAL}RESULT:    ${BLD}$conf - ${RED}is not empty${NORMAL}"
   elif [[ $fsize > 0 && $usesdns == 1 ]]
   then
      nameservers="$(grep nameserver $file67b)"
      if [[ $nameservers ]]
      then
         for server in ${nameservers[@]}
         do
            (( nsvrcnt++ ))
            echo -e "${NORMAL}RESULT:    ${BLD}c. $server${NORMAL}"
         done
         if (( $nsvrcnt >= 2 ))
         then
            fail=0
         else
            fail=2
         fi
      else
         echo -e "${NORMAL}RESULT:    ${RED}c. No name servers found in $file67b${NORMAL}"
      fi
   elif [[ $fsize == 0 && $usesdns == 1 ]]
   then
      echo -e "${NORMAL}RESULT:    ${RED}c. No name servers found in $file67b${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${RED}b. $file67b not found${NORMAL}"   
fi

if [[ $fail == 0 ]]
then
   echo -e "${NORMAL}$hostname, $severity67, $controlid, $stigid67, $ruleid67, $cci67, $datetime, ${GRN}PASSED, DNS is used and two or more name servers are listed in $file67b${NORMAL}"
elif [[ $fail == 2 ]]
then
   echo -e "${NORMAL}$hostname, $severity67, $controlid, $stigid67, $ruleid67, $cci67, $datetime, ${RED}FAILED, DNS is used but two or more name servers are not listed in $file67b${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity67, $controlid, $stigid67, $ruleid67, $cci67, $datetime, ${RED}FAILED, DNS is not used but $file67b is not empty.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid68${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid68${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid68${NORMAL}"
echo -e "${NORMAL}CCI:       $cci68${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 68:   ${BLD}$title68a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title68b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title68c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity68${NORMAL}"

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

file68arr=('/run/sysctl.d/*' '/etc/sysctl.d/*' '/usr/local/lib/sysctl.d/*' '/usr/lib/sysctl.d/*' '/lib/sysctl.d/*' '/etc/sysctl.conf')

net4cfg=null
val=null

check1=""
check2=""

for xfile in ${file68arr[@]}
do
   v4asr="$(grep -r 'net.ipv4.conf.all.accept_source_route' $xfile 2>/dev/null)"
   if [[ $v4asr ]]
   then
      for yfile in ${v4asr[@]}
      do
         filename="$(echo $xfile | awk -F: '{print $1}')"
         v4asrval="$(echo $yfile | awk -F'= ' '{print $2}')"
         if [[ ${yfile:0:1} == '#' ]]
         then
            echo -e "${NORMAL}RESULT:    ${CYN}a. $filename:${NORMAL}$yfile${NORMAL}"
         elif [[ $v4asrval == 0 ]]
         then
            echo -e "${NORMAL}RESULT:    ${CYN}a. $filename:${BLD}$yfile${NORMAL}"
            check1="pass"
         else
            echo -e "${NORMAL}RESULT:    ${CYN}a. $filename:${RED}$yfile${NORMAL}"
            check1="fail"
         fi
      done
   fi
done
      
net4cfg="$(sysctl -a 2>&1 | grep net.ipv4.conf.all.accept_source_route)"

if [[ $net4cfg ]]
then
   for line in ${net4cfg[@]}
   do
      val="$(echo $line | awk -F= '{print $2/ //}')"
      if [[ $val == 0 ]]
      then
         echo -e "${NORMAL}RESULT:    ${BLD}b. $line${NORMAL}"
         check2="pass"
      else
         echo -e "${NORMAL}RESULT:    ${RED}b. $line${NORMAL}"
         check2="fail"
      fi
   done
   if [[ $check1 == "pass" && $check2 == "pass" ]]
   then
      echo -e "${NORMAL}$hostname, $severity68, $controlid, $stigid68, $ruleid68, $cci68, $datetime, ${GRN}PASSED, The system is not allowed to forward IPv4 source-routed packets${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity68, $controlid, $stigid68, $ruleid68, $cci68, $datetime, ${RED}FAILED, The system is allowed to forward IPv4 source-routed packets by default${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity68, $controlid, $stigid68, $ruleid68, $cci68, $datetime, ${RED}FAILED, \"sysctl -a\" did not return 'net.ipv4.conf.all.accept_source_route'.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid69${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid69${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid69${NORMAL}"
echo -e "${NORMAL}CCI:       $cci69${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 69:   ${BLD}$title69a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title69b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title69c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity69${NORMAL}"

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

file69arr=('/run/sysctl.d/*' '/etc/sysctl.d/*' '/usr/local/lib/sysctl.d/*' '/usr/lib/sysctl.d/*' '/lib/sysctl.d/*' '/etc/sysctl.conf')

net4cfg=null
val=null

check1=""
check2=""

for xfile in ${file69arr[@]}
do
   v4rpfilter="$(grep -r 'net.ipv4.conf.all.rp_filter' $xfile 2>/dev/null)"
   if [[ $v4rpfilter ]]
   then
      for yfile in ${v4rpfilter[@]}
      do
         filename="$(echo $xfile | awk -F: '{print $1}')"
         v4rpfilterval="$(echo $yfile | awk -F'= ' '{print $2}')"
         if [[ ${yfile:0:1} == '#' ]]
         then
            echo -e "${NORMAL}RESULT:    ${CYN}a. $filename:${NORMAL}$yfile${NORMAL}"
         elif [[ $v4rpfilterval == 1 ]]
         then
            echo -e "${NORMAL}RESULT:    ${CYN}a. $filename:${BLD}$yfile${NORMAL}"
            check1="pass"
         else
            echo -e "${NORMAL}RESULT:    ${CYN}a. $filename:${RED}$yfile${NORMAL}"
            check1="fail"
         fi
      done
   fi
done
      
net4cfg="$(sysctl -a 2>&1 | grep net.ipv4.conf.all.rp_filter)"

if [[ $net4cfg ]]
then
   for line in ${net4cfg[@]}
   do
      val="$(echo $line | awk -F= '{print $2/ //}')"
      if [[ $val == 1 ]]
      then
         echo -e "${NORMAL}RESULT:    ${BLD}b. $line${NORMAL}"
         check2="pass"
      else
         echo -e "${NORMAL}RESULT:    ${RED}b. $line${NORMAL}"
         check2="fail"
      fi
   done
   if [[ $check1 == "pass" && $check2 == "pass" ]]
   then
      echo -e "${NORMAL}$hostname, $severity69, $controlid, $stigid69, $ruleid69, $cci69, $datetime, ${GRN}PASSED, The system uses a reverse-path filter for IPv4 network trafic.${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity69, $controlid, $stigid69, $ruleid69, $cci69, $datetime, ${RED}FAILED, The system does not use a reverse-path filter for IPv4 network traffic.${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity69, $controlid, $stigid69, $ruleid69, $cci69, $datetime, ${RED}FAILED, \"sysctl -a\" did not return 'net.ipv4.conf.all.rp_filter'.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid70${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid70${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid70${NORMAL}"
echo -e "${NORMAL}CCI:       $cci70${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 70:   ${BLD}$title70a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title70b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title70c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity70${NORMAL}"

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

file70arr=('/run/sysctl.d/*' '/etc/sysctl.d/*' '/usr/local/lib/sysctl.d/*' '/usr/lib/sysctl.d/*' '/lib/sysctl.d/*' '/etc/sysctl.conf')

net4cfg=null
val=null

check1=""
check2=""

for xfile in ${file70arr[@]}
do
   v4rpfilter="$(grep -r 'net.ipv4.conf.default.rp_filter' $xfile 2>/dev/null)"
   if [[ $v4rpfilter ]]
   then
      for yfile in ${v4rpfilter[@]}
      do
         filename="$(echo $xfile | awk -F: '{print $1}')"
         v4rpfilterval="$(echo $yfile | awk -F'= ' '{print $2}')"
         if [[ ${yfile:0:1} == '#' ]]
         then
            echo -e "${NORMAL}RESULT:    ${CYN}a. $filename:${NORMAL}$yfile${NORMAL}"
         elif [[ $v4rpfilterval == 1 ]]
         then
            echo -e "${NORMAL}RESULT:    ${CYN}a. $filename:${BLD}$yfile${NORMAL}"
            check1="pass"
         else
            echo -e "${NORMAL}RESULT:    ${CYN}a. $filename:${RED}$yfile${NORMAL}"
            check1="fail"
         fi
      done
   fi
done
      
net4cfg="$(sysctl -a 2>&1 | grep net.ipv4.conf.default.rp_filter)"

if [[ $net4cfg ]]
then
   for line in ${net4cfg[@]}
   do
      val="$(echo $line | awk -F= '{print $2/ //}')"
      if [[ $val == 1 ]]
      then
         echo -e "${NORMAL}RESULT:    ${BLD}b. $line${NORMAL}"
         check2="pass"
      else
         echo -e "${NORMAL}RESULT:    ${RED}b. $line${NORMAL}"
         check2="fail"
      fi
   done
   if [[ $check1 == "pass" && $check2 == "pass" ]]
   then
      echo -e "${NORMAL}$hostname, $severity70, $controlid, $stigid70, $ruleid70, $cci70, $datetime, ${GRN}PASSED, The system uses a default reverse-path filter for IPv4 network trafic.${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity70, $controlid, $stigid70, $ruleid70, $cci70, $datetime, ${RED}FAILED, The system does not use a default reverse-path filter for IPv4 network traffic.${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity70, $controlid, $stigid70, $ruleid70, $cci70, $datetime, ${RED}FAILED, \"sysctl -a\" did not return 'net.ipv4.conf.default.rp_filter'.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid71${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid71${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid71${NORMAL}"
echo -e "${NORMAL}CCI:       $cci71${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 71:   ${BLD}$title71a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title71b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title71c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity71${NORMAL}"

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

file71arr=('/run/sysctl.d/*' '/etc/sysctl.d/*' '/usr/local/lib/sysctl.d/*' '/usr/lib/sysctl.d/*' '/lib/sysctl.d/*' '/etc/sysctl.conf')

net4cfg=null
val=null

check1=""
check2=""

for xfile in ${file71arr[@]}
do
   v4dasr="$(grep -r 'net.ipv4.conf.default.accept_source_route' $xfile 2>/dev/null)"
   if [[ $v4dasr ]]
   then
      for yfile in ${v4dasr[@]}
      do
         filename="$(echo $xfile | awk -F: '{print $1}')"
         v4rpfilterval="$(echo $yfile | awk -F'= ' '{print $2}')"
         if [[ ${yfile:0:1} == '#' ]]
         then
            echo -e "${NORMAL}RESULT:    ${CYN}a. $filename:${NORMAL}$yfile${NORMAL}"
         elif [[ $v4rpfilterval == 0 ]]
         then
            echo -e "${NORMAL}RESULT:    ${CYN}a. $filename:${BLD}$yfile${NORMAL}"
            check1="pass"
         else
            echo -e "${NORMAL}RESULT:    ${CYN}a. $filename:${RED}$yfile${NORMAL}"
            check1="fail"
         fi
      done
   fi
done
      
net4cfg="$(sysctl -a 2>&1 | grep net.ipv4.conf.default.accept_source_route)"

if [[ $net4cfg ]]
then
   for line in ${net4cfg[@]}
   do
      val="$(echo $line | awk -F= '{print $2/ //}')"
      if [[ $val == 0 ]]
      then
         echo -e "${NORMAL}RESULT:    ${BLD}b. $line${NORMAL}"
         check2="pass"
      else
         echo -e "${NORMAL}RESULT:    ${RED}b. $line${NORMAL}"
         check2="fail"
      fi
   done
   if [[ $check1 == "pass" && $check2 == "pass" ]]
   then
      echo -e "${NORMAL}$hostname, $severity71, $controlid, $stigid71, $ruleid71, $cci71, $datetime, ${GRN}PASSED, The system does not forward IPv4 source-routed packets by default.${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity71, $controlid, $stigid71, $ruleid71, $cci71, $datetime, ${RED}FAILED, The system forwards IPv4 source-routed packets by default.${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity71, $controlid, $stigid71, $ruleid71, $cci71, $datetime, ${RED}FAILED, \"sysctl -a\" did not return 'net.ipv4.conf.default.accept_source_route'.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid72${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid72${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid72${NORMAL}"
echo -e "${NORMAL}CCI:       $cci72${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 72:   ${BLD}$title72a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title72b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title72c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity72${NORMAL}"

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

file72arr=('/run/sysctl.d/*' '/etc/sysctl.d/*' '/usr/local/lib/sysctl.d/*' '/usr/lib/sysctl.d/*' '/lib/sysctl.d/*' '/etc/sysctl.conf')

net4cfg=null
val=null

check1=""
check2=""

for xfile in ${file72arr[@]}
do
   v4icmpignr="$(grep -r 'net.ipv4.icmp_echo_ignore_broadcast' $xfile 2>/dev/null)"
   if [[ $v4icmpignr ]]
   then
      for yfile in ${v4icmpignr[@]}
      do
         filename="$(echo $xfile | awk -F: '{print $1}')"
         v4icmpignrval="$(echo $yfile | awk -F'= ' '{print $2}')"
         if [[ ${yfile:0:1} == '#' ]]
         then
            echo -e "${NORMAL}RESULT:    ${CYN}a. $filename:${NORMAL}$yfile${NORMAL}"
         elif [[ $v4icmpignrval == 1 ]]
         then
            echo -e "${NORMAL}RESULT:    ${CYN}a. $filename:${BLD}$yfile${NORMAL}"
            check1="pass"
         else
            echo -e "${NORMAL}RESULT:    ${CYN}a. $filename:${RED}$yfile${NORMAL}"
            check1="fail"
         fi
      done
   fi
done
      
net4cfg="$(sysctl -a 2>&1 | grep net.ipv4.icmp_echo_ignore_broadcast)"

if [[ $net4cfg ]]
then
   for line in ${net4cfg[@]}
   do
      val="$(echo $line | awk -F= '{print $2/ //}')"
      if [[ $val == 1 ]]
      then
         echo -e "${NORMAL}RESULT:    ${BLD}b. $line${NORMAL}"
         check2="pass"
      else
         echo -e "${NORMAL}RESULT:    ${RED}b. $line${NORMAL}"
         check2="fail"
      fi
   done
   if [[ $check1 == "pass" && $check2 == "pass" ]]
   then
      echo -e "${NORMAL}$hostname, $severity72, $controlid, $stigid72, $ruleid72, $cci72, $datetime, ${GRN}PASSED, The system does not respond to IPv4 ICMP echoes sent to a broadcast address.${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity72, $controlid, $stigid72, $ruleid72, $cci72, $datetime, ${RED}FAILED, The system responds to IPv4 ICMP echoes sent to a broadcast address.${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity72, $controlid, $stigid72, $ruleid72, $cci72, $datetime, ${RED}FAILED, \"sysctl -a\" did not return 'net.ipv4.icmp_echo_ignore_broadcast'.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid73${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid73${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid73${NORMAL}"
echo -e "${NORMAL}CCI:       $cci73${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 73:   ${BLD}$title73a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title73b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title73c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity73${NORMAL}"

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

file73arr=('/run/sysctl.d/*' '/etc/sysctl.d/*' '/usr/local/lib/sysctl.d/*' '/usr/lib/sysctl.d/*' '/lib/sysctl.d/*' '/etc/sysctl.conf')

net4cfg=null
val=null

check1=""
check2=""

for xfile in ${file73arr[@]}
do
   v4dar="$(grep -r 'net.ipv4.conf.default.accept_redirects' $xfile 2>/dev/null)"
   if [[ $v4dar ]]
   then
      for yfile in ${v4dar[@]}
      do
         filename="$(echo $xfile | awk -F: '{print $1}')"
         v4darval="$(echo $yfile | awk -F'= ' '{print $2}')"
         if [[ ${yfile:0:1} == '#' ]]
         then
            echo -e "${NORMAL}RESULT:    ${CYN}a. $filename:${NORMAL}$yfile${NORMAL}"
         elif [[ $v4darval == 0 ]]
         then
            echo -e "${NORMAL}RESULT:    ${CYN}a. $filename:${BLD}$yfile${NORMAL}"
            check1="pass"
         else
            echo -e "${NORMAL}RESULT:    ${CYN}a. $filename:${RED}$yfile${NORMAL}"
            check1="fail"
         fi
      done
   fi
done
      
net4cfg="$(sysctl -a 2>&1 | grep net.ipv4.conf.default.accept_redirects)"

if [[ $net4cfg ]]
then
   for line in ${net4cfg[@]}
   do
      val="$(echo $line | awk -F= '{print $2/ //}')"
      if [[ $val == 0 ]]
      then
         echo -e "${NORMAL}RESULT:    ${BLD}b. $line${NORMAL}"
         check2="pass"
      else
         echo -e "${NORMAL}RESULT:    ${RED}b. $line${NORMAL}"
         check2="fail"
      fi
   done
   if [[ $check1 == "pass" && $check2 == "pass" ]]
   then
      echo -e "${NORMAL}$hostname, $severity73, $controlid, $stigid73, $ruleid73, $cci73, $datetime, ${GRN}PASSED, The system prevents IPv4 ICMP redirect messages from being accepted by default.${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity73, $controlid, $stigid73, $ruleid73, $cci73, $datetime, ${RED}FAILED, The system does not prevent IPv4 ICMP redirect messages from being accepted by default.${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity73, $controlid, $stigid73, $ruleid73, $cci73, $datetime, ${RED}FAILED, \"sysctl -a\" did not return 'net.ipv4.conf.default.accept_redirects'.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid74${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid74${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid74${NORMAL}"
echo -e "${NORMAL}CCI:       $cci74${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 74:   ${BLD}$title74a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title74b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title74c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity74${NORMAL}"

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

file74arr=('/run/sysctl.d/*' '/etc/sysctl.d/*' '/usr/local/lib/sysctl.d/*' '/usr/lib/sysctl.d/*' '/lib/sysctl.d/*' '/etc/sysctl.conf')

net4cfg=null
val=null

check1=""
check2=""

for xfile in ${file74arr[@]}
do
   v4aar="$(grep -r 'net.ipv4.conf.all.accept_redirects' $xfile 2>/dev/null)"
   if [[ $v4aar ]]
   then
      for yfile in ${v4aar[@]}
      do
         filename="$(echo $xfile | awk -F: '{print $1}')"
         v4darval="$(echo $yfile | awk -F'= ' '{print $2}')"
         if [[ ${yfile:0:1} == '#' ]]
         then
            echo -e "${NORMAL}RESULT:    ${CYN}a. $filename:${NORMAL}$yfile${NORMAL}"
         elif [[ $v4darval == 0 ]]
         then
            echo -e "${NORMAL}RESULT:    ${CYN}a. $filename:${BLD}$yfile${NORMAL}"
            check1="pass"
         else
            echo -e "${NORMAL}RESULT:    ${CYN}a. $filename:${RED}$yfile${NORMAL}"
            check1="fail"
         fi
      done
   fi
done
      
net4cfg="$(sysctl -a 2>&1 | grep net.ipv4.conf.all.accept_redirects)"

if [[ $net4cfg ]]
then
   for line in ${net4cfg[@]}
   do
      val="$(echo $line | awk -F= '{print $2/ //}')"
      if [[ $val == 0 ]]
      then
         echo -e "${NORMAL}RESULT:    ${BLD}b. $line${NORMAL}"
         check2="pass"
      else
         echo -e "${NORMAL}RESULT:    ${RED}b. $line${NORMAL}"
         check2="fail"
      fi
   done
   if [[ $check1 == "pass" && $check2 == "pass" ]]
   then
      echo -e "${NORMAL}$hostname, $severity74, $controlid, $stigid74, $ruleid74, $cci74, $datetime, ${GRN}PASSED, The system prevents IPv4 ICMP redirect messages from being accepted.${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity74, $controlid, $stigid74, $ruleid74, $cci74, $datetime, ${RED}FAILED, The system does not prevent IPv4 ICMP redirect messages from being accepted.${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity74, $controlid, $stigid74, $ruleid74, $cci74, $datetime, ${RED}FAILED, \"sysctl -a\" did not return 'net.ipv4.conf.all.accept_redirects'.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid75${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid75${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid75${NORMAL}"
echo -e "${NORMAL}CCI:       $cci75${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 75:   ${BLD}$title75a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title75b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title75c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity75${NORMAL}"

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

file75arr=('/run/sysctl.d/*' '/etc/sysctl.d/*' '/usr/local/lib/sysctl.d/*' '/usr/lib/sysctl.d/*' '/lib/sysctl.d/*' '/etc/sysctl.conf')

net4cfg=null
val=null

check1=""
check2=""

for xfile in ${file75arr[@]}
do
   v4dsr="$(grep -r 'net.ipv4.conf.default.send_redirects' $xfile 2>/dev/null)"
   if [[ $v4dsr ]]
   then
      for yfile in ${v4dsr[@]}
      do
         filename="$(echo $xfile | awk -F: '{print $1}')"
         v4dsrval="$(echo $yfile | awk -F'= ' '{print $2}')"
         if [[ ${yfile:0:1} == '#' ]]
         then
            echo -e "${NORMAL}RESULT:    ${CYN}a. $filename:${NORMAL}$yfile${NORMAL}"
         elif [[ $v4dsrval == 0 ]]
         then
            echo -e "${NORMAL}RESULT:    ${CYN}a. $filename:${BLD}$yfile${NORMAL}"
            check1="pass"
         else
            echo -e "${NORMAL}RESULT:    ${CYN}a. $filename:${RED}$yfile${NORMAL}"
            check1="fail"
         fi
      done
   fi
done
      
net4cfg="$(sysctl -a 2>&1 | grep net.ipv4.conf.default.send_redirects)"

if [[ $net4cfg ]]
then
   for line in ${net4cfg[@]}
   do
      val="$(echo $line | awk -F= '{print $2/ //}')"
      if [[ $val == 0 ]]
      then
         echo -e "${NORMAL}RESULT:    ${BLD}b. $line${NORMAL}"
         check2="pass"
      else
         echo -e "${NORMAL}RESULT:    ${RED}b. $line${NORMAL}"
         check2="fail"
      fi
   done
   if [[ $check1 == "pass" && $check2 == "pass" ]]
   then
      echo -e "${NORMAL}$hostname, $severity75, $controlid, $stigid75, $ruleid75, $cci75, $datetime, ${GRN}PASSED, The system does not allow interfaces to perform IPv4 ICMP redirects by default.${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity75, $controlid, $stigid75, $ruleid75, $cci75, $datetime, ${RED}FAILED, The system allows interfaces to perform IPv4 ICMP redirects by default.${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity75, $controlid, $stigid75, $ruleid75, $cci75, $datetime, ${RED}FAILED, \"sysctl -a\" did not return 'net.ipv4.conf.default.send_redirects'.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid76${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid76${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid76${NORMAL}"
echo -e "${NORMAL}CCI:       $cci76${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 76:   ${BLD}$title76a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title76b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title76c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity76${NORMAL}"

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

file76arr=('/run/sysctl.d/*' '/etc/sysctl.d/*' '/usr/local/lib/sysctl.d/*' '/usr/lib/sysctl.d/*' '/lib/sysctl.d/*' '/etc/sysctl.conf')

net4cfg=null
val=null

check1=""
check2=""

for xfile in ${file76arr[@]}
do
   v4asr="$(grep -r 'net.ipv4.conf.all.send_redirects' $xfile 2>/dev/null)"
   if [[ $v4asr ]]
   then
      for yfile in ${v4asr[@]}
      do
         filename="$(echo $xfile | awk -F: '{print $1}')"
         v4asrval="$(echo $yfile | awk -F'= ' '{print $2}')"
         if [[ ${yfile:0:1} == '#' ]]
         then
            echo -e "${NORMAL}RESULT:    ${CYN}a. $filename:${NORMAL}$yfile${NORMAL}"
         elif [[ $v4darval == 0 ]]
         then
            echo -e "${NORMAL}RESULT:    ${CYN}a. $filename:${BLD}$yfile${NORMAL}"
            check1="pass"
         else
            echo -e "${NORMAL}RESULT:    ${CYN}a. $filename:${RED}$yfile${NORMAL}"
            check1="fail"
         fi
      done
   fi
done
      
net4cfg="$(sysctl -a 2>&1 | grep net.ipv4.conf.all.send_redirects)"

if [[ $net4cfg ]]
then
   for line in ${net4cfg[@]}
   do
      val="$(echo $line | awk -F= '{print $2/ //}')"
      if [[ $val == 0 ]]
      then
         echo -e "${NORMAL}RESULT:    ${BLD}b. $line${NORMAL}"
         check2="pass"
      else
         echo -e "${NORMAL}RESULT:    ${RED}b. $line${NORMAL}"
         check2="fail"
      fi
   done
   if [[ $check1 == "pass" && $check2 == "pass" ]]
   then
      echo -e "${NORMAL}$hostname, $severity76, $controlid, $stigid76, $ruleid76, $cci76, $datetime, ${GRN}PASSED, The system does not allow interfaces to perform IPv4 ICMP redirects.${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity76, $controlid, $stigid76, $ruleid76, $cci76, $datetime, ${RED}FAILED, The system allows interfaces to perform IPv4 ICMP redirects.${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity76, $controlid, $stigid76, $ruleid76, $cci76, $datetime, ${RED}FAILED, \"sysctl -a\" did not return 'net.ipv4.conf.all.send_redirects'.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid77${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid77${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid77${NORMAL}"
echo -e "${NORMAL}CCI:       $cci77${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 77:   ${BLD}$title77a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title77b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title77c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity77${NORMAL}"

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

ifpromiscuous="$(ip link | grep -i promisc)"

if [[ $ifpromiscuous ]]
then
   for interface in ${ifpromiscuous[@]}
   do
      echo -e "${NORMAL}RESULT:    ${RED}$interface${NORMAL}"
   done
   echo -e "${NORMAL}$hostname, $severity77, $controlid, $stigid77, $ruleid77, $cci77, $datetime, ${RED}FAILED, There are network interfaces in promiscuous mode${NORMAL}"
else
   echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity77, $controlid, $stigid77, $ruleid77, $cci77, $datetime, ${GRN}PASSED, There are no network interfaces in promiscuous mode${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid78${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid78${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid78${NORMAL}"
echo -e "${NORMAL}CCI:       $cci78${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 78:   ${BLD}$title78a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title78b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title78c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity78${NORMAL}"

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

postfixrpm="$(yum list installed postfix | grep postfix)"

fail=1

if [[ $postfixrpm ]]
then
   echo -e "${NORMAL}RESULT:    ${BLD}a. $postfixrpm${NORMAL}"
   postfixstatus="$(systemctl status postfix)"
   if [[ $postfixstatus ]]
   then
      for line in ${postfixstatus[@]}
      do
         if [[ $line =~ 'Loaded:' || $line =~ 'postfix.service' ]]
         then
            echo -e "${NORMAL}RESULT:    ${BLD}b. $line${NORMAL}"
         elif [[ $line =~ 'Active:' && $line =~ 'dead' ]]
         then
            echo -e "${NORMAL}RESULT:    ${BLD}b. $line${NORMAL}"
            fail=2
         elif [[ $line =~ 'Active:' && $line =~ 'running' ]]
         then
            echo -e "${NORMAL}RESULT:    ${BLD}b. $line${NORMAL}"
            restrictions="$(postconf -n smtpd_client_restrictions 2>/dev/null)"
            if [[ $restrictions ]]
            then
               restrictvals="$(echo $restrictions | awk -F= '{print $2}')"
               if [[ $restrictvals ]]
               then
                  if [[ $restrictvals =~ 'permit_mynetworks' && $restrictvals =~ 'reject' ]]
                  then
                     echo -e "${NORMAL}RESULT:    ${BLD}c. $restrictions${NORMAL}"
                     fail=0
                  else
                     echo -e "${NORMAL}RESULT:    ${RED}c. $restrictions${NORMAL}"
                  fi
               else
                  echo -e "${NORMAL}RESULT:    ${RED}c. $restrictions${NORMAL}"
               fi
               break
            else
               echo -e "${NORMAL}RESULT:    ${RED}c. \"smtpd_client_restrictions\" is not defined in postconf${NORMAL}"
            fi
#         else
#            echo -e "${NORMAL}RESULT:    b. $line${NORMAL}"
         fi
      done
   fi
   if [[ $fail == 0 ]]
   then
      echo -e "${NORMAL}$hostname, $severity78, $controlid, $stigid78, $ruleid78, $cci78, $datetime, ${GRN}PASSED, Unrestricted Mail Relaying: The system prevents unrestricted mail relaying.${NORMAL}"
   elif [[ $fail == 2 ]]
   then
      echo -e "${NORMAL}$hostname, $severity78, $controlid, $stigid78, $ruleid78, $cci78, $datetime, ${GRN}N/A, Unrestricted Mail Relaying: The \"postfix.service\" is not running.${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity78, $controlid, $stigid78, $ruleid78, $cci78, $datetime, ${RED}FAILED, Unrestricted Mail Relaying: The system does not prevent unrestricted mail relaying.${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${BLD}a. Nothing returned${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity78, $controlid, $stigid78, $ruleid78, $cci78, $datetime, ${GRN}N/A, Unrestricted Mail Relaying: Not Applicable: Postfix is not installed.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid79${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid79${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid79${NORMAL}"
echo -e "${NORMAL}CCI:       $cci79${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 79:   ${BLD}$title79a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title79b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title79c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity79${NORMAL}"

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

isinstalled="$(yum list installed vsftpd 2>/dev/null | grep vsftpd)"

if [[ $isinstalled ]]
then
   echo -e "${NORMAL}RESULT:    ${RED}$isinstalled${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity79, $controlid, $stigid79, $ruleid79, $cci79, $datetime, ${RED}FAILED, File Transfer Protocol (vsftpd): VSFTPD is installed.${NORMAL}"
else
   echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity79, $controlid, $stigid79, $ruleid79, $cci79, $datetime, ${GRN}PASSED, File Transfer Protocol (vsftpd): VSFTPD is not installed.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid80${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid80${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid80${NORMAL}"
echo -e "${NORMAL}CCI:       $cci80${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 80:   ${BLD}$title80a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title80b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title80c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity80${NORMAL}"

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

isinstalled="$(yum list installed tftp-server 2>/dev/null | grep tftp-server)"

if [[ $isinstalled ]]
then
   echo -e "${NORMAL}RESULT:    ${RED}$isinstalled${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity80, $controlid, $stigid80, $ruleid80, $cci80, $datetime, ${RED}FAILED, Trivial File Transfer Protocol: \"tftp-server\" is installed.${NORMAL}"
else
   echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity80, $controlid, $stigid80, $ruleid80, $cci80, $datetime, ${GRN}PASSED, Trivial File Transfer Protocol: \"tftp-server\" is not installed.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid81${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid81${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid81${NORMAL}"
echo -e "${NORMAL}CCI:       $cci81${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 81:   ${BLD}$title81a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title81b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title81c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity81${NORMAL}"

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

file81="/etc/ssh/sshd_config"
fail=1

x11fwd="$(grep -i x11forwarding $file81 | grep -v '^#')"

if [[ $x11fwd ]]
then
   x11fwdval="$(echo $x11fwd | awk '{print $2}')"
   if [[ $x11fwdval == 'no' ]]
   then
      echo -e "${NORMAL}RESULT:    ${BLD}$x11fwd${NORMAL}"
      fail=0
   else
      echo -e "${NORMAL}RESULT:    ${RED}$x11fwd${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${BLD}\"x11forwarding\" is not defined in $file81${NORMAL}"
fi

if [[ $fail == 0 ]]
then
   echo -e "${NORMAL}$hostname, $severity81, $controlid, $stigid81, $ruleid81, $cci81, $datetime, ${GRN}PASSED, X11Forwarding is disabled.${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity81, $controlid, $stigid81, $ruleid81, $cci81, $datetime, ${RED}FAILED, X11Forwarding is not disabled.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid82${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid82${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid82${NORMAL}"
echo -e "${NORMAL}CCI:       $cci82${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 82:   ${BLD}$title82a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title82b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title82c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity82${NORMAL}"

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

file82="/etc/xinetd.d/tftp"

isinstalled="$(yum list installed tftp-server 2>/dev/null | grep tftp-server)"
fail=1

if [[ $isinstalled ]]
then
   echo -e "${NORMAL}RESULT:    ${RED}$isinstalled${NORMAL}"
   if [[ -f $file82 ]]
   then
      svrargs="$(grep server_args $file82)"
      if [[ $svrargs ]]
      then
         argsval="$(echo $svrargs | awk -F= '{print $2}')"
         if [[ $argsval =~ '-s /var/lib/tftpboot' ]]
         then
            echo -e "${NORMAL}RESULT:    ${BLD}$svrargs${NORMAL}"
            fail=0
         else
            echo -e "${NORMAL}RESULT:    ${RED}$svrargs${NORMAL}"
         fi
      else
         echo -e "${NORMAL}RESULT:    ${RED}\"server_args\" is not defined in $file82${NORMAL}"
      fi
   else
      echo -e "${NORMAL}RESULT:    ${BLD}$file82 not found${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${BLD}\"tftp-server\" is not installed${NORMAL}"
   fail=2
fi

if [[ $fail == 0 ]]
then
   echo -e "${NORMAL}$hostname, $severity82, $controlid, $stigid82, $ruleid82, $cci82, $datetime, ${GRN}PASSED, Trivial File Transfer Protocol: The TFTP server is configured to operate in secure mode${NORMAL}"
elif [[ $fail == 2 ]]
then
   echo -e "${NORMAL}$hostname, $severity82, $controlid, $stigid82, $ruleid82, $cci82, $datetime, ${GRN}N/A, Trivial File Transfer Protocol: \"tftp-server\" is not installed.${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity82, $controlid, $stigid82, $ruleid82, $cci82, $datetime, ${GRN}PASSED, Trivial File Transfer Protocol: The TFTP server is not configured to operate in secure mode${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid83${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid83${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid83${NORMAL}"
echo -e "${NORMAL}CCI:       $cci83${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 83:   ${BLD}$title83a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title83b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title83c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity83${NORMAL}"

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

fail=1

gui="$(rpm -qa 2>/dev/null | grep xorg | grep server)"
if [[ $gui ]]
then
   for line in ${gui[@]}
   do
      echo -e "${NORMAL}RESULT:    a. $line${NORMAL}"
   done
   guidefault="$(systemctl get-default)"
   if [[ $guidefault ]]
   then
      if [[ $guidefault == 'multi-user.target' ]]
      then
         echo -e "${NORMAL}RESULT:    ${BLD}b. $guidefault${NORMAL}"
         fail=0
      else
         echo -e "${NORMAL}RESULT:    ${RED}b. $guidefault${NORMAL}"
         fail=2
      fi
   else
      echo -e "${NORMAL}RESULT:    ${BLD}a. Nothing returned${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    a. A graphical user interface is not installed${NORMAL}"
fi

if [[ $fail == 0 ]]
then
   echo -e "${NORMAL}$hostname, $severity83, $controlid, $stigid83, $ruleid83, $cci83, $datetime, ${CYN}VERIFY, A Windows display manager is installed and is set to \"multi-user.target\". Ask the System Administrator to verify that a GUI is an operational requirement.${NORMAL}"
elif [[ $fail == 2 ]]
then
   echo -e "${NORMAL}$hostname, $severity83, $controlid, $stigid83, $ruleid83, $cci83, $datetime, ${RED}FAILED, A graphical user interface is installed, but is not set to \"multi-user.target\".${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity83, $controlid, $stigid83, $ruleid83, $cci83, $datetime, ${GRN}N/A, A graphical user interface is not installed.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid84${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid84${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid84${NORMAL}"
echo -e "${NORMAL}CCI:       $cci84${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 84:   ${BLD}$title84a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title84b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title84c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity84${NORMAL}"

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

file84arr=('/run/sysctl.d/*' '/etc/sysctl.d/*' '/usr/local/lib/sysctl.d/*' '/usr/lib/sysctl.d/*' '/lib/sysctl.d/*' '/etc/sysctl.conf')

net4cfg=null
val=null

check1=""
check2=""

for xfile in ${file84arr[@]}
do
   if [[ -f $xfile ]]
   then
      v4fwd="$(grep -rw 'net.ipv4.ip_forward' $xfile 2>/dev/null)"
      if [[ $v4fwd ]]
      then
         for yfile in ${v4fwd[@]}
         do
            if [[ -f $yfile ]]
            then
               filename="$(echo $xfile | awk -F: '{print $1}')"
               v4fwdval="$(echo $yfile | awk -F'= ' '{print $2}')"
               if [[ ${yfile:0:1} == '#' ]]
               then
                  echo -e "${NORMAL}RESULT:    ${CYN}a. $filename:${NORMAL}$yfile${NORMAL}"
               elif [[ $v4fwdval == 0 ]]
               then
                  echo -e "${NORMAL}RESULT:    ${CYN}a. $filename:${BLD}$yfile${NORMAL}"
                  check1="pass"
               else
                  echo -e "${NORMAL}RESULT:    ${CYN}a. $filename:${RED}$yfile${NORMAL}"
                  check1="fail"
               fi
            else
               echo -e "${NORMAL}RESULT:    ${CYN}a. $yfile:${NORMAL}(does not exist)${NORMAL}"
            fi
         done
      fi
   else
      echo -e "${NORMAL}RESULT:    ${CYN}a. $xfile:${NORMAL}(does not exist)${NORMAL}"
   fi
done

net4cfg="$(sysctl -a 2>&1 | grep -w net.ipv4.ip_forward)"

if [[ $net4cfg ]]
then
   for line in ${net4cfg[@]}
   do
      val="$(echo $line | awk -F'= ' '{print $2}')"
      if [[ $val == 0 ]]
      then
         echo -e "${NORMAL}RESULT:    ${BLD}b. $line${NORMAL}"
         check2="pass"
      else
         echo -e "${NORMAL}RESULT:    ${RED}b. $line${NORMAL}"
         check2="fail"
      fi
   done
   if [[ $check1 == "pass" && $check2 == "pass" ]]
   then
      echo -e "${NORMAL}$hostname, $severity84, $controlid, $stigid84, $ruleid84, $cci84, $datetime, ${GRN}PASSED, The system is not performing packet forwarding.${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity84, $controlid, $stigid84, $ruleid84, $cci84, $datetime, ${RED}FAILED, The system is configured to perform packet forwarding.${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity84, $controlid, $stigid84, $ruleid84, $cci84, $datetime, ${RED}FAILED, \"sysctl -a\" did not return 'net.ipv4.ip_forward'.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid85${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid85${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid85${NORMAL}"
echo -e "${NORMAL}CCI:       $cci85${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 85:   ${BLD}$title85a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title85b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title85c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity85${NORMAL}"

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

file85="/etc/fstab"

fail=1

nfsmnts="$(cat $file85 | grep nfs)"

if [[ $nfsmnts ]]
then
   for mnt in ${nfsmnts[@]}
   do
      flags="$(echo $mnt | awk '{print $4}')"
      if [[ $flags =~ 'sec=' && $flags =~ 'krb5:krb5i:krb5p' &&
          ! $flags =~ 'sys'
         ]]
      then
         echo -e "${NORMAL}RESULT:    ${BLD}$mnt${NORMAL}"
         fail=0
      else
         echo -e "${NORMAL}RESULT:    ${RED}$mnt${NORMAL}"
      fi
   done
   if [[ $fail == 0 ]]
   then
      echo -e "${NORMAL}$hostname, $severity85, $controlid, $stigid85, $ruleid85, $cci85, $datetime, ${GRN}PASSED, NFS Secure: The Network File System (NFS) is configured to use RPCSEC_GSS${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity85, $controlid, $stigid85, $ruleid85, $cci85, $datetime, ${RED}FAILED, NFS Secure: The Network File System (NFS) is not configured to use RPCSEC_GSS${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${BLD}No NFS mounts found${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity85, $controlid, $stigid85, $ruleid85, $cci85, $datetime, ${GRN}N/A, NFS Secure: Not Applicable: NFS mounts are not used.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid86${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid86${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid86${NORMAL}"
echo -e "${NORMAL}CCI:       $cci86${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 86:   ${BLD}$title86a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title86b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title86c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity86${NORMAL}"

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

file86="/etc/snmp/snmpd.conf"
fail=1
running=0

snmpdstat="$(systemctl status snmpd 2>/dev/null)"
if [[ $snmpdstat ]]
then
   filelocation="$(ls -al $file86)"
   if [[ $filelocation ]]
   then
      echo -e "${NORMAL}RESULT:    ${BLD}$filelocation${NORMAL}"
      communities="$(cat $file86 | egrep '(public|private)' | grep -v '^#')"
      if [[ $communities ]]
      then
         for community in ${communities[@]}
         do
            echo -e "${NORMAL}RESULT:    ${RED}$community${NORMAL}"
         done
      else
         echo -e "${NORMAL}RESULT:    ${BLD}No default SNMP communities found${NORMAL}"
         fail=0
      fi
   else
      echo -e "${NORMAL}RESULT:    ${BLD}$file86 not found${NORMAL}"
      fail=2
   fi
else
   echo -e "${NORMAL}RESULT:    ${BLD}The \"snmpd.service\" was not found${NORMAL}"
   fail=2
fi

if [[ $fail == 0 ]]
then
   echo -e "${NORMAL}$hostname, $severity86, $controlid, $stigid86, $ruleid86, $cci86, $datetime, ${GRN}PASSED, SNMP community strings: No default SNMP community strings found${NORMAL}"
elif [[ $fail == 2 ]]
then
   echo -e "${NORMAL}$hostname, $severity86, $controlid, $stigid86, $ruleid86, $cci86, $datetime, ${GRN}N/A, SNMP community strings: Not Applicable: $file86 not found${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity86, $controlid, $stigid86, $ruleid86, $cci86, $datetime, ${RED}FAILED, SNMP community strings: SNMP is running with default community strings${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid87${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid87${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid87${NORMAL}"
echo -e "${NORMAL}CCI:       $cci87${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 87:   ${BLD}$title87a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title87b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title87c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity87${NORMAL}"

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

fwpkgs="$(yum list installed | grep firewalld)"
fwcmd="$(command -v firewall-cmd)"

file87a="/etc/hosts.allow"
file87b="/etc/hosts.deny"

fail1=0
fail2=0
fail3=0
fail4=0
enabled=0
running=0

if [[ $fwpkgs ]]
then
   for pkg in ${fwpkgs[@]}
   do
      echo -e "${NORMAL}RESULT:    ${BLD}$pkg${NORMAL}"
   done
   fwdstate="$(systemctl status firewalld.service)"
   if [[ $fwdstate ]]
   then
      for line in ${fwdstate[@]}
      do
         if [[ $line =~ 'Loaded' && $line =~ 'enabled' ]]
         then
            enabled=1
            echo -e "${NORMAL}RESULT:    ${BLD}a. $line${NORMAL}"
         fi
         if [[ $line =~ 'Active' && $line =~ 'running' ]]
         then
            running=1
            echo -e "${NORMAL}RESULT:    ${BLD}a. $line${NORMAL}"
         elif [[ $line =~ 'Active' && $line =~ 'dead' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}a. $line${NORMAL}"
            fail1=1
         else
            echo -e "${NORMAL}RESULT:    a. $line${NORMAL}"
         fi
      done
      if (( $enabled == 1 && $running == 1 ))
      then
         if [[ $fwcmd ]]
         then
            dzone="$($fwcmd --get-default-zone)"
            if [[ $dzone ]]
            then
               if [[ $dzone == 'public' ]]
               then
                  echo -e "${NORMAL}RESULT:    ${BLD}b. FirewallD Default Zone: $dzone${NORMAL}"
               else
                  echo -e "${NORMAL}RESULT:    ${RED}b. FirewallD Default Zone: $dzone${NORMAL}"
               fi
               zhostnsvcs="$($fwcmd --list-all --zone=$dzone)"
               if [[ $zhostnsvcs ]]
               then
                  for line in ${zhostnsvcs[@]}
                  do
                     if [[ $line =~ 'public' && $line =~ 'active' ]]
                     then
                        echo -e "${NORMAL}RESULT:    ${BLD}c. $line${NORMAL}"
                     else
                        echo -e "${NORMAL}RESULT:    c. $line${NORMAL}"
                     fi
                  done
               else
                  echo -e "${NORMAL}RESULT:    ${RED}c. Zone hosts and services: nothing returned${NORMAL}"
                  fail=1
               fi
            else
               echo -e "${NORMAL}RESULT:    ${RED}b. FirewallD Default Zone: Nothing returned${NORMAL}"
               fail=1
            fi
         else
            echo -e "${NORMAL}RESULT:    ${RED}The 'firewalld-cmd' command was not found${NORMAL}"
            fail=1
         fi
      else
         echo -e "${NORMAL}RESULT:    ${RED}FirewallD is not enabled and running${NORMAL}"
      fi
   else
      echo -e "${NORMAL}RESULT:    ${RED}FirewallD is not running${NORMAL}"
      fail=1
   fi
else
   echo -e "${NORMAL}RESULT:    ${BLD}The firewalld package is not installed${NORMAL}"
   fail1=1
fi
if [[ -f $file87a ]]
then
   hafile="$(ls -al $file87a)"
   echo -e "${NORMAL}RESULT:    ${BLD}d. $hafile${NORMAL}"
   echo -e "${NORMAL}RESULT:    ${BLD}$file87a--------------------${NORMAL}"
   h_allow_active="$(cat $file87a | grep -v '^#')"
   if [[ ! $h_allow_active ]]
   then
      fail2=1
   fi
   h_allow_val="$(cat $file87a)"
   if [[ $h_allow_val ]]
      then
      for line in ${h_allow_val[@]}
      do
         if [[ ${line:0:1} == '#' ]]
         then
            echo -e "${NORMAL}RESULT:    ${CYN}$line${NORMAL}"
         else
            echo -e "${NORMAL}RESULT:    $line${NORMAL}"
         fi
      done
   else
      echo -e "${NORMAL}RESULT:    -is empty-${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    $file87a was not found${NORMAL}"
fi
if [[ -f $file87b ]]
then
   hdfile="$(ls -al $file87b)"
   echo -e "${NORMAL}RESULT:    ${BLD}e. $hdfile${NORMAL}"
   echo -e "${NORMAL}RESULT:    ${BLD}$file87b---------------------${NORMAL}"
   h_deny_active="$(cat $file87b | grep -v '^#')"
   if [[ ! $h_deny_active ]]
   then
      fail3=1
   fi
   h_deny="$(ls -al /etc/hosts.deny)"
   h_deny_val="$(cat /etc/hosts.deny)"
   if [[ $h_deny_val ]]
   then
      for line in ${h_deny_val[@]}
      do
         echo -e "${NORMAL}RESULT:    ${CYN}$line${NORMAL}"
      done
   else
      echo -e "${NORMAL}RESULT:    -is empty-${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    /etc/hosts.deny was not found${NORMAL}"
fi

iptblstat="$(systemctl status iptables.service 2>/dev/null)"
if [[ $iptblstat ]]
then
   for line in ${iptblstat[@]}
   do
      if [[ $line =~ 'Loaded' && $line =~ 'enabled' ]]
      then
         enabled=1
         echo -e "${NORMAL}RESULT:    ${BLD}a. $line${NORMAL}"
      fi
      if [[ $line =~ 'Active' && $line =~ 'running' ]]
      then
         running=1
         echo -e "${NORMAL}RESULT:    ${BLD}a. $line${NORMAL}"
      elif [[ $line =~ 'Active' && ($line =~ 'dead' || $line =~ 'exited') ]]
      then
         echo -e "${NORMAL}RESULT:    ${RED}a. $line${NORMAL}"
         fail1=1
      else
         echo -e "${NORMAL}RESULT:    a. $line${NORMAL}"
      fi
   done
else
   echo -e "${NORMAL}RESULT:    ${RED}The \"iptables.service\" could not be found${NORMAL}"
fi
iptblon="$(iptables -L | egrep -iv '(^chain|^target)')"
if [[  ${#iptblon[@]} =  0 ]]
then
   fail4=1
fi

iptbls="$(iptables -L)"
if [[ $iptbls ]]
then
   echo -e "${NORMAL}RESULT:    ${BLD}IPv4 IPTABLES -------------------------------------${NORMAL}"
   for line in ${iptbls[@]}
   do
      if [[ $line =~ 'Chain' ]]
      then
         echo
         echo -e "${NORMAL}RESULT:    ${CYN}$line${NORMAL}"
      else
         echo -e "${NORMAL}RESULT:    $line${NORMAL}"
      fi
   done
else
   fail4=1
fi
if (( $fail1 == 1 && $fail2 == 1 && $fail3 == 1 && $fail4 == 1 ))
then
   echo -e "${NORMAL}$hostname, $severity87, $controlid, $stigid87, $ruleid87, $cci87, $datetime, ${RED}FAILED, (Firewall): A firewall or tcpwrapper service is not in use${NORMAL}"
else  
   echo -e "${NORMAL}$hostname, $severity87, $controlid, $stigid87, $ruleid87, $cci87, $datetime, ${CYN}VERIFY, (Firewall): Ask the ISSO System Administrator or Network Engineer to verify that the system grants or denies access to specific hosts and services in accordance with the approved PPSM and network architecture.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid88${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid88${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid88${NORMAL}"
echo -e "${NORMAL}CCI:       $cci88${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 88:   ${BLD}$title88a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title88b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title88c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity88${NORMAL}"

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

enabled=0
running=0
configured=0

isinstalled="$(yum list installed | grep libreswan)"
sysctlcmd="$(command -v systemctl)"

if [[ $isinstalled ]]
then
   for pkg in ${isinstalled[@]}
   do
      echo -e "${NORMAL}RESULT:    ${BLD}a. $pkg${NORMAL}"
   done
   if [[ $sysctlcmd ]]
   then
      ipsecstat="$($sysctlcmd status ipsec)"
      if [[ $ipsecstat ]]
      then
         for line in ${ipsecstat[@]}
         do
            if [[ $line =~ 'Loaded' && $line =~ 'disabled' ]]
            then
               echo -e "${NORMAL}RESULT:    ${BLD}b. $line${NORMAL}"
            elif [[ $line =~ 'Loaded' && $line =~ 'enabled' ]]
            then
               enabled=1
               echo -e "${NORMAL}RESULT:    ${RED}b. $line${NORMAL}"
            elif [[ $line =~ 'Active' && $line =~ 'dead' ]]
            then
               echo -e "${NORMAL}RESULT:    ${BLD}b. $line${NORMAL}"
            elif [[ $line =~ 'Active' && $line =~ 'running' ]]
            then
               running=1
               echo -e "${NORMAL}RESULT:    ${RED}b. $line${NORMAL}"
               
               if [[ -f /etc/ipsec.conf ]]
               then
                  tuncfg="$(grep -i conn /etc/ipsec.conf)"
                  if [[ $tuncfg ]]
                  then
                     configured=1
                     for tun in ${tuncfg[@]}
                     do 
                        echo -e "${NORMAL}RESULT:    ${RED}c. $tun${NORMAL}"
                     done
                  else
                     echo -e "${NORMAL}RESULT:    c. /etc/ipsec.conf: (empty)${NORMAL}"
                  fi
               else
                  echo -e "${NORMAL}RESULT:    c. /etc/ipsec.conf: not found${NORMAL}"
               fi

               if [[ -d /etc/ipsec.d ]]
               then
                  tuncfg2="$(grep -i conn /etc/ipsec.d/*.conf)"
                  if [[ $tuncfg2 ]]
                  then
                     configured=1
                     for tun in ${tuncfg2[@]}
                     do 
                        echo -e "${NORMAL}RESULT:    ${RED}d. $tun${NORMAL}"
                     done    
                  else
                     echo -e "${NORMAL}RESULT:    d. /etc/ipsec.d/*.conf: (empty)${NORMAL}"
                  fi
               else
                  echo -e "${NORMAL}RESULT:    d. /etc/ipsec.d/*.conf: not found${NORMAL}"
               fi

            else
               echo -e "${NORMAL}RESULT:    b. $line${NORMAL}"
            fi
         done
      else
         echo -e "${NORMAL}RESULT:    b. 'systemctl --status ipsec' - Nothing returned${NORMAL}"
      fi
   else
      echo -e "${NORMAL}RESULT:    a. The 'systemctl' command was not found${NORMAL}"
      fail=1
   fi
   if (( $enabled == 1 && $configured == 1 && $running == 1 ))
   then
      echo -e "${NORMAL}$hostname, $severity88, $controlid, $stigid88, $ruleid88, $cci88, $datetime, ${RED}FAILED, IP Tunneling: IP Tunneling is installed and configured and running. Have the ISSO verify it is documented.${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity88, $controlid, $stigid88, $ruleid88, $cci88, $datetime, ${GRN}PASSED, IP Tunneling: IP Tunneling is installed but it is not running.${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${BLD}'libreswan' is not installed${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity88, $controlid, $stigid88, $ruleid88, $cci88, $datetime, ${GRN}PASSED, IP Tunneling: IP Tunneling is not installed.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid89${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid89${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid89${NORMAL}"
echo -e "${NORMAL}CCI:       $cci89${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 89:   ${BLD}$title89a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title89b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title89c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity89${NORMAL}"

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

file89arr=('/run/sysctl.d/*' '/etc/sysctl.d/*' '/usr/local/lib/sysctl.d/*' '/usr/lib/sysctl.d/*' '/lib/sysctl.d/*' '/etc/sysctl.conf')

net6cfg=null
val=null

check1=""
check2=""

for xfile in ${file89arr[@]}
do
   v6asr="$(grep -r 'net.ipv6.conf.all.accept_source_route' $xfile 2>/dev/null)"
   if [[ $v6asr ]]
   then
      for yfile in ${v6asr[@]}
      do
         filename="$(echo $xfile | awk -F: '{print $1}')"
         v6asrval="$(echo $yfile | awk -F'= ' '{print $2}')"
         if [[ ${yfile:0:1} == '#' ]]
         then
            echo -e "${NORMAL}RESULT:    ${CYN}a. $filename:${NORMAL}$yfile${NORMAL}"
         elif [[ $v6asrval == 0 ]]
         then
            echo -e "${NORMAL}RESULT:    ${CYN}a. $filename:${BLD}$yfile${NORMAL}"
            check1="pass"
         else
            echo -e "${NORMAL}RESULT:    ${CYN}a. $filename:${RED}$yfile${NORMAL}"
            check1="fail"
         fi
      done
   fi
done
      
net6cfg="$(sysctl -a 2>&1 | grep net.ipv6.conf.all.accept_source_route)"

if [[ $net6cfg ]]
then
   for line in ${net6cfg[@]}
   do
      val="$(echo $line | awk -F'= ' '{print $2}')"
      if [[ $val == 0 ]]
      then
         echo -e "${NORMAL}RESULT:    ${BLD}b. $line${NORMAL}"
         check2="pass"
      else
         echo -e "${NORMAL}RESULT:    ${RED}b. $line${NORMAL}"
         check2="fail"
      fi
   done
   if [[ $check1 == "pass" && $check2 == "pass" ]]
   then
      echo -e "${NORMAL}$hostname, $severity89, $controlid, $stigid89, $ruleid89, $cci89, $datetime, ${GRN}PASSED, The system does not forward IPv6 source-routed packets.${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity89, $controlid, $stigid89, $ruleid89, $cci89, $datetime, ${RED}FAILED, The system forwards IPv6 source-routed packets.${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity89, $controlid, $stigid89, $ruleid89, $cci89, $datetime, ${RED}FAILED, \"sysctl -a\" did not return 'net.ipv6.conf.all.accept_source_route'.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid90${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid90${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid90${NORMAL}"
echo -e "${NORMAL}CCI:       $cci90${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 90:   ${BLD}$title90a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title90b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title90c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity90${NORMAL}"

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

fail=1

isinstalled="$(rpm -qa | grep -i mcafeetp 2>/dev/null | grep mcafeetp)"
if [[ $isinstalled ]]
then
   for pkg in ${isinstalled[@]}
   do
      echo -e "${NORMAL}RESULT:    ${BLD}a. $pkg${NORMAL}"
      isrunning="$(ps -ef | grep -i mcafeetp | grep -v 'grep')"
      if [[ $isrunning ]]
      then
         echo -e "${NORMAL}RESULT:    ${BLD}b. $pkg${NORMAL}"
      else
         echo -e "${NORMAL}RESULT:    ${RED}b. Nothing returned${NORMAL}"
      fi
   done
else
   echo -e "${NORMAL}RESULT:    ${RED}a. Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
   echo -e "${NORMAL}$hostname, $severity90, $controlid, $stigid90, $ruleid90, $cci90, $datetime, ${GRN}PASSED, The system implements the Endpoint Security for Unix Threat Prevention tool.${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity90, $controlid, $stigid90, $ruleid90, $cci90, $datetime, ${RED}FAILED, The system does not implement the Endpoint Security for Unix Threat Prevention tool.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid91${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid91${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid91${NORMAL}"
echo -e "${NORMAL}CCI:       $cci91${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 91:   ${BLD}$title91a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title91b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title91c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity91${NORMAL}"

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

logdir91="/var/log/clamav"
isinstalled=""
installed=0
crontab=0
cronlog=0
fail=1

isinstalled="$(yum list installed clamav | grep clamav)"
if [[ $isinstalled ]]
then
   installed=1
   for line in ${isinstalled[@]}
   do
      echo -e "${NORMAL}RESULT:    ${BLD}a. $line${NORMAL}"
      crontab="$(crontab -l | grep clam)"
      if [[ $crontab ]]
      then
         cronjob=1
         for job in ${crontab[@]}
         do
            echo -e "${NORMAL}RESULT:    ${BLD}b. $job${NORMAL}"
         done
      else
         echo -e "${NORMAL}RESULT:    ${RED}b. No cron jobs found${NORMAL}"
      fi
      if [[ $cronjob == 1 ]]
      then
         clamlog="$(ls -al /var/log/clamav | grep clam)"
         if [[ $clamlog ]]
         then
            cronlog=1
            for log in ${clamlog[@]}
            do
               echo -e "${NORMAL}RESULT:    ${BLD}c. $log${NORMAL}"
            done
         else
            echo -e "${NORMAL}RESULT:    ${RED}c. No clamscan logs found in $logdir91${NORMAL}"
         fi
      fi
   done
else
   echo -e "${NORMAL}RESULT:    ${RED}a. A virus scan program was not found${NORMAL}"
fi

if [[ $installed == 1 && $cronjob == 1 && $cronlog == 1 ]]
then
   echo -e "${NORMAL}$hostname, $severity91, $controlid, $stigid91, $ruleid91, $cci91, $datetime, ${GRN}PASSED, The Red Hat Enterprise Linux operating system uses a virus scan program.${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity91, $controlid, $stigid91, $ruleid91, $cci91, $datetime, ${RED}PASSED, The Red Hat Enterprise Linux operating system does not use a virus scan program.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid92${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid92${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid92${NORMAL}"
echo -e "${NORMAL}CCI:       $cci92${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 92:   ${BLD}$title92a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title92b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title92c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity92${NORMAL}"

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

dir92="/etc/dconf"
run=0
open=0
mount=0
lockrun=0
lockopen=0
lockmount=0
fail=1

auto="$(egrep -ir '(automount|autorun)' $dir92*/* 2>/dev/null | grep -v '/org/gnome/desktop/media-handling' | grep -v 'Binary')"
lock="$(egrep -ir '(automount|autorun)' $dir92*/* 2>/dev/null | grep '/org/gnome/desktop/media-handling' | grep -v 'Binary')"

if [[ -d $dir92 ]]
then
   if [[ $auto ]]
   then
      for line in ${auto[@]}
      do
         file="$(echo $line | awk -F: '{print $1}')"
         val="$(echo $line | awk -F: '{print $2}')"
         if [[ $val == "autorun-never=true" ]]
         then
            echo -e "${NORMAL}RESULT:    ${CYN}a. $file:${BLD}$val${NORMAL}"
            run=1
         elif [[ $val == "automount-open=false" ]]
         then
            echo -e "${NORMAL}RESULT:    ${CYN}a. $file:${BLD}$val${NORMAL}"
            open=1
         elif [[ $val == "automount=false" ]]
         then
            echo -e "${NORMAL}RESULT:    ${CYN}a. $file:${BLD}$val${NORMAL}"
            mount=1
         else
            echo -e "${NORMAL}RESULT:    a. $line${NORMAL}"
         fi

      done
   else
      echo -e "${NORMAL}RESULT:    a. $line${NORMAL}"
   fi
   if [[ $lock ]]
   then
      for line in ${lock[@]}
      do
         file="$(echo $line | awk -F: '{print $1}')"
         val="$(echo $line | awk -F: '{print $2}')"
         if [[ $val =~ "autorun-never" ]]
         then
            echo -e "${NORMAL}RESULT:    ${CYN}b. $file:${BLD}$val${NORMAL}"
            lockrun=1
         elif [[ $val =~ "automount-open" ]]
         then
            echo -e "${NORMAL}RESULT:    ${CYN}b. $file:${BLD}$val${NORMAL}"
            lockopen=1
         elif [[ $val =~ "automount" ]]
         then
            echo -e "${NORMAL}RESULT:    ${CYN}b. $file:${BLD}$val${NORMAL}"
            lockmount=1
         else
            echo -e "${NORMAL}RESULT:    b. $line${NORMAL}"
         fi
      done
      if [[ $run == 1 && $open == 1 && $mount == 1 &&
            $lockrun == 1 && $lockopen == 1 && $lockmount == 1
         ]]
      then
        fail=0
      fi
   else
      echo -e "${NORMAL}RESULT:    ${RED}b. Nothing returned${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${RED}$dir92 not found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
   echo -e "${NORMAL}$hostname, $severity92, $controlid, $stigid92, $ruleid92, $cci92, $datetime, ${GRN}PASSED, The system disables the graphical user interface automounter.${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity92, $controlid, $stigid92, $ruleid92, $cci92, $datetime, ${GRN}PASSED, The system does not disable the graphical user interface automounter.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid93${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid93${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid93${NORMAL}"
echo -e "${NORMAL}CCI:       $cci93${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 93:   ${BLD}$title93a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title93b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title93c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity93${NORMAL}"

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

filesystem="$(df -hl | grep -v 'Filesystem')"
fail=0

for fs in ${filesystem[@]}
do
   part="$(echo $fs | awk '{print $6}')"
   worldwrite="$(find $part -type d -name '(mnt|pcap)' -prune -o -type d -perm -0002 -uid +999 2>/dev/null -print)"
   if [[ $worldwrite ]]
   then
      for line in ${worldwrite[@]}
      do
         echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
         fail=1
      done
   fi
done
if [[ $fail == 0 ]]
then
   echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity93, $controlid, $stigid93, $ruleid93, $cci93, $datetime, ${GRN}N/A, No world-writable directories owned by accounts other than root sys bin or an aplication user were found.${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity93, $controlid, $stigid93, $ruleid93, $cci93, $datetime, ${RED}FILED, The system is not configured so that all world-writable directories are owned by root sys bin or an application user.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid94${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid94${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid94${NORMAL}"
echo -e "${NORMAL}CCI:       $cci94${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 94:   ${BLD}$title94a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title94b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title94c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity94${NORMAL}"

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

file94="/etc/ssh/sshd_config"
fail=1

if [[ -f $file94 ]]
then
   ulh="$(grep -i x11uselocalhost $file94)"
   if [[ $ulh ]]
   then
      val="$(echo $ulh | awk '{print $2}')"
      if [[ $val == 'yes' && ${ulh:0:1} != '#' ]]
      then
         echo -e "${NORMAL}RESULT:    ${BLD}$ulh${NORMAL}"
         fail=0
      else
         echo -e "${NORMAL}RESULT:    ${RED}$ulh${NORMAL}"
      fi
   else
      echo -e "${NORMAL}RESULT:    ${RED}\"X11UseLocalhost\" is not defined in $file94${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${RED}$file94 not found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
   echo -e "${NORMAL}$hostname, $severity94, $controlid, $stigid94, $ruleid94, $cci94, $datetime, ${GRN}PASSED, The Red Hat Enterprise Linux operating system SSH daemon prevents remote hosts from connecting to the proxy display.${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity94, $controlid, $stigid94, $ruleid94, $cci94, $datetime, ${RED}FAILED, The Red Hat Enterprise Linux operating system SSH daemon does not prevent remote hosts from connecting to the proxy display.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid95${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid95${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid95${NORMAL}"
echo -e "${NORMAL}CCI:       $cci95${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 95:   ${BLD}$title95a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title95b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title95c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity95${NORMAL}"

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

file95arr=('/etc/sudoers' '/etc/sudoers.d/*')
all1=0
all2=0
fail=0

for file in ${file95arr[@]}
do
   if [[ -f $file ]]
   then
      all="$(grep -iw 'all' $file)"
      if [[ $all ]]
      then
         for line in ${all[@]}
         do
            if [[ ${line:0:3} == "ALL" ]]
            then
               IFS=' ' read -a perm <<< $line
               for el in ${perm[@]}
               do
                  if [[ $el == 'ALL=(ALL)' ]]
                  then
                     all2=1
                  elif [[ $el == 'ALL' ]]
                  then
                     all1=1
                  fi
               done
               if [[ $all1 == 1 && $all2 == 1 ]]
               then
                  echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
                  fail=1
               else
                  echo -e "${NORMAL}RESULT:    $line${NORMAL}"
               fi
            else
               echo -e "${NORMAL}RESULT:    $line${NORMAL}"
            fi
         done
      else
         echo -e "${NORMAL}RESULT:    Nothing returned${NORMAL}"
      fi
   else
      echo -e "${NORMAL}RESULT:    $file not found${NORMAL}"
   fi
done

if [[ $fail == 0 ]]
then
   echo -e "${NORMAL}$hostname, $severity95, $controlid, $stigid95, $ruleid95, $cci95, $datetime, ${GRN}PASSED, The Red Hat Enterprise Linux operating system restricts privilege elevation to authorized personnel.${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity95, $controlid, $stigid95, $ruleid95, $cci95, $datetime, ${RED}FAILED, The Red Hat Enterprise Linux operating system does not restrict privilege elevation to authorized personnel.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid96${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid96${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid96${NORMAL}"
echo -e "${NORMAL}CCI:       $cci96${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 96:   ${BLD}$title96a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title96b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title96c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity96${NORMAL}"

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

file96="/etc/shadow"
fail=0

nullpw="$(awk -F: '!$2 {print $1}' $file96)"

if [[ $nullpw ]]
then
   for line in ${nullpw[@]}
   do
      echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
      fail=1
   done
else
   echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"   
fi

if [[ $fail == 0 ]]
then
   echo -e "${NORMAL}$hostname, $severity96, $controlid, $stigid96, $ruleid96, $cci96, $datetime, ${GRN}PASSED, The Red Hat Enterprise Linux operating system does not have accounts configured with blank or null passwords.${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity96, $controlid, $stigid96, $ruleid96, $cci96, $datetime, ${RED}FAILED, The Red Hat Enterprise Linux operating system has accounts configured with blank or null passwords.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid97${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid97${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid97${NORMAL}"
echo -e "${NORMAL}CCI:       $cci97${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 97:   ${BLD}$title97a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title97b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title97c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity97${NORMAL}"

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

file97="/etc/sudoers"
fail=1

include="$(grep include $file97)"

if [[ $include ]]
then
   key="$(echo $include | awk '{print $1}')"
   val="$(echo $include | awk '{print $2}')"
   if [[ $key == '#includedir' && $val == '/etc/sudoers.d' ]]
   then
      echo -e "${NORMAL}RESULT:    ${BLD}$include${NORMAL}"
      fail=0
   else
      echo -e "${NORMAL}RESULT:    ${RED}$include${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${RED}\"include\" not defined in $file97${NORMAL}"
fi

if [[ $fail == 0 ]]
then
   echo -e "${NORMAL}$hostname, $severity97, $controlid, $stigid97, $ruleid97, $cci97, $datetime, ${GRN}PASSED, The Red Hat Enterprise Linux operating system specifies the default "include" directory for the /etc/sudoers file.${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity97, $controlid, $stigid97, $ruleid97, $cci97, $datetime, ${RED}FAILED, The Red Hat Enterprise Linux operating system does not specify the default "include" directory for the /etc/sudoers file.${NORMAL}"
fi

exit

