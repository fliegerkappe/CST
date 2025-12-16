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

echo "Child PID: $$"
echo "Parent PID: $PPID"

controlid="CM-6 Configuration Settings"

title1a="RHEL 9 must be a vendor-supported release."
title1b="Checking with 'cat /etc/redhat-release'."
title1c="Expecting:${YLO} Red Hat Enterprise Linux release 9.2 (Plow) (or newer)
           NOTE: If the release is not supported by the vendor, this is a finding."${BLD}
cci1="CCI-000366"
stigid1="RHEL-09-211010"
severity1="CAT I"
ruleid1="SV-257777r991589"
vulnid1="V-257777"

title2a="RHEL 9 vendor packaged system security patches and updates must be installed and up to date."
title2b="Checking with 'yum history list'."
title2c="Expecting: ${YLO}package updates are performed within program requirements.
           Note: If package updates have not been performed on the system within the timeframe the site/program documentation requires, this is a finding."${BLD}
cci2="CCI-000366"
stigid2="RHEL-09-211015"	
severity2="CAT II"
ruleid2="SV-257778r991589"
vulnid2="V-257778"

title3a="The graphical display manager must not be installed on RHEL 9 unless approved."
title3b="Checking with: 'systemctl get-default'"
title3c="Expecting: ${YLO}multi-user.target${BLD}
           NOTE: ${YLO}If the system default target is not set to \"multi-user.target\" and the Information System Security Officer (ISSO) lacks a documented requirement for a graphical user interface, this is a finding."${BLD}
cci3="CCI-000366"
stigid3="RHEL-09-211035"
severity3="CAT II"
ruleid3="SV-257781r991589"
vulnid3="V-257781"

title4a="RHEL 9 must enable the hardware random number generator entropy gatherer service."
title4b="Checking with: 
           a. uname -r (returns the kernel major.minor version)
           b. fips-mode-setup --check
           c. systemctl is-active rngd"
title4c="Expecting: ${YLO}
           a. 5.6 or higher
           b. FIPS mode is enabled.
           c. inactive
           NOTE: Note: For RHEL 9 systems running with kernel FIPS mode enabled as specified by RHEL-09-671010, this requirement is Not Applicable.
           NOTE: If the kernel is lower than version 5.6 and the \"rngd\" service is not active, this is a finding.
           NOTE: If the kernel is 5.6 or higher, the rng-tools package is no longer required. The rng-tools package is a set of utilities used in earlier kernel releases for PKI certificate generation. If the result of this test returns \"inactive\", you can check if random number creation works by performing a simple test with \"dd if=/dev/random of=/dev/null bs=1024 count=1 iflag=fullblock\". If random number generation is working, you should almost instantly see:
           1+0 records in
           1+0 records out
           1024 bytes (1.0 kB, 1.0 KiB) copied, 0.0199623 s, 51.3 kB/s (or something similar in speed)"${BLD}
cci4="CCI-000366"
stigid4="RHEL-09-211035"
severity4="CAT III"
ruleid4="SV-257782r991589"
vulnid4="V-257782"

title5a="RHEL 9 /boot/grub2/grub.cfg file must be group-owned by root."
title5b="Checking with: stat -c \"%G %n\" /boot/grub2/grub.cfg"
title5c="Expecting: ${YLO}root /boot/grub2/grub.cfg
           NOTE: If \"/boot/grub2/grub.cfg\" file does not have a group owner of \"root\", this is a finding."${BLD}
cci5="CCI-000366"
stigid5="RHEL-09-212025"
severity5="CAT II"
ruleid5="SV-257790r991589"
vulnid5="V-257790"

title6a="RHEL 9 /boot/grub2/grub.cfg file must be owned by root."
title6b="Checking with: stat -c \"%U %n\" /boot/grub2/grub.cfg"
title6c="Expecting: ${YLO}root /boot/grub2/grub.cfg
           NOTE: If \"/boot/grub2/grub.cfg\" file does not have an owner of \"root\", this is a finding."${BLD}
cci6="CCI-000366"
stigid6="RHEL-09-212030"
severity6="CAT II"
ruleid6="SV-257791r991589"
vulnid6="V-257791"

title7a="RHEL 9 must disable storing core dumps."
title7b="Checking with: grep -i storage /etc/systemd/coredump.conf"
title7c="Expecting: ${YLO}Storage=none
           NOTE: If the \"Storage\" item is missing, commented out, or the value is anything other than \"none\" and the need for core dumps is not documented with the information system security officer (ISSO) as an operational requirement for all domains that have the \"core\" item assigned, this is a finding."${BLD}
cci7="CCI-000366"
stigid7="RHEL-09-213090"
severity7="CAT II"
ruleid7="SV-257813r991589"
vulnid7="V-257813"

title8a="RHEL 9 must disable core dumps for all users."
title8b="Checking with: grep -r -s core /etc/security/limits.conf /etc/security/limits.d/*.conf"
title8c="Expecting: ${YLO}/etc/security/limits.conf:* hard core 0
           NOTE: This can be set as a global domain (with the * wildcard) but may be set differently for multiple domains.
           NOTE: If the \"core\" item is missing, commented out, or the value is anything other than \"0\" and the need for core dumps is not documented with the information system security officer (ISSO) as an operational requirement for all domains that have the \"core\" item assigned, this is a finding."${BLD}
cci8="CCI-000366"
stigid8="RHEL-09-213095"
severity8="CAT II"
ruleid8="SV-257814r991589"
vulnid8="V-257814"

title9a="RHEL 9 must disable acquiring, saving, and processing core dumps."
title9b="Checking with: systemctl status systemd-coredump.socket"
title9c="Expecting: ${YLO}
           systemd-coredump.socket
           Loaded: masked (Reason: Unit systemd-coredump.socket is masked.)
           Active: inactive (dead)
           NOTE: If the \"systemd-coredump.socket\" is loaded and not masked and the need for core dumps is not documented with the information system security officer (ISSO) as an operational requirement, this is a finding."${BLD}
cci9="CCI-000366"
stigid9="RHEL-09-213100"
severity9="CAT II"
ruleid9="SV-257815r991589"
vulnid9="V-257815"

title10a="RHEL 9 must have the gnutls-utils package installed."
title10b="Checking with: dnf list --installed gnutls-utils"
title10c="Expecting: ${YLO}gnutls-utils.x86_64          3.7.3-9.el9
           NOTE: If the \"gnutls-utils\" package is not installed, this is a finding."${BLD}
cci10="CCI-000366"
stigid10="RHEL-09-215080"
severity10="CAT II"
ruleid10="SV-257839r991589"
vulnid10="V-257839"

title11a="RHEL 9 must have the nss-tools package installed."
title11b="Checking with: dnf list --installed nss-tools"
title11c="Expecting: ${YLO}nss-tools.x86_64          3.71.0-7.el9
           NOTE: If the \"nss-tools\" package is not installed, this is a finding."${BLD}
cci11="CCI-000366"
stigid11="RHEL-09-215085"
severity11="CAT II"
ruleid11="SV-257840r991589"
vulnid11="V-257840"

title12a="A separate RHEL 9 file system must be used for user home directories (such as /home or an equivalent)."
title12b="Checking with: mount | grep /home"
title12c="Expecting: ${YLO}
           UUID=fba5000f-2ffa-4417-90eb-8c54ae74a32f on /home type ext4 (rw,nodev,nosuid,noexec,seclabel)
           NOTE: If a separate entry for \"/home\" is not in use, this is a finding."${BLD}
cci12="CCI-000366"
stigid12="RHEL-09-231010"
severity12="CAT II"
ruleid12="SV-257843r991589"
vulnid12="V-257843"

title13a="RHEL 9 must prevent code from being executed on file systems that contain user home directories."
title13b="Checking with: mount | grep /home"
title13c="Expecting: ${YLO}tmpfs on /home type xfs (rw,nodev,nosuid,noexec,seclabel)
           NOTE: If a separate file system has not been created for the user home directories (user home directories are mounted under \"/\"), this is automatically a finding, as the \"noexec\" option cannot be used on the "/" system.
           NOTE: If the \"/home\" file system is mounted without the \"noexec\" option, this is a finding."${BLD}
cci13="CCI-000366"
stigid13="RHEL-09-231055"
severity13="CAT II"
ruleid13="SV-257852r991589"
vulnid13="V-257852"

title14a="RHEL 9 must prevent code from being executed on file systems that are used with removable media."
title14b="Checking with: more /etc/fstab"
title14c="Expecting: ${YLO}
           UUID=2bc871e4-e2a3-4f29-9ece-3be60c835222 /mnt/usbflash vfat noauto,owner,ro,nosuid,nodev,${BLD}noexec${YLO} 0 0
           NOTE: If a file system found in \"/etc/fstab\" refers to removable media and it does not have the \"noexec\" option set, this is a finding."${BLD}
cci14="CCI-000366"
stigid14="RHEL-09-231080"
severity14="CAT II"
ruleid14="SV-257857r991589"
vulnid14="V-257857"

title15a="RHEL 9 must prevent special devices on file systems that are used with removable media."
title15b="Checking with: more /etc/fstab"
title15c="Expecting: ${YLO}
           UUID=2bc871e4-e2a3-4f29-9ece-3be60c835222 /mnt/usbflash vfat noauto,owner,ro,nosuid,${BLD}nodev${YLO},noexec 0 0
           NOTE: If a file system found in \"/etc/fstab\" refers to removable media and it does not have the \"nodev\" option set, this is a finding."${BLD}
cci15="CCI-000366"
stigid15="RHEL-09-231085"
severity15="CAT II"
ruleid15="SV-257858r991589"
vulnid15="V-257858"

title16a="RHEL 9 must prevent files with the setuid and setgid bit set from being executed on file systems that are used with removable media."
title16b="Checking with: more /etc/fstab"
title16c="Expecting: ${YLO}
           UUID=2bc871e4-e2a3-4f29-9ece-3be60c835222 /mnt/usbflash vfat noauto,owner,ro,${BLD}nosuid${YLO},nodev,noexec 0 0
           NOTE: If a file system found in \"/etc/fstab\" refers to removable media and it does not have the \"nosuid\" option set, this is a finding."${BLD}
cci16="CCI-000366"
stigid16="RHEL-09-231090"
severity16="CAT II"
ruleid16="SV-257859r991589"
vulnid16="V-257859"

title17a="RHEL 9 must prevent special devices on non-root local partitions."
title17b="checking with: mount | grep '^/dev\S* on /\S' | grep --invert-match 'nodev'"
title17c="Expecting: ${YLO}Nothing returned
           NOTE: If any output is produced, this is a finding."${BLD}
cci17="CCI-000366"
stigid17="RHEL-09-231200"
severity17="CAT II"
ruleid17="SV-257881r991589"
vulnid17="V-257881"

title18a="RHEL 9 /etc/group file must have mode 0644 or less permissive to prevent unauthorized access."
title18b="Checking with: stat -c \"%a %n\" /etc/group"
title18c="Expecting: ${YLO}644 /etc/group
           NOTE: If a value of "0644" or less permissive is not returned, this is a finding."${BLD}
cci18="CCI-000366"
stigid18="RHEL-09-232055"
severity18="CAT II"
ruleid18="SV-257891r991589"
vulnid18="V-257891"

title19a="RHEL 9 /etc/group- file must have mode 0644 or less permissive to prevent unauthorized access."
title19b="Checking with: stat -c \"%a %n\" /etc/group-"
title19c="Expecting: ${YLO}644 /etc/group-
           NOTE: If a value of "0644" or less permissive is not returned, this is a finding."${BLD}
cci19="CCI-000366"
stigid19="RHEL-09-232060"
severity19="CAT II"
ruleid19="SV-257892r991589"
vulnid19="V-257892"

title20a="RHEL 9 /etc/gshadow file must have mode 0000 or less permissive to prevent unauthorized access."
title20b="Checking with: stat -c \"%a %n\" /etc/gshadow"
title20c="Expecting: ${YLO}0 /etc/gshadow
           NOTE: If a value of "0" is not returned, this is a finding."${BLD}
cci20="CCI-000366"
stigid20="RHEL-09-232065"
severity20="CAT II"
ruleid20="SV-257893r991589"
vulnid20="V-257893"

title21a="RHEL 9 /etc/gshadow- file must have mode 0000 or less permissive to prevent unauthorized access."
title21b="Checking with: stat -c \"%a %n\" /etc/gshadow-"
title21c="Expecting: ${YLO}0 /etc/gshadow-
           NOTE: If a value of "0" is not returned, this is a finding."${BLD}
cci21="CCI-000366"
stigid21="RHEL-09-232070"
severity21="CAT II"
ruleid21="SV-257894r991589"
vulnid21="V-257894"

title22a="RHEL 9 /etc/passwd file must have mode 0644 or less permissive to prevent unauthorized access."
title22b="Checking with: stat -c \"%a %n\" /etc/passwd"
title22c="Expecting: ${YLO}644 /etc/passwd
           NOTE: If a value of "0644" or less permissive is not returned, this is a finding."${BLD}
cci22="CCI-000366"
stigid22="RHEL-09-232075"
severity22="CAT II"
ruleid22="SV-257895r991589"
vulnid22="V-257895"

title23a="RHEL 9 /etc/passwd- file must have mode 0644 or less permissive to prevent unauthorized access."
title23b="Checking with: stat -c \"%a %n\" /etc/passwd-"
title23c="Expecting: ${YLO}644 /etc/passwd-
           NOTE: If a value of "0644" or less permissive is not returned, this is a finding."${BLD}
cci23="CCI-000366"
stigid23="RHEL-09-232080"
severity23="CAT II"
ruleid23="SV-257896r991589"
vulnid23="V-257896"

title24a="RHEL 9 /etc/shadow- file must have mode 0000 or less permissive to prevent unauthorized access."
title24b="Checking with: stat -c \"%a %n\" /etc/shadow-"
title24c="Expecting: ${YLO}0 /etc/shadow-
           NOTE: If a value of "0" is not returned, this is a finding."${BLD}
cci24="CCI-000366"
stigid24="RHEL-09-232085"
severity24="CAT II"
ruleid24="SV-257897r991589"
vulnid24="V-257897"

title25a="RHEL 9 /etc/group file must be owned by root."
title25b="Checking with: stat -c \"%U %n\" /etc/group"
title25c="Expecting: ${YLO}root /etc/group
           NOTE: If \"/etc/group\" file does not have an owner of \"root\", this is a finding."${BLD}
cci25="CCI-000366"
stigid25="RHEL-09-232090"
severity25="CAT II"
ruleid25="SV-257898r991589"
vulnid25="V-257898"

title26a="RHEL 9 /etc/group file must be group-owned by root."
title26b="Checking with: stat -c \"%G %n\" /etc/group"
title26c="Expecting: ${YLO}root /etc/group
           NOTE: If \"/etc/group\" file does not have a group owner of \"root\", this is a finding."${BLD}
cci26="CCI-000366"
stigid26="RHEL-09-232095"
severity26="CAT II"
ruleid26="SV-257899r991589"
vulnid26="V-257899"

title27a="RHEL 9 /etc/group- file must be owned by root."
title27b="Checking with: stat -c \"%U %n\" /etc/group-"
title27c="Expecting: ${YLO}root /etc/group-
           NOTE: If \"/etc/group-\" file does not have an owner of \"root\", this is a finding."${BLD}
cci27="CCI-000366"
stigid27="RHEL-09-232100"
severity27="CAT II"
ruleid27="SV-257900r991589"
vulnid27="V-257900"

title28a="RHEL 9 /etc/group- file must be group-owned by root."
title28b="Checking with: stat -c \"%G %n\" /etc/group-"
title28c="Expecting: ${YLO}root /etc/group-
           NOTE: If \"/etc/group-\" file does not have a group owner of \"root\", this is a finding."${BLD}
cci28="CCI-000366"
stigid28="RHEL-09-232105"
severity28="CAT II"
ruleid28="SV-257901r991589"
vulnid28="V-257901"

title29a="RHEL 9 /etc/gshadow file must be owned by root."
title29b="Checking with: stat -c \"%U %n\" /etc/gshadow"
title29c="Expecting: ${YLO}root /etc/gshadow
           NOTE: If \"/etc/gshadow\" file does not have an owner of \"root\", this is a finding."${BLD}
cci29="CCI-000366"
stigid29="RHEL-09-232110"
severity29="CAT II"
ruleid29="SV-257902r991589"
vulnid29="V-257902"

title30a="RHEL 9 /etc/gshadow file must be group-owned by root."
title30b="Checking with: stat -c \"%G %n\" /etc/gshadow"
title30c="Expecting: ${YLO}root /etc/gshadow
           NOTE: If \"/etc/gshadow\" file does not have a group owner of \"root\", this is a finding."${BLD}
cci30="CCI-000366"
stigid30="RHEL-09-232115"
severity30="CAT II"
ruleid30="SV-257903r991589"
vulnid30="V-257903"

title31a="RHEL 9 /etc/gshadow- file must be owned by root."
title31b="Checking with: stat -c \"%U %n\" /etc/gshadow-"
title31c="Expecting: ${YLO}root /etc/gshadow-
           NOTE: If \"/etc/gshadow-\" file does not have an owner of \"root\", this is a finding."${BLD}
cci31="CCI-000366"
stigid31="RHEL-09-232120"
severity31="CAT II"
ruleid31="SV-257904r991589"
vulnid31="V-257904"

title32a="RHEL 9 /etc/gshadow- file must be group-owned by root."
title32b="Checking with: stat -c \"%G %n\" /etc/gshadow-"
title32c="Expecting: ${YLO}root /etc/gshadow
           NOTE: If \"/etc/gshadow-\" file does not have a group owner of \"root\", this is a finding."${BLD}
cci32="CCI-000366"
stigid32="RHEL-09-232125"
severity32="CAT II"
ruleid32="SV-257905r991589"
vulnid32="V-257905"

title33a="RHEL 9 /etc/passwd file must be owned by root."
title33b="Checking with: stat -c \"%U %n\" /etc/passwd"
title33c="Expecting: ${YLO}root /etc/passwd
           NOTE: If \"/etc/passwd\" file does not have an owner of \"root\", this is a finding."${BLD}
cci33="CCI-000366"
stigid33="RHEL-09-232130"
severity33="CAT II"
ruleid33="SV-257906r991589"
vulnid33="V-257906"

title34a="RHEL 9 /etc/passwd file must be group-owned by root."
title34b="Checking with: stat -c \"%G %n\" /etc/passwd"
title34c="Expecting: ${YLO}root /etc/passwd
           NOTE: If \"/etc/passwd\" file does not have a group owner of \"root\", this is a finding."${BLD}
cci34="CCI-000366"
stigid34="RHEL-09-232135"
severity34="CAT II"
ruleid34="SV-257907r991589"
vulnid34="V-257907"

title35a="RHEL 9 /etc/passwd- file must be owned by root."
title35b="Checking with: stat -c \"%U %n\" /etc/passwd-"
title35c="Expecting: ${YLO}root /etc/passwd-
           NOTE: If \"/etc/passwd-\" file does not have an owner of \"root\", this is a finding."${BLD}
cci35="CCI-000366"
stigid35="RHEL-09-232140"
severity35="CAT II"
ruleid35="SV-257908r991589"
vulnid35="V-257908"

title36a="RHEL 9 /etc/passwd- file must be group-owned by root."
title36b="Checking with: stat -c \"%G %n\" /etc/passwd-"
title36c="Expecting: ${YLO}root /etc/passwd-
           NOTE: If \"/etc/passwd-\" file does not have a group owner of \"root\", this is a finding."${BLD}
cci36="CCI-000366"
stigid36="RHEL-09-232145"
severity36="CAT II"
ruleid36="SV-257909r991589"
vulnid36="V-257909"

title37a="RHEL 9 /etc/shadow file must be owned by root."
title37b="Checking with: stat -c \"%U %n\" /etc/shadow"
title37c="Expecting: ${YLO}root /etc/shadow
           NOTE: If \"/etc/shadow\" file does not have an owner of \"root\", this is a finding."${BLD}
cci37="CCI-000366"
stigid37="RHEL-09-232150"
severity37="CAT II"
ruleid37="SV-257910r991589"
vulnid37="V-257910"

title38a="RHEL 9 /etc/shadow file must be group-owned by root."
title38b="Checking with: stat -c \"%G %n\" /etc/shadow"
title38c="Expecting: ${YLO}root /etc/shadow
           NOTE: If \"/etc/shadow\" file does not have a group owner of \"root\", this is a finding."${BLD}
cci38="CCI-000366"
stigid38="RHEL-09-232155"
severity38="CAT II"
ruleid38="SV-257911r991589"
vulnid38="V-257911"

title39a="RHEL 9 /etc/shadow- file must be owned by root."
title39b="Checking with: stat -c \"%U %n\" /etc/shadow-"
title39c="Expecting: ${YLO}root /etc/shadow-
           NOTE: If \"/etc/shadow-\" file does not have an owner of \"root\", this is a finding."${BLD}
cci39="CCI-000366"
stigid39="RHEL-09-232160"
severity39="CAT II"
ruleid39="SV-257912r991589"
vulnid39="V-257912"

title40a="RHEL 9 /etc/shadow- file must be group-owned by root."
title40b="Checking with: stat -c \"%G %n\" /etc/shadow-"
title40c="Expecting: ${YLO}root /etc/shadow-
           NOTE: If \"/etc/shadow-\" file does not have a group owner of \"root\", this is a finding."${BLD}
cci40="CCI-000366"
stigid40="RHEL-09-232165"
severity40="CAT II"
ruleid40="SV-257913r991589"
vulnid40="V-257913"

title41a="RHEL 9 cron configuration files directory must be owned by root."
title41b="Checking with: stat -c \"%U %n\" /etc/cron*"
title41c="Expecting: ${YLO}
           root /etc/cron.d
           root /etc/cron.daily
           root /etc/cron.deny
           root /etc/cron.hourly
           root /etc/cron.monthly
           root /etc/crontab
           root /etc/cron.weekly
           NOTE: If any crontab is not owned by root, this is a finding."${BLD}
cci41="CCI-000366"
stigid41="RHEL-09-232230"
severity41="CAT II"
ruleid41="SV-257926r991589"
vulnid41="V-257926"

title42a="RHEL 9 cron configuration files directory must be group-owned by root."
title42b="Checking with: stat -c \"%G %n\" /etc/cron*"
title42c="Expecting: ${YLO}
           root /etc/cron.d
           root /etc/cron.daily
           root /etc/cron.deny
           root /etc/cron.hourly
           root /etc/cron.monthly
           root /etc/crontab
           root /etc/cron.weekly
           NOTE: If any crontab is not owned by root, this is a finding."${BLD}
cci42="CCI-000366"
stigid42="RHEL-09-232235"
severity42="CAT II"
ruleid42="SV-257927r991589"
vulnid42="V-257927"

title43a="All RHEL 9 local files and directories must have a valid group owner."
title43b="Checking with:
           df --local -P | awk {'if (NR!=1) print \$6'} | xargs -I '{}' find '{}' -xdev -nogroup"
title43c="Expecting: ${YLO}Nothing returned
           NOTE: If any files on the system do not have an assigned group, this is a finding."${BLD}
cci43="CCI-000366"
stigid43="RHEL-09-232250"
severity43="CAT II"
ruleid43="SV-257930r991589"
vulnid43="V-257930"

title44a="All RHEL 9 local files and directories must have a valid owner."
title44b="Checking with:
           df --local -P | awk {'if (NR!=1) print \$6'} | xargs -I '{}' find '{}' -xdev -nouser"
title44c="Expecting: ${YLO}Nothing returned
           NOTE: If any files on the system do not have an assigned owner, this is a finding."${BLD}
cci44="CCI-000366"
stigid44="RHEL-09-232255"
severity44="CAT II"
ruleid44="SV-257931r991589"
vulnid44="V-257931"

title45a="RHEL 9 /etc/shadow file must have mode 0000 to prevent unauthorized access."
title45b="Checking with: stat -c \"%a %n\" /etc/shadow"
title45c="Expecting: ${YLO}0 /etc/shadow
           NOTE: If a value of "0" is not returned, this is a finding."${BLD}
cci45="CCI-000366"
stigid45="RHEL-09-232270"
severity45="CAT II"
ruleid45="SV-257934r991589"
vulnid45="V-257934"

title46a="RHEL 9 network interfaces must not be in promiscuous mode."
title46b="Checking with: ip link | grep -i promisc"
title46c="Expecting: ${YLO}Nothing returned
           NOTE: If network interfaces are found on the system in promiscuous mode and their use has not been approved by the ISSO and documented, this is a finding."${BLD}
cci46="CCI-000366"
stigid46="RHEL-09-251040"
severity46="CAT II"
ruleid46="SV-257941r991589"
vulnid46="V-257941"

title47a="There must be no shosts.equiv files on RHEL 9."
title47b="Checking with: find / -name shosts.equiv"
title47c="Expecting: ${YLO}Nothing returned
           NOTE: If a \"shosts.equiv\" file is found, this is a finding."${BLD}
cci47="CCI-000366"
stigid47="RHEL-09-252070"
severity47="CAT I"
ruleid47="SV-257955r991589"
vulnid47="V-257955"

title48a="There must be no .shosts files on RHEL 9."
title48b="Checking with: find / -name .shosts"
title48c="Expecting: ${YLO}Nothing returned
           NOTE: If a \"shosts.equiv\" file is found, this is a finding."${BLD}
cci48="CCI-000366"
stigid48="RHEL-09-252075"
severity48="CAT I"
ruleid48="SV-257956r991589"
vulnid48="V-257956"

title49a="RHEL 9 must not allow interfaces to perform Internet Control Message Protocol (ICMP) redirects by default."
title49b="Checking with: 
           a. sysctl net.ipv4.conf.default.send_redirects
	   b. /usr/lib/systemd/systemd-sysctl --cat-config | egrep -v '^(#|;)' | grep -F net.ipv4.conf.default.send_redirects | tail -1"
title49c="Expectin: ${YLO}
           a. net.ipv4.conf.default.send_redirects=0
           b. net.ipv4.conf.default.send_redirects = 0
           NOTE a: If the returned line does not have a value of \"0\", or a line is not returned, this is a finding.
           NOTE b: If \"net.ipv4.conf.default.send_redirects\" is not set to \"0\" and is not documented with the information system security officer (ISSO) as an operational requirement or is missing, this is a finding."${BLD}
cci49="CCI-000366"
stigid49="RHEL-09-253070"
severity49="CAT II"
ruleid49="SV-257969r991589"
vulnid49="V-257969"

title50a="RHEL 9 SSH public host key files must have mode 0644 or less permissive."
title50b="Checking with: stat -c \"%a %n\" /etc/ssh/*.pub"
title50c="Expecting: ${YLO}
           644 /etc/ssh/ssh_host_dsa_key.pub
           644 /etc/ssh/ssh_host_ecdsa_key.pub
           644 /etc/ssh/ssh_host_ed25519_key.pub
           644 /etc/ssh/ssh_host_rsa_key.pub
           NOTE: If any key.pub file has a mode more permissive than "0644", this is a finding."${BLD}
cci50="CCI-000366"
stigid50="RHEL-09-255125"
severity50="CAT II"
ruleid50="SV-258001r991589"
vulnid50="V-258001"

title51a="RHEL 9 SSH daemon must not allow compression or must only allow compression after successful authentication."
title51b="Checking with:/usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print \$4}' | tr -d '\\\\r' | tr '\\\\n' ' ' | xargs grep -iH '^\s*compression'"
title51c="Expecting: ${YLO}Compression delayed
           NOTE: If the \"Compression\" keyword is set to \"yes\", is missing, or the returned line is commented out, this is a finding."${BLD}
cci51="CCI-000366"
stigid51="RHEL-09-255130"
severity51="CAT II"
ruleid51="SV-258002r991589"
vulnid51="V-258002"

title52a="RHEL 9 effective dconf policy must match the policy keyfiles."
title52b="Checking with: 

function dconf_needs_update { for db in \$(find /etc/dconf/db -maxdepth 1 -type f); do db_mtime=\$(stat -c %Y \"\$db\"); keyfile_mtime=\$(stat -c %Y \"\$db\".d/* | sort -n | tail -1); if [ -n \"\$db_mtime\" ] && [ -n \"\$keyfile_mtime\" ] && [ \"\$db_mtime\" -lt \"\$keyfile_mtime\" ]; then echo \"\$db needs update\"; return 1; fi; done; }; dconf_needs_update
"
title52c="Expecting: ${YLO}Nothing returned
           NOTE: If the command has any output, then a dconf database needs to be updated, and this is a finding.
           NOTE: This requirement assumes the use of the RHEL 9 default graphical user interface, the GNOME desktop environment. If the system does not have any graphical user interface installed, this requirement is Not Applicable."${BLD}
cci52="CCI-000366"
stigid52="RHEL-09-271090"
severity52="CAT II"
ruleid52="SV-258028r991589"
vulnid52="V-258028"

title53a="All RHEL 9 local interactive user accounts must be assigned a home directory upon creation."
title53b="Checking with: grep -i create_home /etc/login.defs"
title53c="Expecting: ${YLO}CREATE_HOME yes
           NOTE: If the value for \"CREATE_HOME\" parameter is not set to \"yes\", the line is missing, or the line is commented out, this is a finding."${BLD}
cci53="CCI-000366"
stigid53="RHEL-09-411020"
severity53="CAT II"
ruleid53="SV-258043r991589"
vulnid53="V-258043"

title54a="RHEL 9 system accounts must not have an interactive login shell."
title54b="Checking with: awk -F: '(\$3<1000){print \$1 \":\" \$3 \":\" \$7}' /etc/passwd"
title54c="Expecting: ${YLO}
           root:0:/bin/bash
           bin:1:/sbin/nologin
           daemon:2:/sbin/nologin
           adm:3:/sbin/nologin
           lp:4:/sbin/nologin
           NOTE: If any system account (other than the root account) has a login shell and it is not documented with the information system security officer (ISSO), this is a finding."${BLD}
cci54="CCI-000366"
stigid54="RHEL-09-411035"
severity54="CAT II"
ruleid54="SV-258046r991589"
vulnid54="V-258046"

title55a="All RHEL 9 local interactive users must have a home directory assigned in the /etc/passwd file."
title55b="Checking with: awk -F: '(\$3>=1000)&&(\$7 !~ /nologin/){print \$1, \$3, \$6}' /etc/passwd"
title55c="Expecting: ${YLO}
           smithk 1000 /home/smithk
           scsaustin 1001 /home/scsaustin
           djohnson 1002 /home/djohnson
           NOTE: If users home directory is not defined, this is a finding."${BLD}
cci55="CCI-000366"
stigid55="RHEL-09-411060"
severity55="CAT II"
ruleid55="SV-258051r991589"
vulnid55="V-258051"

title56a="All RHEL 9 local interactive user home directories defined in the /etc/passwd file must exist."
title56b="Checking with: pwck -r"
title56c="Expecting: ${YLO}No interactive user accounts returned.
           NOTE: The output should not return any interactive users. If users home directory does not exist, this is a finding."${BLD}
cci56="CCI-000366"
stigid56="RHEL-09-411065"
severity56="CAT II"
ruleid56="SV-258052r991589"
vulnid56="V-258052"

title57a="All RHEL 9 local interactive user home directories must be group-owned by the home directory owner's primary group."
title57b="Checking with: 
           a. ls -ld \$(awk -F: '(\$3>=1000)&&(\$7 !~ /nologin/){print \$6}' /etc/passwd)
           b. grep \$(grep <user> /etc/passwd | awk -F: '{print \$4}') /etc/group"
title57c="Expecting: ${YLO}(example)
           a. drwxr-x--- 2 wadea admin 4096 Jun 5 12:41 wadea
           b. uid=1000(wadea) gid=1000(wadea) groups=1000(wadea)
           NOTE: If the user home directory referenced in \"/etc/passwd\" is not group-owned by that user's primary GID, this is a finding."${BLD}
cci57="CCI-000366"
stigid57="RHEL-09-411070"
severity57="CAT II"
ruleid57="SV-258053r991589"
vulnid57="V-258053"

title58a="The root account must be the only account having unrestricted access to RHEL 9 system."
title58b="Checking with: awk -F: '\$3 == 0 {print \$1}' /etc/passwd"
title58c="Expecting: ${YLO}root
           NOTE: If any accounts other than \"root\" have a UID of \"0\", this is a finding."${BLD}
cci58="CCI-000366"
stigid58="RHEL-09-411100"
severity58="CAT I"
ruleid58="SV-258059r991589"
vulnid58="V-258059"

title59a="Local RHEL 9 initialization files must not execute world-writable programs."
title59b="Checking with: find /home -perm -002 -type f -name \".[^.]*\" -exec ls -ld {} \;"
title59c="Expecting: ${YLO}Nothing returned
           NOTE: If any local initialization files are found to reference world-writable files, this is a finding."${BLD}
cci59="CCI-000366"
stigid59="RHEL-09-411115"
severity59="CAT II"
ruleid59="SV-258062r991589"
vulnid59="V-258062"

title60a="RHEL 9 must enforce a delay of at least four seconds between logon prompts following a failed logon attempt."
title60b="Checking with: grep -i fail_delay /etc/login.defs"
title60c="Expecting: ${YLO}FAIL_DELAY 4
           NOTE: If the value of \"FAIL_DELAY\" is not set to \"4\" or greater, or the line is commented out, this is a finding."${BLD}
cci60="CCI-000366"
stigid60="RHEL-09-412050"
severity60="CAT II"
ruleid60="SV-258071r991588"
vulnid60="V-258071"

title61a="RHEL 9 must define default permissions for all authenticated users in such a way that the user can only read and modify their own files."
title61b="Checking with: grep -i umask /etc/login.defs"
title61c="Expecting: ${YLO}UMASK 077
           NOTE: If the value for the \"UMASK\" parameter is not \"077\", or the \"UMASK\" parameter is missing or is commented out, this is a finding."${BLD}
cci61="CCI-000366"
stigid61="RHEL-09-412065"
severity61="CAT II"
ruleid61="SV-258074r991590"
vulnid61="V-258074"

title62a="RHEL 9 must define default permissions for the system default profile."
title62b="Checking with: grep umask /etc/profile"
title62c="Expecting: ${YLO}umask 077
           NOTE: If the value for the \"umask\" parameter is not \"077\", or the \"umask\" parameter is missing or is commented out, this is a finding."${BLD}
cci62="CCI-000366"
stigid62="RHEL-09-412070"
severity62="CAT II"
ruleid62="SV-258075r991590"
vulnid62="V-258075"

title63a="RHEL 9 must display the date and time of the last successful account logon upon logon."
title63b="Checking with: grep pam_lastlog /etc/pam.d/postlogin"
title63c="Expecting: ${YLO}session required pam_lastlog.so showfailed
           NOTE: If \"pam_lastlog\" is missing from \"/etc/pam.d/postlogin\" file, or the silent option is present, this is a finding."${BLD}
cci63="CCI-000366"
stigid63="RHEL-09-412075"
severity63="CAT III"
ruleid63="SV-258076r991589"
vulnid63="V-258076"

title64a="RHEL 9 must not have accounts configured with blank or null passwords."
title64b="Checking with: awk -F: '!\$2 {print \$1}' /etc/shadow"
title64c="Expecting: ${YLO}Nothing returned
           NOTE: If the command returns any results, this is a finding."${BLD}
cci64="CCI-000366"
stigid64="RHEL-09-611155"
severity64="CAT II"
ruleid64="SV-258120r991589"
vulnid64="V-258120"

title65a="The rsyslog service on RHEL 9 must be active."
title65b="Checking with: systemctl is-active rsyslog"
title65c="Expecting: ${YLO}active
           NOTE: If the rsyslog service is not active, this is a finding."${BLD}
cci65="CCI-000366"
stigid65="RHEL-09-652020"
severity65="CAT II"
ruleid65="SV-258142r991589"
vulnid65="V-258142"

title66a="RHEL 9 must produce audit records containing information to establish the identity of any individual or process associated with the event."
title66b="Checking with: grep log_format /etc/audit/auditd.conf"
title66c="Expecting: ${YLO}log_format = ENRICHED
           NOTE: If the \"log_format\" option is not \"ENRICHED\", or the line is commented out, this is a finding."${BLD}
cci66="CCI-000366 CCI-001487"
stigid66="RHEL-09-653100"
severity66="CAT II"
ruleid66="SV-258169r991556"
vulnid66="V-258169"

title67a="RHEL 9 must write audit records to disk."
title67b="Checking with: grep write_logs /etc/audit/auditd.con"
title67c="Expecting: ${YLO}write_logs = yes
           NOTE: If \"write_logs\" does not have a value of \"yes\", the line is commented out, or the line is missing, this is a finding."${BLD}
cci67="CCI-000366"
stigid67="RHEL-09-653105"
severity67="CAT II"
ruleid67="SV-258170r991589"
vulnid67="V-258170"

title68a="RHEL 9 must disable the ability of systemd to spawn an interactive boot process."
title68b="Checking with: grubby --info=ALL | grep args | grep 'systemd.confirm_spawn'"
title68c="Expecting: ${YLO}Nothing returned
           NOTE: If any output is returned, this is a finding."${BLD}
cci68="CCI-000366"
stigid68="RHEL-09-212015"
severity68="CAT II"
ruleid68="SV-257788r1044838"
vulnid68="V-257788"

title69a="RHEL 9 must disable the kernel.core_pattern."
title69b="Checking with: sysctl kernel.core_pattern"
title69c="Expecting: ${YLO}kernel.core_pattern = |/bin/false
           NOTE: If the returned line does not have a value of \"|/bin/false\", or a line is not returned and the need for core dumps is not documented with the information system security officer (ISSO) as an operational requirement, this is a finding."${BLD}
cci69="CCI-000366"
stigid69="RHEL-09-213040"
severity69="CAT II"
ruleid69="SV-257803r1106429"
vulnid69="V-257803"

title70a="RHEL 9 must disable core dump backtraces."
title70b="Checking with: grep -i ProcessSizeMax /etc/systemd/coredump.conf"
title70c="Expecting: ${YLO}ProcessSizeMax=0
           NOTE: If the \"ProcessSizeMax\" item is missing or commented out, or the value is anything other than \"0\", and the need for core dumps is not documented with the information system security officer (ISSO) as an operational requirement for all domains that have the \"core\" item assigned, this is a finding."${BLD}
cci70="CCI-000366"
stigid70="RHEL-09-213085"
severity70="CAT II"
ruleid70="SV-257812r1051005"
vulnid70="V-257812"

title71a="RHEL 9 must disable the use of user namespaces."
title71b="Checking with: sysctl user.max_user_namespaces"
title71c="Expecting: ${YLO}user.max_user_namespaces = 0
           NOTE: If the returned line does not have a value of \"0\", or a line is not returned, this is a finding."${BLD}
cci71="CCI-000366"
stigid71="RHEL-09-213105"
severity71="CAT II"
ruleid71="SV-257816r1106435"
vulnid71="V-257816"

title72a="The kdump service on RHEL 9 must be disabled."
title72b="Checking with:
           a. systemctl is-enabled  kdump
           b. systemctl show  kdump  | grep \"LoadState\|UnitFileState\""
title72c="Expecting: ${YLO}
           a. disabled
           b. LoadState=masked
           b. UnitFileState=masked
           NOTE: If the \"kdump\" service is loaded or active, and is not masked, this is a finding.
           NOTE: If the \"kdump\" service is \"inactive\" and the \"LoadState\" and \"UnitFileState\" are \"masked\", this is not a finding. Attempting to enable the kdump.service will result in \"Failed to enable unit: Unit file /etc/systemd/system/kdump.service is masked.\""${BLD}
cci72="CCI-000366"
stigid72="RHEL-09-213115"
severity72="CAT II"
ruleid72="SV-257818r1044876"
vulnid72="V-257818"

title73a="RHEL 9 must be configured so that the cryptographic hashes of system files match vendor values."
title73b="Checking with: rpm -Va --noconfig | awk '\$1 ~ /..5/ && \$2 != \"c\"'"
title73c="Expecting: ${YLO}Nothing returned
           NOTE: If there is output, this is a finding."${BLD}
cci73="CCI-000366"
stigid73="RHEL-09-214030"
severity73="CAT II"
ruleid73="SV-257823r1051231"
vulnid73="V-257823"

title74a="RHEL 9 must not have a Trivial File Transfer Protocol (TFTP) server package installed."
title74b="Checking with: dnf list --installed tftp-server"
title74c="Expecting: ${YLO}Error: No matching Packages to list
           NOTE: If the \"tftp-server\" package is installed, this is a finding."${BLD}
cci74="CCI-000366"
stigid74="RHEL-09-215060"
severity74="CAT I"
ruleid74="SV-257835r1102037"
vulnid74="V-257835"

title75a="RHEL 9 must not have the quagga package installed."
title75b="Checking with: dnf list --installed quagga"
title75c="Expecting: ${YLO}Error: No matching Packages to list
           NOTE: If the \"quagga\" package is installed and is not documented with the information system security officer (ISSO) as an operational requirement, this is a finding."${BLD}
cci75="CCI-000366"
stigid75="RHEL-09-215065"
severity75="CAT II"
ruleid75="SV-257836r1044908"
vulnid75="V-257836"

title76a="A graphical display manager must not be installed on RHEL 9 unless approved."
title76b="Checking with: dnf list --installed \"xorg-x11-server-common\""
title76c="Expecting: ${YLO}Error: No matching Packages to list
           NOTE: If the \"xorg-x11-server-common\" package is installed, and the use of a graphical user interface has not been documented with the information system security officer (ISSO) as an operational requirement, this is a finding."${BLD}
cci76="CCI-000366"
stigid76="RHEL-09-215070"
severity76="CAT II"
ruleid76="SV-257837r1044910"
vulnid76="V-257837"

title77a="RHEL 9 must have the rng-tools package installed."
title77b="Checking with: dnf list --installed rng-tools"
title77c="Expecting: ${YLO}(example) rng-tools.x86_64          6.14-2.git.b2b7934e.el9
           NOTE: If the \"rng-tools\" package is not installed, this is a finding."${BLD}
cci77="CCI-000366"
stigid77="RHEL-09-215090"
severity77="CAT II"
ruleid77="SV-257841r1044914"
vulnid77="V-257841"

title78a="RHEL 9 must use a separate file system for /tmp."
title78b="Checking with: mount | grep /tmp"
title78c="Expecting: ${YLO}
           dev/mapper/rhel-tmp on /tmp type xfs (rw,nodev,nosuid,noexec,seclabel)
           NOTE: If a separate entry for \"/tmp\" is not in use, this is a finding."${BLD}
cci78="CCI-000366"
stigid78="RHEL-09-231015"
severity78="CAT II"
ruleid78="SV-257844r1044918"
vulnid78="V-257844"

title79a="RHEL 9 must use a separate file system for /var."
title79b="Checking with: mount | grep /var"
title79c="Expecting: ${YLO}
           /dev/mapper/rootvg-varlv on /var type xfs (rw,relatime,seclabel,attr2,inode64,logbufs=8,logbsize=32k,noquota)
           NOTE: Options displayed for mount may differ.
           NOTE: If a separate entry for "/var" is not in use, this is a finding."${BLD}
cci79="CCI-000366"
stigid79="RHEL-09-231020"
severity79="CAT III"
ruleid79="SV-257845r1044920"
vulnid79="V-257845"

title80a="RHEL 9 must use a separate file system for /var/log."
title80b="Checking with: mount | grep /var/log"
title80c="Expecting: ${YLO}
           /dev/mapper/rhel-var_log on /var/log type xfs (rw,nosuid,nodev,noexec,relatime,seclabel,attr2,inode64,logbufs=8,logbsize=32k)
           NOTE: Options displayed for mount may differ.
           NOTE: If a separate entry for \"/var/log\" is not in use, this is a finding."${BLD}
cci80="CCI-000366"
stigid80="RHEL-09-231025"
severity80="CAT III"
ruleid80="SV-257846r1044922"
vulnid80="V-257846"

title81a="RHEL 9 must use a separate file system for /var/tmp."
title81b="Checking with: mount | grep /var/tmp"
title81c="Expecting: ${YLO}
           /dev/mapper/rhel-var_tmp on /var/tmp type xfs (rw,nosuid,nodev,noexec,relatime,seclabel,attr2,inode64,logbufs=8,logbsize=32k)
           NOTE: Options displayed for mount may differ.
           NOTE: If a separate entry for \"/var/tmp\" is not in use, this is a finding."${BLD}
cci81="CCI-000366"
stigid81="RHEL-09-231035"
severity81="CAT II"
ruleid81="SV-257848r1044926"
vulnid81="V-257848"

title82a="RHEL 9 must prevent special devices on file systems that are imported via Network File System (NFS)."
title82b="Checking with: grep nfs /etc/fstab"
title82c="Expecting: ${YLO}
           Nothing returned, or
           192.168.22.2:/mnt/export /data nfs4 rw,nosuid,${BLD}nodev${YLO},noexec,sync,soft,sec=krb5:krb5i:krb5p
           NOTE: If no NFS mounts are configured, this requirement is Not Applicable.
           NOTE: If the system is mounting file systems via NFS and the \"nodev\" option is missing, this is a finding."${BLD}
cci82="CCI-000366"
stigid82="RHEL-09-231065"
severity82="CAT II"
ruleid82="SV-257854r1044934"
vulnid82="V-257854"

title83a="RHEL 9  must prevent code from being executed on file systems that are imported via Network File System (NFS)."
title83b="Checking with: grep nfs /etc/fstab"
title83c="Expecting: ${YLO}
           Nothing returned, or
           192.168.22.2:/mnt/export /data nfs4 rw,nosuid,nodev,${BLD}noexec${YLO},sync,soft,sec=krb5:krb5i:krb5p
           NOTE: If no NFS mounts are configured, this requirement is Not Applicable.
           NOTE: If the system is mounting file systems via NFS and the \"noexec\" option is missing, this is a finding."${BLD}
cci83="CCI-000366"
stigid83="RHEL-09-231070"
severity83="CAT II"
ruleid83="SV-257855r1044936"
vulnid83="V-257855"

title84a="RHEL 9 must prevent files with the setuid and setgid bit set from being executed on file systems that are imported via Network File System (NFS)."
title84b="Checking with: grep nfs /etc/fstab"
title84c="Expecting: ${YLO}
           Nothing returned, or
           192.168.22.2:/mnt/export /data nfs4 rw,${BLD}nosuid${YLO},nodev,noexec,sync,soft,sec=krb5:krb5i:krb5p
           NOTE: If no NFS mounts are configured, this requirement is Not Applicable.
           NOTE: If the system is mounting file systems via NFS and the \"nosuid\" option is missing, this is a finding."${BLD}
cci84="CCI-000366"
stigid84="RHEL-09-231075"
severity84="CAT II"
ruleid84="SV-257856r1044938"
vulnid84="V-257856"

title85a="RHEL 9 permissions of cron configuration files and directories must not be modified from the operating system defaults."
title85b="Checking with: rpm --verify cronie crontabs | awk '! (\$2 == \"c\" && \$1 ~ /^.\..\.\.\.\..\./) {print \$0}"
title85c="Expecting: ${YLO}Nothing returned
           NOTE: If the command returns any output, this is a finding."${BLD}
cci85="CCI-000366"
stigid85="RHEL-09-232040"
severity85="CAT II"
ruleid85="SV-257888r1069378"
vulnid85="V-257888"

title86a="All RHEL 9 local initialization files must have mode 0740 or less permissive."
title86b="Checking with: find /home/bingwa/.[^.]* -maxdepth 0 -perm -740 -exec stat -c \"%a %n\" {} \; | more"
title86c="Expecting: ${YLO}755 /home/bingwa/.somepermissivefile (example)
           If any local initialization files are returned, this indicates a mode more permissive than "0740", and this is a finding."${BLD}
cci86="CCI-000366"
stigid86="RHEL-09-232045"
severity86="CAT II"
ruleid86="SV-257889r1044959"
vulnid86="V-257889"

title87a="All RHEL 9 local interactive user home directories must have mode 0750 or less permissive."
title87b="Checking with: stat -L -c '%a %n' \$(awk -F: '(\$3>=1000)&&(\$7 !~ /nologin/){print \$6}' /etc/passwd) 2>/dev/null"
title87c="Expecting: ${YLO}Nothing returned
           NOTE: If home directories referenced in \"/etc/passwd\" do not have a mode of \"0750\" or less permissive, this is a finding.
           NOTE: This may miss interactive users that have been assigned a privileged user identifier (UID). Evidence of interactive use may be obtained from a number of log files containing system logon information."${BLD}
cci87="CCI-000366"
stigid87="RHEL-09-232050"
severity87="CAT II"
ruleid87="SV-257890r1044961"
vulnid87="V-257890"

title88a="RHEL 9 must be configured so that all system device files are correctly labeled to prevent unauthorized modification."
title88b="Checking with:
           a. find /dev -context *:device_t:* \( -type c -o -type b \) -printf \"%p %Z\\\\n\"
           b. find /dev -context *:unlabeled_t:* \( -type c -o -type b \) -printf \"%p %Z\\\\n\""
title88c="Expecting: ${YLO}Nothing returned
           NOTE: There are device files, such as \"/dev/vmci\", that are used when the operating system is a host virtual machine. They will not be owned by a user on the system and require the \"device_t\" label to operate. These device files are not a finding.
           NOTE: If there is output from either of these commands, other than already noted, this is a finding."${BLD}
cci88="CCI-000366"
stigid88="RHEL-09-232260"
severity88="CAT II"
ruleid88="SV-257932r1014838"
vulnid88="V-257932"

title89a="The RHEL 9 firewall must employ a deny-all, allow-by-exception policy for allowing connections to other systems."
title89b="Checking with: 
           a. firewall-cmd --state
           b. firewall-cmd --get-active-zones
           c. firewall-cmd --list-all --zone=\$(firewall-cmd --get-default-zone)"
title89c="Expecting: ${YLO}
           a. running
           b. drop
           b.   interfaces: ens192 (example)
           c. drop (active)
           c.   target: ${BLD}DROP${YLO}
           c.   icmp-block-inversion: no
           c.   interfaces: ens192
           c.   sources:
           c.   services: ssh
           c.   ports:
           c.   protocols:
           c.   forward: yes
           c.   masquerade: no
           c.   forward-ports:
           c.   source-ports:
           c.   icmp-blocks:
           c.   rich rules:
           NOTE: If no zones are active on the RHEL 9 interfaces or if runtime and permanent targets are set to a different option other than \"DROP\", this is a finding."${BLD}	
cci89="CCI-000366"
stigid89="RHEL-09-251020"
severity89="CAT II"
ruleid89="SV-257937r1106310"
vulnid89="V-257937"

title90a="RHEL 9 must enable hardening for the Berkeley Packet Filter just-in-time compiler."
title90b="Checking with: sysctl net.core.bpf_jit_harden"
title90c="Expecting: ${YLO}net.core.bpf_jit_harden = 2
           NOTE: If the returned line does not have a value of \"2\", or a line is not returned, this is a finding."${BLD}
cci90="CCI-000366"
stigid90="RHEL-09-251045"
severity90="CAT II"
ruleid90="SV-257942r1106314"
vulnid90="V-257942"

title91a="RHEL 9 systems using Domain Name Servers (DNS) resolution must have at least two name servers configured."
title91b="Checking with: nameserver /etc/resolv.conf"
title91c="Expecting: ${YLO} (example)
           nameserver 192.168.1.2
           nameserver 192.168.1.3
           NOTE: If the system is running in a cloud platform and the cloud provider gives a single, highly available IP address for DNS configuration, this control is Not Applicable.
           NOTE: If fewer than two lines are returned that are not commented out, this is a finding."${BLD}
cci91="CCI-000366"
stigid91="RHEL-09-252035"
severity91="CAT II"
ruleid91="SV-257948r1045004"
vulnid91="V-257948"

title92a="RHEL 9 must configure a DNS processing mode in Network Manager."
title92b="Checking with: NetworkManager --print-config"
title92c="Expecting: ${YLO}
           [main]
           dns=none
           NOTE: If the dns key under main does not exist or is not set to \"none\" or \"default\", this is a finding."${BLD}
cci92="CCI-000366"
stigid92="RHEL-09-252040"
severity92="CAT II"
ruleid92="SV-257949r1014841"
vulnid92="V-257949"

title93a="RHEL 9 must not have unauthorized IP tunnels configured."
title93b="Checking with: 
           a. systemctl is-active ipsec
           b. grep -rni conn /etc/ipsec.conf /etc/ipsec.d/ | grep -v \"#\""
title93c="Expecting: ${YLO}
           a. Inactive
           b. Nothing returned
           NOTE: If the IPsec tunnels are active and not approved, this is a finding."${BLD}
cci93="CCI-000366"
stigid93="RHEL-09-252045"
severity93="CAT II"
ruleid93="SV-257950r1045006"
vulnid93="V-257950"

title94a="RHEL 9 must be configured to prevent unrestricted mail relaying."
title94b="Checking with: 
           a. dnf list -installed postfix
           b. postconf -n smtpd_client_restrictions"
title94c="Expecting: ${YLO}
           a. Error: No matching Packages to list (or)
           a. postfix-2:3.5.9-18.el9.x86_64
           b. bash: postconf: command not found... (or)
           b. smtpd_client_restrictions = permit_mynetworks,reject
           NOTE: If postfix is not installed, this is Not Applicable.
           NOTE: If the \"smtpd_client_restrictions\" parameter contains any entries other than \"permit_mynetworks\" and \"reject\", and the additional entries have not been documented with the information system security officer (ISSO), this is a finding."${BLD}
cci94="CCI-000366"
stigid94="RHEL-09-252050"
severity94="CAT II"
ruleid94="SV-257951r1014843"
vulnid94="V-257951"

title95a="RHEL 9 must ignore Internet Protocol version 4 (IPv4) Internet Control Message Protocol (ICMP) redirect messages."
title95b="Checking with: sysctl net.ipv4.conf.all.accept_redirects"
title95c="Expecting: ${YLO}net.ipv4.conf.all.accept_redirects = 0
           NOTE: If the returned line does not have a value of \"0\", a line is not returned, or the line is commented out, this is a finding."${BLD}
cci95="CCI-000366"
stigid95="RHEL-09-253015"
severity95="CAT II"
ruleid95="SV-257958r1106319"
vulnid95="V-257958"

title96a="RHEL 9 must not forward Internet Protocol version 4 (IPv4) source-routed packets."
title96b="Checking with: sysctl net.ipv4.conf.all.accept_source_route"
title96c="Expecting: ${YLO}net.ipv4.conf.all.accept_source_route = 0
           If the returned line does not have a value of \"0\", a line is not returned, or the line is commented out, this is a finding."${BLD}
cci96="CCI-000366"
stigid96="RHEL-09-253020"
severity96="CAT II"
ruleid96="SV-257959r1102024"
vulnid96="V-257959"

title97a="RHEL 9 must log IPv4 packets with impossible addresses."
title97b="Checking with: sysctl net.ipv4.conf.all.log_martians"
title97c="Expecting: ${YLO}net.ipv4.conf.all.log_martians = 1
           NOTE: If the returned line does not have a value of \"1\", a line is not returned, or the line is commented out, this is a finding."${BLD}
cci97="CCI-000366"
stigid97="RHEL-09-253025"
severity97="CAT II"
ruleid97="SV-257960r1106321"
vulnid97="V-257960"

title98a="RHEL 9 must log IPv4 packets with impossible addresses by default."
title98b="Checking with: sysctl net.ipv4.conf.default.log_martians"
title98c="Expecting: ${YLO}net.ipv4.conf.default.log_martians = 1
           NOTE: If the returned line does not have a value of \"1\", a line is not returned, or the line is commented out, this is a finding."${BLD}
cci98="CCI-000366"
stigid98="RHEL-09-253030"
severity98="CAT II"
ruleid98="SV-257961r1106323"
vulnid98="V-257961"

title99a="RHEL 9 must use reverse path filtering on all IPv4 interfaces."
title99b="Checking with: sysctl net.ipv4.conf.all.rp_filter"
title99c="Expecting: ${YLO}net.ipv4.conf.all.rp_filter = 1
           NOTE: If the returned line does not have a value of \"1\" or \"2\", or a line is not returned, this is a finding."${BLD}
cci99="CCI-000366"
stigid99="RHEL-09-253035"
severity99="CAT II"
ruleid99="SV-257962r1106437"
vulnid99="V-257962"

title100a="RHEL 9 must prevent IPv4 Internet Control Message Protocol (ICMP) redirect messages from being accepted."
title100b="Checking with: sysctl net.ipv4.conf.default.accept_redirects"
title100c="Expecxting: ${YLO}net.ipv4.conf.default.accept_redirects = 0
           NOTE: If the returned line does not have a value of \"0\", a line is not returned, or the line is commented out, this is a finding."${BLD}
cci100="CCI-000366"
stigid100="RHEL-09-253040"
severity100="CAT II"
ruleid100="SV-257963r1106328"
vulnid100="V-257963"

title101a="RHEL 9 must not forward IPv4 source-routed packets by default."
title101b="Checking with: sysctl net.ipv4.conf.default.accept_source_route"
title101c="Expecting: ${YLO}net.ipv4.conf.default.accept_source_route = 0
           NOTE: If the returned line does not have a value of \"0\", a line is not returned, or the line is commented out, this is a finding."${BLD}
cci101="CCI-000366"
stigid101="RHEL-09-253045"
severity101="CAT II"
ruleid101="SV-257964r1106438"
vulnid101="V-257964"

title102a="RHEL 9 must use a reverse-path filter for IPv4 network traffic when possible by default."
title102b="Checking with: sysctl net.ipv4.conf.default.rp_filter"
title102c="Expecting: ${YLO}net.ipv4.conf.default.rp_filter = 1
           NOTE: If the returned line does not have a value of \"1\", or a line is not returned, this is a finding."${BLD}
cci102="CCI-000366"
stigid102="RHEL-09-253050"
severity102="CAT II"
ruleid102="SV-257965r1106333"
vulnid102="V-257965"

title103a="RHEL 9 must not respond to Internet Control Message Protocol (ICMP) echoes sent to a broadcast address."
title103b="Checking with: sysctl net.ipv4.icmp_echo_ignore_broadcasts"
title103c="Expecting: ${YLO}net.ipv4.icmp_echo_ignore_broadcasts = 1
           NOTE: If the returned line does not have a value of \"1\", a line is not returned, or the retuned line is commented out, this is a finding."${BLD}
cci103="CCI-000366"
stigid103="RHEL-09-253055"
severity103="CAT II"
ruleid103="SV-257966r1106440"
vulnid103="V-257966"

title104a="RHEL 9 must limit the number of bogus Internet Control Message Protocol (ICMP) response errors logs."
title104b="Checking with: sysctl net.ipv4.icmp_ignore_bogus_error_responses"
title104c="Expecting: ${YLO}net.ipv4.icmp_ignore_bogus_error_responses = 1
           NOTE: If \"net.ipv4.icmp_ignore_bogus_error_responses\" is not set to \"1\", this is a finding."${BLD}
cci104="CCI-000366"
stigid104="RHEL-09-253060"
severity104="CAT II"
ruleid104="SV-257967r1106337"
vulnid104="V-257967"

title105a="RHEL 9 must not send Internet Control Message Protocol (ICMP) redirects."
title105b="Checking with: sysctl net.ipv4.conf.all.send_redirects"
title105c="Expecting: ${YLO}net.ipv4.conf.all.send_redirects = 0
           NOTE: If the returned line does not have a value of \"0\", or a line is not returned, this is a finding."${BLD}
cci105="CCI-000366"
stigid105="RHEL-09-253065"
severity105="CAT II"
ruleid105="SV-257968r1106339"
vulnid105="V-257968"

title106a="RHEL 9 must not enable IPv4 packet forwarding unless the system is a router."
title106b="Checking with: sysctl net.ipv4.conf.all.forwarding"
title106c="Expecting: ${YLO}net.ipv4.conf.all.forwarding = 0
           NOTE: If the IPv4 forwarding value is not \"0\" and is not documented with the information system security officer (ISSO) as an operational requirement, this is a finding."${BLD}
cci106="CCI-000366"
stigid106="RHEL-09-253075"
severity106="CAT II"
ruleid106="SV-257970r1106442"
vulnid106="V-257970"

title107a="RHEL 9 must not accept router advertisements on all IPv6 interfaces."
title107b="Checking with: sysctl  net.ipv6.conf.all.accept_ra"
title107c="Expecting: ${YLO}net.ipv6.conf.all.accept_ra = 0
           NOTE: If the \"accept_ra\" value is not \"0\" and is not documented with the information system security officer (ISSO) as an operational requirement, this is a finding."${BLD}
cci107="CCI-000366"
stigid107="RHEL-09-254010"
severity107="CAT II"
ruleid107="SV-257971r1106444"
vulnid107="V-257971"

title108a="RHEL 9 must ignore IPv6 Internet Control Message Protocol (ICMP) redirect messages."
title108b="Checking with: sysctl net.ipv6.conf.all.accept_redirects"
title108c="Expecting: ${YLO}net.ipv6.conf.all.accept_redirects = 0
           NOTE: If the returned line does not have a value of \"0\", a line is not returned, or the line is commented out, this is a finding."${BLD}
cci108="CCI-000366"
stigid108="RHEL-09-254015"
severity108="CAT II"
ruleid108="SV-257972r1106446"
vulnid108="V-257972"

title109a="RHEL 9 must not forward IPv6 source-routed packets."
title109b="Checking with: sysctl net.ipv6.conf.all.accept_source_route"
title109c="Expecting: ${YLO}net.ipv6.conf.all.accept_source_route = 0
           NOTE: If the returned line does not have a value of \"0\", a line is not returned, or the line is commented out, this is a finding."${BLD}
cci109="CCI-000366"
stigid109="RHEL-09-254020"
severity109="CAT II"
ruleid109="SV-257973r1106448"
vulnid109="V-257973"

title110a="RHEL 9 must not enable IPv6 packet forwarding unless the system is a router."
title110b="Checking with: sysctl net.ipv6.conf.all.forwarding"
title110c="Expecting: ${YLO}net.ipv6.conf.all.forwarding = 0
           NOTE: If the IPv6 forwarding value is not \"0\" and is not documented with the information system security officer (ISSO) as an operational requirement, this is a finding."${BLD}
cci110="CCI-000366"
stigid110="RHEL-09-254025"
severity110="CAT II"
ruleid110="SV-257974r1106450"
vulnid110="V-257974"

title111a="RHEL 9 must not accept router advertisements on all IPv6 interfaces by default."
title111b="Checking with: sysctl  net.ipv6.conf.default.accept_ra"
title111c="Expecting: ${YLO}net.ipv6.conf.default.accept_ra = 0
           NOTE: If the \"accept_ra\" value is not \"0\" and is not documented with the information system security officer (ISSO) as an operational requirement, this is a finding."${BLD}
cci111="CCI-000366"
stigid111="RHEL-09-254030"
severity111="CAT II"
ruleid111="SV-257975r1106452"
vulnid111="V-257975"

title112a="RHEL 9 must prevent IPv6 Internet Control Message Protocol (ICMP) redirect messages from being accepted."
title112b="Checking with: sysctl net.ipv6.conf.default.accept_redirects"
title112c="Expecting: ${YLO}net.ipv6.conf.default.accept_redirects = 0
           NOTE: If the returned line does not have a value of \"0\", a line is not returned, or the line is commented out, this is a finding."${BLD}
cci112="CCI-000366"
stigid112="RHEL-09-254035"
severity112="CAT II"
ruleid112="SV-257976r1106454"
vulnid112="V-257976"

title113a="RHEL 9 must not forward IPv6 source-routed packets by default."
title113b="Checking with: sysctl net.ipv6.conf.default.accept_source_route"
title113c="Expecting: ${YLO}net.ipv6.conf.default.accept_source_route = 0
           NOTE: If the returned line does not have a value of \"0\", a line is not returned, or the line is commented out, this is a finding."${BLD}
cci113="CCI-000366"
stigid113="RHEL-09-254040"
severity113="CAT II"
ruleid113="SV-257977r1106456"
vulnid113="V-257977"

title114a="RHEL 9 must have the openssh-clients package installed."
title114b="Checking with: dnf list --installed openssh-clients"
title114c="Expecting: ${YLO}(example) openssh-clients.x86_64          8.7p1-8.el9
           NOTE: If the \"openssh-clients\" package is not installed, this is a finding."${BLD}
cci114="CCI-000366"
stigid114="RHEL-09-255020"
severity114="CAT II"
ruleid114="SV-257980r1045016"
vulnid114="V-257980"

title115a="RHEL 9 must not allow a noncertificate trusted host SSH logon to the system."
title115b="Checking with: 
           /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print \$4}' | tr -d '\\\\r' | tr '\\\\n' ' ' | xargs grep -iH '^\s*hostbasedauthentication'"
title115c="Expecting: ${YLO}HostbasedAuthentication no
           NOTE: If the \"HostbasedAuthentication\" keyword is not set to \"no\", is missing, or is commented out, this is a finding."${BLD}
cci115="CCI-000366"
stigid115="RHEL-09-255080"
severity115="CAT II"
ruleid115="SV-257992r1045047"
vulnid115="V-257992"

title116a="RHEL 9 must not allow users to override SSH environment variables."
title116b="Checking with: 
           /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print \$4}' | tr -d '\\\\r' | tr '\\\\n' ' ' | xargs grep -iH '^\s*permituserenvironment'"
title116c="Expecting: ${YLO}PermitUserEnvironment no
           NOTE: If \"PermitUserEnvironment\" is set to \"yes\", is missing completely, or is commented out, this is a finding."${BLD}
cci116="CCI-000366"
stigid116="RHEL-09-255085"
severity116="CAT II"
ruleid116="SV-257993r1045049"
vulnid116="V-257993"

title117a="RHEL 9 SSH server configuration file must be group-owned by root."
title117b="Checking with: find /etc/ssh/sshd_config /etc/ssh/sshd_config.d -exec stat -c \"%G %n\" {} \;"
title117c="Expecting: ${YLO}
           root /etc/ssh/sshd_config
           root /etc/ssh/sshd_config.d
           root /etc/ssh/sshd_config.d/50-cloud-init.conf
           root /etc/ssh/sshd_config.d/50-redhat.conf
           NOTE: If the \"/etc/ssh/sshd_config\" file or \"/etc/ssh/sshd_config.d\" or any files in the sshd_config.d directory do not have a group owner of \"root\", this is a finding."${BLD}
cci117="CCI-000366"
stigid117="RHEL-09-255105"
severity117="CAT II"
ruleid117="SV-257997r1069370"
vulnid117="V-257997"

title118a="The RHEL 9 SSH server configuration file must be owned by root."
title118b="Checking with: find /etc/ssh/sshd_config /etc/ssh/sshd_config.d -exec stat -c \"%U %n\" {} \;"
title118c="Expecting: ${YLO}
           root /etc/ssh/sshd_config
           root /etc/ssh/sshd_config.d
           root /etc/ssh/sshd_config.d/50-cloud-init.conf
           root /etc/ssh/sshd_config.d/50-redhat.conf
           NOTE: If the \"/etc/ssh/sshd_config\" file or \"/etc/ssh/sshd_config.d\" or any files in the \"sshd_config.d\" directory do not have an owner of \"root\", this is a finding."${BLD}
cci118="CCI-000366"
stigid118="RHEL-09-255110"
severity118="CAT II"
ruleid118="SV-257998r1082181"
vulnid118="V-257998"

title119a="RHEL 9 SSH server configuration files' permissions must not be modified."
title119b="Checking with: rpm --verify openssh-server"
title119c="Expecting: ${YLO}Nothing returned
           NOTE: If the command returns any output, this is a finding."${BLD}
cci119="CCI-000366"
stigid119="RHEL-09-255115"
severity119="CAT II"
ruleid119="SV-257999r1082182"
vulnid119="V-257999"

title120a="RHEL 9 SSH private host key files must have mode 0640 or less permissive."
title120b="Checking with: stat -c \"%a %n\" /etc/ssh/*_key"
title120c="Expecting: ${YLO}
           640 /etc/ssh/ssh_host_dsa_key
           640 /etc/ssh/ssh_host_ecdsa_key
           640 /etc/ssh/ssh_host_ed25519_key
           640 /etc/ssh/ssh_host_rsa_key
           NOTE: If any private host key file has a mode more permissive than "0640", this is a finding."${BLD}
cci120="CCI-000366"
stigid120="RHEL-09-255120"
severity120="CAT II"
ruleid120="SV-258000r1045063"
vulnid120="V-258000"

title121a="RHEL 9 SSH daemon must not allow rhosts authentication."
title121b="Checking with: /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print \$4}' | tr -d '\\\\r' | tr '\\\\n' ' ' | xargs grep -iH '^\s*ignorerhosts'"
title121c="Expecting: ${YLO}IgnoreRhosts yes
           NOTE: If the value is returned as \"no\", the returned line is commented out, or no output is returned, this is a finding."${BLD}
cci121="CCI-000366"
stigid121="RHEL-09-255145"
severity121="CAT II"
ruleid121="SV-258005r1045069"
vulnid121="V-258005"

title122a="RHEL 9 SSH daemon must not allow known hosts authentication."
title122b="Checking with: /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print \$4}' | tr -d '\\\\r' | tr '\\\\n' ' ' | xargs grep -iH '^\s*ignoreuserknownhosts'"
title122c="Expecting: ${YLO}IgnoreUserKnownHosts yes
           If the value is returned as \"no\", the returned line is commented out, or no output is returned, this is a finding."${BLD}
cci122="CCI-000366"
stigid122="RHEL-09-255150"
severity122="CAT II"
ruleid122="SV-258006r1045071"
vulnid122="V-258006"

title123a="RHEL 9 SSH daemon must disable remote X connections for interactive users."
title123b="Checking with: /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print \$4}' | tr -d '\\\\r' | tr '\\\\n' ' ' | xargs grep -iH '^\s*x11forwarding'"
title123c="Expecting: ${YLO}X11forwarding no
           NOTE: If the value is returned as \"yes\", the returned line is commented out, or no output is returned, and X11 forwarding is not documented with the information system security officer (ISSO) as an operational requirement, this is a finding."${BLD}
cci123="CCI-000366"
stigid123="RHEL-09-255155"
severity123="CAT II"
ruleid123="SV-258007r1045073"
vulnid123="V-258007"

title124a="RHEL 9 SSH daemon must perform strict mode checking of home directory configuration files."
title124b="Checking with: $ /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print \$4}' | tr -d '\\\\r' | tr '\\\\n' ' ' | xargs grep -iH '^\s*strictmodes'"
title124c="Expecting: ${YLO}StrictModes yes
           NOTE: If the \"StrictModes\" keyword is set to \"no\", the returned line is commented out, or no output is returned, this is a finding."${BLD}
cci124="CCI-000366"
stigid124="RHEL-09-255160"
severity124="CAT II"
ruleid124="SV-258008r1045075"
vulnid124="V-258008"

title125a="RHEL 9 SSH daemon must display the date and time of the last successful account logon upon an SSH logon."
title125b="Checing with: /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print \$4}' | tr -d '\\\\r' | tr '\\\\n' ' ' | xargs grep -iH '^\s*printlastlog'"
title125c="Expecting: ${YLO}PrintLastLog yes
           NOTE: If the \"PrintLastLog\" keyword is set to \"no\", the returned line is commented out, or no output is returned, this is a finding."${BLD}
cci125="CCI-000366"
stigid125="RHEL-09-255165"
severity125="CAT II"
ruleid125="SV-258009r1045077"
vulnid125="V-258009"

title126a="RHEL 9 SSH daemon must prevent remote hosts from connecting to the proxy display."
title126b="Checking with: /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print \$4}' | tr -d '\\\\r' | tr '\\\\n' ' ' | xargs grep -iH '^\s*x11uselocalhost'"
title126c="Expecting: ${YLO}AutomaticLoginEnable=false
           NOTE: If the value of \"AutomaticLoginEnable\" is not set to \"false\", this is a finding."${BLD}
cci126="CCI-000366"
stigid126="RHEL-09-255175"
severity126="CAT II"
ruleid126="SV-258011r1045079"
vulnid126="V-258011"

title127a="RHEL 9 must not allow unattended or automatic logon via the graphical user interface."
title127b="Checking with: grep -i automaticlogin /etc/gdm/custom.conf"
title127c="Expecting: ${YLO}AutomaticLoginEnable=false
           NOTE: If the value of \"AutomaticLoginEnable\" is not set to \"false\", this is a finding."${BLD}
cci127="CCI-000366"
stigid127="RHEL-09-271040"
severity127="CAT I"
ruleid127="SV-258018r1045090"
vulnid127="V-258018"

title128a="RHEL 9 must disable the ability of a user to restart the system from the login screen."
title128b="Checking with: gsettings get org.gnome.login-screen disable-restart-buttons"
title128c="Expecting: ${YLO}true
           NOTE: If \"disable-restart-buttons\" is \"false\", this is a finding."${BLD}
cci128="CCI-000366"
stigid128="RHEL-09-271095"
severity128="CAT II"
ruleid128="SV-258029r1045109"
vulnid128="V-258029"

title129a="RHEL 9 must prevent a user from overriding the disable-restart-buttons setting for the graphical user interface."
title129b="Checking with: gsettings writable org.gnome.login-screen disable-restart-buttons"
title129c="Expecting: ${YLO}false
           NOTE: If \"disable-restart-buttons\" is writable and the result is \"true\", this is a finding."${BLD}
cci129="CCI-000366"
stigid129="RHEL-09-271100"
severity129="CAT II"
ruleid129="SV-258030r1045112"
vulnid129="V-258030"

title130a="RHEL 9 must disable the ability of a user to accidentally press Ctrl-Alt-Del and cause a system to shut down or reboot."
title130b="Checking with: gsettings get org.gnome.settings-daemon.plugins.media-keys logout"
title130c="Expecting: ${YLO}['']
           NOTE: This requirement assumes the use of the RHEL 9 default graphical user interface, the GNOME desktop environment. If the system does not have any graphical user interface installed, this requirement is Not Applicable.
           NOTE: If the GNOME desktop is configured to shut down when Ctrl-Alt-Del is pressed, this is a finding."${BLD}
cci130="CCI-000366"
stigid130="RHEL-09-271105"
severity130="CAT II"
ruleid130="SV-258031r1045114"
vulnid130="V-258031"

title131a="RHEL 9 must prevent a user from overriding the Ctrl-Alt-Del sequence settings for the graphical user interface."
title131b="Checking with: gsettings writable org.gnome.settings-daemon.plugins.media-keys logout"
title131c="Expecting: ${YLO}false
           NOTE: If \"logout\" is writable and the result is \"true\", this is a finding."${BLD}
cci131="CCI-000366"
stigid131="RHEL-09-271110"
severity131="CAT II"
ruleid131="SV-258032r1045117"
vulnid131="V-258032"

title132a="RHEL 9 must disable the user list at logon for graphical user interfaces."
title132b="Checking with: gsettings get org.gnome.login-screen disable-user-list"
title132c="Expecting: ${YLO}true
           NOTE: This requirement assumes the use of the RHEL 9 default graphical user interface, the GNOME desktop environment. If the system does not have any graphical user interface installed, this requirement is Not Applicable
           NOTE: If the setting is \"false\", this is a finding."${BLD}
cci132="CCI-000366"
stigid132="RHEL-09-271115"
severity132="CAT II"
ruleid132="SV-258033r1045120"
vulnid132="V-258033"

title133a="RHEL 9 must set the umask value to 077 for all local interactive user accounts."
title133b="Checking with: find /home -maxdepth 2 -type f -name \".[^.]*\" -exec grep -iH -d skip --exclude=.bash_history umask {} \;"
title133c="Expecting: ${YLO}Nothing returned or a list of initialization files that define a umask value, like;
           /home/wadea/.bash_history:grep -i umask /etc/bashrc /etc/csh.cshrc /etc/profile
           /home/wadea/.bash_history:grep -i umask /etc/login.defs
           /home/wadea/.bash_umask:umask 077
           NOTE: If \"/home\" is not the default location for interactive user home directories, you need to replace \"/home\" with the new home path in the \"find\" command.
           NOTE: If any local interactive user initialization files are found to have a umask statement that sets a value less restrictive than \"077\", this is a finding."${BLD}
cci133="CCI-000366"
stigid133="RHEL-09-411025"
severity133="CAT II"
ruleid133="SV-258044r1045135"
vulnid133="V-258044"

title134a="Executable search paths within the initialization files of all local interactive RHEL 9 users must only contain paths that resolve to the system default or the users home directory."
title134b="Checking with: find /home -maxdepth 2 -type f -name \".[^.]*\" -exec grep -iH -d skip --exclude=.bash_history path= {} \;"
title134c="Expecting: ${YLO}PATH=\"\$HOME/.local/bin:\$HOME/bin:\$PATH\"
           NOTE: If \"/home\" is not the default location for interactive user home directories, you need to replace \"/home\" with the new home path in the \"find\" command.
           NOTE: If any local interactive user initialization files have executable search path statements that include directories outside of their home directory, and this is not documented with the ISSO as an operational requirement, this is a finding."${BLD}
cci134="CCI-000366"
stigid134="RHEL-09-411055"
severity134="CAT II"
ruleid134="SV-258050r1045137"
vulnid134="V-258050"

title135a="RHEL 9 must not have unauthorized accounts."
title135b="Checking with: less /etc/passwd"
title135c="Expecting: ${YLO}
           root:x:0:0:root:/root:/bin/bash
           ...
           games:x:12:100:games:/usr/games:/sbin/nologin
           scsaustin:x:1001:1001:scsaustin:/home/scsaustin:/bin/bash
           djohnson:x:1002:1002:djohnson:/home/djohnson:/bin/bash
           NOTE: Interactive user accounts generally will have a user identifier (UID) of 1000 or greater, a home directory in a specific partition, and an interactive shell.
           NOTE: Obtain the list of interactive user accounts authorized to be on the system from the system administrator or information system security officer (ISSO) and compare it to the list of local interactive user accounts on the system.
           NOTE: If there are unauthorized local user accounts on the system, this is a finding."${BLD}
cci135="CCI-000366"
stigid135="RHEL-09-411095"
severity135="CAT II"
ruleid135="SV-258058r1045148"
vulnid135="V-258058"

title136a="RHEL 9 must define default permissions for the bash shell."
title136b="Checking with: umask /etc/bashrc"
title136c="Exptecting: ${YLO}[ \`umask\` -eq 0 ] && umask 077
           NOTE: If the value for the \"umask\" parameter is not \"077\", or the \"umask\" parameter is missing or is commented out, this is a finding."${BLD}
cci136="CCI-000366"
stigid136="RHEL-09-412055"
severity136="CAT II"
ruleid136="SV-258072r1045155"
vulnid136="V-258072"

title137a="RHEL 9 must define default permissions for the c shell."
title137b="Checking with: grep umask /etc/csh.cshrc"
title137c="Expecting: ${YLO}umask 077
           NOTE: If the value for the \"umask\" parameter is not "077", or the \"umask\" parameter is missing or is commented out, this is a finding.
           NOTE: ${RED}If the value of the \"umask\" parameter is set to \"000\" in the \"/etc/csh.cshrc\" file, the Severity is raised to a CAT I."${BLD}
cci137="CCI-000366"
stigid137="RHEL-09-412060"
severity137="CAT II"
ruleid137="SV-258073r1045157"
vulnid137="V-258073"

title138a="RHEL 9 policycoreutils-python-utils package must be installed."
title138b="Checking with: dnf list --installed policycoreutils-python-utils"
title138c="Expecting: ${YLO}(example) policycoreutils-python-utils.noarch          3.3-6.el9_0
           NOTE: If the \"policycoreutils-python-utils\" package is not installed, this is a finding."${BLD}
cci138="CCI-000366"
stigid138="RHEL-09-431030"
severity138="CAT II"
ruleid138="SV-258082r1045166"
vulnid138="V-258082"

title139a="RHEL 9 must use the invoking user's password for privilege escalation when using \"sudo\"."
title139b="Checking  with: egrep -ir '(!rootpw|!targetpw|!runaspw)' /etc/sudoers /etc/sudoers.d/ | grep -v '#'"
title139c="Expecting: ${YLO}
           /etc/sudoers:Defaults !targetpw
           /etc/sudoers:Defaults !rootpw
           /etc/sudoers:Defaults !runaspw
           NOTE: If no results are returned, this is a finding.
           NOTE: If results are returned from more than one file location, this is a finding.
           NOTE: If \"Defaults !targetpw\" is not defined, this is a finding.
           NOTE: If \"Defaults !rootpw\" is not defined, this is a finding.
           NOTE: If \"Defaults !runaspw\" is not defined, this is a finding."${BLD}
cci139="CCI-000366"
stigid139="RHEL-09-432020"
severity139="CAT II"
ruleid139="SV-258085r1045173"
vulnid139="V-258085"

title140a="RHEL 9 must restrict privilege elevation to authorized personnel."
title140b="Checking with: grep -iwR 'ALL' /etc/sudoers /etc/sudoers.d/ | grep -v '#'"
title140c="Expecting: ${YLO}
           ALL     ALL=(ALL) ALL
           ALL     ALL=(ALL:ALL) ALL
           NOTE: If the either of the above entries are returned, this is a finding:"${BLD}
cci140="CCI-000366"
stigid140="RHEL-09-432030"
severity140="CAT II"
ruleid140="SV-258087r1102071"
vulnid140="V-258087"

title141a="RHEL 9 must not allow blank or null passwords."
title141b="Checking with: grep -i nullok /etc/pam.d/system-auth /etc/pam.d/password-auth"
title141c="Expecting: ${YLO}Nothing returned
           NOTE: If output is produced, this is a finding."${BLD}
cci141="CCI-000366"
stigid141="RHEL-09-611025"
severity141="CAT I"
ruleid141="SV-258094r1045187"
vulnid141="V-258094"

title142a="RHEL 9 must ensure the password complexity module is enabled in the system-auth file."
title142b="Checking with: grep pam_pwquality /etc/pam.d/system-auth"
title142c="Expecting: ${YLO}password required pam_pwquality.so
           NOTE: If the command does not return a line containing the value \"pam_pwquality.so\", the word \"required\" is missing, or the line is commented out, this is a finding."${BLD}
cci142="CCI-000366"
stigid142="RHEL-09-611045"
severity142="CAT II"
ruleid142="SV-258098r1045195"
vulnid142="V-258098"

title143a="RHEL 9 must prevent the use of dictionary words for passwords."
title143b="Checking with: grep dictcheck /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf"
title143c="Expecting: ${YLO}/etc/security/pwquality.conf:dictcheck = 1
           If \"dictcheck\" does not have a value other than \"0\", or is commented out, this is a finding."${BLD}
cci143="CCI-000366"
stigid143="RHEL-09-611105"
severity143="CAT II"
ruleid143="SV-258110r1045223"
vulnid143="V-258110"

title144a="RHEL 9 must use a file integrity tool that is configured to use FIPS 140-3-approved cryptographic hashes for validating file contents and directories."
title144b="Checking with: grep sha512 /etc/aide.conf"
title144c="Expecting: ${YLO}All=p+i+n+u+g+s+m+S+sha512+acl+xattrs+selinux
           NOTE: This script is based on the \"aide.conf\" file delivered by the DISA STIG profile on the \"rhel-9.6-x86_64-server-dvd.iso\" image.
           NOTE: If the \"sha512\" rule is not being used on all uncommented selection lines in the \"/etc/aide.conf\" file, or another file integrity tool is not using FIPS 140-3-approved cryptographic hashes for validating file contents and directories, this is a finding."${BLD}
cci144="CCI-000366"
stigid144="RHEL-09-651020"
severity144="CAT II"
ruleid144="SV-258136r1045270"
vulnid144="V-258136"

title145a="RHEL 9 must be configured so that the file integrity tool verifies Access Control Lists (ACLs)."
title145b="Checking with: grep acl /etc/aide.conf"
title145c="Expecting: ${YLO}All= p+i+n+u+g+s+m+S+sha512+acl+xattrs+selinux
           NOTE: This script is based on the \"aide.conf\" file delivered by the DISA STIG profile on the \"rhel-9.6-x86_64-server-dvd.iso\" image.
           NOTE: If the \"acl\" rule is not being used on all uncommented selection lines in the \"/etc/aide.conf\" file, or ACLs are not being checked by another file integrity tool, this is a finding."${BLD}
cci145="CCI-000366"
stigid145="RHEL-09-651030"
severity145="CAT III"
ruleid145="SV-258138r1045274"
vulnid145="V-258138"

title146a="RHEL 9 must be configured so that the file integrity tool verifies extended attributes."
title146b="Checking with: grep xattrs /etc/aide.conf"
title146c="Expecting: ${YLO}All= p+i+n+u+g+s+m+S+sha512+acl+xattrs+selinux
           NOTE: This script is based on the \"aide.conf\" file delivered by the DISA STIG profile on the \"rhel-9.6-x86_64-server-dvd.iso\" image.
           NOTE: If the \"xattrs\" rule is not being used on all uncommented selection lines in the \"/etc/aide.conf\" file, or extended attributes are not being checked by another file integrity tool, this is a finding."${BLD}
cci146="CCI-000366"
stigid146="RHEL-09-651035"
severity146="CAT III"
ruleid146="SV-258139r1045276"
vulnid146="V-258139"

title147a="RHEL 9 must be configured so that the rsyslog daemon does not accept log messages from other servers unless the server is being used for log aggregation."
title147b="Checking with: (combined into one output)
           grep -i modload /etc/rsyslog.conf /etc/rsyslog.d/*
           grep -i 'load=\"imtcp\"' /etc/rsyslog.conf /etc/rsyslog.d/*
           grep -i 'load=\"imrelp\"' /etc/rsyslog.conf /etc/rsyslog.d/*
           grep -i serverrun /etc/rsyslog.conf /etc/rsyslog.d/*
           grep -i 'port=\"\S*\"' /etc/rsyslog.conf /etc/rsyslog.d/*"
title147c="Expecting: ${YLO}
           /etc/rsyslog.conf:#input(type=\"imudp\" port=\"514\")
           /etc/rsyslog.conf:#input(type=\"imtcp\" port=\"514\")
           /etc/rsyslog.conf:#Target=\"remote_host\" Port=\"XXX\" Protocol=\"tcp\")
           
           NOTE: If any uncommented lines are returned by the commands, rsyslog is configured to receive remote messages, and this is a finding.
           NOTE: An error about no files or directories from the above commands may be returned. This is not a finding."${BLD}
cci147="CCI-000366"
stigid147="RHEL-09-652025"
severity147="CAT II"
ruleid147="SV-258143r1045283"
vulnid147="V-258143"

title148a="RHEL 9 must use cron logging."
title148b="Checking with: 
           a. grep -s cron /etc/rsyslog.conf /etc/rsyslog.d/*.conf
           b. logger -p local0.info \"Test message for all facilities.\"
           c. tail /var/log/messages | grep 'Test message for all facilities.'"
title148c="Expecting: ${YLO}
           a. /etc/rsyslog.conf:*.info;mail.none;authpriv.none;cron.none /var/log/messages
           a. /etc/rsyslog.conf:cron.* /var/log/cron
           b. (no output)
           c. Test message for all facilities.
           NOTE: If another logging package is used, substitute the utility configuration file for \"/etc/rsyslog.conf\" or \"/etc/rsyslog.d/*.conf\" files.
           NOTE: If \"rsyslog\" is not logging messages for the cron facility or all facilities, this is a finding."${BLD}
cci148="CCI-000366"
stigid148="RHEL-09-652060"
severity148="CAT II"
ruleid148="SV-258150r1045296"
vulnid148="V-258150"

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

file1="/etc/redhat-release"
fail=0

year="$(date "+%Y")"
month="$(date "+%m")"

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file1 ]]
then

   osmake="$(echo $os | awk '{print $1}')"

   case $osmake in
      'Red')
          release="$(echo $os | awk '{print $6}')"
          ;;
      'CentOS')
          release="$(echo $os | awk '{print $4}')"
          ;;
   esac

   major="$(echo $release | awk -F. '{print $1}')"
   minor="$(echo $release | awk -F. '{print $2}')"

   case $major.$minor in
     9.0)
        if [[ $year > 2024 ||
            ( $year == 2024 && $month > 4 )
           ]]
        then
          fail=1
        fi
        ;;
     9.1)
        if [[ $year > 2023 ||
            ( $year == 2023 && $month > 5 )
           ]]
        then
          fail=1
        fi
        ;;
     9.2)
        if [[ $year > 2025 ||
            ( $year == 2025 && $month > 4 )
           ]]
        then
          fail=1
        fi
	    ;;
     9.3)
        if [[ $year > 2024 ||
            ( $year == 2024 && $month > 4 )
           ]]
        then
          fail=1
        fi
        ;;
     9.4)
        if [[ $year > 2026 ||
            ( $year == 2026 && $month > 4 )
           ]]
        then
          fail=1
        fi
        ;;
     9.5)
        if [[ $year > 2025 ||
            ( $year == 2025 && $month > 4 )
           ]]
        then
          fail=1
        fi
        ;;
     9.6)
        if [[ $year > 2027 ||
            ( $year == 2027 && $month > 4 )
           ]]
        then
          fail=1
        fi
        ;;
     9.7)
        if [[ $year > 2026 ||
            ( $year == 2026 && $month > 4 )
           ]]
        then
          fail=1
        fi
        ;;
     9.8)
        if [[ $year > 2028 ||
            ( $year == 2028 && $month > 4 )
           ]]
        then
          fail=1
        fi
        ;;
     9.9)
        if [[ $year > 2027 ||
            ( $year == 2027 && $month > 4 )
           ]]
        then
          fail=1
        fi
        ;;
    9.10)
        if [[ $year > 2032 ||
            ( $year == 2032 && $month > 5 )
           ]]
        then
          fail=1
        fi
        ;;
      *)
	fail=2
   esac

   if [[ $fail == 0 ]]
   then
      echo -e "${NORMAL}RESULT:    ${BLD}$os${NORMAL}"
      fail=0
   else
      echo -e "${NORMAL}RESULT:    ${RED}$os${NORMAL}"
   fi

   if [[ $fail == 0 ]]
   then
      echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${GRN}PASSED, The operating system is a vendor supported release.${NORMAL}"
   elif [[ $fail == 2 ]]
   then
     echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${CYN}VERIFY, Unable to determine if the vendor supports the release.${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${RED}FAILED, The operating system is not a vendor supported release.${NORMAL}"
   fi
else
    echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${RED}FAILED, Vendor Supported OS: $file1 not found${NORMAL}"
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

IFS=' '

yumhistory="$(dnf history --cacheonly list | more)"

datetime="$(date +%FT%H:%M:%S)"

if [[ $yumhistory ]]
then
  echo -e "${NORMAL}RESULT: ${BLD}$yumhistory${NORMAL}"
  echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${CYN}VERIFY, Verify the operating system security patches and updates are applied at a frequency determined by the site or Program Management Office (PMO). ${NORMAL}"
else
  echo -e "${NORMAL}RESULT: ${RED}No history of security updates and patches found.${NORMAL}"
  echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${RED}FAILED, Operating system security patches and updates could not be verified.${NORMAL}"
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

target="$(systemctl get-default)"
if [[ $target == 'multi-user.target' ]]
then
  echo -e "${NORMAL}RESULT:    ${BLD}$target${NORMAL}"
  fail=0
else
  echo -e "${NORMAL}RESULT:    ${RED}$target${NORMAL}" 
fi

if [[ $fail == 0 ]]
then
   echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${GRN}PASSED, A Windows display manager is not set as the default target.${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${RED}FAILED, A Windows display manager is set as the default target.${NORMAL}"
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
fipsmode=0

datetime="$(date +%FT%H:%M:%S)"

knl_major="$(uname -r | awk -F- '{print $1}' | awk -F. '{print $1}')"
knl_minor="$(uname -r | awk -F- '{print $1}' | awk -F. '{print $2}')"

isenabled="$(fips-mode-setup --check)"

echo -e "${NORMAL}RESULT:    a. $knl_major.$knl_minor${NORMAL}"

if [[ $isenabled == 'FIPS mode is enabled.' ]]
then
  echo -e "${NORMAL}RESULT:    b. ${BLD}$isenabled${NORMAL}"
  echo -e "${NORMAL}RESULT:    c. (skipped}${NORMAL}"
  fail=3
else
  echo -e "${NORMAL}RESULT:    b. ${RED}$isenabled${NORMAL}"

  isactive="$(systemctl is-active rngd)"
  if  [[ $knl_major -lt  5 ]]
  then
    if [[ $isactive == 'active' ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}c. $isactive${NORMAL}"
      fail=0
    else
      echo -e "${NORMAL}RESULT:    ${RED}c. $isactive${NORMAL}"
    fi
  elif [[ $knl_major == 5 && (( $knl_minor -lt 6 )) ]]
  then
    fail=2
    if [[ $isactive == 'active' ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}c. $isactive${NORMAL}"
      fail=0
    else
      echo -e "${NORMAL}RESULT:    ${RED}c. $isactive${NORMAL}"
    fi
  else
    echo -e "${NORMAL}RESULT:    c. $isactive${NORMAL}"
    fail=2
  fi
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${GRN}PASSED, RHEL 9 enables the hardware random number generator entropy gatherer service.${NORMAL}"
elif [[ $fail == 2 ]]
then
  echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${GRN}N/A, As of kernel 5.6 RHEL 9 no longer requires the \"rng-tools\" package and does not need the \"rngd\" service to be \"active\".${NORMAL}"
elif [[ $fail == 3 ]]
then
  echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${GRN}N/A, RHEL 9 is running with kernel FIPS mode enabled. This requirement is Not Applicable.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${RED}FAILED, RHEL 9 does not enable the hardware random number generator entropy gatherer service.${NORMAL}"
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

stat="$(stat -c "%G %n" /boot/grub2/grub.cfg)"

if [[ $stat ]]
then
  owner="$(echo $stat | awk '{print $1}')"
  if [[ $owner == 'root' ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}$stat${NORMAL}"
    fail=0
  else
    echo -e "${NORMAL}RESULT:    ${RED}$stat${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity5, $controlid, $stigid5, $ruleid5, $cci5, $datetime, ${GRN}PASSED, RHEL 9 /boot/grub2/grub.cfg file is group-owned by root.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity5, $controlid, $stigid5, $ruleid5, $cci5, $datetime, ${RED}FAILED, RHEL 9 /boot/grub2/grub.cfg file is not group-owned by root.${NORMAL}"
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

fail=1

datetime="$(date +%FT%H:%M:%S)"

stat="$(stat -c "%U %n" /boot/grub2/grub.cfg)"

if [[ $stat ]]
then
  owner="$(echo $stat | awk '{print $1}')"
  if [[ $owner == 'root' ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}$stat${NORMAL}"
    fail=0
  else
    echo -e "${NORMAL}RESULT:    ${RED}$stat${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity6, $controlid, $stigid6, $ruleid6, $cci6, $datetime, ${GRN}PASSED, RHEL 9 /boot/grub2/grub.cfg file is owned by root.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity6, $controlid, $stigid6, $ruleid6, $cci6, $datetime, ${RED}FAILED, RHEL 9 /boot/grub2/grub.cfg file is not owned by root.${NORMAL}"
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

fail=1

datetime="$(date +%FT%H:%M:%S)"

storage="$(grep -i storage /etc/systemd/coredump.conf)"

if [[ $storage ]]
then
  for line in ${storage[@]}
  do
    setting="$(echo $line | awk -F= '{print $2}')"
    if [[ $setting == 'none' && ${setting:0:1} != "#" ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
      fail=0
    else
      echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity7, $controlid, $stigid7, $ruleid7, $cci7, $datetime, ${GRN}PASSED, RHEL 9 disables storing core dumps.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity6, $controlid, $stigid6, $ruleid6, $cci6, $datetime, ${RED}FAILED, RHEL 9 does not disable storing core dumps.${NORMAL}"
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

fail=1

cds="$(grep -r -s '^[^#].*core' /etc/security/limits.conf /etc/security/limits.d/*.conf)"
cdstat="$(echo $cds | tr -s ' ')"

datetime="$(date +%FT%H:%M:%S)"

if [[ $cdstat ]]
then
  if [[ $cdstat =~ '* hard core 0' ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}$cdstat${NORMAL}"
    fail=0
  else
    echo -e "${NORMAL}RESULT:    ${RED}$cdstat${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity8, $controlid, $stigid8, $ruleid8, $cci8, $datetime, ${GRN}PASSED, RHEL 9 disables core dumps for all users.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity8, $controlid, $stigid8, $ruleid8, $cci8, $datetime, ${RED}FAILED, RHEL 9 does not disable core dumps for all users.${NORMAL}"
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

fail=1

scdstat="$(systemctl status systemd-coredump.socket | tr -s ' ')"

datetime="$(date +%FT%H:%M:%S)"

if [[ $scdstat ]]
then
  for line in ${scdstat[@]}
  do
    if [[ ($line =~ "Loaded:" && $line =~ "masked" ) ||
           $line =~ "Active:" && $line =~ "inactive (dead)" ]]
    then
      fail=0
      echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
    elif [[ ($line =~ "Loaded:" && ! $line =~ "masked") ||
            ($line =~ "Active:" && ! $line =~ "inactive (dead)") ]]
    then
      echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    $line${NORMAL}"
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${BLD}systemd-coredump.socket is not configured${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity9, $controlid, $stigid9, $ruleid9, $cci9, $datetime, ${GRN}PASSED, RHEL 9 (masks) disables acquiring saving and processing core dumps.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity9, $controlid, $stigid9, $ruleid9, $cci9, $datetime, ${RED}FAILED, RHEL 9 does not (mask) disable acquiring saving and processing core dumps.${NORMAL}"
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

fail=1

datetime="$(date +%FT%H:%M:%S)"

isinstalled="$(dnf list --installed 2>&1 gnutls-utils | grep -Ev 'Updating|installed')"

if [[ $isinstalled ]]
then
  fail=0
  echo -e "${NORMAL}RESULT:    ${BLD}$isinstalled${NORMAL}"
else
  echo -e "${NORMAL}RESULT:    ${RED}$isinstalled${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity10, $controlid, $stigid10, $ruleid10, $cci10, $datetime, ${GRN}PASSED, RHEL 9 has the gnutls-utils package installed.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity10, $controlid, $stigid10, $ruleid10, $cci10, $datetime, ${RED}FAILED, RHEL 9 does not have the gnutls-utils package installed.${NORMAL}"
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

fail=1

datetime="$(date +%FT%H:%M:%S)"

isinstalled="$(dnf list --installed 2>&1 nss-tools | grep -Ev 'Updating|Installed')"

if [[ $isinstalled ]]
then
  fail=0
  echo -e "${NORMAL}RESULT:    ${BLD}$isinstalled${NORMAL}"
else
  echo -e "${NORMAL}RESULT:    ${RED}$isinstalled${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity11, $controlid, $stigid11, $ruleid11, $cci11, $datetime, ${GRN}PASSED, RHEL 9 has the nss-tools package installed.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity11, $controlid, $stigid11, $ruleid11, $cci11, $datetime, ${RED}FAILED, RHEL 9 does not have the nss-tools package installed.${NORMAL}"
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

fail=1

datetime="$(date +%FT%H:%M:%S)"

home="$(mount | grep " /home ")"

if [[ $home ]]
then
  if [[ $home =~ 'on /home ' ]]
  then
    fail=0
    echo -e "${NORMAL}RESULT:    ${BLD}$home${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}$home${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity12, $controlid, $stigid12, $ruleid12, $cci12, $datetime, ${GRN}PASSED, A separate RHEL 9 file system is used for user home directories.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity12, $controlid, $stigid12, $ruleid12, $cci12, $datetime, ${RED}FAILED, A separate RHEL 9 file system is not used for user home directories${NORMAL}"
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

fail=1

datetime="$(date +%FT%H:%M:%S)"

home="$(mount | grep " /home ")"

if [[ $home ]]
then
  if [[ $home =~ 'on /home ' && $home =~ 'noexec' ]]
  then
    fail=0
    echo -e "${NORMAL}RESULT:    ${BLD}$home${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}$home${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity13, $controlid, $stigid13, $ruleid13, $cci13, $datetime, ${GRN}PASSED, RHEL 9 prevents code from being executed on file systems that contain user home directories.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity13, $controlid, $stigid13, $ruleid13, $cci13, $datetime, ${RED}FAILED, RHEL 9 does not prevent code from being executed on file systems that contain user home directories.${NORMAL}"
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

fail=0

datetime="$(date +%FT%H:%M:%S)"

# In a restricted environment, "more /etc/fstab" will not work. You
# have to use "cat /etc/fstab" instead

fs="$(cat /etc/fstab | egrep '(usb|vfs|exfat|vfat|flash)')"

if [[ $fs ]]
then
  if (( $fs !~ 'noexec' ))
  then
    fail=1
    echo -e "${NORMAL}RESULT:    ${RED}$fs${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${BLD}$fs${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    Nothing returned${NORMAL}"
  fail=2
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity14, $controlid, $stigid14, $ruleid14, $cci14, $datetime, ${GRN}PASSED, RHEL 9 prevents code from being executed on file systems that are used with removable media.${NORMAL}"
elif [[ $fail == 2 ]]
then
  echo -e "${NORMAL}$hostname, $severity14, $controlid, $stigid14, $ruleid14, $cci14, $datetime, ${GRN}N/A, No file systems found in "/etc/fstab" that refer to removable media.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity14, $controlid, $stigid14, $ruleid14, $cci14, $datetime, ${RED}FAILED, RHEL 9 does not prevent code from being executed on file systems that are used with removable media.${NORMAL}"
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

fail=0

datetime="$(date +%FT%H:%M:%S)"

# In a restricted environment, "more /etc/fstab" will not work. You
# have to use "cat /etc/fstab" instead

fs="$(cat /etc/fstab | egrep '(usb|vfs|exfat|vfat|flash)')"

if [[ $fs ]]
then
  if (( $fs !~ 'nodev' ))
  then
    fail=1
    echo -e "${NORMAL}RESULT:    ${RED}$fs${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${BLD}$fs${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    Nothing returned${NORMAL}"
  fail=2
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity15, $controlid, $stigid15, $ruleid15, $cci15, $datetime, ${GRN}PASSED, RHEL 9 prevents special devices on file systems that are used with removable media.${NORMAL}"
elif [[ $fail == 2 ]]
then
  echo -e "${NORMAL}$hostname, $severity15, $controlid, $stigid15, $ruleid15, $cci15, $datetime, ${GRN}N/A, No file systems found in "/etc/fstab" that refer to removable media.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity15, $controlid, $stigid15, $ruleid15, $cci15, $datetime, ${RED}FAILED, RHEL 9 does not prevent special devices on file systems that are used with removable media.${NORMAL}"
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

fail=0

datetime="$(date +%FT%H:%M:%S)"

# In a restricted environment, "more /etc/fstab" will not work. You
# have to use "cat /etc/fstab" instead

fs="$(cat /etc/fstab | egrep '(usb|vfs|exfat|vfat|flash)')"

if [[ $fs ]]
then
  if (( $fs !~ 'nosuid' || $fs !~ 'nosgid' ))
  then
    fail=1
    echo -e "${NORMAL}RESULT:    ${RED}$fs${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${BLD}$fs${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    Nothing returned${NORMAL}"
  fail=2
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity16, $controlid, $stigid16, $ruleid16, $cci16, $datetime, ${GRN}PASSED, RHEL 9 prevents files with the setuid and setgid bit set from being executed on file systems that are used with removable media.${NORMAL}"
elif [[ $fail == 2 ]]
then
  echo -e "${NORMAL}$hostname, $severity16, $controlid, $stigid16, $ruleid16, $cci16, $datetime, ${GRN}N/A, No file systems found in "/etc/fstab" that refer to removable media.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity16, $controlid, $stigid16, $ruleid16, $cci16, $datetime, ${RED}FAILED, RHEL 9 does not prevent files with the setuid and setgid bit set from being executed on file systems that are used with removable media.${NORMAL}"
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

fail=0

datetime="$(date +%FT%H:%M:%S)"

fs="$(mount | grep '^/dev\S* on /\S' | grep --invert-match 'nodev')"

if [[ $fs ]]
then
  fail=1
  echo -e "${NORMAL}RESULT:    ${RED}$fs${NORMAL}"
else
  echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity17, $controlid, $stigid17, $ruleid17, $cci17, $datetime, ${GRN}PASSED, RHEL 9 prevents special devices on non-root local partitions.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity17, $controlid, $stigid17, $ruleid16, $cci17, $datetime, ${RED}FAILED, RHEL 9 does not prevent special devices on non-root local partitions.${NORMAL}"
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

fail=1

datetime="$(date +%FT%H:%M:%S)"

mode="$(stat -c "%a %n" /etc/group)"
if [[ $mode ]]
then
  if  (( ${mode:0:1} <= 6 &&
         ${mode:1:1} <= 4 &&
         ${mode:2:1} <= 4
      ))
  then
    echo -e "${NORMAL}RESULT:    ${BLD}$mode${NORMAL}"
    fail=0
  else
    echo -e "${NORMAL}RESULT:    ${RED}$mode${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity18, $controlid, $stigid18, $ruleid18, $cci18, $datetime, ${GRN}PASSED, The RHEL 9 /etc/group file is mode 0644 or less permissive to prevent unauthorized access.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity18, $controlid, $stigid18, $ruleid18, $cci18, $datetime, ${RED}FAILED, The RHEL 9 /etc/group file is not mode 0644 or less permissive to prevent unauthorized access.${NORMAL}"
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

fail=1

datetime="$(date +%FT%H:%M:%S)"

mode="$(stat -c "%a %n" /etc/group-)"
if [[ $mode ]]
then
  if  (( ${mode:0:1} <= 6 &&
         ${mode:1:1} <= 4 &&
         ${mode:2:1} <= 4
      ))
  then
    echo -e "${NORMAL}RESULT:    ${BLD}$mode${NORMAL}"
    fail=0
  else
    echo -e "${NORMAL}RESULT:    ${RED}$mode${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity19, $controlid, $stigid19, $ruleid19, $cci19, $datetime, ${GRN}PASSED, The RHEL 9 /etc/group- file is mode 0644 or less permissive to prevent unauthorized access.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity19, $controlid, $stigid19, $ruleid19, $cci19, $datetime, ${RED}FAILED, The RHEL 9 /etc/group- file is not mode 0644 or less permissive to prevent unauthorized access.${NORMAL}"
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
echo -e "${NORMAL}           ${BLD}$title20b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title20c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity20${NORMAL}"

IFS='
'

fail=1

datetime="$(date +%FT%H:%M:%S)"

mode="$(stat -c "%a %n" /etc/gshadow)"
if [[ $mode ]]
then
  if [[ ${mode:0:2} == "0 " ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}$mode${NORMAL}"
    fail=0
  else
    echo -e "${NORMAL}RESULT:    ${RED}$mode${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity20, $controlid, $stigid20, $ruleid20, $cci20, $datetime, ${GRN}PASSED, The RHEL 9 /etc/gshadow file is mode 0000 to prevent unauthorized access.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity20, $controlid, $stigid20, $ruleid20, $cci20, $datetime, ${RED}FAILED, The RHEL 9 /etc/gshadow file is not mode 0000 to prevent unauthorized access.${NORMAL}"
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

fail=1

datetime="$(date +%FT%H:%M:%S)"

mode="$(stat -c "%a %n" /etc/gshadow-)"
if [[ $mode ]]
then
  if [[ ${mode:0:2} == "0 " ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}$mode${NORMAL}"
    fail=0
  else
    echo -e "${NORMAL}RESULT:    ${RED}$mode${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity21, $controlid, $stigid21, $ruleid21, $cci21, $datetime, ${GRN}PASSED, The RHEL 9 /etc/gshadow- file is mode 0000 to prevent unauthorized access.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity21, $controlid, $stigid21, $ruleid21, $cci21, $datetime, ${RED}FAILED, The RHEL 9 /etc/gshadow- file is not mode 0000 to prevent unauthorized access.${NORMAL}"
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

fail=1

datetime="$(date +%FT%H:%M:%S)"

mode="$(stat -c "%a %n" /etc/passwd)"
if [[ $mode ]]
then
  if  (( ${mode:0:1} <= 6 &&
         ${mode:1:1} <= 4 &&
         ${mode:2:1} <= 4
      ))
  then
    echo -e "${NORMAL}RESULT:    ${BLD}$mode${NORMAL}"
    fail=0
  else
    echo -e "${NORMAL}RESULT:    ${RED}$mode${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity22, $controlid, $stigid22, $ruleid22, $cci22, $datetime, ${GRN}PASSED, The RHEL 9 /etc/passwd file is mode 0644 or less permissive to prevent unauthorized access.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity22, $controlid, $stigid22, $ruleid22, $cci22, $datetime, ${RED}FAILED, The RHEL 9 /etc/passwd file is not mode 0644 or less permissive to prevent unauthorized access.${NORMAL}"
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

fail=1

datetime="$(date +%FT%H:%M:%S)"

mode="$(stat -c "%a %n" /etc/passwd-)"
if [[ $mode ]]
then
  if  (( ${mode:0:1} <= 6 &&
         ${mode:1:1} <= 4 &&
         ${mode:2:1} <= 4
      ))
  then
    echo -e "${NORMAL}RESULT:    ${BLD}$mode${NORMAL}"
    fail=0
  else
    echo -e "${NORMAL}RESULT:    ${RED}$mode${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity23, $controlid, $stigid23, $ruleid23, $cci23, $datetime, ${GRN}PASSED, The RHEL 9 /etc/passwd- file is mode 0644 or less permissive to prevent unauthorized access.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity23, $controlid, $stigid23, $ruleid23, $cci23, $datetime, ${RED}FAILED, The RHEL 9 /etc/passwd- file is not mode 0644 or less permissive to prevent unauthorized access.${NORMAL}"
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
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity24${NORMAL}"

IFS='
'

fail=1

datetime="$(date +%FT%H:%M:%S)"

mode="$(stat -c "%a %n" /etc/shadow-)"
if [[ $mode ]]
then
  if [[ ${mode:0:2} == "0 " ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}$mode${NORMAL}"
    fail=0
  else
    echo -e "${NORMAL}RESULT:    ${RED}$mode${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity24, $controlid, $stigid24, $ruleid24, $cci24, $datetime, ${GRN}PASSED, The RHEL 9 /etc/shadow- file is mode 0000 to prevent unauthorized access.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity24, $controlid, $stigid24, $ruleid24, $cci24, $datetime, ${RED}FAILED, The RHEL 9 /etc/shadow- file is not mode 0000 to prevent unauthorized access.${NORMAL}"
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

fail=1

datetime="$(date +%FT%H:%M:%S)"

stat="$(stat -c "%U %n" /etc/group)"

if [[ $stat ]]
then
  owner="$(echo $stat | awk '{print $1}')"
  if [[ $owner == 'root' ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}$stat${NORMAL}"
    fail=0
  else
    echo -e "${NORMAL}RESULT:    ${RED}$stat${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity25, $controlid, $stigid25, $ruleid25, $cci25, $datetime, ${GRN}PASSED, RHEL 9 /etc/group file is owned by root.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity25, $controlid, $stigid25, $ruleid25, $cci25, $datetime, ${RED}FAILED, RHEL 9 /etc/group file is not owned by root.${NORMAL}"
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

fail=1

datetime="$(date +%FT%H:%M:%S)"

stat="$(stat -c "%G %n" /etc/group)"

if [[ $stat ]]
then
  owner="$(echo $stat | awk '{print $1}')"
  if [[ $owner == 'root' ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}$stat${NORMAL}"
    fail=0
  else
    echo -e "${NORMAL}RESULT:    ${RED}$stat${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity26, $controlid, $stigid26, $ruleid26, $cci26, $datetime, ${GRN}PASSED, RHEL 9 /etc/group file is group-owned by root.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity26, $controlid, $stigid26, $ruleid26, $cci26, $datetime, ${RED}FAILED, RHEL 9 /etc/group file is not group-owned by root.${NORMAL}"
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

fail=1

datetime="$(date +%FT%H:%M:%S)"

stat="$(stat -c "%U %n" /etc/group-)"

if [[ $stat ]]
then
  owner="$(echo $stat | awk '{print $1}')"
  if [[ $owner == 'root' ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}$stat${NORMAL}"
    fail=0
  else
    echo -e "${NORMAL}RESULT:    ${RED}$stat${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity27, $controlid, $stigid27, $ruleid27, $cci27, $datetime, ${GRN}PASSED, RHEL 9 /etc/group- file is owned by root.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity27, $controlid, $stigid27, $ruleid27, $cci27, $datetime, ${RED}FAILED, RHEL 9 /etc/group- file is not owned by root.${NORMAL}"
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

fail=1

datetime="$(date +%FT%H:%M:%S)"

stat="$(stat -c "%G %n" /etc/group-)"

if [[ $stat ]]
then
  owner="$(echo $stat | awk '{print $1}')"
  if [[ $owner == 'root' ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}$stat${NORMAL}"
    fail=0
  else
    echo -e "${NORMAL}RESULT:    ${RED}$stat${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity28, $controlid, $stigid28, $ruleid28, $cci28, $datetime, ${GRN}PASSED, RHEL 9 /etc/group- file is group-owned by root.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity28, $controlid, $stigid28, $ruleid28, $cci28, $datetime, ${RED}FAILED, RHEL 9 /etc/group- file is not group-owned by root.${NORMAL}"
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

fail=1

datetime="$(date +%FT%H:%M:%S)"

stat="$(stat -c "%U %n" /etc/gshadow)"

if [[ $stat ]]
then
  owner="$(echo $stat | awk '{print $1}')"
  if [[ $owner == 'root' ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}$stat${NORMAL}"
    fail=0
  else
    echo -e "${NORMAL}RESULT:    ${RED}$stat${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity29, $controlid, $stigid29, $ruleid29, $cci29, $datetime, ${GRN}PASSED, RHEL 9 /etc/gshadow file is owned by root.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity29, $controlid, $stigid29, $ruleid29, $cci29, $datetime, ${RED}FAILED, RHEL 9 /etc/gshadow file is not owned by root.${NORMAL}"
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

fail=1

datetime="$(date +%FT%H:%M:%S)"

stat="$(stat -c "%G %n" /etc/gshadow)"

if [[ $stat ]]
then
  owner="$(echo $stat | awk '{print $1}')"
  if [[ $owner == 'root' ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}$stat${NORMAL}"
    fail=0
  else
    echo -e "${NORMAL}RESULT:    ${RED}$stat${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity30, $controlid, $stigid30, $ruleid30, $cci30, $datetime, ${GRN}PASSED, RHEL 9 /etc/gshadow file is group-owned by root.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity30, $controlid, $stigid30, $ruleid30, $cci30, $datetime, ${RED}FAILED, RHEL 9 /etc/gshadow file is not group-owned by root.${NORMAL}"
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

fail=1

datetime="$(date +%FT%H:%M:%S)"

stat="$(stat -c "%U %n" /etc/gshadow-)"

if [[ $stat ]]
then
  owner="$(echo $stat | awk '{print $1}')"
  if [[ $owner == 'root' ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}$stat${NORMAL}"
    fail=0
  else
    echo -e "${NORMAL}RESULT:    ${RED}$stat${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity31, $controlid, $stigid31, $ruleid31, $cci31, $datetime, ${GRN}PASSED, RHEL 9 /etc/gshadow- file is owned by root.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity31, $controlid, $stigid31, $ruleid31, $cci31, $datetime, ${RED}FAILED, RHEL 9 /etc/gshadow- file is not owned by root.${NORMAL}"
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

fail=1

datetime="$(date +%FT%H:%M:%S)"

stat="$(stat -c "%G %n" /etc/gshadow-)"

if [[ $stat ]]
then
  owner="$(echo $stat | awk '{print $1}')"
  if [[ $owner == 'root' ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}$stat${NORMAL}"
    fail=0
  else
    echo -e "${NORMAL}RESULT:    ${RED}$stat${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity32, $controlid, $stigid32, $ruleid32, $cci32, $datetime, ${GRN}PASSED, RHEL 9 /etc/gshadow- file is group-owned by root.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity32, $controlid, $stigid32, $ruleid32, $cci32, $datetime, ${RED}FAILED, RHEL 9 /etc/gshadow- file is not group-owned by root.${NORMAL}"
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

fail=1

datetime="$(date +%FT%H:%M:%S)"

stat="$(stat -c "%U %n" /etc/passwd)"

if [[ $stat ]]
then
  owner="$(echo $stat | awk '{print $1}')"
  if [[ $owner == 'root' ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}$stat${NORMAL}"
    fail=0
  else
    echo -e "${NORMAL}RESULT:    ${RED}$stat${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity33, $controlid, $stigid33, $ruleid33, $cci33, $datetime, ${GRN}PASSED, RHEL 9 /etc/passwd file is owned by root.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity33, $controlid, $stigid33, $ruleid33, $cci33, $datetime, ${RED}FAILED, RHEL 9 /etc/passwd file is not owned by root.${NORMAL}"
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

fail=1

datetime="$(date +%FT%H:%M:%S)"

stat="$(stat -c "%G %n" /etc/passwd)"

if [[ $stat ]]
then
  owner="$(echo $stat | awk '{print $1}')"
  if [[ $owner == 'root' ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}$stat${NORMAL}"
    fail=0
  else
    echo -e "${NORMAL}RESULT:    ${RED}$stat${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity34, $controlid, $stigid34, $ruleid34, $cci34, $datetime, ${GRN}PASSED, RHEL 9 /etc/passwd file is group-owned by root.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity34, $controlid, $stigid34, $ruleid34, $cci34, $datetime, ${RED}FAILED, RHEL 9 /etc/passwd file is not group-owned by root.${NORMAL}"
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

fail=1

datetime="$(date +%FT%H:%M:%S)"

stat="$(stat -c "%U %n" /etc/passwd-)"

if [[ $stat ]]
then
  owner="$(echo $stat | awk '{print $1}')"
  if [[ $owner == 'root' ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}$stat${NORMAL}"
    fail=0
  else
    echo -e "${NORMAL}RESULT:    ${RED}$stat${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity35, $controlid, $stigid35, $ruleid35, $cci35, $datetime, ${GRN}PASSED, RHEL 9 /etc/passwd- file is owned by root.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity35, $controlid, $stigid35, $ruleid35, $cci35, $datetime, ${RED}FAILED, RHEL 9 /etc/passwd- file is not owned by root.${NORMAL}"
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

fail=1

datetime="$(date +%FT%H:%M:%S)"

stat="$(stat -c "%G %n" /etc/passwd-)"

if [[ $stat ]]
then
  owner="$(echo $stat | awk '{print $1}')"
  if [[ $owner == 'root' ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}$stat${NORMAL}"
    fail=0
  else
    echo -e "${NORMAL}RESULT:    ${RED}$stat${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity36, $controlid, $stigid36, $ruleid36, $cci36, $datetime, ${GRN}PASSED, RHEL 9 /etc/passwd- file is group-owned by root.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity36, $controlid, $stigid36, $ruleid36, $cci36, $datetime, ${RED}FAILED, RHEL 9 /etc/passwd- file is not group-owned by root.${NORMAL}"
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

fail=1

datetime="$(date +%FT%H:%M:%S)"

stat="$(stat -c "%U %n" /etc/shadow)"

if [[ $stat ]]
then
  owner="$(echo $stat | awk '{print $1}')"
  if [[ $owner == 'root' ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}$stat${NORMAL}"
    fail=0
  else
    echo -e "${NORMAL}RESULT:    ${RED}$stat${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity37, $controlid, $stigid37, $ruleid37, $cci37, $datetime, ${GRN}PASSED, RHEL 9 /etc/shadow file is owned by root.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity37, $controlid, $stigid37, $ruleid37, $cci37, $datetime, ${RED}FAILED, RHEL 9 /etc/shadow file is not owned by root.${NORMAL}"
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

fail=1

datetime="$(date +%FT%H:%M:%S)"

stat="$(stat -c "%G %n" /etc/shadow)"

if [[ $stat ]]
then
  owner="$(echo $stat | awk '{print $1}')"
  if [[ $owner == 'root' ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}$stat${NORMAL}"
    fail=0
  else
    echo -e "${NORMAL}RESULT:    ${RED}$stat${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity38, $controlid, $stigid38, $ruleid38, $cci38, $datetime, ${GRN}PASSED, RHEL 9 /etc/shadow file is group-owned by root.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity38, $controlid, $stigid38, $ruleid38, $cci38, $datetime, ${RED}FAILED, RHEL 9 /etc/shadow file is not group-owned by root.${NORMAL}"
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

fail=1

datetime="$(date +%FT%H:%M:%S)"

stat="$(stat -c "%U %n" /etc/shadow-)"

if [[ $stat ]]
then
  owner="$(echo $stat | awk '{print $1}')"
  if [[ $owner == 'root' ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}$stat${NORMAL}"
    fail=0
  else
    echo -e "${NORMAL}RESULT:    ${RED}$stat${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity39, $controlid, $stigid39, $ruleid39, $cci39, $datetime, ${GRN}PASSED, RHEL 9 /etc/shadow- file is owned by root.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity39, $controlid, $stigid39, $ruleid39, $cci39, $datetime, ${RED}FAILED, RHEL 9 /etc/shadow- file is not owned by root.${NORMAL}"
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

fail=1

datetime="$(date +%FT%H:%M:%S)"

stat="$(stat -c "%G %n" /etc/shadow-)"

if [[ $stat ]]
then
  owner="$(echo $stat | awk '{print $1}')"
  if [[ $owner == 'root' ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}$stat${NORMAL}"
    fail=0
  else
    echo -e "${NORMAL}RESULT:    ${RED}$stat${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity40, $controlid, $stigid40, $ruleid40, $cci40, $datetime, ${GRN}PASSED, RHEL 9 /etc/shadow- file is group-owned by root.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity40, $controlid, $stigid40, $ruleid40, $cci40, $datetime, ${RED}FAILED, RHEL 9 /etc/shadow- file is not group-owned by root.${NORMAL}"
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

fail=0

datetime="$(date +%FT%H:%M:%S)"

stat="$(stat -c "%U %n" /etc/cron*)"

if [[ $stat ]]
then
  for line in ${stat[@]}
  do
    owner="$(echo $line | awk '{print $1}')"
    if [[ $owner == 'root' ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
      fail=1
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity41, $controlid, $stigid41, $ruleid41, $cci41, $datetime, ${GRN}PASSED, RHEL 9 /etc/cron files are owned by root.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity41, $controlid, $stigid41, $ruleid41, $cci41, $datetime, ${RED}FAILED, Some or all RHEL 9 /etc/cron files are not owned by root.${NORMAL}"
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

fail=0

datetime="$(date +%FT%H:%M:%S)"

stat="$(stat -c "%G %n" /etc/cron*)"

if [[ $stat ]]
then
  for line in ${stat[@]}
  do
    owner="$(echo $line | awk '{print $1}')"
    if [[ $owner == 'root' ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
      fail=1
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity42, $controlid, $stigid42, $ruleid42, $cci42, $datetime, ${GRN}PASSED, RHEL 9 /etc/cron files are group-owned by root.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity42, $controlid, $stigid42, $ruleid42, $cci42, $datetime, ${RED}FAILED, Some or all RHEL 9 /etc/cron files are not owned by root.${NORMAL}"
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

fail=0

datetime="$(date +%FT%H:%M:%S)"

notvalid="$(df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nogroup 2>/dev/null)"

if [[ $notvalid ]]
then
  fail=1
  for line in ${notvalid[@]}
  do
    echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
  done
else
  echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity43, $controlid, $stigid43, $ruleid43, $cci43, $datetime, ${GRN}PASSED, All RHEL 9 local files and directories have valid group owners.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity43, $controlid, $stigid43, $ruleid43, $cci43, $datetime, ${RED}FAILED, Some or all RHEL 9 files and or directories do not have valid group owners.${NORMAL}"
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

fail=0

datetime="$(date +%FT%H:%M:%S)"

notvalid="$(df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nouser 2>/dev/null)"

if [[ $notvalid ]]
then
  fail=1
  for line in ${notvalid[@]}
  do
    echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
  done
else
  echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity44, $controlid, $stigid44, $ruleid44, $cci44, $datetime, ${GRN}PASSED, All RHEL 9 local files and directories have valid owners.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity44, $controlid, $stigid44, $ruleid44, $cci44, $datetime, ${RED}FAILED, Some or all RHEL 9 files and or directories do not have valid owners.${NORMAL}"
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

fail=1

datetime="$(date +%FT%H:%M:%S)"

mode="$(stat -c "%a %n" /etc/shadow)"
if [[ $mode ]]
then
  if [[ ${mode:0:2} == "0 " ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}$mode${NORMAL}"
    fail=0
  else
    echo -e "${NORMAL}RESULT:    ${RED}$mode${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity45, $controlid, $stigid45, $ruleid45, $cci45, $datetime, ${GRN}PASSED, The RHEL 9 /etc/shadow file is mode 0000 to prevent unauthorized access.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity45, $controlid, $stigid45, $ruleid45, $cci45, $datetime, ${RED}FAILED, The RHEL 9 /etc/shadow file is not mode 0000 to prevent unauthorized access.${NORMAL}"
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

fail=0

datetime="$(date +%FT%H:%M:%S)"

promiscuous="$(ip link | grep -i promisc)"

if [[ $promiscuous ]]
then
  fail=1
  for line in ${promiscuous[@]}
  do
    echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
  done
else
  echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity46, $controlid, $stigid46, $ruleid46, $cci46, $datetime, ${GRN}PASSED, There are no RHEL 9 interfaces in promiscuous mode.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity46, $controlid, $stigid46, $ruleid46, $cci46, $datetime, ${RED}FAILED, There are RHEL 9 interfaces in promiscuous mode.${NORMAL}"
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

fail=0

datetime="$(date +%FT%H:%M:%S)"

shosts="$(find / -name shosts.equiv 2>/dev/null)"

if [[ $shosts ]]
then
  fail=1
  for line in ${shosts[@]}
  do
    echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
  done
else
  echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity47, $controlid, $stigid47, $ruleid47, $cci47, $datetime, ${GRN}PASSED, There are no \"shosts.equiv\" files.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity47, $controlid, $stigid47, $ruleid47, $cci47, $datetime, ${RED}FAILED, A \"shosts.equiv\" file was found.${NORMAL}"
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

fail=0

datetime="$(date +%FT%H:%M:%S)"

shosts="$(find / -name .shosts 2>/dev/null)"

if [[ $shosts ]]
then
  fail=1
  for line in ${shosts[@]}
  do
    echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
  done
else
  echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity48, $controlid, $stigid48, $ruleid48, $cci48, $datetime, ${GRN}PASSED, There are no \".shosts\" files.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity48, $controlid, $stigid48, $ruleid47, $cci48, $datetime, ${RED}FAILED, A \".shosts\" file was found.${NORMAL}"
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

fail=0

datetime="$(date +%FT%H:%M:%S)"

defsendredir="$(sysctl net.ipv4.conf.default.send_redirects)"
if [[ $defsendredir ]]
then
  defsendredirval="$(echo $defsendredir | awk -F= '{print $2}' | sed 's/ //g' 2>/dev/null)"
  if [[ $defsendredirval == 0 && ${defsendredir:0:1} != "#" ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}a. $defsendredir${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}a. $defsendredir${NORMAL}"
    fail=1
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}a. \"net.ipv4.conf.default.send_redirects\" not defined${NORMAL}"
  fail=1
fi

isconfig="$(/usr/lib/systemd/systemd-sysctl --cat-config | egrep -v '^(#|;)' | grep -F net.ipv4.conf.default.send_redirects | tail -1 2>/dev/null)"
if [[ $isconfig ]]
then
  for line in ${isconfig[@]}
  do
    isconfigval="$(echo $line | awk -F= '{print $2}' | sed 's/ //g')"
    if [[ $isconfigval != 0 && ${isconfig:0:1} != "#" ]]
    then
      echo -e "${NORMAL}RESULT:    ${RED}b. $line${NORMAL}"
      fail=1
    else
      echo -e "${NORMAL}RESULT:    ${BLD}b. $line${NORMAL}"
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${RED}b. \"net.ipv4.conf.default.send_redirects\" not defined.${NORMAL}"
  fail=1
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity49, $controlid, $stigid49, $ruleid49, $cci49, $datetime, ${GRN}PASSED, RHEL 9 does not allow interfaces to perform IPv4 Internet Control Message Protocol (ICMP) redirects by default.${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity49, $controlid, $stigid49, $ruleid49, $cci49, $datetime, ${RED}FAILED, RHEL 9 either allows interfaces to perform IPv4 Internet Control Message Protocol (ICMP) redirects by default or it is not defined in a config file.${NORMAL}"
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

fail=0

datetime="$(date +%FT%H:%M:%S)"

mode="$(stat -c "%a %n" /etc/ssh/*.pub)"
if [[ $mode ]]
then
  for line in ${mode[@]}
  do
    if  (( ${line:0:1} <= 6 &&
           ${line:1:1} <= 4 &&
           ${line:2:1} <= 4
        ))
    then
      echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
      fail=1
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity50, $controlid, $stigid50, $ruleid50, $cci50, $datetime, ${GRN}PASSED, RHEL 9 SSH public host key files are mode 0644 or less permissive.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity50, $controlid, $stigid50, $ruleid50, $cci50, $datetime, ${RED}FAILED, RHEL 9 SSH public host key files are not mode 0644 or less permissive.${NORMAL}"
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

fail=1

datetime="$(date +%FT%H:%M:%S)"

delayed="$(/usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs grep -iH '^\s*compression' | awk -F: '{print $2}')"

if [[ $delayed ]]
then
  delayedval="$(echo $delayed | awk '{print $2}')"
  if [[ $delayedval != "yes" && ${delayed:0:1} != "#" ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}$delayed${NORMAL}"
    fail=0
  else
    echo -e "${NORMAL}RESULT:    ${RED}$delayed${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity51, $controlid, $stigid51, $ruleid51, $cci51, $datetime, ${GRN}PASSED, RHEL 9 SSH daemon does not allow compression or only allows compression after successful authentication.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity51, $controlid, $stigid51, $ruleid51, $cci51, $datetime, ${RED}FAILED, RHEL 9 SSH daemon allows compression.${NORMAL}"
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

fail=0

datetime="$(date +%FT%H:%M:%S)"

isinstalled="$(dnf list --installed 2>&1 gnutls-utils | grep -Ev 'Updating|Installed')"

if [[ $isinstalled ]]
then

  update="$(function dconf_needs_update { for db in $(find /etc/dconf/db -maxdepth 1 -type f); do db_mtime=$(stat -c %Y "$db"); keyfile_mtime=$(stat -c %Y "$db".d/* | sort -n | tail -1); if [ -n "$db_mtime" ] && [ -n "$keyfile_mtime" ] && [ "$db_mtime" -lt "$keyfile_mtime" ]; then echo "$db needs update"; return 1; fi; done; }; dconf_needs_update)"

  if [[ $update ]]
  then
    fail=1
    echo -e "${NORMAL}RESULT:    ${RED}$update${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}The default Gnome graphical user interface is not installed.${NORMAL}"
  fail=2
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity52, $controlid, $stigid52, $ruleid52, $cci52, $datetime, ${GRN}PASSED, The effective RHEL 9 dconf policy matches the policy keyfiles.${NORMAL}"
elif [[ $fail == 2 ]]
then
  echo -e "${NORMAL}$hostname, $severity52, $controlid, $stigid52, $ruleid52, $cci52, $datetime, ${GRN}N/A, The RHEL 9 default graphical user interface is not installed. This requirement is Not Applicable.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity52, $controlid, $stigid52, $ruleid52, $cci52, $datetime, ${RED}FAILED, The effective RHEL 9 dconf policy does not match the policy keyfiles.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid53${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid53${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid53${NORMAL}"
echo -e "${NORMAL}CCI:       $cci53${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 53:   ${BLD}$title53a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title53b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title53c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity53${NORMAL}"

IFS='
'

fail=1

datetime="$(date +%FT%H:%M:%S)"

isset="$(grep -i create_home /etc/login.defs)"

if [[ $isset ]]
then
  setval="$(echo $isset | awk '{print $2}')"
  if [[ $setval == "yes" ]]
  then
    fail=0
    echo -e "${NORMAL}RESULT:    ${BLD}$isset${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}$isset${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity53, $controlid, $stigid53, $ruleid53, $cci53, $datetime, ${GRN}PASSED, All local interactive users on RHEL 9 are assigned a home directory upon creation.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity53, $controlid, $stigid53, $ruleid53, $cci53, $datetime, ${RED}FAILED, All local interactive users on RHEL 9 are not assigned a home directory upon creation.${NORMAL}"
fi

echo
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

fail=0

datetime="$(date +%FT%H:%M:%S)"

accounts="$(awk -F: '($3<1000){print $1 ":" $3 ":" $7}' /etc/passwd)"

if [[ $accounts ]]
then
  for line in ${accounts[@]}
  do
    login="$(echo $line | awk -F: '{print $1}')"
    shell="$(echo $line | awk -F: '{print $3}')"
    if ! [[ $shell =~ ('nologin'|'sync'|'shutdown'|'halt'|'false') ]]
    then
      if [[ $login != "root" ]]
      then
        fail=1
        echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
      else
        echo -e "${NORMAL}RESULT:    $line${NORMAL}"
      fi
    else
      echo -e "${NORMAL}RESULT:    $line${NORMAL}"
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity54, $controlid, $stigid54, $ruleid54, $cci54, $datetime, ${GRN}PASSED, RHEL 9 system accounts do not have an interactive login shell.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity54, $controlid, $stigid54, $ruleid54, $cci54, $datetime, ${RED}FAILED, RHEL 9 system accounts have an interactive login shell.${NORMAL}"
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

fail=0

datetime="$(date +%FT%H:%M:%S)"

accounts="$(awk -F: '($3>=1000)&&($7 !~ /nologin/){print $1, $3, $6}' /etc/passwd)"

if [[ $accounts ]]
then
  for line in ${accounts[@]}
  do
    homedir="$(echo $line | awk '{print $3}')"
    if [[ $homedir ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
    else
      fail=1
      echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
    fi
  done
else
  echo -e "${NORMAL}RESULT:    Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity55, $controlid, $stigid55, $ruleid55, $cci55, $datetime, ${GRN}PASSED, All RHEL 9 local interactive users have a home directory assigned in the /etc/passwd file.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity55, $controlid, $stigid55, $ruleid55, $cci55, $datetime, ${RED}FAILED, All RHEL 9 local interactive users do not have a home directory assigned in the /etc/passwd file.${NORMAL}"
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

fail=0

datetime="$(date +%FT%H:%M:%S)"

nohomedir="$(pwck -r | grep -v pwck)"

if [[ $nohomedir ]]
then
  for line in ${nohomedir[@]}
  do
    user="$(echo $line | awk -F"'" '{print $2}')"
    uid="$(grep $user /etc/passwd | awk -F: '{print $3}')"
    if (( $uid >= 1000 ))
    then
      fail=1
      echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    $line ($user is not an interactive user)${NORMAL}"
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity56, $controlid, $stigid56, $ruleid56, $cci56, $datetime, ${GRN}PASSED, All RHEL 9 local interactive user home directories defined in the /etc/passwd file exist.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity56, $controlid, $stigid56, $ruleid56, $cci56, $datetime, ${RED}FAILED, All RHEL 9 local interactive user home directories defined in the /etc/passwd file do not exist.${NORMAL}"
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

fail=0

datetime="$(date +%FT%H:%M:%S)"

file57a="/etc/passwd"
file57b="/etc/group"
fail=0

udperm="$(ls -ld $(awk -F: '($3>=1000)&&($7 !~ /nologin/){print $6}' /etc/passwd))"
if [[ ${#udperm[@]} > 0 ]]
then
  for line in ${udperm[@]}
  do
    home="$(echo $line | awk '{print $9}')"
    user="$(echo $home | awk -F '/' '{print $3}')"
    uid="$(id $user)"
    gid="$(echo $line | awk '{print $4}')"
    pgid="$(grep $(grep $user /etc/passwd | awk -F: '{print $4}') /etc/group)"
    if [[ $(echo $pgid | awk -F: '{print $1}') == $gid ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}a. $line is group-owned by $user's primary gid\n           b. $uid${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${RED}a. $line is not group-owned by $user's primary gid\n           b. $uid${NORMAL}"
      fail=1
    fi
  done
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity57, $controlid, $stigid57, $ruleid57, $cci57, $datetime, ${GRN}PASSED, All RHEL 9 local interactive user home directories are group-owned by the home directory owner's primary group.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity57, $controlid, $stigid57, $ruleid57, $cci57, $datetime, ${RED}FAILED, All RHEL 9 local interactive user home directories are not group-owned by the home directory owner's primary group.${NORMAL}"
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

fail=1

datetime="$(date +%FT%H:%M:%S)"

isroot="$(awk -F: '$3 == 0 {print $1}' /etc/passwd)"

if [[ ${#isroot[@]} = 1 && ${isroot[0]} == "root" ]]
then
  fail=0
  echo -e "${NORMAL}RESULT:    ${BLD}${isroot[0]}${NORMAL}"
else
  for line in ${isroot[@]}
  do
    echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
  done
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity58, $controlid, $stigid58, $ruleid58, $cci58, $datetime, ${GRN}PASSED, The root account is the only account having unrestricted access to RHEL 9 system.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity58, $controlid, $stigid58, $ruleid58, $cci58, $datetime, ${RED}FAILED, The root account is not the only account having unrestricted access to RHEL 9 system.${NORMAL}"
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

fail=0

datetime="$(date +%FT%H:%M:%S)"

worldwritable="$(find /home -perm -002 -type f -name ".[^.]*" -exec ls -ld {} \;)"

if [[ $worldwritable ]]
then
  fail=1
  for line in ${worldwritable[@]}
  do
    echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
  done
else
  echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity59, $controlid, $stigid59, $ruleid59, $cci59, $datetime, ${GRN}PASSED, Local RHEL 9 initialization files do not execute world-writable programs.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity59, $controlid, $stigid59, $ruleid59, $cci59, $datetime, ${RED}FAILED, Local RHEL 9 initialization files execute world-writable programs.${NORMAL}"
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

fail=1

datetime="$(date +%FT%H:%M:%S)"

delay="$(grep -i fail_delay /etc/login.defs)"

if [[ $delay ]]
then
  for line in ${delay[@]}
  do
    delayval="$(echo $line| awk '{print $2}')"
    if [[ ${line:0:1} != "#" ]] && (( $delayval >= 4 ))
    then
      echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
      fail=0
    else
      echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity60, $controlid, $stigid60, $ruleid60, $cci60, $datetime, ${GRN}PASSED, RHEL 9 enforces a delay of at least four seconds between logon prompts following a failed logon attempt.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity60, $controlid, $stigid60, $ruleid60, $cci60, $datetime, ${RED}FAILED, RHEL 9 does not enforce a delay of at least four seconds between logon prompts following a failed logon attempt.${NORMAL}"
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

fail=1

datetime="$(date +%FT%H:%M:%S)"

mask="$(grep -i umask /etc/login.defs)"

if [[ $mask ]]
then
  for line in ${mask[@]}
  do
    maskval="$(echo $line| awk '{print $2}')"
    if [[ ${line:0:1} != "#" ]] && (( $maskval == "077" ))
    then
      echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
      fail=0
    else
      echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity61, $controlid, $stigid61, $ruleid61, $cci61, $datetime, ${GRN}PASSED, RHEL 9 defines default permissions for all authenticated users in such a way that the user can only read and modify their own files.${NORMAL}"
elif [[ $fail == 2 ]]
then
  echo -e "${NORMAL}$hostname, $severity61, $controlid, $stigid61, $ruleid61, $cci61, $datetime, ${RED}FAILED, RHEL 9's definition of default permissions for all authenticated users is incorrect.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity61, $controlid, $stigid61, $ruleid61, $cci61, $datetime, ${RED}FAILED, RHEL 9 does not define default permissions for all authenticated users in such a way that the user can only read and modify their own files.${NORMAL}"
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

fail=1

datetime="$(date +%FT%H:%M:%S)"

mask="$(grep umask /etc/profile)"

if [[ $mask ]]
then
  for line in ${mask[@]}
  do
    maskval="$(echo $line| awk '{print $2}')"
    if [[ ${line:0:1} != "#" ]] && (( $maskval == "077" ))
    then
      echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
      fail=0
    else
      echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity62, $controlid, $stigid62, $ruleid62, $cci62, $datetime, ${GRN}PASSED, RHEL 9 defines default permissions for the system default profile as \"077\".${NORMAL}"
elif [[ $fail == 2 ]]
then
  echo -e "${NORMAL}$hostname, $severity62, $controlid, $stigid62, $ruleid62, $cci62, $datetime, ${RED}FAILED, RHEL 9's definition of default permissions for the system default profile is incorrect.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity62, $controlid, $stigid62, $ruleid62, $cci62, $datetime, ${RED}FAILED, RHEL 9 does not define default permissions for the system default profile.${NORMAL}"
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

fail=1

file63="/etc/pam.d/postlogin"
datetime="$(date +%FT%H:%M:%S)"

if [[ -e $file63 ]]
then
  lastlogon="$(grep pam_lastlog $file63)"
  if [[ $lastlogon ]]
  then
    for line in ${lastlogon[@]}
    do
      if [[ $line =~ ('default=1'|'required') ]]
      then
        echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
	fail=0
      elif [[ $lastlogon =~ "silent" && ${lastlogon:0:1} != "#" ]] ||
  	   [[ ${lastlogon:0:1} == "#" ]]
      then
        echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
      else
        echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
      fi
    done
  else
    echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}$file63 not found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity63, $controlid, $stigid63, $ruleid63, $cci63, $datetime, ${GRN}PASSED, RHEL 9 displays the date and time of the last successful account logon upon logon.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity63, $controlid, $stigid63, $ruleid63, $cci63, $datetime, ${RED}FAILED, RHEL 9 does not display the date and time of the last successful account logon upon logon.${NORMAL}"
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

fail=0

datetime="$(date +%FT%H:%M:%S)"

isblank="$(awk -F: '!$2 {print $1}' /etc/shadow)"

if [[ $isblank ]]
then
  fail=1
  for line in ${isblank[@]}
  do
    echo -e "${NORMAL}RESULT:    ${RED}$line has no password${NORMAL}"
  done
else
  echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity64, $controlid, $stigid64, $ruleid64, $cci64, $datetime, ${GRN}PASSED, RHEL 9 does not have accounts configured with blank or null passwords.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity64, $controlid, $stigid64, $ruleid64, $cci64, $datetime, ${RED}FAILED, RHEL 9 has accounts configured with blank or null passwords.${NORMAL}"
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

fail=1

datetime="$(date +%FT%H:%M:%S)"

isactive="$(systemctl is-active rsyslog)"

if [[ $isactive && $isactive == "active" ]]
then
  if [[ $isactive == "active" ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}$isactive${NORMAL}"
    fail=0
  else
    echo -e "${NORMAL}RESULT:    ${RED}$isactive${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity65, $controlid, $stigid65, $ruleid65, $cci65, $datetime, ${GRN}PASSED, The rsyslog service on RHEL 9 is active.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity65, $controlid, $stigid65, $ruleid65, $cci65, $datetime, ${RED}FAILED, The rsyslog service on RHEL 9 is not active.${NORMAL}"
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

fail=1

datetime="$(date +%FT%H:%M:%S)"

format="$(grep log_format /etc/audit/auditd.conf)"

if [[ $format ]]
then
  value="$(echo $format | awk -F= '{print $2}' | sed 's/ //')"
  if [[ $value == "ENRICHED" ]]
  then
    fail=0
    echo -e "${NORMAL}RESULT:    ${BLD}$format${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}$format${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity66, $controlid, $stigid66, $ruleid66, $cci66, $datetime, ${GRN}PASSED, RHEL 9 produces audit records containing information to establish the identity of any individual or process associated with the event.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity66, $controlid, $stigid66, $ruleid66, $cci66, $datetime, ${RED}FAILED, RHEL 9 does not produce audit records containing information to establish the identity of any individual or process associated with the event.${NORMAL}"
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

fail=1

datetime="$(date +%FT%H:%M:%S)"

writelogs="$(grep write_logs /etc/audit/auditd.conf)"

if [[ $writelogs ]]
then
  value="$(echo $writelogs | awk -F= '{print $2}' | sed 's/ //')"
  if [[ $value == "yes" ]]
  then
    fail=0
    echo -e "${NORMAL}RESULT:    ${BLD}$writelogs${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}$writelogs${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity67, $controlid, $stigid67, $ruleid67, $cci67, $datetime, ${GRN}PASSED, RHEL 9 writes audit records to disk.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity67, $controlid, $stigid67, $ruleid67, $cci67, $datetime, ${RED}FAILED, RHEL 9 does not write audit records to disk.${NORMAL}"
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

fail=0

datetime="$(date +%FT%H:%M:%S)"

spawn="$(grubby --info=ALL | grep args | grep 'systemd.confirm_spawn')"

if [[ $spawn ]]
then
  fail=1
  for line in ${spawn[@]}
  do
    echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
  done
else
  echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity68, $controlid, $stigid68, $ruleid68, $cci68, $datetime, ${GRN}PASSED, RHEL 9 disables the ability of systemd to spawn an interactive boot process.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity68, $controlid, $stigid68, $ruleid68, $cci68, $datetime, ${RED}FAILED, RHEL 9 does not disable the ability of systemd to spawn an interactive boot process.${NORMAL}"
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

fail=1

datetime="$(date +%FT%H:%M:%S)"

pattern="$(sysctl kernel.core_pattern)"

if [[ $pattern ]]
then
  setting="$(echo $pattern | awk -F= '{print $2}' | sed 's/ //')"
  if [[ $setting == "|/bin/false" ]]
  then
    fail=0
    echo -e "${NORMAL}RESULT:    ${BLD}$pattern${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}$pattern${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity69, $controlid, $stigid69, $ruleid69, $cci69, $datetime, ${GRN}PASSED, RHEL 9 disables the kernel.core_pattern.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity69, $controlid, $stigid69, $ruleid69, $cci69, $datetime, ${RED}FAILED, RHEL 9 does not disable the kernel.core_pattern.${NORMAL}"
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

fail=1

datetime="$(date +%FT%H:%M:%S)"

sizemax="$(grep -i ProcessSizeMax /etc/systemd/coredump.conf)"

if [[ $sizemax ]]
then
  for line in ${sizemax[@]}
  do
    value="$(echo $line | awk -F= '{print $2}')"
    if [[ $value == 0 && ${line:0:1} != "#" ]]
    then
      fail=0
      echo -e "${NORMAL}RESULT:    ${BLD}$sizemax${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${RED}$sizemax${NORMAL}"
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity70, $controlid, $stigid70, $ruleid70, $cci70, $datetime, ${GRN}PASSED, RHEL 9 disables core dump backtraces.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity70, $controlid, $stigid70, $ruleid70, $cci70, $datetime, ${RED}FAILED, RHEL 9 does not disable core dump backtraces.${NORMAL}"
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

fail=1

datetime="$(date +%FT%H:%M:%S)"

usermax="$(sysctl user.max_user_namespaces)"

if [[ $usermax ]]
then
  for line in ${usermax[@]}
  do
    value="$(echo $line | awk -F= '{print $2}' | sed 's/ //')"
    if [[ $value == 0 && ${line:0:1} != "#" ]]
    then
      fail=0
      echo -e "${NORMAL}RESULT:    ${BLD}$usermax${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${RED}$usermax${NORMAL}"
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity71, $controlid, $stigid71, $ruleid71, $cci71, $datetime, ${GRN}PASSED, RHEL 9 disables the use of user namespaces.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity71, $controlid, $stigid71, $ruleid71, $cci71, $datetime, ${RED}FAILED, RHEL 9 does not disable the use of user namespaces.${NORMAL}"
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

isdisabled="$(systemctl is-active kdump)"
ismasked="$(systemctl show kdump | grep "LoadState\|UnitFileState")"

if [[ $isdisabled ]]
then
  if [[ $isdisabled == "masked" || $isdisabled == "inactive" ]]
  then
    disabled=1
    echo -e "${NORMAL}RESULT:    ${BLD}a. $isdisabled${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}a. $isdisabled${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}a. Nothing returned${NORMAL}"
fi

if [[ $ismasked ]]
then
  masked=0
  for line in ${ismasked[@]}
  do
    if [[ $line =~ '=masked' ]]
    then
      masked=1
      echo -e "${NORMAL}RESULT:    ${BLD}b. $line${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${RED}b. $line${NORMAL}"
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${RED}b. Nothing returned${NORMAL}"
fi

if [[ $disabled == 1 && $masked == 1 ]]
then
  echo -e "${NORMAL}$hostname, $severity72, $controlid, $stigid72, $ruleid72, $cci72, $datetime, ${GRN}PASSED, The kdump service on RHEL 9 is disabled.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity72, $controlid, $stigid72, $ruleid72, $cci72, $datetime, ${RED}FAILED, The kdump service on RHEL 9 is not disabled.${NORMAL}"
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

fail=0

datetime="$(date +%FT%H:%M:%S)"

hashmatch=$(rpm -Va --noconfig | awk '$1 ~ /..5/ && $2 != "c"')

if [[ $hashmatch ]]
then
  fail=1
  for line in ${hashmatch[@]}
  do
    echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
  done
else
  echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity73, $controlid, $stigid73, $ruleid73, $cci73, $datetime, ${GRN}PASSED, RHEL 9 is configured so that the cryptographic hashes of system files match vendor values.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity73, $controlid, $stigid73, $ruleid73, $cci73, $datetime, ${RED}FAILED, RHEL 9 is not configured so that the cryptographic hashes of system files match vendor values.${NORMAL}"
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

fail=1

datetime="$(date +%FT%H:%M:%S)"

isinstalled="$(dnf list --installed 2>&1 tftp-server | grep -Ev 'Updating|Installed')"

if [[ $isinstalled ]]
then
  if [[ $isinstalled =~ "No matching Packages" ]]
  then
    fail=0
    for line in ${isinstalled[@]}
    do
      if [[ $line =~ "Error:" ]]
      then
	echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
      fi
    done
  else
    for line in ${isinstalled[@]}
    do
      echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
    done
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity74, $controlid, $stigid74, $ruleid74, $cci74, $datetime, ${GRN}PASSED, RHEL 9 does not have a Trivial File Transfer Protocol (TFTP) server package installed.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity74, $controlid, $stigid74, $ruleid74, $cci74, $datetime, ${RED}FAILED, RHEL 9 has a Trivial File Transfer Protocol (TFTP) server package installed.${NORMAL}"
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

fail=1

datetime="$(date +%FT%H:%M:%S)"

isinstalled="$(dnf list --installed 2>&1 quagga | grep -Ev 'Updating|Installed')"

if [[ $isinstalled ]]
then
  if [[ $isinstalled =~ "No matching Packages" ]]
  then
    fail=0
    for line in ${isinstalled[@]}
    do
      if [[ $line =~ "Error:" ]]
      then
        echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
      fi
    done
  else
    for line in ${isinstalled[@]}
    do
      echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
    done
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity75, $controlid, $stigid75, $ruleid75, $cci75, $datetime, ${GRN}PASSED, RHEL 9 does not have the quagga package installed.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity75, $controlid, $stigid75, $ruleid75, $cci75, $datetime, ${RED}FAILED, RHEL 9 has the quaagga package installed.${NORMAL}"
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

fail=1

datetime="$(date +%FT%H:%M:%S)"

isinstalled="$(dnf list --installed 2>&1 'xorg-x11-server-common' | grep -Ev 'Updating|Installed')"

if [[ $isinstalled ]]
then
  if [[ $isinstalled =~ "No matching Packages" ]]
  then
    fail=0
    for line in ${isinstalled[@]}
    do
      if [[ $line =~ "Error:" ]]
      then
        echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
      fi
    done
  else
    for line in ${isinstalled[@]}
    do
      echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
    done
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity76, $controlid, $stigid76, $ruleid76, $cci76, $datetime, ${GRN}PASSED, RHEL 9 does not have a graphical display manager package installed.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity76, $controlid, $stigid76, $ruleid76, $cci76, $datetime, ${RED}FAILED, RHEL 9 has a graphical display manager package installed.${NORMAL}"
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

fail=0

datetime="$(date +%FT%H:%M:%S)"

isinstalled="$(dnf list --installed 2>&1 rng-tools | grep -Ev 'Updating|Installed')"

if [[ $isinstalled ]]
then
  if [[ $isinstalled =~ "No matching Packages" ]]
  then
    fail=1
    for line in ${isinstalled[@]}
    do
      if [[ $line =~ "Error:" ]]
      then
        echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
      fi
    done
  else
    for line in ${isinstalled[@]}
    do
      echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
    done
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity77, $controlid, $stigid77, $ruleid77, $cci77, $datetime, ${GRN}PASSED, RHEL 9 has the rng-tools package installed.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity77, $controlid, $stigid77, $ruleid77, $cci77, $datetime, ${RED}FAILED, RHEL 9 does not have the rng-tools package installed.${NORMAL}"
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

fail=1

datetime="$(date +%FT%H:%M:%S)"

fs="$(mount | grep /tmp | grep 'on /tmp ')"

if [[ $fs ]]
then
  fail=0  
  echo -e "${NORMAL}RESULT:    ${BLD}$fs${NORMAL}"
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity78, $controlid, $stigid78, $ruleid78, $cci78, $datetime, ${GRN}PASSED, RHEL 9 uses a separate file system for /tmp.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity78, $controlid, $stigid78, $ruleid78, $cci78, $datetime, ${RED}FAILED, RHEL 9 does not use a separate file system for /tmp.${NORMAL}"
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

fail=1

datetime="$(date +%FT%H:%M:%S)"

fs="$(mount | grep /var | grep 'on /var ')"

if [[ $fs ]]
then
  fail=0
  echo -e "${NORMAL}RESULT:    ${BLD}$fs${NORMAL}"
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity79, $controlid, $stigid79, $ruleid79, $cci79, $datetime, ${GRN}PASSED, RHEL 9 uses a separate file system for /var.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity79, $controlid, $stigid79, $ruleid79, $cci79, $datetime, ${RED}FAILED, RHEL 9 does not use a separate file system for /var.${NORMAL}"
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

fail=1

datetime="$(date +%FT%H:%M:%S)"

fs="$(mount | grep /var/log | grep 'on /var/log ')"

if [[ $fs ]]
then
  fail=0
  echo -e "${NORMAL}RESULT:    ${BLD}$fs${NORMAL}"
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity80, $controlid, $stigid80, $ruleid80, $cci80, $datetime, ${GRN}PASSED, RHEL 9 uses a separate file system for /var/log.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity80, $controlid, $stigid80, $ruleid80, $cci80, $datetime, ${RED}FAILED, RHEL 9 does not use a separate file system for /var/log.${NORMAL}"
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

fail=1

datetime="$(date +%FT%H:%M:%S)"

fs="$(mount | grep /var/tmp | grep 'on /var/tmp ')"

if [[ $fs ]]
then
  fail=0
  echo -e "${NORMAL}RESULT:    ${BLD}$fs${NORMAL}"
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity81, $controlid, $stigid81, $ruleid81, $cci81, $datetime, ${GRN}PASSED, RHEL 9 uses a separate file system for /var/tmp.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity81, $controlid, $stigid81, $ruleid81, $cci81, $datetime, ${RED}FAILED, RHEL 9 does not use a separate file system for /var/tmp.${NORMAL}"
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

fail=0

datetime="$(date +%FT%H:%M:%S)"

nfs="$(grep nfs /etc/fstab)"

if [[ $nfs ]]
then
  for line in ${nfs[@]}
  do
    if [[ $line =~ 'nodev' ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
    else
      fail=1
      echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
  fail=2
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity82, $controlid, $stigid82, $ruleid82, $cci82, $datetime, ${GRN}PASSED, RHEL 9 prevents special devices on file systems that are imported via Network File System (NFS).${NORMAL}"
elif [[ $fail == 2 ]]
then
  echo -e "${NORMAL}$hostname, $severity82, $controlid, $stigid82, $ruleid82, $cci82, $datetime, ${GRN}N/A, No file systems imported via Network File System (NFS) found. This requirement is Not Applicable.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity82, $controlid, $stigid82, $ruleid82, $cci82, $datetime, ${RED}FAILED, RHEL 9 does not prevent special devices on file systems that are imported via Network File System (NFS).${NORMAL}"
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

fail=0

datetime="$(date +%FT%H:%M:%S)"

nfs="$(grep nfs /etc/fstab)"

if [[ $nfs ]]
then
  for line in ${nfs[@]}
  do
    if [[ $line =~ 'noexec' ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
    else
      fail=1
      echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
  fail=2
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity83, $controlid, $stigid83, $ruleid83, $cci83, $datetime, ${GRN}PASSED, RHEL 9 prevents code from being executed on file systems that are imported via Network File System (NFS).${NORMAL}"
elif [[ $fail == 2 ]]
then
  echo -e "${NORMAL}$hostname, $severity83, $controlid, $stigid83, $ruleid83, $cci83, $datetime, ${GRN}N/A, No file systems imported via Network File System (NFS) found. This requirement is Not Applicable.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity83, $controlid, $stigid83, $ruleid83, $cci83, $datetime, ${RED}FAILED, RHEL 9 does not prevent code from being executed on file systems that are imported via Network File System (NFS).${NORMAL}"
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

fail=0

datetime="$(date +%FT%H:%M:%S)"

nfs="$(grep nfs /etc/fstab)"

if [[ $nfs ]]
then
  for line in ${nfs[@]}
  do
    if [[ $line =~ 'nosuid' ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
    else
      fail=1
      echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
  fail=2
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity84, $controlid, $stigid84, $ruleid84, $cci84, $datetime, ${GRN}PASSED, RHEL 9 prevents code from being executed on file systems that are imported via Network File System (NFS).${NORMAL}"
elif [[ $fail == 2 ]]
then
  echo -e "${NORMAL}$hostname, $severity84, $controlid, $stigid84, $ruleid84, $cci84, $datetime, ${GRN}N/A, No file systems imported via Network File System (NFS) found. This requirement is Not Applicable.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity84, $controlid, $stigid84, $ruleid84, $cci84, $datetime, ${RED}FAILED, RHEL 9 does not prevent code from being executed on file systems that are imported via Network File System (NFS).${NORMAL}"
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

fail=0

datetime="$(date +%FT%H:%M:%S)"

perms="$(rpm --verify cronie crontabs | awk '! ($2 == "c" && $1 ~ /^.\..\.\.\.\..\./) {print $0}')"

if [[ $perms ]]
then
  fail=1
  for line in ${perms[@]}
  do
    echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}" 
  done
else
  echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity85, $controlid, $stigid85, $ruleid85, $cci85, $datetime, ${GRN}PASSED, RHEL 9 permissions of cron configuration files and directories are not modified from the operating system defaults.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity85, $controlid, $stigid85, $ruleid85, $cci85, $datetime, ${RED}FAILED, RHEL 9 permissions of cron configuration files and directories are modified from the operating system defaults.${NORMAL}"
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

fail=0

datetime="$(date +%FT%H:%M:%S)"

users="$(awk -F: '($2 != "*" && $2 != "!*" && $2 != "!!" && $2 != ".") {print $1}' /etc/shadow)"
for usr in ${users[@]}
do
  homedir="$(grep $usr /etc/passwd | awk -F: '{print $6}')"
  fileperms="$(find $homedir/.[^.]* -maxdepth 0 -perm -740 -exec stat -c "%a %n" {} \; 2>/dev/null | more)" 
  if [[ $fileperms ]]
  then
    for line in ${fileperms[@]}
    do
      mode="$(echo $line | awk '{print $1}')"
      if [[ ${mode:1:1} > 4 ||
	    ${mode:2:1} > 0
         ]]
      then
	fail=1
        echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
      fi
    done
  fi
done

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
  echo -e "${NORMAL}$hostname, $severity86, $controlid, $stigid86, $ruleid86, $cci86, $datetime, ${GRN}PASSED, All RHEL 9 local initialization files are mode 0740 or less permissive.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity86, $controlid, $stigid86, $ruleid86, $cci86, $datetime, ${RED}FAILED, All RHEL 9 local initialization files are not mode 0740 or less permissive.${NORMAL}"
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

fail=0

datetime="$(date +%FT%H:%M:%S)"

homeperms="$(stat -L -c '%a %n' $(awk -F: '($3>=1000)&&($7 !~ /nologin/){print $6}' /etc/passwd) 2>/dev/null)"
if [[ $homeperms ]]
then
  for line in ${homeperms[@]}
  do
    mode="$(echo $line | awk '{print $1}')"
    if [[ ${mode:1:1} > 5 ||
          ${mode:2:1} > 0
       ]]
    then
      fail=1
      echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
    fi
  done
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
  echo -e "${NORMAL}$hostname, $severity87, $controlid, $stigid87, $ruleid87, $cci87, $datetime, ${GRN}PASSED, All RHEL 9 local local interactive user home directories are mode 0750 or less permissive.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity87, $controlid, $stigid87, $ruleid87, $cci87, $datetime, ${RED}FAILED, All RHEL 9 local local interactive user home directories are not mode 0750 or less permissive.${NORMAL}"
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

fail=0

datetime="$(date +%FT%H:%M:%S)"

cmd1="$(find /dev -context *:device_t:* \( -type c -o -type b \) -printf "%p %Z\n")"
cmd2="$(find /dev -context *:unlabeled_t:* \( -type c -o -type b \) -printf "%p %Z\n")"

cmdout=("$cmd1" "$cmd2")

if [[ $cmdout ]]
then
  fail=1
  for line in ${cmdout[@]}
  do
    echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
  done
else
  echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity88, $controlid, $stigid88, $ruleid88, $cci88, $datetime, ${GRN}PASSED, RHEL 9 is configured so that all system device files are correctly labeled to prevent unauthorized modification.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity88, $controlid, $stigid88, $ruleid88, $cci88, $datetime, ${RED}FAILED, RHEL 9 is not configured so that all system device files are correctly labeled to prevent unauthorized modification.${NORMAL}"
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

fail=0

datetime="$(date +%FT%H:%M:%S)"

fwstate="$(firewall-cmd --state)"
if [[ $fwstate == "running" ]]
then
  echo -e "${NORMAL}RESULT:    ${BLD}a. $fwstate${NORMAL}"
  default="$(firewall-cmd --get-default-zone)"
  zones="$(firewall-cmd --get-active-zones)"
  if [[ $zones ]]
  then
    zone=""
    for line in ${zones[@]}
    do
      if [[ ${line:0:1} != " " ]]
      then
	zone+=$line
	if [[ $line == $default ]]
	then
	  echo -e "${NORMAL}RESULT:    ${BLD}b. $line (default zone)${NORMAL}"
        else
	  echo -e "${NORMAL}RESULT:    ${BLD}b. $line${NORMAL}"
        fi
      else
	echo -e "${NORMAL}RESULT:    ${BLD}b. $line${NORMAL}"
      fi
    done
    for line in ${zone[@]}
    do
      rules="$(firewall-cmd --list-all --zone=$line)"
      if [[ $rules ]]
      then
        for rule in ${rules[@]}
        do
          if [[ $rule =~ "target" && ! $rule =~ "DROP" ]]
          then
            echo -e "${NORMAL}RESULT:    ${RED}c. $rule${NORMAL}"
	    fail=1
          else
            echo -e "${NORMAL}RESULT:    ${BLD}c. $rule${NORMAL}"
          fi
        done
      else
        echo -e "${NORMAL}RESULT:    ${RED}c. There are no active rules${NORMAL}"
	fail=1
      fi
    done
  else
    echo -e "${NORMAL}RESULT:    ${RED}b. There are no active zones${NORMAL}"
    fail=1
  fi    
else
  echo -e "${NORMAL}RESULT:    ${RED}a. $fwstate${NORMAL}"
  fail=1
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity89, $controlid, $stigid89, $ruleid89, $cci89, $datetime, ${GRN}PASSED, The RHEL 9 firewall employs a deny-all allow-by-exception policy for allowing connections to other systems.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity89, $controlid, $stigid89, $ruleid89, $cci89, $datetime, ${RED}FAILED, The RHEL 9 firewall does not employ a deny-all allow-by-exception policy for allowing connections to other systems.${NORMAL}"
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

fail=1

datetime="$(date +%FT%H:%M:%S)"

harden="$(sysctl net.core.bpf_jit_harden)"

if [[ $harden ]]
then
  value="$(echo $harden | awk -F= '{print $2}' | sed 's/ //')"
  if [[ $value == 2 ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}$harden${NORMAL}"
    fail=0
  else
    echo -e "${NORMAL}RESULT:    ${RED}$harden${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity90, $controlid, $stigid90, $ruleid90, $cci90, $datetime, ${GRN}PASSED, RHEL 9 enables hardening for the Berkeley Packet Filter just-in-time compiler.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity90, $controlid, $stigid90, $ruleid90, $cci90, $datetime, ${RED}FAILED, RHEL 9 does not enable hardening for the Berkeley Packet Filter just-in-time compiler.${NORMAL}"
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

fail=1

datetime="$(date +%FT%H:%M:%S)"

svrcnt=0

nameservers="$(grep nameserver /etc/resolv.conf)"

if [[ $nameservers ]]
then
  count=0
  for server in ${nameservers[@]}
  do
    if [[ ${server:0:1} != "#" ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}$server${NORMAL}"
      (( count++ ))
    else
      echo -e "${NORMAL}RESULT:    ${RED}$server${NORMAL}"
    fi
  done
  if (( $count >= 2 ))
  then
    fail=0
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity91, $controlid, $stigid91, $ruleid91, $cci91, $datetime, ${GRN}PASSED, At least two name servers are configured.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity91, $controlid, $stigid91, $ruleid91, $cci91, $datetime, ${RED}FAILED, At least two name servers are not configured.${NORMAL}"
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

fail=1

datetime="$(date +%FT%H:%M:%S)"

svrcnt=0

config="$(NetworkManager --print-config)"

if [[ $config ]]
then
  for line in ${config[@]}
  do
    if [[ $line =~ "dns" ]]
    then
      setting="$(echo $line | awk -F= '{print $2}')"
      if [[ ($setting == "none" || $setting == "default") &&
	     ${line:0:1} != "#"
	 ]]
      then
        fail=0
        echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
      else
        echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
      fi
    else
      echo -e "${NORMAL}RESULT:    $line${NORMAL}"
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity92, $controlid, $stigid92, $ruleid92, $cci92, $datetime, ${GRN}PASSED, RHEL 9 configures a DNS processing mode in Network Manager.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity92, $controlid, $stigid92, $ruleid92, $cci92, $datetime, ${RED}FAILED, RHEL 9 does not configure a DNS processing mode in Network Manager.${NORMAL}"
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

fail=1

datetime="$(date +%FT%H:%M:%S)"

isactive="$(systemctl -i is-active ipsec)"
conn="$(grep -rni conn /etc/ipsec.conf /etc/ipsec.d/ | grep -v "#")"

shopt -s nocasematch
if [[ $isactive == "inactive" ]]
then
  echo -e "${NORMAL}RESULT:    ${BLD}a. $isactive\n           b. (skipping)${NORMAL}"
  fail=0
else
  echo -e "${NORMAL}RESULT:    ${RED}a. $isactive${NORMAL}"
  if [[ $conn ]]
  then
    for line in ${conn[@]}
    do
      echo -e "${NORMAL}RESULT:    ${CYN}b. $line${NORMAL}"
    done
  else
    echo -e "${NORMAL}RESULT:    ${BLD}b. Nothing returned${NORMAL}"
    fail=0
  fi
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity93, $controlid, $stigid93, $ruleid93, $cci93, $datetime, ${GRN}PASSED, RHEL 9 does not have unauthorized IP tunnels configured.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity93, $controlid, $stigid93, $ruleid93, $cci93, $datetime, ${CYN}VERIFY, RHEL 9 has unauthorized IP tunnels configured.${NORMAL}"
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

fail=1

datetime="$(date +%FT%H:%M:%S)"

isinstalled="$(dnf list --installed 2>&1 postfix | grep -Ev 'Updating|Installed')"

if [[ $isinstalled ]]
then
  if [[ $isinstalled =~ "No matching Packages" ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}a. $isinstalled\n           b. (skipping)${NORMAL}"
    fail=2
  else
    echo -e "${NORMAL}RESULT:    ${BLD}a. $isinstalled${NORMAL}"
    conf="$(postconf -n smtpd_client_restrictions)"
    if [[ $conf ]]
    then
      setting="$(echo $line | awk -F= '{print $2}' | sed 's/ //g')"
      if [[ $setting == "permit_mynetworks,reject" ]]
      then
        echo -e "${NORMAL}RESULT:    ${BLD}b. $line${NORMAL}"
        fail=0
      else
        echo -e "${NORMAL}RESULT:    ${RED}b. $line${NORMAL}"
      fi
    else
      echo -e "${NORMAL}RESULT:    ${RED}b. Nothing returned${NORMAL}"
    fi
  fi
else
  echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
  fail=2
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity94, $controlid, $stigid94, $ruleid94, $cci94, $datetime, ${GRN}PASSED, RHEL 9 is configured to prevent unrestricted mail relaying.${NORMAL}"
elif [[ $fail == 2 ]]
then
  echo -e "${NORMAL}$hostname, $severity94, $controlid, $stigid94, $ruleid94, $cci94, $datetime, ${GRN}N/A, Postfix is not installed, this requirement is Not Applicable.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity94, $controlid, $stigid94, $ruleid94, $cci94, $datetime, ${RED}FAILED, RHEL 9 is not configured to prevent unrestricted mail relaying.${NORMAL}"
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

fail=1

datetime="$(date +%FT%H:%M:%S)"

redirect="$(sysctl net.ipv4.conf.all.accept_redirects)"

if [[ $redirect ]]
then
  value="$(echo $redirect | awk -F= '{print $2}' | sed 's/ //')"
  if [[ $value == 0 && ${redirect:0:1} != "#" ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}$redirect${NORMAL}"
    fail=0
  else
    echo -e "${NORMAL}RESULT:    ${RED}$redirect${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity95, $controlid, $stigid95, $ruleid95, $cci95, $datetime, ${GRN}PASSED, RHEL 9 ignores Internet Protocol version 4 (IPv4) Internet Control Message Protocol (ICMP) redirect messages.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity95, $controlid, $stigid95, $ruleid95, $cci95, $datetime, ${RED}FAILED, RHEL 9 does not ignore Internet Protocol version 4 (IPv4) Internet Control Message Protocol (ICMP) redirect messages.${NORMAL}"
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

fail=1

datetime="$(date +%FT%H:%M:%S)"

sourceroute="$(sysctl net.ipv4.conf.all.accept_source_route)"

if [[ $sourceroute ]]
then
  value="$(echo $sourceroute | awk -F= '{print $2}' | sed 's/ //')"
  if [[ $value == 0 && ${sourceroute:0:1} != "#" ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}$sourceroute${NORMAL}"
    fail=0
  else
    echo -e "${NORMAL}RESULT:    ${RED}$sourceroute${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity96, $controlid, $stigid96, $ruleid96, $cci96, $datetime, ${GRN}PASSED, RHEL 9 does not forward Internet Protocol version 4 (IPv4) source-routed packets.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity96, $controlid, $stigid96, $ruleid96, $cci96, $datetime, ${RED}FAILED, RHEL 9 forwards Internet Protocol version 4 (IPv4) source-routed packets.${NORMAL}"
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

fail=1

datetime="$(date +%FT%H:%M:%S)"

martians="$(sysctl net.ipv4.conf.all.log_martians)"

if [[ $martians ]]
then
  value="$(echo $martians | awk -F= '{print $2}' | sed 's/ //')"
  if [[ $value == 1 && ${martians:0:1} != "#" ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}$martians${NORMAL}"
    fail=0
  else
    echo -e "${NORMAL}RESULT:    ${RED}$martians${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity97, $controlid, $stigid97, $ruleid97, $cci97, $datetime, ${GRN}PASSED, RHEL 9 logs IPv4 packets with impossible addresses.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity96, $controlid, $stigid97, $ruleid97, $cci97, $datetime, ${RED}FAILED, RHEL 9 does not log IPv4 packets with impossible addresses.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid98${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid98${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid98${NORMAL}"
echo -e "${NORMAL}CCI:       $cci98${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 98:   ${BLD}$title98a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title98b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title98c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity98${NORMAL}"

IFS='
'

fail=1

datetime="$(date +%FT%H:%M:%S)"

martians="$(sysctl net.ipv4.conf.default.log_martians)"

if [[ $martians ]]
then
  value="$(echo $martians | awk -F= '{print $2}' | sed 's/ //')"
  if [[ $value == 1 && ${martians:0:1} != "#" ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}$martians${NORMAL}"
    fail=0
  else
    echo -e "${NORMAL}RESULT:    ${RED}$martians${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity98, $controlid, $stigid98, $ruleid98, $cci98, $datetime, ${GRN}PASSED, RHEL 9 logs IPv4 packets with impossible addresses by default.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity98, $controlid, $stigid98, $ruleid98, $cci98, $datetime, ${RED}FAILED, RHEL 9 does not log IPv4 packets with impossible addresses by default.${NORMAL}"
fi


echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid99${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid99${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid99${NORMAL}"
echo -e "${NORMAL}CCI:       $cci99${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 99:   ${BLD}$title99a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title99b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title99c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity99${NORMAL}"

IFS='
'

fail=1

datetime="$(date +%FT%H:%M:%S)"

rpfilter="$(sysctl net.ipv4.conf.all.rp_filter)"

if [[ $rpfilter ]]
then
  value="$(echo $rpfilter | awk -F= '{print $2}' | sed 's/ //')"
  if [[ $value == 1 || $value == 2 && ${rpfilter:0:1} != "#" ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}$rpfilter${NORMAL}"
    fail=0
  else
    echo -e "${NORMAL}RESULT:    ${RED}$rpfilter${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity99, $controlid, $stigid99, $ruleid99, $cci99, $datetime, ${GRN}PASSED, RHEL 9 uses reverse path filtering on all IPv4 interfaces.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity99, $controlid, $stigid99, $ruleid99, $cci99, $datetime, ${RED}FAILED, RHEL 9 does not use reverse path filtering on all IPv4 interfaces.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid100${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid100${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid100${NORMAL}"
echo -e "${NORMAL}CCI:       $cci100${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 100:  ${BLD}$title100a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title100b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title100c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity100${NORMAL}"

IFS='
must not respond to Internet Control Message Protocol (ICMP) echoes sent to a broadcast address'

fail=1

datetime="$(date +%FT%H:%M:%S)"

redirects="$(sysctl net.ipv4.conf.default.accept_redirects)"

if [[ $redirects ]]
then
  value="$(echo $redirects | awk -F= '{print $2}' | sed 's/ //')"
  if [[ $value == 0 && ${redirects:0:1} != "#" ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}$redirects${NORMAL}"
    fail=0
  else
    echo -e "${NORMAL}RESULT:    ${RED}$redirects${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity100, $controlid, $stigid100, $ruleid100, $cci100, $datetime, ${GRN}PASSED, RHEL 9 prevents IPv4 Internet Control Message Protocol (ICMP) redirect messages from being accepted.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity100, $controlid, $stigid100, $ruleid100, $cci100, $datetime, ${RED}FAILED, RHEL 9 does not prevent IPv4 Internet Control Message Protocol (ICMP) redirect messages from being accepted..${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid101${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid101${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid101${NORMAL}"
echo -e "${NORMAL}CCI:       $cci101${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 101:  ${BLD}$title101a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title101b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title101c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity101${NORMAL}"

IFS='
'

fail=1

datetime="$(date +%FT%H:%M:%S)"

sourceroute="$(sysctl net.ipv4.conf.default.accept_source_route)"

if [[ $sourceroute ]]
then
  value="$(echo $sourceroute | awk -F= '{print $2}' | sed 's/ //')"
  if [[ $value == 0 && ${sourceroute:0:1} != "#" ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}$sourceroute${NORMAL}"
    fail=0
  else
    echo -e "${NORMAL}RESULT:    ${RED}$sourceroute${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity101, $controlid, $stigid101, $ruleid101, $cci101, $datetime, ${GRN}PASSED, RHEL 9 does not forward IPv4 source-routed packets by default.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity101, $controlid, $stigid101, $ruleid101, $cci101, $datetime, ${RED}FAILED, RHEL 9 forwards IPv4 source-routed packets by default.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid102${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid102${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid102${NORMAL}"
echo -e "${NORMAL}CCI:       $cci102${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 102:  ${BLD}$title102a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title102b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title102c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity102${NORMAL}"

IFS='
'

fail=1

datetime="$(date +%FT%H:%M:%S)"

rpfilter="$(sysctl net.ipv4.conf.default.rp_filter)"

if [[ $rpfilter ]]
then
  value="$(echo $rpfilter | awk -F= '{print $2}' | sed 's/ //')"
  if [[ $value == 1 && ${rpfilter:0:1} != "#" ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}$rpfilter${NORMAL}"
    fail=0
  else
    echo -e "${NORMAL}RESULT:    ${RED}$rpfilter${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity102, $controlid, $stigid102, $ruleid102, $cci102, $datetime, ${GRN}PASSED, RHEL 9 uses a reverse-path filter for IPv4 network traffic when possible by default.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity102, $controlid, $stigid102, $ruleid102, $cci102, $datetime, ${RED}FAILED, RHEL 9 does not use a reverse-path filter for IPv4 network traffic when possible by default.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid103${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid103${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid103${NORMAL}"
echo -e "${NORMAL}CCI:       $cci103${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 103:  ${BLD}$title103a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title103b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title103c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity103${NORMAL}"

IFS='
'

fail=1

datetime="$(date +%FT%H:%M:%S)"

broadcast="$(sysctl net.ipv4.icmp_echo_ignore_broadcasts)"

if [[ $broadcast ]]
then
  value="$(echo $broadcast | awk -F= '{print $2}' | sed 's/ //')"
  if [[ $value == 1 && ${broadcast:0:1} != "#" ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}$broadcast${NORMAL}"
    fail=0
  else
    echo -e "${NORMAL}RESULT:    ${RED}$broadcast${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity103, $controlid, $stigid103, $ruleid103, $cci103, $datetime, ${GRN}PASSED, RHEL 9 does not respond to Internet Control Message Protocol (ICMP) echoes sent to a broadcast address${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity103, $controlid, $stigid103, $ruleid103, $cci103, $datetime, ${RED}FAILED, RHEL 9 responds to Internet Control Message Protocol (ICMP) echoes sent to a broadcast address${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid104${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid104${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid104${NORMAL}"
echo -e "${NORMAL}CCI:       $cci104${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 104:  ${BLD}$title104a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title104b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title104c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity104${NORMAL}"

IFS='
'

fail=1

datetime="$(date +%FT%H:%M:%S)"

bogus="$(sysctl net.ipv4.icmp_ignore_bogus_error_responses)"

if [[ $bogus ]]
then
  value="$(echo $bogus | awk -F= '{print $2}' | sed 's/ //')"
  if [[ $value == 1 && ${bogus:0:1} != "#" ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}$bogus${NORMAL}"
    fail=0
  else
    echo -e "${NORMAL}RESULT:    ${RED}$bogus${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity104, $controlid, $stigid104, $ruleid104, $cci104, $datetime, ${GRN}PASSED, RHEL 9 limits the number of bogus Internet Control Message Protocol (ICMP) response errors logs.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity104, $controlid, $stigid104, $ruleid104, $cci104, $datetime, ${RED}FAILED, RHEL 9 does not limit the number of bogus Internet Control Message Protocol (ICMP) response errors logs.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid105${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid105${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid105${NORMAL}"
echo -e "${NORMAL}CCI:       $cci105${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 105:  ${BLD}$title105a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title105b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title105c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity105${NORMAL}"

IFS='
'

fail=1

datetime="$(date +%FT%H:%M:%S)"

redirect="$(sysctl net.ipv4.conf.all.send_redirects)"

if [[ $redirect ]]
then
  value="$(echo $redirect | awk -F= '{print $2}' | sed 's/ //')"
  if [[ $value == 0 && ${redirect:0:1} != "#" ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}$redirect${NORMAL}"
    fail=0
  else
    echo -e "${NORMAL}RESULT:    ${RED}$redirect${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity105, $controlid, $stigid105, $ruleid105, $cci105, $datetime, ${GRN}PASSED, RHEL 9 does not send Internet Control Message Protocol (ICMP) redirects.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity105, $controlid, $stigid105, $ruleid105, $cci105, $datetime, ${RED}FAILED, RHEL 9 sends Internet Control Message Protocol (ICMP) redirects.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid106${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid106${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid106${NORMAL}"
echo -e "${NORMAL}CCI:       $cci106${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 106:  ${BLD}$title106a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title106b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title106c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity106${NORMAL}"

IFS='
'

fail=1

datetime="$(date +%FT%H:%M:%S)"

forwarding="$(sysctl net.ipv4.conf.all.forwarding)"

if [[ $forwarding ]]
then
  value="$(echo $forwarding | awk -F= '{print $2}' | sed 's/ //')"
  if [[ $value == 0 && ${forwarding:0:1} != "#" ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}$forwarding${NORMAL}"
    fail=0
  else
    echo -e "${NORMAL}RESULT:    ${RED}$forwarding${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity106, $controlid, $stigid106, $ruleid106, $cci106, $datetime, ${GRN}PASSED, RHEL 9 does not enable IPv4 packet forwarding unless the system is a router.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity106, $controlid, $stigid106, $ruleid106, $cci106, $datetime, ${RED}FAILED, RHEL 9 enables IPv4 packet forwarding as a router.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid107${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid107${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid107${NORMAL}"
echo -e "${NORMAL}CCI:       $cci107${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 107:  ${BLD}$title107a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title107b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title107c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity107${NORMAL}"

IFS='
'

fail=1

datetime="$(date +%FT%H:%M:%S)"

routerads="$(sysctl net.ipv6.conf.all.accept_ra)"

if [[ $routerads ]]
then
  value="$(echo $routerads | awk -F= '{print $2}' | sed 's/ //')"
  if [[ $value == 0 && ${routerads:0:1} != "#" ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}$routerads${NORMAL}"
    fail=0
  else
    echo -e "${NORMAL}RESULT:    ${RED}$routerads${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity107, $controlid, $stigid107, $ruleid107, $cci107, $datetime, ${GRN}PASSED, RHEL 9 does not accept router advertisements on all IPv6 interfaces.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity107, $controlid, $stigid107, $ruleid107, $cci107, $datetime, ${RED}FAILED, RHEL 9 accepts router advertisements on all IPv6 interfaces.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid108${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid108${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid108${NORMAL}"
echo -e "${NORMAL}CCI:       $cci108${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 108:  ${BLD}$title108a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title108b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title108c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity108${NORMAL}"

IFS='
'

fail=1

datetime="$(date +%FT%H:%M:%S)"

redirects="$(sysctl net.ipv6.conf.all.accept_redirects)"

if [[ $redirects ]]
then
  value="$(echo $redirects | awk -F= '{print $2}' | sed 's/ //')"
  if [[ $value == 0 && ${redirects:0:1} != "#" ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}$redirects${NORMAL}"
    fail=0
  else
    echo -e "${NORMAL}RESULT:    ${RED}$redirects${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity108, $controlid, $stigid108, $ruleid108, $cci108, $datetime, ${GRN}PASSED, RHEL 9 ignores IPv6 Internet Control Message Protocol (ICMP) redirect messages.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity108, $controlid, $stigid108, $ruleid108, $cci108, $datetime, ${RED}FAILED, RHEL 9 does not ignore IPv6 Internet Control Message Protocol (ICMP) redirect messages.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid109${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid109${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid109${NORMAL}"
echo -e "${NORMAL}CCI:       $cci109${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 109:  ${BLD}$title109a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title109b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title109c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity109${NORMAL}"

IFS='
'

fail=1

datetime="$(date +%FT%H:%M:%S)"

sourceroute="$(sysctl net.ipv6.conf.all.accept_source_route)"

if [[ $sourceroute ]]
then
  value="$(echo $sourceroute | awk -F= '{print $2}' | sed 's/ //')"
  if [[ $value == 0 && ${sourceroute:0:1} != "#" ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}$sourceroute${NORMAL}"
    fail=0
  else
    echo -e "${NORMAL}RESULT:    ${RED}$sourceroute${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity109, $controlid, $stigid109, $ruleid109, $cci109, $datetime, ${GRN}PASSED, RHEL 9 does not forward IPv6 source-routed packets.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity109, $controlid, $stigid109, $ruleid109, $cci109, $datetime, ${RED}FAILED, RHEL 9 forwards IPv6 source-routed packets.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid110${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid110${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid110${NORMAL}"
echo -e "${NORMAL}CCI:       $cci110${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 110:  ${BLD}$title110a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title110b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title110c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity110${NORMAL}"

IFS='
'

fail=1

datetime="$(date +%FT%H:%M:%S)"

forwarding="$(sysctl net.ipv6.conf.all.forwarding)"

if [[ $forwarding ]]
then
  value="$(echo $forwarding | awk -F= '{print $2}' | sed 's/ //')"
  if [[ $value == 0 && ${forwarding:0:1} != "#" ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}$forwarding${NORMAL}"
    fail=0
  else
    echo -e "${NORMAL}RESULT:    ${RED}$forwarding${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity110, $controlid, $stigid110, $ruleid110, $cci110, $datetime, ${GRN}PASSED, RHEL 9 does not enable IPv6 packet forwarding unless the system is a router.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity110, $controlid, $stigid110, $ruleid110, $cci110, $datetime, ${RED}FAILED, RHEL 9 enables IPv6 packet forwarding as a router.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid111${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid111${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid111${NORMAL}"
echo -e "${NORMAL}CCI:       $cci111${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 111:  ${BLD}$title111a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title111b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title111c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity111${NORMAL}"

IFS='
'

fail=1

datetime="$(date +%FT%H:%M:%S)"

acceptra="$(sysctl net.ipv6.conf.default.accept_ra)"

if [[ $acceptra ]]
then
  value="$(echo $acceptra | awk -F= '{print $2}' | sed 's/ //')"
  if [[ $value == 0 && ${acceptra:0:1} != "#" ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}$acceptra${NORMAL}"
    fail=0
  else
    echo -e "${NORMAL}RESULT:    ${RED}$acceptra${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity111, $controlid, $stigid111, $ruleid111, $cci111, $datetime, ${GRN}PASSED, RHEL 9 does not accept router advertisements on all IPv6 interfaces by default.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity111, $controlid, $stigid111, $ruleid111, $cci111, $datetime, ${RED}FAILED, RHEL 9 accept router advertisements on all IPv6 interfaces by default.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid112${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid112${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid112${NORMAL}"
echo -e "${NORMAL}CCI:       $cci112${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 112:  ${BLD}$title112a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title112b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title112c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity112${NORMAL}"

IFS='
'

fail=1

datetime="$(date +%FT%H:%M:%S)"

recirects="$(sysctl net.ipv6.conf.default.accept_redirects)"

if [[ $redirects ]]
then
  value="$(echo $redirects | awk -F= '{print $2}' | sed 's/ //')"
  if [[ $value == 0 && ${redirects:0:1} != "#" ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}$redirects${NORMAL}"
    fail=0
  else
    echo -e "${NORMAL}RESULT:    ${RED}$redirects${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity112, $controlid, $stigid112, $ruleid112, $cci112, $datetime, ${GRN}PASSED, RHEL 9 prevents IPv6 Internet Control Message Protocol (ICMP) redirect messages from being accepted.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity112, $controlid, $stigid112, $ruleid112, $cci112, $datetime, ${RED}FAILED, RHEL 9 does not prevent IPv6 Internet Control Message Protocol (ICMP) redirect messages from being accepted.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid113${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid113${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid113${NORMAL}"
echo -e "${NORMAL}CCI:       $cci113${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 113:  ${BLD}$title113a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title113b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title113c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity113${NORMAL}"

IFS='
'

fail=1

datetime="$(date +%FT%H:%M:%S)"

sourceroute="$(sysctl net.ipv6.conf.default.accept_source_route)"

if [[ $sourceroute ]]
then
  value="$(echo $sourceroute | awk -F= '{print $2}' | sed 's/ //')"
  if [[ $value == 0 && ${sourceroute:0:1} != "#" ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}$sourceroute${NORMAL}"
    fail=0
  else
    echo -e "${NORMAL}RESULT:    ${RED}$sourceroute${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity113, $controlid, $stigid113, $ruleid113, $cci113, $datetime, ${GRN}PASSED, RHEL 9 does not forward IPv6 source-routed packets by default.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity113, $controlid, $stigid113, $ruleid113, $cci113, $datetime, ${RED}FAILED, RHEL 9 forwards IPv6 source-routed packets by default.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid114${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid114${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid114${NORMAL}"
echo -e "${NORMAL}CCI:       $cci114${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 114:  ${BLD}$title114a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title114b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title114c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity114${NORMAL}"

IFS='
'

fail=0

datetime="$(date +%FT%H:%M:%S)"

isinstalled="$(dnf list --installed 2>&1 openssh-clients | grep -Ev 'Updating|Installed')"

if [[ $isinstalled ]]
then
  if [[ $isinstalled =~ "No matching Packages" ]]
  then
    fail=1
    for line in ${isinstalled[@]}
    do
      if [[ $line =~ "Error:" ]]
      then
        echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
      fi
    done
  else
    for line in ${isinstalled[@]}
    do
      echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
    done
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity114, $controlid, $stigid114, $ruleid114, $cci114, $datetime, ${GRN}PASSED, RHEL 9 has the openssh-clients package installed.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity114, $controlid, $stigid114, $ruleid114, $cci114, $datetime, ${RED}FAILED, RHEL 9 does not have the openssh-clients package installed.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid115${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid115${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid115${NORMAL}"
echo -e "${NORMAL}CCI:       $cci115${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 115:  ${BLD}$title115a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title115b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title115c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity115${NORMAL}"

IFS='
'

fail=1

datetime="$(date +%FT%H:%M:%S)"

trust="$(/usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs grep -iH '^\s*hostbasedauthentication')"

if [[ $trust ]]
then
  file="$(echo $trust | awk -F: '{print $1}')"
  setting="$(echo $trust | awk -F: '{print $2}')"
  value="$(echo $setting | awk '{print $2}')"
  if [[ $value == "no" && ${setting:0:1} != "#" ]]
  then
    fail=0
    echo -e "${NORMAL}RESULT:    ${CYN}$file:${BLD}$setting${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${CYN}$file:${RED}$setting${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity115, $controlid, $stigid115, $ruleid115, $cci115, $datetime, ${GRN}PASSED, RHEL 9 does not allow a noncertificate trusted host SSH logon to the system.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity115, $controlid, $stigid115, $ruleid115, $cci115, $datetime, ${RED}FAILED, RHEL 9 allows a noncertificate trusted host SSH logon to the system.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid116${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid116${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid116${NORMAL}"
echo -e "${NORMAL}CCI:       $cci116${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 116:  ${BLD}$title116a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title116b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title116c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity116${NORMAL}"

IFS='
'

fail=1

datetime="$(date +%FT%H:%M:%S)"

userenv="$(/usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs grep -iH '^\s*permituserenvironment')"

if [[ $userenv ]]
then
  file="$(echo $userenv | awk -F: '{print $1}')"
  setting="$(echo $userenv | awk -F: '{print $2}')"
  value="$(echo $setting | awk '{print $2}')"
  if [[ $value == "no" && ${setting:0:1} != "#" ]]
  then
    fail=0
    echo -e "${NORMAL}RESULT:    ${CYN}$file:${BLD}$setting${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${CYN}$file:${RED}$setting${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity116, $controlid, $stigid116, $ruleid116, $cci116, $datetime, ${GRN}PASSED, RHEL 9 does not allow users to override SSH environment variables.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity116, $controlid, $stigid116, $ruleid116, $cci116, $datetime, ${RED}FAILED, RHEL 9 allows users to override SSH environment variables.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid117${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid117${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid117${NORMAL}"
echo -e "${NORMAL}CCI:       $cci117${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 117:  ${BLD}$title117a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title117b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title117c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity117${NORMAL}"

IFS='
'

fail=1

datetime="$(date +%FT%H:%M:%S)"

stat="$(find 2>/dev/null /etc/ssh/sshd_config /etc/ssh/sshd_config.d -exec stat -c "%G %n" {} \;)"

if [[ $stat ]]
then
  for line in ${stat[@]}
  do
    gowner="$(echo $stat | awk '{print $1}')"
    if [[ $gowner == 'root' ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
      fail=0
    else
      echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity117, $controlid, $stigid117, $ruleid117, $cci117, $datetime, ${GRN}PASSED, RHEL 9 SSH server configuration files are group-owned by root.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity117, $controlid, $stigid117, $ruleid117, $cci117, $datetime, ${RED}FAILED, RHEL 9 SSH server configuration files are not group-owned by root.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid118${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid118${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid118${NORMAL}"
echo -e "${NORMAL}CCI:       $cci118${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 118:  ${BLD}$title118a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title118b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title118c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity118${NORMAL}"

IFS='
'

fail=1

datetime="$(date +%FT%H:%M:%S)"

stat="$(find /etc/ssh/sshd_config /etc/ssh/sshd_config.d -exec stat -c "%U %n" {} \;)"

if [[ $stat ]]
then
  for line in ${stat[@]}
  do
    owner="$(echo $stat | awk '{print $1}')"
    if [[ $owner == 'root' ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
      fail=0
    else
      echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity118, $controlid, $stigid118, $ruleid118, $cci118, $datetime, ${GRN}PASSED, RHEL 9 SSH server configuration files are owned by root.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity118, $controlid, $stigid118, $ruleid118, $cci118, $datetime, ${RED}FAILED, RHEL 9 SSH server configuration files are not owned by root.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid119${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid119${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid119${NORMAL}"
echo -e "${NORMAL}CCI:       $cci119${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 119:  ${BLD}$title119a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title119b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title119c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity119${NORMAL}"

IFS='
'

fail=0

datetime="$(date +%FT%H:%M:%S)"

valid="$(rpm --verify openssh-server)"

if [[ $valid ]]
then
  fail=1
  for line in ${valid[@]}
  do
    echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
  done
else
  echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity119, $controlid, $stigid119, $ruleid119, $cci119, $datetime, ${GRN}PASSED, RHEL 9 SSH server configuration files' permissions are not modified.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity119, $controlid, $stigid119, $ruleid119, $cci119, $datetime, ${RED}FAILED, RHEL 9 SSH server configuration files' permissions are modified.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid120${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid120${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid120${NORMAL}"
echo -e "${NORMAL}CCI:       $cci120${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 120:  ${BLD}$title120a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title120b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title120c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity120${NORMAL}"

IFS='
'

fail=0

datetime="$(date +%FT%H:%M:%S)"

mode="$(stat -c "%a %n" /etc/ssh/*_key)"
if [[ $mode ]]
then
  for line in ${mode[@]}
  do
    if  (( ${line:0:1} <= 6 &&
           ${line:1:1} <= 4 &&
           ${line:2:1} <= 0
        ))
    then
      echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
      fail=1
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity120, $controlid, $stigid120, $ruleid120, $cci120, $datetime, ${GRN}PASSED, RHEL 9 SSH private host key files are mode 0640 or less permissive.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity120, $controlid, $stigid120, $ruleid120, $cci120, $datetime, ${RED}FAILED, RHEL 9 SSH private host key files are not mode 0640 or less permissive.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid121${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid121${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid121${NORMAL}"
echo -e "${NORMAL}CCI:       $cci121${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 121:  ${BLD}$title121a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title121b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title121c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity121${NORMAL}"

IFS='
'

fail=1

datetime="$(date +%FT%H:%M:%S)"

rhost="$(/usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs grep -iH '^\s*hostbasedauthentication')"

if [[ $rhost ]]
then
  file="$(echo $rhost | awk -F: '{print $1}')"
  setting="$(echo $rhost | awk -F: '{print $2}')"
  value="$(echo $setting | awk '{print $2}')"
  if [[ $value == "no" && ${setting:0:1} != "#" ]]
  then
    fail=0
    echo -e "${NORMAL}RESULT:    ${CYN}$file:${BLD}$setting${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${CYN}$file:${RED}$setting${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity121, $controlid, $stigid121, $ruleid121, $cci121, $datetime, ${GRN}PASSED, RHEL 9 SSH daemon does not allow rhosts authentication.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity121, $controlid, $stigid121, $ruleid121, $cci121, $datetime, ${RED}FAILED, RHEL 9 SSH daemon allows rhosts authentication.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid122${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid122${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid122${NORMAL}"
echo -e "${NORMAL}CCI:       $cci122${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 122:  ${BLD}$title122a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title122b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title122c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity122${NORMAL}"

IFS='
'

fail=1

datetime="$(date +%FT%H:%M:%S)"

knownhost="$(/usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs grep -iH '^\s*ignoreuserknownhosts')"

if [[ $knownhost ]]
then
  file="$(echo $knownhost | awk -F: '{print $1}')"
  setting="$(echo $knownhost | awk -F: '{print $2}')"
  value="$(echo $setting | awk '{print $2}')"
  if [[ $value == "yes" && ${setting:0:1} != "#" ]]
  then
    fail=0
    echo -e "${NORMAL}RESULT:    ${CYN}$file:${BLD}$setting${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${CYN}$file:${RED}$setting${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity122, $controlid, $stigid122, $ruleid122, $cci122, $datetime, ${GRN}PASSED, RHEL 9 SSH daemon does not allow known hosts authentication.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity122, $controlid, $stigid122, $ruleid122, $cci122, $datetime, ${RED}FAILED, RHEL 9 SSH daemon allows known hosts authentication.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid123${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid123${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid123${NORMAL}"
echo -e "${NORMAL}CCI:       $cci123${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 123:  ${BLD}$title123a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title123b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title123c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity123${NORMAL}"

IFS='
'

fail=1

datetime="$(date +%FT%H:%M:%S)"

uknownhost="$(/usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs grep -iH '^\s*x11forwarding')"

if [[ $uknownhost ]]
then
  file="$(echo $uknownhost | awk -F: '{print $1}')"
  setting="$(echo $uknownhost | awk -F: '{print $2}')"
  value="$(echo $setting | awk '{print $2}')"
  if [[ $value == "no" && ${setting:0:1} != "#" ]]
  then
    fail=0
    echo -e "${NORMAL}RESULT:    ${CYN}$file:${BLD}$setting${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${CYN}$file:${RED}$setting${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity123, $controlid, $stigid123, $ruleid123, $cci123, $datetime, ${GRN}PASSED, RHEL 9 SSH daemon disables remote X connections for interactive users.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity123, $controlid, $stigid123, $ruleid123, $cci123, $datetime, ${RED}FAILED, RHEL 9 SSH daemon does not disable remote X connections for interactive users.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid124${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid124${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid124${NORMAL}"
echo -e "${NORMAL}CCI:       $cci124${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 124:  ${BLD}$title124a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title124b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title124c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity124${NORMAL}"

IFS='
'

fail=1

datetime="$(date +%FT%H:%M:%S)"

smodes="$(/usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs grep -iH '^\s*strictmodes')"

if [[ $smodes ]]
then
  file="$(echo $smodes | awk -F: '{print $1}')"
  setting="$(echo $smodes | awk -F: '{print $2}')"
  value="$(echo $setting | awk '{print $2}')"
  if [[ $value == "yes" && ${setting:0:1} != "#" ]]
  then
    fail=0
    echo -e "${NORMAL}RESULT:    ${CYN}$file:${BLD}$setting${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${CYN}$file:${RED}$setting${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity124, $controlid, $stigid124, $ruleid124, $cci124, $datetime, ${GRN}PASSED, RHEL 9 SSH daemon performs strict mode checking of home directory configuration files.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity124, $controlid, $stigid124, $ruleid124, $cci124, $datetime, ${RED}FAILED, RHEL 9 SSH daemon does not perform strict mode checking of home directory configuration files.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid125${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid125${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid125${NORMAL}"
echo -e "${NORMAL}CCI:       $cci125${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 125:  ${BLD}$title125a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title125b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title125c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity125${NORMAL}"

IFS='
'

fail=1

datetime="$(date +%FT%H:%M:%S)"

lastlog="$(/usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs grep -iH '^\s*printlastlog')"

if [[ $lastlog ]]
then
  file="$(echo $lastlog | awk -F: '{print $1}')"
  setting="$(echo $lastlog | awk -F: '{print $2}')"
  value="$(echo $setting| awk '{print $2}')"
  if [[ $value == "yes" && ${setting:0:1} != "#" ]]
  then
    fail=0
    echo -e "${NORMAL}RESULT:    ${CYN}$file:${BLD}$setting${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${CYN}$file:${RED}$setting${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity125, $controlid, $stigid125, $ruleid125, $cci125, $datetime, ${GRN}PASSED, RHEL 9 SSH daemon displays the date and time of the last successful account logon upon an SSH logon.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity125, $controlid, $stigid125, $ruleid125, $cci125, $datetime, ${RED}FAILED, RHEL 9 SSH daemon does not display the date and time of the last successful account logon upon an SSH logon.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid126${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid126${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid126${NORMAL}"
echo -e "${NORMAL}CCI:       $cci126${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 126:  ${BLD}$title126a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title126b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title126c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity126${NORMAL}"

IFS='
'

fail=1

datetime="$(date +%FT%H:%M:%S)"

x11local="$(/usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs grep -iH '^\s*x11uselocalhost')"

if [[ $x11local ]]
then
  file="$(echo $x11local | awk -F: '{print $1}')"
  setting="$(echo $x11local | awk -F: '{print $2}')"
  value="$(echo $setting| awk '{print $2}')"
  if [[ $value == "yes" && ${setting:0:1} != "#" ]]
  then
    fail=0
    echo -e "${NORMAL}RESULT:    ${CYN}$file:${BLD}$setting${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${CYN}$file:${RED}$setting${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity126, $controlid, $stigid126, $ruleid126, $cci126, $datetime, ${GRN}PASSED, RHEL 9 SSH daemon prevents remote hosts from connecting to the proxy display.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity126, $controlid, $stigid126, $ruleid126, $cci126, $datetime, ${RED}FAILED, RHEL 9 SSH daemon does not prevent remote hosts from connecting to the proxy display.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid127${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid127${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid127${NORMAL}"
echo -e "${NORMAL}CCI:       $cci127${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 127:  ${BLD}$title127a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title127b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title127c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity127${NORMAL}"

IFS='
'

fail=1

datetime="$(date +%FT%H:%M:%S)"

login="$(grep -i automaticlogin /etc/gdm/custom.conf)"

if [[ $login ]]
then
  for line in ${login[@]}
  do
    value="$(echo $line | awk -F= '{print $2}' | tr '[:upper:]' '[:lower:]')"
    if [[ $value == "false" && ${login:0:1} != "#" ]]
    then
      fail=0
      echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity127, $controlid, $stigid127, $ruleid127, $cci127, $datetime, ${GRN}PASSED, RHEL 9 does not allow unattended or automatic logon via the graphical user interface.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity127, $controlid, $stigid127, $ruleid127, $cci127, $datetime, ${RED}FAILED, RHEL 9 allows unattended or automatic logon via the graphical user interface.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid128${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid128${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid128${NORMAL}"
echo -e "${NORMAL}CCI:       $cci128${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 128:  ${BLD}$title128a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title128b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title128c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity128${NORMAL}"

IFS='
'

fail=1

datetime="$(date +%FT%H:%M:%S)"

screen="$(gsettings get org.gnome.login-screen disable-restart-buttons)"

if [[ $screen ]]
then
  if [[ $screen == "true" ]]
  then
    fail=0
    echo -e "${NORMAL}RESULT:    ${BLD}$screen${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}$screen${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity128, $controlid, $stigid128, $ruleid128, $cci128, $datetime, ${GRN}PASSED, RHEL 9 disables the ability of a user to restart the system from the login screen.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity128, $controlid, $stigid128, $ruleid128, $cci128, $datetime, ${RED}FAILED, RHEL 9 does not disable the ability of a user to restart the system from the login screen.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid129${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid129${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid129${NORMAL}"
echo -e "${NORMAL}CCI:       $cci129${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 129:  ${BLD}$title129a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title129b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title129c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity129${NORMAL}"

IFS='
'

fail=1

datetime="$(date +%FT%H:%M:%S)"

rbuttons="$(gsettings 2>&1 writable org.gnome.login-screen disable-restart-buttons)"

if [[ $rbuttons ]]
then
  for line in ${rbuttons[@]}
  do
    value="$(echo $line | tr '[:upper:]' '[:lower:]')"
    if [[ $value == "false" && ${line:0:1} != "#" ]]
    then
      fail=0
      echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity129, $controlid, $stigid129, $ruleid129, $cci129, $datetime, ${GRN}PASSED, RHEL 9 prevents a user from overriding the disable-restart-buttons setting for the graphical user interface.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity129, $controlid, $stigid129, $ruleid129, $cci129, $datetime, ${RED}FAILED, RHEL 9 does not prevent a user from overriding the disable-restart-buttons setting for the graphical user interface.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid130${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid130${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid130${NORMAL}"
echo -e "${NORMAL}CCI:       $cci130${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 130:  ${BLD}$title130a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title130b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title130c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity130${NORMAL}"

IFS='
'

fail=1

datetime="$(date +%FT%H:%M:%S)"

isinstalled="$(dnf list --installed 2>&1 gnome-desktop | grep -Ev 'Updating|Installed')" 

if [[ $isinstalled ]]
then
  keys="$(gsettings get org.gnome.settings-daemon.plugins.media-keys logout)"
  if [[ $keys ]]
  then
    if [[ $keys == "['']" ]]
    then
      fail=0
      echo -e "${NORMAL}RESULT:    ${BLD}$keys${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${RED}$keys${NORMAL}"
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
  fail=2
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity130, $controlid, $stigid130, $ruleid130, $cci130, $datetime, ${GRN}PASSED, RHEL 9 disables the ability of a user to accidentally press Ctrl-Alt-Del and cause a system to shut down or reboot.${NORMAL}"
elif [[ $fail == 2 ]]
then
  echo -e "${NORMAL}$hostname, $severity130, $controlid, $stigid130, $ruleid130, $cci130, $datetime, ${GRN}N/A, The RHEL 9 default GNOME desktop graphical user interface is not installed. This requirement is Not Applicable.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity130, $controlid, $stigid130, $ruleid130, $cci130, $datetime, ${RED}FAILED, RHEL 9 does not disable the ability of a user to accidentally press Ctrl-Alt-Del and cause a system to shut down or reboot.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid131${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid131${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid131${NORMAL}"
echo -e "${NORMAL}CCI:       $cci131${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 131:  ${BLD}$title131a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title131b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title131c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity131${NORMAL}"

IFS='
'

fail=1

datetime="$(date +%FT%H:%M:%S)"

isinstalled="$(dnf list --installed 2>&1 gnome-desktop | grep -Ev 'Updating|Installed')"

if [[ $isinstalled ]]
then
  mkeys="$(gsettings 2>&1 writable org.gnome.settings-daemon.plugins.media-keys logout)"
  if [[ $mkeys ]]
  then
    for line in ${mkeys[@]}
    do
      value="$(echo $line | tr '[:upper:]' '[:lower:]')"
      if [[ $value == "false" && ${line:0:1} != "#" ]]
      then
        fail=0
        echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
      else
        echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
      fi
    done
  else
    echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
  fi
else
  fail=2
  echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity131, $controlid, $stigid131, $ruleid131, $cci131, $datetime, ${GRN}PASSED, RHEL 9 prevents a user from overriding the Ctrl-Alt-Del sequence settings for the graphical user interface.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity131, $controlid, $stigid131, $ruleid131, $cci131, $datetime, ${RED}FAILED, RHEL 9 does not prevent a user from overriding the Ctrl-Alt-Del sequence settings for the graphical user interface.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid132${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid132${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid132${NORMAL}"
echo -e "${NORMAL}CCI:       $cci132${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 132:  ${BLD}$title132a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title132b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title132c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity132${NORMAL}"

IFS='
'

fail=1

datetime="$(date +%FT%H:%M:%S)"

isinstalled="$(dnf list --installed 2>&1 gnome-desktop | grep -Ev 'Updating|Installed')"

if [[ $isinstalled ]]
then
  list="$(gsettings 2>&1 get org.gnome.login-screen disable-user-list)"
  if [[ $list ]]
  then
    for line in ${list[@]}
    do
      value="$(echo $line | tr '[:upper:]' '[:lower:]')"
      if [[ $value == "true" && ${line:0:1} != "#" ]]
      then
        fail=0
        echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
      else
        echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
      fi
    done
  else
    echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
  fail=2
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity132, $controlid, $stigid132, $ruleid132, $cci132, $datetime, ${GRN}PASSED, RHEL 9 disables the user list at logon for graphical user interfaces.${NORMAL}"
elif [[ $fail == 2 ]]
then
  echo -e "${NORMAL}$hostname, $severity132, $controlid, $stigid132, $ruleid132, $cci132, $datetime, ${GRN}N/A, The RHEL 9 default GNOME desktop graphical user interface is not installed. This requirement is Not Applicable.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity132, $controlid, $stigid132, $ruleid132, $cci132, $datetime, ${RED}FAILED, RHEL 9 does not disable the user list at logon for graphical user interfaces.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid133${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid133${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid133${NORMAL}"
echo -e "${NORMAL}CCI:       $cci133${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 133:  ${BLD}$title133a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title133b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title133c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity133${NORMAL}"

IFS='
'

fail=0

datetime="$(date +%FT%H:%M:%S)"

defined="$(find /home -maxdepth 2 -type f -name ".[^.]*" -exec grep -iH -d skip --exclude=.bash_history umask {} \;)"

if [[ $defined ]]
then
  for line in ${defined[@]}
  do
    value="$(echo $line | awk '{print $2}')"
    if (( ${value:0:1} < 7 ||
	  ${value:1:1} > 0 ||
	  ${value:2:1} > 0
       ))
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
  echo -e "${NORMAL}$hostname, $severity133, $controlid, $stigid133, $ruleid133, $cci133, $datetime, ${GRN}PASSED, RHEL 9 sets the umask value to 077 for all local interactive user accounts.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity133, $controlid, $stigid133, $ruleid133, $cci133, $datetime, ${RED}FAILED, RHEL 9 does not set the umask value to 077 for all local interactive user accounts.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid134${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid134${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid134${NORMAL}"
echo -e "${NORMAL}CCI:       $cci134${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 134:  ${BLD}$title134a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title134b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title134c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity134${NORMAL}"

IFS='
'

fail=0

datetime="$(date +%FT%H:%M:%S)"


users="$(awk -F: '($2 != "*" && $2 != "!*" && $2 != "!!" && $2 != ".") {print $1}' /etc/shadow)"
path="$(find /home -maxdepth 2 -type f -name ".[^.]*" -exec grep -iH -d skip --exclude=.bash_history path= {} \;)"

if [[ $path ]]
then
  for line in ${path[@]}
  do
    if ! [[ $line =~ "=\"\$HOME/.local/bin" ||
	    $line =~ ":\$HOME/bin" 
         ]]
    then
      fail=1
      echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
    fi
  done
else
  if [[ $users ]]
  then
    fail=1
    echo -e "${NORMAL}RESULT:    ${RED}Nothing returned. You should have something for each interactive user.${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned. No interactive users found.${NORMAL}"
  fi
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity134, $controlid, $stigid134, $ruleid134, $cci134, $datetime, ${GRN}PASSED, Executable search paths within the initialization files of all local interactive RHEL 9 users only contain paths that resolve to the system default or the users home directory.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity134, $controlid, $stigid134, $ruleid134, $cci134, $datetime, ${RED}FAILED, Executable search paths within the initialization files of all local interactive RHEL 9 users do not only contain paths that resolve to the system default or the users home directory.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid135${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid135${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid135${NORMAL}"
echo -e "${NORMAL}CCI:       $cci135${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 135:  ${BLD}$title135a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title135b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title135c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity135${NORMAL}"

IFS='
'

fail=0

datetime="$(date +%FT%H:%M:%S)"

users="$(less /etc/passwd)"

if [[ $users ]]
then
  for line in ${users[@]}
  do
    shell="$(echo $line | awk -F: '{print $7}')"
    if ! [[ $shell =~ ('nologin'|'sync'|'shutdown'|'halt'|'false') ]]
    then
      if ! [[ $line =~ "root" ]]
      then
        echo -e "${NORMAL}RESULT:    ${CYN}$line${NORMAL}"
        fail=2
      else
        echo -e "${NORMAL}RESULT:    $line${NORMAL}"
      fi
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
  fail=1
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity135, $controlid, $stigid135, $ruleid135, $cci135, $datetime, ${GRN}PASSED, RHEL 9 does not have unauthorized accounts.${NORMAL}"
elif [[ $fail == 2 ]]
then
  echo -e "${NORMAL}$hostname, $severity135, $controlid, $stigid135, $ruleid135, $cci135, $datetime, ${CYN}VERIFY, Have the ISSO verify that the interactive users are authorized accounts.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity135, $controlid, $stigid135, $ruleid135, $cci135, $datetime, ${RED}FAILED, The command \"less /etc/passwd\" returned nothing.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid136${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid136${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid136${NORMAL}"
echo -e "${NORMAL}CCI:       $cci136${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 136:  ${BLD}$title136a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title136b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title136c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity136${NORMAL}"

IFS='
'

fail=1

datetime="$(date +%FT%H:%M:%S)"

maskline="$(grep umask /etc/bashrc | sed 's/^ *//')"

if [[ $maskline ]]
then
  for line in ${maskline[@]}
  do
    mask="$(echo $line | awk '{print $NF}')"
    if [[ $mask == "077" && ${line:0:1} != "#" ]]
    then
      fail=0
      echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity136, $controlid, $stigid136, $ruleid136, $cci136, $datetime, ${GRN}PASSED, RHEL 9 defines default permissions for the bash shell.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity136, $controlid, $stigid136, $ruleid136, $cci136, $datetime, ${RED}FAILED, RHEL 9 either does not define default permissions for the bash shell or the permissions are incorrect.${NORMAL}"
fi
  
echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid137${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid137${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid137${NORMAL}"
echo -e "${NORMAL}CCI:       $cci137${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 137:  ${BLD}$title137a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title137b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title137c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity137${NORMAL}"

IFS='
'

fail=1

datetime="$(date +%FT%H:%M:%S)"

maskline="$(grep umask 2>&1 /etc/csh.cshrc | sed 's/^ *//')"

if [[ $maskline ]]
then
  for line in ${maskline[@]}
  do
    mask="$(echo $line | awk '{print $2}')"
    if [[ $mask == "077" && ${line:0:1} != "#" ]]
    then
      fail=0
      echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity137, $controlid, $stigid137, $ruleid137, $cci137, $datetime, ${GRN}PASSED, RHEL 9 defines default permissions for the c shell.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity136, $controlid, $stigid136, $ruleid136, $cci136, $datetime, ${RED}FAILED, RHEL 9 either does not define default permissions for the c shell or the permissions are incorrect.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid138${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid138${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid138${NORMAL}"
echo -e "${NORMAL}CCI:       $cci138${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 138:  ${BLD}$title138a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title138b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title138c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity138${NORMAL}"

IFS='
'

fail=1

datetime="$(date +%FT%H:%M:%S)"

isinstalled="$(dnf list --installed 2>&1 policycoreutils-python-utils | grep -Ev 'Updating|Installed')"

if [[ $isinstalled ]]
then
  for line in ${isinstalled[@]}
  do
    if [[ ${isinstalled:0:1} != "#" ]]
    then
      fail=0
      echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity138, $controlid, $stigid138, $ruleid138, $cci138, $datetime, ${GRN}PASSED, RHEL 9 policycoreutils-python-utils package is installed.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity138, $controlid, $stigid138, $ruleid138, $cci138, $datetime, ${RED}FAILED, RHEL 9 policycoreutils-python-utils package is not installed.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid139${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid139${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid139${NORMAL}"
echo -e "${NORMAL}CCI:       $cci139${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 139:  ${BLD}$title139a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title139b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title139c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity139${NORMAL}"

IFS='
'

fail=1

datetime="$(date +%FT%H:%M:%S)"

config="$(egrep -ir '(!rootpw|!targetpw|!runaspw)' /etc/sudoers /etc/sudoers.d/ | grep -v '#')"

target=0
root=0
runas=0

if [[ $config ]]
then
  for line in ${config[@]}
  do
    value="$(echo $line | awk '{print $2}')"
    case "$value" in
      "!targetpw")
         (( target++ ))
	 echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
         ;;
      "!rootpw")
	 (( root++ ))
	 echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
	 ;;
      "!runaspw")
         (( runas++ ))
	 echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
	 ;;
      *)
	 echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
	 ;;
    esac
  done
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $target == 1 && $root == 1 && $runas == 1 ]]
then
  echo -e "${NORMAL}$hostname, $severity139, $controlid, $stigid139, $ruleid139, $cci139, $datetime, ${GRN}PASSED, RHEL 9 uses the invoking user's password for privilege escalation when using \"sudo\".${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity139, $controlid, $stigid139, $ruleid139, $cci139, $datetime, ${RED}FAILED, RHEL 9 does not use the invoking user's password for privilege escalation when using \"sudo\".${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid140${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid140${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid140${NORMAL}"
echo -e "${NORMAL}CCI:       $cci140${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 140:  ${BLD}$title140a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title140b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title140c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity140${NORMAL}"

IFS='
'

fail=0

datetime="$(date +%FT%H:%M:%S)"

all="$(grep -iwR 'ALL' /etc/sudoers /etc/sudoers.d/ | sed 's/ *//g' | grep -v '#')"

if [[ $all ]]
then
  for line in ${all[@]}
  do
    if [[ $line == "ALL ALL=(ALL) ALL" || $line == "ALL ALL=(ALL:ALL) ALL" ]]
    then
      fail=1
      echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity140, $controlid, $stigid140, $ruleid140, $cci140, $datetime, ${GRN}PASSED, RHEL 9 restricts privilege elevation to authorized personnel.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity140, $controlid, $stigid140, $ruleid140, $cci140, $datetime, ${RED}FAILED, RHEL 9 does not restrict privilege elevation to authorized personnel.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid141${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid141${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid141${NORMAL}"
echo -e "${NORMAL}CCI:       $cci141${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 141:  ${BLD}$title141a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title141b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title141c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity141${NORMAL}"

IFS='
'

fail=0

datetime="$(date +%FT%H:%M:%S)"

nullok="$(grep -i nullok /etc/pam.d/system-auth /etc/pam.d/password-auth)"

if [[ $nullok ]]
then
  fail=1
  for line in ${nullok[@]}
  do
    echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
  done
else
  echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity141, $controlid, $stigid141, $ruleid141, $cci141, $datetime, ${GRN}PASSED, RHEL 9 does not allow blank or null passwords.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity141, $controlid, $stigid141, $ruleid141, $cci141, $datetime, ${RED}FAILED, RHEL 9 allows blank or null passwords.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid142${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid142${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid142${NORMAL}"
echo -e "${NORMAL}CCI:       $cci142${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 142:  ${BLD}$title142a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title142b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title142c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity142${NORMAL}"

IFS='
'

fail=1

datetime="$(date +%FT%H:%M:%S)"

quality="$(grep pam_pwquality /etc/pam.d/system-auth)"

if [[ $quality ]]
then
  for line in ${quality[@]}
  do
    if [[ ${line:0:1} != "#" && $line =~ "required"  ]]
    then
      fail=0
      echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity142, $controlid, $stigid142, $ruleid142, $cci142, $datetime, ${GRN}PASSED, RHEL 9 ensures the password complexity module is enabled in the system-auth file.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity142, $controlid, $stigid142, $ruleid142, $cci142, $datetime, ${RED}FAILED, RHEL 9 does not ensure the password complexity module is enabled in the system-auth file.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid143${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid143${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid143${NORMAL}"
echo -e "${NORMAL}CCI:       $cci143${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 143:  ${BLD}$title143a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title143b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title143c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity143${NORMAL}"

IFS='
'

fail=1

datetime="$(date +%FT%H:%M:%S)"

dict="$(grep dictcheck 2>/dev/null /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf)"

if [[ $dict ]]
then
  for line in ${dict[@]}
  do
    file="$(echo $line | awk -F: '{print $1}')"
    setting="$(echo $line | awk -F: '{print $2}')"
    value="$(echo $setting| awk -F= '{print $2}' | sed 's/ //')"
    if [[ $value == "1" && ${setting:0:1} != "#" ]]
    then
      fail=0
      echo -e "${NORMAL}RESULT:    ${CYN}$file:${BLD}$setting${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${CYN}$file:${RED}$setting${NORMAL}"
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity143, $controlid, $stigid143, $ruleid143, $cci143, $datetime, ${GRN}PASSED, RHEL 9 prevent the use of dictionary words for passwords.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity143, $controlid, $stigid143, $ruleid143, $cci143, $datetime, ${RED}FAILED, RHEL 9 does not prevent the use of dictionary words for passwords.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid144${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid144${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid144${NORMAL}"
echo -e "${NORMAL}CCI:       $cci144${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 144:  ${BLD}$title144a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title144b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title144c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity144${NORMAL}"

IFS='
'

fail=0

datetime="$(date +%FT%H:%M:%S)"

search="sha512"

isinstalled="$(dnf list --installed 2>/dev/null aide | grep -Ev 'Updating|Installed')"

if [[ $isinstalled ]]
then

  location="$(find / 2>/dev/null -not -path '/mnt/*' -name aide.conf)"

  if [[ $location ]]
  then

    # In a restricted environment, "more /etc/aide.conf" will not work. You
    # have to use "cat /etc/aide.conf" instead

    echo -e "${NORMAL}RESULT:    ${BLD}\"aide.conf\" is in $location${NORMAL}"
    aideconfig="$(cat $location | grep -v "^!"| grep -v "=" | grep -v "^#" | grep -v "@@" | grep -v "verbose" | grep -v "dbout" | grep -v "report_url" | grep -v "^:::" | grep -v "^/etc/aide.conf$")"

    categories="$(cat $location | grep -v "^!" | grep "=" | grep -v "^#" | grep -v "@@" | grep -v "verbose" | grep -v "dbout" | grep -v "report_url")"

    badcat=( )
    goodcat=( )

    for line in ${categories[@]}
    do
      if ! [[ $line =~ $search ]]
      then
        badcat+=("$line")
      else
        goodcat+=("$line")
      fi
    done

    echo -e "${YLO}SHA512 Categories ---------------------------------${NORMAL}"
    for line in ${goodcat[@]}
    do
      echo -e "${NORMAL}RESULT:    $line${NORMAL}"
    done

    echo #blank line

    echo -e "${YLO}SHA512 Selections ---------------------------------${NORMAL}"
    for line in ${aideconfig[@]}
    do
      found=0
      for category in ${goodcat[@]}
      do
        cat="$(echo $category | awk '{print $1}')"
        compare="$(echo $line | awk '{print $2}')"
        if [[ $compare == $cat || $line =~ $search ]]
        then
          echo -e "${NORMAL}RESULT:    $line${NORMAL}"
          found=1
          break
        fi
      done
      if [[ $found == 0 ]]
      then
        if (( ${#badcat[@]} > 0 ))
        then
          for category in ${badcat[@]}
          do
            cat="$(echo $category | awk '{print $1}')"
            compare="$(echo $line | awk '{print $2}')"
            if [[ $compare == $cat || $line =~ $search ]]
            then
              echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
              fail=1
              break
            fi
          done
        fi
      fi
    done
  else
    echo -e "${NORMAL}RESULT:    ${RED}\"aide.conf\" not found${NORMAL}"
    fail=1
  fi
else
  fail=1
  echo -e "${NORMAL}RESULT:    ${RED}The \"aide\" package is not installed${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity144, $controlid, $stigid144, $ruleid144, $cci144, $datetime, ${GRN}PASSED, RHEL 9 uses a file integrity tool that is configured to use FIPS 140-3-approved cryptographic hashes for validating file contents and directories.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity144, $controlid, $stigid144, $ruleid144, $cci144, $datetime, ${RED}FAILED, RHEL 9 does not use a file integrity tool that is configured to use FIPS 140-3-approved cryptographic hashes for validating file contents and directories.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid145${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid145${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid145${NORMAL}"
echo -e "${NORMAL}CCI:       $cci145${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 145:  ${BLD}$title145a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title145b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title145c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity145${NORMAL}"

IFS='
'

fail=0

datetime="$(date +%FT%H:%M:%S)"

search="acl"

isinstalled="$(dnf list --installed 2>/dev/null aide | grep -Ev 'Updating|Installed')"

if [[ $isinstalled ]]
then

  location="$(find / 2>/dev/null -not -path '/mnt/*' -name aide.conf)"

  if [[ $location ]]
  then

    # In a restricted environment, "more /etc/aide.conf" will not work. You
    # have to use "cat /etc/aide.conf" instead

    echo -e "${NORMAL}RESULT:    ${BLD}\"aide.conf\" is in $location${NORMAL}"
    aideconfig="$(cat $location | grep -v "^!"| grep -v "=" | grep -v "^#" | grep -v "@@" | grep -v "verbose" | grep -v "dbout" | grep -v "report_url" | grep -v "^:::" | grep -v "^/etc/aide.conf$")"

    categories="$(cat $location | grep -v "^!" | grep "=" | grep -v "^#" | grep -v "@@" | grep -v "verbose" | grep -v "dbout" | grep -v "report_url")"

    badcat=( )
    goodcat=( )

    for line in ${categories[@]}
    do
      if ! [[ $line =~ $search ]]
      then
        badcat+=("$line")
      else
        goodcat+=("$line")
      fi
    done

    echo -e "${YLO}ACL Categories -----------------------------------${NORMAL}"
    for line in ${goodcat[@]}
    do
      echo -e "${NORMAL}RESULT:    $line${NORMAL}"
    done

    echo #blank line
  
    echo -e "${YLO}ACL Selections -----------------------------------${NORMAL}"
    for line in ${aideconfig[@]}
    do
      found=0
      for category in ${goodcat[@]}
      do
        cat="$(echo $category | awk '{print $1}')"
        compare="$(echo $line | awk '{print $2}')"
        if [[ $compare == $cat || $line =~ $search ]]
        then
          echo -e "${NORMAL}RESULT:    $line${NORMAL}"
          found=1
          break
        fi
      done
      if [[ $found == 0 ]]
      then
        if (( ${#badcat[@]} > 0 ))
        then
          for category in ${badcat[@]}
          do
            cat="$(echo $category | awk '{print $1}')"
            compare="$(echo $line | awk '{print $2}')"
            if [[ $compare == $cat || $line =~ $search ]]
            then
              echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
              fail=1
              break
            fi
          done
        fi
      fi
    done
  else
    echo -e "${NORMAL}RESULT:    ${RED}\"aide.conf\" not found${NORMAL}"
    fail=1
  fi
else
  fail=1
  echo -e "${NORMAL}RESULT:    ${RED}The \"aide\" package is not installed${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity145, $controlid, $stigid145, $ruleid145, $cci145, $datetime, ${GRN}PASSED, RHEL 9 is configured so that the file integrity tool verifies Access Control Lists (ACLs).${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity145, $controlid, $stigid145, $ruleid145, $cci145, $datetime, ${RED}FAILED, RHEL 9 is not configured so that the file integrity tool verifies Access Control Lists (ACLs).${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid146${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid146${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid146${NORMAL}"
echo -e "${NORMAL}CCI:       $cci146${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 146:  ${BLD}$title146a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title146b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title146c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity146${NORMAL}"

IFS='
'

fail=0

datetime="$(date +%FT%H:%M:%S)"

search="xattrs"

isinstalled="$(dnf list --installed 2>/dev/null aide | grep -Ev 'Updating|Installed')"

if [[ $isinstalled ]]
then

  location="$(find / 2>/dev/null -not -path '/mnt/*' -name aide.conf)"

  if [[ $location ]]
  then

    # In a restricted environment, "more /etc/aide.conf" will not work. You
    # have to use "cat /etc/aide.conf" instead

    echo -e "${NORMAL}RESULT:    ${BLD}\"aide.conf\" is in $location${NORMAL}"
    aideconfig="$(cat $location | grep -v "^!"| grep -v "=" | grep -v "^#" | grep -v "@@" | grep -v "verbose" | grep -v "dbout" | grep -v "report_url" | grep -v "^:::" | grep -v "^/etc/aide.conf$")"

    categories="$(cat $location | grep -v "^!" | grep "=" | grep -v "^#" | grep -v "@@" | grep -v "verbose" | grep -v "dbout" | grep -v "report_url")"

    badcat=( )
    goodcat=( )

    for line in ${categories[@]}
    do
      if ! [[ $line =~ $search ]]
      then
        badcat+=("$line")
      else
        goodcat+=("$line")
      fi
    done

    echo -e "${YLO}XATTRS Categories --------------------------------${NORMAL}"
    for line in ${goodcat[@]}
    do
      echo -e "${NORMAL}RESULT:    $line${NORMAL}"
    done

    echo #blank line

    echo -e "${YLO}XATTRS Selections --------------------------------${NORMAL}"
    for line in ${aideconfig[@]}
    do
      found=0
      for category in ${goodcat[@]}
      do
        cat="$(echo $category | awk '{print $1}')"
        compare="$(echo $line | awk '{print $2}')"
        if [[ $compare == $cat || $line =~ $search ]]
        then
          echo -e "${NORMAL}RESULT:    $line${NORMAL}"
          found=1
          break
        fi
      done
      if [[ $found == 0 ]]
      then
        if (( ${#badcat[@]} > 0 ))
        then
          for category in ${badcat[@]}
          do
            cat="$(echo $category | awk '{print $1}')"
            compare="$(echo $line | awk '{print $2}')"
            if [[ $compare == $cat || $line =~ $search ]]
            then
              echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
              fail=1
              break
            fi
          done
        fi
      fi
    done
  else
    echo -e "${NORMAL}RESULT:    ${RED}\"aide.conf\" not found${NORMAL}"
    fail=1
  fi
else
  fail=1
  echo -e "${NORMAL}RESULT:    ${RED}The \"aide\" package is not installed${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity146, $controlid, $stigid146, $ruleid146, $cci146, $datetime, ${GRN}PASSED, RHEL 9 is configured so that the file integrity tool verifies extended attributes.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity146, $controlid, $stigid146, $ruleid146, $cci146, $datetime, ${RED}FAILED, RHEL 9 is not configured so that the file integrity tool verifies extended attributes.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid147${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid147${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid147${NORMAL}"
echo -e "${NORMAL}CCI:       $cci147${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 147:  ${BLD}$title147a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title147b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title147c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity147${NORMAL}"

IFS='
'

fail=0

datetime="$(date +%FT%H:%M:%S)"

cmd1="$(grep -i modload /etc/rsyslog.conf /etc/rsyslog.d/* 2>/dev/null)"
cmd2="$(grep -i 'load="imtcp"' /etc/rsyslog.conf /etc/rsyslog.d/* 2>/dev/null)"
cmd3="$(grep -i 'load="imrelp"' /etc/rsyslog.conf /etc/rsyslog.d/* 2>/dev/null)"
cmd4="$(grep -i serverrun /etc/rsyslog.conf /etc/rsyslog.d/* 2>/dev/null)"
cmd5="$(grep -i 'port="\S*"' /etc/rsyslog.conf /etc/rsyslog.d/* 2>/dev/null)"

cmdarr=($cmd1 $cmd2 $cmd3 $cmd4 $cmd5)

for line in ${cmdarr[@]}
do
  if [[ $line =~ ":" ]]
  then
    file="$(echo $line | awk -F: '{print $1}')"
    conf="$(echo $line | awk -F: '{print $2}')"
    if [[ ${conf:0:1} != "#" ]]
    then
      fail=1
      echo -e "${NORMAL}RESULT:    ${CYN}$file:${RED}$conf${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${CYN}$file:${BLD}$conf${NORMAL}"
    fi
  elif [[ ${line:0:1} != "#" ]]
  then
    fail=1
    echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
  fi
done

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity147, $controlid, $stigid147, $ruleid147, $cci147, $datetime, ${GRN}PASSED, The RHEL 9 rsyslog daemon does not accept log messages from other servers.${NORMAL}" 
else
  echo -e "${NORMAL}$hostname, $severity147, $controlid, $stigid147, $ruleid147, $cci147, $datetime, ${RED}FAILED, The RHEL 9 rsyslog daemon accepts log messages from other servers.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid148${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid148${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid148${NORMAL}"
echo -e "${NORMAL}CCI:       $cci148${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 148:  ${BLD}$title148a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title148b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title148c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity148${NORMAL}"

IFS='
'

fail=1

datetime="$(date +%FT%H:%M:%S)"

cron_test() {
  logger -p local0.info "Test message for all facilities."; exec /bin/bash
}

cron_test &

sleep 3 # give crond a little time to catch the message.

cmd1="$(grep -s cron /etc/rsyslog.conf /etc/rsyslog.d/*.conf)"
cmd2="$(exec tail /var/log/messages | grep 'Test message for all facilities.')"

if [[ $cmd1 ]]
then
  for line in ${cmd1[@]}
  do
    if [[ $line =~ ('cron.'|'/var/log/cron') ]]
    then
      fail=0
      echo -e "${NORMAL}RESULT:    ${BLD}a. $line${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    a. $line${NORMAL}"
    fi
  done
fi

if [[ $cmd2 ]]
then
  fail=0
  for line in ${cmd2[@]}
  do
    echo -e "${NORMAL}RESULT:    ${BLD}c. $line${NORMAL}"
  done
else
  echo -e "${NORMAL}RESULT:    ${RED}c. Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity148, $controlid, $stigid148, $ruleid148, $cci148, $datetime, ${GRN}PASSED, The RHEL 9 \"rsyslog\" daemon is configured to log cron events.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity148, $controlid, $stigid148, $ruleid148, $cci148, $datetime, ${RED}FAILED, The RHEL 9 \"rsyslog\" daemon is not configured to log cron events.${NORMAL}"
fi

exit 
