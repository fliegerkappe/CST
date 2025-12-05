#! /bin/bash

# AU-12 Audit Generation
#
# Control: The information system:
# a. Provides audit record generation capability for the auditable events defined in AU-2 a. at 
#    [Assignment: organization-defined information system components];
# b. Allows [Assignment: organization-defined personnel or roles] to select which auditable
#    events are to be audited by specific components of the information system; and
# c. Generates audit records for the events defined in AU-2 d. with the content defined in AU-3.

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
NORMAL=`echo "\e[0m"`           # NORMAL

stig="Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Version 3, Release: 10 Benchmark Date: 26 Jan 2023"

hostname="$(uname -n)"

if [[ -f /etc/redhat-release ]]
then
   os="$(cat /etc/redhat-release)"
else
   os="OS not defined"
fi

prog="$(basename $0)"

IFS='
'

controlid="AU-12 Audit Generation"

title1a="The Red Hat Enterprise Linux operating system must audit all uses of the chown syscall."
title1b="Checking with 'grep chown /etc/audit/audit.rules'."
title1c="Expecting:${YLO}
           -a always,exit -F arch=b32 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=unset -k perm_mod
           -a always,exit -F arch=b64 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=unset -k perm_mod
           Note: If both the \"b32\" and \"b64\" audit rules are not defined for the \"chown\", \"fchown\", \"fchownat\", and \"lchown\" syscalls, this is a finding.
           Note: If there are no audit rules defined for the \"chown\" syscall, this is a finding."${BLD}
cci1="CCI-000172"
stigid1="RHEL-07-030370"
severity1="CAT II"
ruleid1="SV-204517r809570_rule"
vulnid1="V-204517"

title2a="The Red Hat Enterprise Linux operating system must audit all uses of the chmod, fchmod, and fchmodat syscalls."
title2b="Checking with 'grep chmod /etc/audit/audit.rules'."
title2c="Expecting:${YLO} 
           -a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=unset -k perm_mod
           -a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=unset -k perm_mod
           Note: If both the \"b32\" and \"b64\" audit rules are not defined for the \"chmod\", \"fchmod\", and \"fchmodat\" syscalls, this is a finding.
           Note: If there are no audit rules defined for the \"chmod\", \"fchmod\", or \"fchmodat\" syscalls, this is a finding."${BLD}
cci2="CCI-000172"
stigid2="RHEL-07-030410"
severity2="CAT II"
ruleid2="SV-204521r809772_rule"
vulnid2="V-204521"

title3a="The Red Hat Enterprise Linux operating system must audit all uses of the setxattr, fsetxattr, lsetxattr, removexattr, fremovexattr, and lremovexattr syscalls."
title3b="Checking with 'grep xattr /etc/audit/audit.rules'."
title3c="Expecting: ${YLO}
           -a always,exit -F arch=b32 -S setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr -F auid>=1000 -F auid!=unset -k perm_mod
           -a always,exit -F arch=b64 -S setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr -F auid>=1000 -F auid!=unset -k perm_mod
           Note: If both the \"b32\" and \"b64\" audit rules are not defined for the \"setxattr\", \"fsetxattr\", \"lsetxattr\", \"removexattr\", \"fremovexattr\", and \"lremovexattr\" syscalls, this is a finding.
           Note: If there are no audit rules defined for the \"setxattr\" syscall, this is a finding."${BLD}
cci3="CCI-000172"
stigid3="RHEL-07-030440"
severity3="CAT II"
ruleid3="SV-204524r809775_rule"
vulnid3="V-204524"

title4a="The Red Hat Enterprise Linux operating system must audit all uses of the creat, open, openat, open_by_handle_at, truncate, and ftruncate syscalls."
title4b="Checking with 'grep 'open\|truncate\|creat' /etc/audit/audit.rules'."
title4c="Expecting: ${YLO}
           -a always,exit -F arch=b32 -S creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -k access
           -a always,exit -F arch=b32 -S creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -k access
           -a always,exit -F arch=b64 -S creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -k access
           -a always,exit -F arch=b64 -S creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -k access
           Note: If both the \"b32\" and \"b64\" audit rules are not defined for the \"creat\", \"open\", \"openat\", \"open_by_handle_at\", \"truncate\", and \"ftruncate\" syscalls, this is a finding.
           Note: If the output does not produce a rule containing \"-F exit=-EPERM\", this is a finding.
           Note: If the output does not produce a rule containing \"-F exit=-EACCES\", this is a finding."${BLD}
cci4="CCI-000172"
stigid4="RHEL-07-030500"
severity4="CAT II"
ruleid4="SV-204531r809815_rule"
vulnid4="V-204531"

title5a="The Red Hat Enterprise Linux operating system must audit all uses of the semanage command."
title5b="Checking with 'grep -w '/usr/sbin/semanage' /etc/audit/audit.rules'."
title5c="Expecting:${YLO} 
           -a always,exit -F path=/usr/sbin/semanage -F perm=x -F auid>=1000 -F auid!=unset -k privileged-priv_change
           Note: If the command does not return any output, this is a finding."${BLD}
cci5="CCI-000172"
stigid5="RHEL-07-030560"
severity5="CAT II"
ruleid5="SV-204536r833109_rule"
vulnid5="V-204536"

title6a="The Red Hat Enterprise Linux operating system must audit all uses of the setsebool command."
title6b="Checking with 'grep -w '/usr/sbin/setsebool' /etc/audit/audit.rules'."
title6c="Expecting:${YLO} 
           -a always,exit -F path=/usr/sbin/setsebool -F perm=x -F auid>=1000 -F auid!=unset -k privileged-priv_change
           Note: If the command does not return any output, this is a finding."${BLD}
cci6="CCI-000172"
stigid6="RHEL-07-030570"
severity6="CAT II"
ruleid6="SV-204537r861017_rule"
vulnid6="V-204537"

title7a="The Red Hat Enterprise Linux operating system must audit all uses of the chcon command."
title7b="Checking with 'grep -w '/usr/bin/chcon' /etc/audit/audit.rules'."
title7c="Expecting:${YLO}
           -a always,exit -F path=/usr/bin/chcon -F perm=x -F auid>=1000 -F auid!=unset -k privileged-priv_change
           Note: If the command does not return any output, this is a finding."${BLD}
cci7="CCI-000172"
stigid7="RHEL-07-030580"
severity7="CAT II"
ruleid7="SV-204538r833115_rule"
vulnid7="V-204538"

title8a="The Red Hat Enterprise Linux operating system must audit all uses of the setfiles command."
title8b="Checking with 'grep -w '/usr/sbin/setfiles' /etc/audit/audit.rules'."
title8c="Expecting:${YlO}
           -a always,exit -F path=/usr/sbin/setfiles -F perm=x -F auid>=1000 -F auid!=unset -k privileged-priv_change
           Note: If the command does not return any output, this is a finding."${BLD}
cci8="CCI-000172"
stigid8="RHEL-07-030590"
severity8="CAT II"
ruleid8="SV-204539r833118_rule"
vulnid8="V-204539"

title9a="The Red Hat Enterprise Linux operating system must generate audit records for all unsuccessful account access events."
title9b="Checking with 'grep -i /var/run/faillock /etc/audit/audit.rules'."
title9c="Expecting:${YLO}
           -w /var/run/faillock -p wa -k logins
           Note: If the command does not return any output, this is a finding."${BLD}
cci9="CCI-000126"
stigid9="RHEL-07-030610"
severity9="CAT II"
ruleid9="SV-204540r603261_rule"
vulnid9="V-204540"

title10a="The Red Hat Enterprise Linux operating system must generate audit records for all successful account access events."
title10b="Checking with 'grep -i '/var/log/lastlog' /etc/audit/audit.rules'."
title10c="Expecting:${YLO}
           -w /var/log/lastlog -p wa -k logins
           Note: If the command does not return any output, this is a finding."${BLD}
cci10="CCI-000126"
stigid10="RHEL-07-030620"
severity10="CAT II"
ruleid10="SV-204541r603261_rule"
vulnid10="V-204541"

title11a="The Red Hat Enterprise Linux operating system must audit all uses of the passwd command."
title11b="Checking with 'grep -i '/usr/bin/passwd' /etc/audit/audit.rules'."
title11c="Expecting:${YLO}
           -a always,exit -F path=/usr/bin/passwd -F perm=x -F auid>=1000 -F auid!=unset -k privileged-passwd
           Note: If the command does not return any output, this is a finding."${BLD}
cci11="CCI-000126"
stigid11="RHEL-07-030630"
severity11="CAT II"
ruleid11="SV-204542r833121_rule"
vulnid11="V-204542"

title12a="The Red Hat Enterprise Linux operating system must audit all uses of the unix_chkpwd command."
title12b="Checking with 'grep -w '/usr/sbin/unix_chkpwd' /etc/audit/audit.rules'."
title12c="Expecting:${YLO} 
           -a always,exit -F path=/usr/sbin/unix_chkpwd -F perm=x -F auid>=1000 -F auid!=unset -k privileged-passwd
           Note: If the command does not return any output, this is a finding."${BLD}
cci12="CCI-000126"
stigid12="RHEL-07-030640"
severity12="CAT II"
ruleid12="SV-204543r883124_rule"
vulnid12="V-204543"

title13a="The Red Hat Enterprise Linux operating system must audit all uses of the gpasswd command."
title13b="Checking with 'grep -i /usr/bin/gpasswd /etc/audit/audit.rules'."
title13c="Expecting:${YLO}
           -a always,exit -F path=/usr/bin/gpasswd -F perm=x -F auid>=1000 -F auid!=unset -k privileged-passwd
           Note: If the command does not return any output, this is a finding."${BLD}
cci13="CCI-000126"
stigid13="RHEL-07-030650"
severity13="CAT II"
ruleid13="SV-204544r833127_rule"
vulnid13="V-204544"

title14a="The Red Hat Enterprise Linux operating system must audit all uses of the chage command."
title14b="Checking with 'grep -w '/usr/bin/chage' /etc/audit/audit.rules'."
title14c="Expecting:${YLO}
           -a always,exit -F path=/usr/bin/chage -F perm=x -F auid>=1000 -F auid!=unset -k privileged-passwd
           Note: If the command does not return any output, this is a finding."${BLD}
cci14="CCI-000126"
stigid14="RHEL-07-030660"
severity14="CAT II"
ruleid14="SV-204545r833130_rule"
vulnid14="V-204545"

title15a="The Red Hat Enterprise Linux operating system must audit all uses of the userhelper command."
title15b="Checking with 'grep -w /usr/'sbin/userhelper' /etc/audit/audit.rules'."
title15c="Expecting:${YLO}
           -a always,exit -F path=/usr/sbin/userhelper -F perm=x -F auid>=1000 -F auid!=unset -k privileged-passwd
           Note: If the command does not return any output, this is a finding."${BLD}
cci15="CCI-000126"
stigid15="RHEL-07-030670"
severity15="CAT II"
ruleid15="SV-204546r833133_rule"
vulnid15="V-204546"

title16a="The Red Hat Enterprise Linux operating system must audit all uses of the su command."
title16b="Checking with 'grep -w /usr/bin/su' /etc/audit/audit.rules'."
title16c="Expecting:${YLO}
           -a always,exit -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=unset -k privileged-priv_change
           Note: If the command does not return any output, this is a finding."${BLD}
cci16="CCI-000126"
stigid16="RHEL-07-030680"
severity16="CAT II"
ruleid16="SV-204547r833136_rule"
vulnid16="V-204547"

title17a="The Red Hat Enterprise Linux operating system must audit all uses of the sudo command."
title17b="Checking with 'grep -w '/usr/bin/sudo' /etc/audit/audit.rules'."
title17c="Expecting:${YLO}
           -a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=unset -k privileged-priv_change
           Note: If the command does not return any output, this is a finding."${BLD}
cci17="CCI-000172"
stigid17="RHEL-07-030690"
severity17="CAT II"
ruleid17="SV-204548r833139_rule"
vulnid17="V-204548"

title18a="The Red Hat Enterprise Linux operating system must audit all uses of the sudoers file and all files in the /etc/sudoers.d/ directory."
title18b="Checking with 'grep -w '/etc/sudoers' /etc/audit/audit.rules'."
title18c="Expecting:${YLO}
           -w /etc/sudoers -p wa -k privileged-actions
           Note: If the command does not return any output, this is a finding."${BLD}
cci18="CCI-000172"
stigid18="RHEL-07-030700"
severity18="CAT II"
ruleid18="SV-204549r603261_rule"
vulnid18="V-204549"

title19a="The Red Hat Enterprise Linux operating system must audit all uses of the newgrp command."
title19b="Checking with 'grep -w '/usr/bin/newgrp' /etc/audit/audit.rules'."
title19c="Expecting:${YLO}
           -a always,exit -F path=/usr/bin/newgrp -F perm=x -F auid>=1000 -F auid!=unset -k privileged-priv_change
           Note: If the command does not return any output, this is a finding."${BLD}
cci19="CCI-000172"
stigid19="RHEL-07-030710"
severity19="CAT II"
ruleid19="SV-204550r833142_rule"
vulnid19="V-204550"

title20a="The Red Hat Enterprise Linux operating system must audit all uses of the chsh command."
title20b="Checking with 'grep -w '/usr/bin/chsh' /etc/audit/audit.rules'."
title20c="Expecting:${YLO}
           -a always,exit -F path=/usr/bin/chsh -F perm=x -F auid>=1000 -F auid!=unset -k privileged-priv_change
           Note: If the command does not return any output, this is a finding."${BLD}
cci20="CCI-000172"
stigid20="RHEL-07-030720"
severity20="CAT II"
ruleid20="SV-204551r833145_rule"
vulnid20="V-204551"

title21a="The Red Hat Enterprise Linux operating system must audit all uses of the ssh-keysign command."
title21b="Checking with 'grep -w '/usr/libexec/openssh/ssh-keysign' /etc/audit/audit.rules'."
title21c="Expecting:${YLO}
           -a always,exit -F path=/usr/libexec/openssh/ssh-keysign -F perm=x -F auid>=1000 -F auid!=unset -k privileged-ssh
           Note: If the command does not return any output, this is a finding."${BLD}
cci21="CCI-000172"
stigid21="RHEL-07-030780"
severity21="CAT II"
ruleid21="SV-204556r833160_rule"
vulnid21="V-204556"

title22a="The Red Hat Enterprise Linux operating system must audit all uses of the crontab command."
title22b="Checking with 'grep -w '/usr/bin/crontab' /etc/audit/audit.rules'."
title22c="Expecting:${YLO} 
           -a always,exit -F path=/usr/bin/crontab -F perm=x -F auid>=1000 -F auid!=unset -k privileged-cron
           Note: If the command does not return any output, this is a finding."${BLD}
cci22="CCI-000172"
stigid22="RHEL-07-030800"
severity22="CAT II"
ruleid22="SV-204557r833163_rule"
vulnid22="V-204557"

title23a="The Red Hat Enterprise Linux operating system must audit all uses of the pam_timestamp_check command."
title23b="Checking with 'grep -w '/sbin/pam_timestamp_check' /etc/audit/audit.rules'."
title23c="Expecting:${YLO}
           -a always,exit -F path=/sbin/pam_timestamp_check -F perm=x -F auid>=1000 -F auid!=unset -k privileged-pam
           Note: If the command does not return any output, this is a finding."
cci23="CCI-000172"
stigid23="RHEL-07-030810"
severity23="CAT II"
ruleid23="SV-204558r833166_rule"
vulnid23="V-204558"

title26a="The Red Hat Enterprise Linux operating system must audit all uses of the delete_module syscall."
title26b="Checking with 'grep -iw delete_module /etc/audit/audit.rules'."
title26c="Expecting:${YLO}
           -a always,exit -F arch=b64 -S delete_module -k module-change
           Note: If both the \"b32\" and \"b64\" audit rules are not defined for the \"delete_module\" syscall, this is a finding.
           Note: If there are no audit rules defined for \"delete_module\", this is a finding."${BLD}
cci26="CCI-000172"
stigid26="RHEL-07-030830"
severity26="CAT II"
ruleid26="SV-204562r833175_rule"
vulnid26="V-204562"

title27a="The Red Hat Enterprise Linux operating system must audit all uses of the kmod command."
title27b="Checking with 'grep -w '/usr/bin/kmod' /etc/audit/audit.rules'."
title27c="Expecting:${YLO}
           -w /usr/bin/kmod -p x -F auid!=4294967295 -k module-change
           Note: If the command does not return any output, this is a finding."${BLD}
cci27="CCI-000172"
stigid27="RHEL-07-030840"
severity27="CAT II"
ruleid27="SV-204563r603261_rule"
vulnid27="V-204563"

title28a="The Red Hat Enterprise Linux operating system must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/passwd."
title28b="Checking with 'grep /etc/passwd /etc/audit/audit.rules'."
title28c="Expecting:${YLO}
           -w /etc/passwd -p wa -k identity
           Note: If the command does not return a line, or the line is commented out, this is a finding."${BLD}
cci28="CCI-000172"
stigid28="RHEL-07-030870"
severity28="CAT II"
ruleid28="SV-204564r603261_rule"
vulnid28="V-204564"

title33a="The Red Hat Enterprise Linux operating system must audit all uses of the unlink syscall."
title33b="Checking with 'grep -iw unlink/etc/audit/audit.rules'."
title33c="Expecting:${YLO}
           -a always,exit -F arch=b32 -S unlink,unlinkat,rename,renameat,rmdir -F auid>=1000 -F auid!=unset -k delete
           -a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat,rmdir -F auid>=1000 -F auid!=unset -k delete
           Note: If both the \"b32\" and \"b64\" audit rules are not defined for the \"unlink\", \"unlinkat\", \"rename\", \"renameat\", and \"rmdir\" syscalls, this is a finding.
           Note: If there are no audit rules defined for the \"unlink\" syscall, this is a finding."${BLD}
cci33="CCI-000172"
stigid33="RHEL-07-030910"
severity33="CAT II"
ruleid33="SV-204572r809825_rule"
vulnid33="V-204572"

title29a="The Red Hat Enterprise Linux operating system must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/group."
title29b="Checking with 'grep /etc/group /etc/audit/audit.rules'."
title29c="Expecting:${YLO} 
           -w /etc/group -p wa -k identity.
           Note: If the command does not return a line, or the line is commented out, this is a finding.${BLD}"
cci29="CCI-000172"
stigid29="RHEL-07-030871"
severity29="CAT II"
ruleid29="SV-204565r603261_rule"
vulnid29="V-204565"

title30a="The Red Hat Enterprise Linux operating system must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/gshadow."
title30b="Checking with 'grep /etc/gshadow /etc/audit/audit.rules'."
title30c="Expecting:${YLO} 
          -w /etc/gshadow -p wa -k identity
           Note: If the command does not return a line, or the line is commented out, this is a finding."${BLD}
cci30="CCI-000172"
stigid30="RHEL-07-030872"
severity30="CAT II"
ruleid30="SV-204566r603261_rule"
vulnid30="V-204566"

title31a="The Red Hat Enterprise Linux operating system must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/shadow."
title31b="Checking with 'grep /etc/shadow /etc/audit/audit.rules'."
title31c="Expecting:${YLO}
           -w /etc/shadow -p wa -k identity.
           Note: If the command does not return a line, or the line is commented out, this is a finding."${BLD}
cci31="CCI-000172"
stigid31="RHEL-07-030873"
severity31="CAT II"
ruleid31="SV-204567r603261_rule"
vulnid31="V-204567"

title32a="The Red Hat Enterprise Linux operating system must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/opasswd."
title32b="Checking with 'grep /etc/security/opasswd /etc/audit/audit.rules'."
title32c="Expecting:${YLO}
           -w /etc/security/opasswd -p wa -k identity
           Note: If the command does not return a line, or the line is commented out, this is a finding."${BLD}
cci32="CCI-000172"
stigid32="RHEL-07-030874"
severity32="CAT II"
ruleid32="SV-204568r744115_rule"
vulnid32="V-204568"

title24a="The Red Hat Enterprise Linux operating system must audit all uses of the create_module syscall."
title24b="Checking with 'grep -w 'create_module' /etc/audit/audit.rules'."
title24c="Expecting:${YLO}
           -a always,exit -F arch=b32 -S create_module -F auid>=1000 -F auid!=unset -k module-change
           -a always,exit -F arch=b64 -S create_module -F auid>=1000 -F auid!=unset -k module-change
           Note: If both the \"b32\" and \"b64\" audit rules are not defined for the \"create_module\" syscall, this is a finding."${BLD}
cci24="CCI-000172"
stigid24="RHEL-07-030819"
severity24="CAT II"
ruleid24="SV-204559r833169_rule"
vulnid24="V-204559"

title25a="The Red Hat Enterprise Linux operating system must audit all uses of the finit_module syscall."
title25b="Checking with 'grep init_module /etc/audit/audit.rules'."
title25c="Expecting:${YLO}
           -a always,exit -F arch=b32 -S init_module,finit_module -F auid>=1000 -F auid!=unset -k modulechange
           -a always,exit -F arch=b64 -S init_module,finit_module -F auid>=1000 -F auid!=unset -k modulechange
           Note: If both the \"b32\" and \"b64\" audit rules are not defined for the \"init_module\" and \"finit_module\" syscalls, this is a finding."${BLD} 
cci25="CCI-000172"
stigid25="RHEL-07-030821"
severity25="CAT II"
ruleid25="SV-204560r833172_rule"
vulnid25="V-204560"

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

file1="/etc/audit/audit.rules"
fail=0
chown32=0
chown64=0
lchown32=0
lchown64=0
fchown32=0
fchown64=0
fchownat32=0
fchownat64=0

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file1 ]]
then
   aurules="$(grep chown $file1 | grep -v '^#')"
   if [[ $aurules ]]
   then
      for rule in ${aurules[@]}
      do
         echo -e "${NORMAL}RESULT:    ${BLD}$rule${NORMAL}"
         if [[ ! $rule =~ '-a always,exit' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-a always,exit'${NORMAL}"
            fail=1
         fi
         if [[ ! $rule =~ 'perm_mod' &&
               ! $rule =~ 'perm-change'
            ]] 
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing perm_mod or perm-change${NORMAL}"
         fi

         IFS=' ' read -a fieldvals <<< "${rule}"

         for field in ${fieldvals[@]}
         do
            if [[ $field =~ 'chown' ]]
            then
               IFS=',' read -r -a chownarr <<< "$field"
               for element in ${chownarr[@]}
               do
                  if [[ $rule =~ "arch=b32" ]]
                  then
                     case $element in
                        'chown')
                           (( chown32++ ))
                           ;;
                        'lchown')
                           (( lchown32++ ))
                           ;;
                        'fchown')
                           (( fchown32++ ))
                           ;;
                        'fchownat')
                           (( fchownat32++ ))
                           ;;
                     esac
                  elif [[ $rule =~ "arch=b64" ]]
                  then
                     case $element in
                        'chown')
                           (( chown64++ ))
                           ;;
                        'lchown')
                           (( lchown64++ ))
                           ;;
                        'fchown')
                           (( fchown64++ ))
                           ;;
                        'fchownat')
                           (( fchownat64++ ))
                           ;;
                     esac
                  fi
               done
            fi   
            if [[ $field =~ 'auid>=' ]]
            then
               auidval="$(echo $field | awk -F'>=' '{print $2}')"
               if (( $auidval > 1000 ))
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid>=' cannot be greater than 1000${NORMAL}"
                  fail=1
               fi
            elif [[ $field =~ 'auid!=' ]]
            then
               auidval="$(echo $field | awk -F'!=' '{print $2}')"
               if (( $auidval != 4294967295 )) && [[ $auidval != "unset" ]]
               then
                  echo -e "${NORMAL}RESULT:    ${RED}\"auid!=\" must be \"4294967295\", or \"unset\".${NORMAL}"
                  fail=1
               fi
            fi
         done
      done
      if [[ $chown32 == 0 ]]
      then
         echo -e "${NORMAL}RESULT:    ${RED}A rule for \"chown\" was not found for \"arch=b32\".${NORMAL}"
         fail=1
      fi
      if [[ $lchown32 == 0 ]]
      then
         echo -e "${NORMAL}RESULT:    ${RED}A rule for \"lchown\" was not found for \"arch=b32\".${NORMAL}"
         fail=1
      fi
      if [[ $fchown32 == 0 ]]
      then
         echo -e "${NORMAL}RESULT:    ${RED}A rule for \"fchown\" was not found for \"arch=b32\".${NORMAL}"
         fail=1
      fi
      if [[ $fchownat32 == 0 ]]
      then
         echo -e "${NORMAL}RESULT:    ${RED}A rule for \"fchownat\" was not found for \"arch=b32\".${NORMAL}"
         fail=1
      fi
      if [[ $chown64 == 0 ]]
      then
         echo -e "${NORMAL}RESULT:    ${RED}A rule for \"chown\" was not found for \"arch=b64\".${NORMAL}"
         fail=1
      fi
      if [[ $lchown64 == 0 ]]
      then
         echo -e "${NORMAL}RESULT:    ${RED}A rule for \"lchown\" was not found for \"arch=b64\".${NORMAL}"
         fail=1
      fi
      if [[ $fchown64 == 0 ]]
      then
         echo -e "${NORMAL}RESULT:    ${RED}A rule for \"fchown\" was not found for \"arch=b64\".${NORMAL}"
         fail=1
      fi
      if [[ $fchownat64 == 0 ]]
      then
         echo -e "${NORMAL}RESULT:    ${RED}A rule for \"fchownat\" was not found for \"arch=b64\".${NORMAL}"
         fail=1
      fi
   else
      echo -e "${NORMAL}RESULT:    ${RED}missing rules for 'chown', 'lchown', 'fchown', and 'fchownat'.${NORMAL}"
      fail=1
   fi

   if [[ $fail == 0 ]]
   then
      echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${GRN}PASSED, Use of the chown lchown fchown and fchownat commands are audited${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${RED}FAILED, Use of the chown lchown fchown and fchownat commands are not audited${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${BLD}$file1 not found${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${RED}FAILED, $file1 not found${NORMAL}"
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

file2="/etc/audit/audit.rules"
fail=0
chmod32=0
chmod64=0
lchmod32=0
lchmod64=0
fchmod32=0
fchmod64=0
fchmodat32=0
fchmodat64=0

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file2 ]]
then
   aurules="$(grep chmod $file2 | grep -v '^#')"
   if [[ $aurules ]]
   then
      for rule in ${aurules[@]}
      do
         echo -e "${NORMAL}RESULT:    ${BLD}$rule${NORMAL}"
         if [[ ! $rule =~ '-a always,exit' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-a always,exit'${NORMAL}"
            fail=1
         fi
         if [[ ! $rule =~ 'perm_mod' &&
               ! $rule =~ 'perm-change'
            ]] 
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing perm_mod or perm-change${NORMAL}"
         fi

         IFS=' ' read -a fieldvals <<< "${rule}"

         for field in ${fieldvals[@]}
         do
            if [[ $field =~ 'chmod' ]]
            then
               IFS=',' read -r -a chmodarr <<< "$field"
               for element in ${chmodarr[@]}
               do
                  if [[ $rule =~ "arch=b32" ]]
                  then
                     case $element in
                        'chmod')
                           (( chmod32++ ))
                           ;;
                        'lchmod')
                           (( lchmod32++ ))
                           ;;
                        'fchmod')
                           (( fchmod32++ ))
                           ;;
                        'fchmodat')
                           (( fchmodat32++ ))
                           ;;
                     esac
                  elif [[ $rule =~ "arch=b64" ]]
                  then
                     case $element in
                        'chmod')
                           (( chmod64++ ))
                           ;;
                        'lchmod')
                           (( lchmod64++ ))
                           ;;
                        'fchmod')
                           (( fchmod64++ ))
                           ;;
                        'fchmodat')
                           (( fchmodat64++ ))
                           ;;
                     esac
                  fi
               done
            fi   
            if [[ $field =~ 'auid>=' ]]
            then
               auidval="$(echo $field | awk -F'>=' '{print $2}')"
               if (( $auidval > 1000 ))
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid>=' cannot be greater than 1000${NORMAL}"
                  fail=1
               fi
            elif [[ $field =~ 'auid!=' ]]
            then
               auidval="$(echo $field | awk -F'!=' '{print $2}')"
               if (( $auidval != 4294967295 )) && [[ $auidval != "unset" ]]
               then
                  echo -e "${NORMAL}RESULT:    ${RED}\"auid!=\" must be \"4294967295\", or \"unset\".${NORMAL}"
                  fail=1
               fi
            fi
         done
      done
      if [[ $chown32 == 0 ]]
      then
         echo -e "${NORMAL}RESULT:    ${RED}A rule for \"chmod\" was not found for \"arch=b32\".${NORMAL}"
         fail=1
      fi
      if [[ $lchown32 == 0 ]]
      then
         echo -e "${NORMAL}RESULT:    ${RED}A rule for \"lchmod\" was not found for \"arch=b32\".${NORMAL}"
         fail=1
      fi
      if [[ $fchown32 == 0 ]]
      then
         echo -e "${NORMAL}RESULT:    ${RED}A rule for \"fchmod\" was not found for \"arch=b32\".${NORMAL}"
         fail=1
      fi
      if [[ $fchownat32 == 0 ]]
      then
         echo -e "${NORMAL}RESULT:    ${RED}A rule for \"fchmodat\" was not found for \"arch=b32\".${NORMAL}"
         fail=1
      fi
      if [[ $chown64 == 0 ]]
      then
         echo -e "${NORMAL}RESULT:    ${RED}A rule for \"chmod\" was not found for \"arch=b64\".${NORMAL}"
         fail=1
      fi
      if [[ $lchown64 == 0 ]]
      then
         echo -e "${NORMAL}RESULT:    ${RED}A rule for \"lchmod\" was not found for \"arch=b64\".${NORMAL}"
         fail=1
      fi
      if [[ $fchown64 == 0 ]]
      then
         echo -e "${NORMAL}RESULT:    ${RED}A rule for \"fchmod\" was not found for \"arch=b64\".${NORMAL}"
         fail=1
      fi
      if [[ $fchownat64 == 0 ]]
      then
         echo -e "${NORMAL}RESULT:    ${RED}A rule for \"fchmodat\" was not found for \"arch=b64\".${NORMAL}"
         fail=1
      fi
   else
      echo -e "${NORMAL}RESULT:    ${RED}missing rules for 'chmod', 'lchmod', 'fchmod', and 'fchmodat'.${NORMAL}"
      fail=1
   fi

   if [[ $fail == 0 ]]
   then
      echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${GRN}PASSED, Use of the chmod lchmod fchmod and fchmodat commands are audited${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${RED}FAILED, Use of the chmod lchmod fchmod and fchmodat commands are not audited${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${BLD}$file2 not found${NORMAL}"
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

file3="/etc/audit/audit.rules"
fail=0
setxattr32=0
setxattr64=0
fsetxattr32=0
fsetxattr64=0
lsetxattr32=0
lsetxattr64=0
removexattr32=0
removexattr64=0
fremovexattr32=0
fremovexattr64=0
lremovexattr32=0
lremovexattr64=0

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file3 ]]
then
   aurules="$(grep xattr $file3 | grep -v '^#')"
   if [[ $aurules ]]
   then
      for rule in ${aurules[@]}
      do
         echo -e "${NORMAL}RESULT:    ${BLD}$rule${NORMAL}"
         if [[ ! $rule =~ '-a always,exit' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-a always,exit'${NORMAL}"
            fail=1
         fi
         if [[ ! $rule =~ 'perm_mod' &&
               ! $rule =~ 'perm-change'
            ]] 
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing perm_mod or perm-change${NORMAL}"
         fi

         IFS=' ' read -a fieldvals <<< "${rule}"

         for field in ${fieldvals[@]}
         do
            if [[ $field =~ 'xattr' ]]
            then
               IFS=',' read -r -a xattrarr <<< "$field"
               for element in ${xattrarr[@]}
               do
                  if [[ $rule =~ "arch=b32" ]]
                  then
                     case $element in
                        'setxattr')
                           (( setxattr32++ ))
                           ;;
                        'fsetxattr')
                           (( fsetxattr32++ ))
                           ;;
                        'lsetxattr')
                           (( lsetxattr32++ ))
                           ;;
                        'removexattr')
                           (( removexattr32++ ))
                           ;;
                        'fremovexattr')
                           (( fremovexattr32++ ))
                           ;;
                        'lremovexattr')
                           (( lremovexattr32++ ))
                           ;;
                     esac
                  elif [[ $rule =~ "arch=b64" ]]
                  then
                     case $element in
                        'setxattr')
                           (( setxattr64++ ))
                           ;;
                        'fsetxattr')
                           (( fsetxattr64++ ))
                           ;;
                        'lsetxattr')
                           (( lsetxattr64++ ))
                           ;;
                        'removexattr')
                           (( removexattr64++ ))
                           ;;
                        'fremovexattr')
                           (( fremovexattr64++ ))
                           ;;
                        'lremovexattr')
                           (( lremovexattr64++ ))
                           ;;
                     esac
                  fi
               done
            fi   
            if [[ $field =~ 'auid>=' ]]
            then
               auidval="$(echo $field | awk -F'>=' '{print $2}')"
               if (( $auidval > 1000 ))
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid>=' cannot be greater than 1000${NORMAL}"
                  fail=1
               fi
            elif [[ $field =~ 'auid!=' ]]
            then
               auidval="$(echo $field | awk -F'!=' '{print $2}')"
               if (( $auidval != 4294967295 )) && [[ $auidval != "unset" ]]
               then
                  echo -e "${NORMAL}RESULT:    ${RED}\"auid!=\" must be \"4294967295\", or \"unset\".${NORMAL}"
                  fail=1
               fi
            fi
         done
      done
      if [[ $setxattr32 == 0 ]]
      then
         echo -e "${NORMAL}RESULT:    ${RED}A rule for \"setxattr\" was not found for \"arch=b32\".${NORMAL}"
         fail=1
      fi
      if [[ $fsetxattr32 == 0 ]]
      then
         echo -e "${NORMAL}RESULT:    ${RED}A rule for \"fsetxattr\" was not found for \"arch=b32\".${NORMAL}"
         fail=1
      fi
      if [[ $lsetxattr32 == 0 ]]
      then
         echo -e "${NORMAL}RESULT:    ${RED}A rule for \"lsetxattr\" was not found for \"arch=b32\".${NORMAL}"
         fail=1
      fi
      if [[ $removexattr32 == 0 ]]
      then
         echo -e "${NORMAL}RESULT:    ${RED}A rule for \"removexattr\" was not found for \"arch=b32\".${NORMAL}"
         fail=1
      fi
      if [[ $fremovexattr32 == 0 ]]
      then
         echo -e "${NORMAL}RESULT:    ${RED}A rule for \"fremovexattr\" was not found for \"arch=b32\".${NORMAL}"
         fail=1
      fi
      if [[ $lremovexattr32 == 0 ]]
      then
         echo -e "${NORMAL}RESULT:    ${RED}A rule for \"lremovexattr\" was not found for \"arch=b32\".${NORMAL}"
         fail=1
      fi
      if [[ $setxattr64 == 0 ]]
      then
         echo -e "${NORMAL}RESULT:    ${RED}A rule for \"setxattr\" was not found for \"arch=b64\".${NORMAL}"
         fail=1
      fi
      if [[ $fsetxattr64 == 0 ]]
      then
         echo -e "${NORMAL}RESULT:    ${RED}A rule for \"fsetxattr\" was not found for \"arch=b64\".${NORMAL}"
         fail=1
      fi
      if [[ $lsetxattr64 == 0 ]]
      then
         echo -e "${NORMAL}RESULT:    ${RED}A rule for \"lsetxattr\" was not found for \"arch=b64\".${NORMAL}"
         fail=1
      fi
      if [[ $removexattr64 == 0 ]]
      then
         echo -e "${NORMAL}RESULT:    ${RED}A rule for \"removexattr\" was not found for \"arch=b64\".${NORMAL}"
         fail=1
      fi
      if [[ $fremovexattr64 == 0 ]]
      then
         echo -e "${NORMAL}RESULT:    ${RED}A rule for \"fremovexattr\" was not found for \"arch=b64\".${NORMAL}"
         fail=1
      fi
      if [[ $lremovexattr64 == 0 ]]
      then
         echo -e "${NORMAL}RESULT:    ${RED}A rule for \"lremovexattr\" was not found for \"arch=b64\".${NORMAL}"
         fail=1
      fi
   else
      echo -e "${NORMAL}RESULT:    ${RED}missing rules for 'chown', 'lchown', 'fchown', and 'fchownat'.${NORMAL}"
      fail=1
   fi

   if [[ $fail == 0 ]]
   then
      echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${GRN}PASSED, Use of all the xattr commands are audited${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${RED}FAILED, Use of all the xattr commands are not audited${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${BLD}$file3 not found${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${RED}FAILED, $file3 not found${NORMAL}"
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

file4="/etc/audit/audit.rules"
fail=0
creat32=0
creat64=0
open32=0
open64=0
openat32=0
openat64=0
handleat32=0
handleat64=0
truncate32=0
truncate64=0
ftruncate32=0
ftruncate64=0

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file4 ]]
then
   aurules="$(grep 'open\|truncate\|creat' $file4 | grep -v '^#')"
   if [[ $aurules ]]
   then
      for rule in ${aurules[@]}
      do
         echo -e "${NORMAL}RESULT:    ${BLD}$rule${NORMAL}"
         if [[ ! $rule =~ '-a always,exit' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-a always,exit'${NORMAL}"
            fail=1
         fi
         if [[ ! $rule =~ 'unsuccesful-' &&
               ! $rule =~ '-modify'
            ]] 
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing 'unsuccessful' or 'modify' key${NORMAL}"
         fi

         IFS=' ' read -a fieldvals <<< "${rule}"

         for field in ${fieldvals[@]}
         do
            if [[ $field =~ 'creat' || $field =~ 'open' || $field =~ 'truncate' ]]
            then
               IFS=',' read -r -a creatarr <<< "$field"
               for element in ${creatarr[@]}
               do
                  if [[ $rule =~ "arch=b32" ]]
                  then
                     case $element in
                        'creat')
                           (( creat32++ ))
                           ;;
                        'open')
                           (( open32++ ))
                           ;;
                        'openat')
                           (( openat32++ ))
                           ;;
                        'open_by_handle_at')
                           (( handleat32++ ))
                           ;;
                        'truncate')
                           (( truncate32++ ))
                           ;;
                        'ftruncate')
                           (( ftruncate32++ ))
                           ;;
                     esac
                  elif [[ $rule =~ "arch=b64" ]]
                  then
                     case $element in
                        'creat')
                           (( creat64++ ))
                           ;;
                        'open')
                           (( open64++ ))
                           ;;
                        'openat')
                           (( openat64++ ))
                           ;;
                        'open_by_handle_at')
                           (( handleat64++ ))
                           ;;
                        'truncate')
                           (( truncate64++ ))
                           ;;
                        'ftruncate')
                           (( ftruncate64++ ))
                           ;;
                     esac
                  fi
               done
            fi   
            if [[ $field =~ 'auid>=' ]]
            then
               auidval="$(echo $field | awk -F'>=' '{print $2}')"
               if (( $auidval > 1000 ))
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid>=' cannot be greater than 1000${NORMAL}"
                  fail=1
               fi
            elif [[ $field =~ 'auid!=' ]]
            then
               auidval="$(echo $field | awk -F'!=' '{print $2}')"
               if (( $auidval != 4294967295 )) && [[ $auidval != "unset" ]]
               then
                  echo -e "${NORMAL}RESULT:    ${RED}\"auid!=\" must be \"4294967295\", or \"unset\".${NORMAL}"
                  fail=1
               fi
            fi
         done
      done
      if [[ $creat32 == 0 ]]
      then
         echo -e "${NORMAL}RESULT:    ${RED}A rule for \"creat\" was not found for \"arch=b32\".${NORMAL}"
         fail=1
      fi
      if [[ $open32 == 0 ]]
      then
         echo -e "${NORMAL}RESULT:    ${RED}A rule for \"open\" was not found for \"arch=b32\".${NORMAL}"
         fail=1
      fi
      if [[ $openat32 == 0 ]]
      then
         echo -e "${NORMAL}RESULT:    ${RED}A rule for \"openat\" was not found for \"arch=b32\".${NORMAL}"
         fail=1
      fi
      if [[ $handleat32 == 0 ]]
      then
         echo -e "${NORMAL}RESULT:    ${RED}A rule for \"open_by_handle_at\" was not found for \"arch=b32\".${NORMAL}"
         fail=1
      fi
      if [[ $truncate32 == 0 ]]
      then
         echo -e "${NORMAL}RESULT:    ${RED}A rule for \"truncate\" was not found for \"arch=b32\".${NORMAL}"
         fail=1
      fi
      if [[ $ftruncate32 == 0 ]]
      then
         echo -e "${NORMAL}RESULT:    ${RED}A rule for \"ftruncate\" was not found for \"arch=b32\".${NORMAL}"
         fail=1
      fi
      if [[ $creat64 == 0 ]]
      then
         echo -e "${NORMAL}RESULT:    ${RED}A rule for \"creat\" was not found for \"arch=b64\".${NORMAL}"
         fail=1
      fi
      if [[ $open64 == 0 ]]
      then
         echo -e "${NORMAL}RESULT:    ${RED}A rule for \"open\" was not found for \"arch=b64\".${NORMAL}"
         fail=1
      fi
      if [[ $openat64 == 0 ]]
      then
         echo -e "${NORMAL}RESULT:    ${RED}A rule for \"openat\" was not found for \"arch=b64\".${NORMAL}"
         fail=1
      fi
      if [[ $handleat64 == 0 ]]
      then
         echo -e "${NORMAL}RESULT:    ${RED}A rule for \"open_by_handle_at\" was not found for \"arch=b64\".${NORMAL}"
         fail=1
      fi
      if [[ $truncate64 == 0 ]]
      then
         echo -e "${NORMAL}RESULT:    ${RED}A rule for \"truncate\" was not found for \"arch=b64\".${NORMAL}"
         fail=1
      fi
      if [[ $ftruncate64 == 0 ]]
      then
         echo -e "${NORMAL}RESULT:    ${RED}A rule for \"ftruncate\" was not found for \"arch=b64\".${NORMAL}"
         fail=1
      fi
   else
      echo -e "${NORMAL}RESULT:    ${RED}missing rules for 'chown', 'lchown', 'fchown', and 'fchownat'.${NORMAL}"
      fail=1
   fi

   if [[ $fail == 0 ]]
   then
      echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${GRN}PASSED, Use of the creat open and truncate commands are all audited${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${RED}FAILED, Use of the creat open and truncate commands are not all audited${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${BLD}$file4 not found${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${RED}FAILED, $file4 not found${NORMAL}"
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

file5="/etc/audit/audit.rules"
fail=0

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file5 ]]
then
   aurules="$(grep -w '/usr/sbin/semanage' $file5 | grep -v '^#')"
   if [[ $aurules ]]
   then
      for rule in ${aurules[@]}
      do
         echo -e "${NORMAL}RESULT:    ${BLD}$rule${NORMAL}"
         if [[ ! $rule =~ '-a always,exit' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-a always,exit'${NORMAL}"
         fi
         if [[ ! $rule =~ '-F path=/usr/sbin/' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-F path=/usr/sbin/'${NORMAL}"
         fi
         if [[ ! $rule =~ '-F perm=x' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-F perm=x'${NORMAL}"
         fi
         if ! [[ $rule =~ 'privileged' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing 'privileged-priv_change'${NORMAL}"
         fi

         IFS=' ' read -a fieldvals <<< "${rule}"

         for field in ${fieldvals[@]}
         do
            if [[ $field =~ 'auid>=' ]]
            then
               auidval="$(echo $field | awk -F'>=' '{print $2}')"
               if (( $auidval > 1000 ))
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid>=' cannot be greater than 1000${NORMAL}"
                  fail=1
               fi
            elif [[ $field =~ 'auid!=' ]]
            then
               auidval="$(echo $field | awk -F'!=' '{print $2}')"
               if (( $auidval != 4294967295 && $auidval != "unset" ))
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid!=' must be 4294967295${NORMAL}"
                  fail=1
               fi
            fi
         done
      done
   else
      echo -e "${NORMAL}RESULT:    ${RED}missing a rule for 'semanage'${NORMAL}"
      fail=1
   fi

   if [[ $fail == 0 ]]
   then
      echo -e "${NORMAL}$hostname, $severity5, $controlid, $stigid5, $ruleid5, $cci5, $datetime, ${GRN}PASSED, Use of the semanage command is audited${NORMAL}"
   elif (( $fail == 2 ))
   then
      echo -e "${NORMAL}$hostname, $severity5, $controlid, $stigid5, $ruleid5, $cci5, $datetime, ${RED}FAILED, Use of the semanage command is not audited${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity5, $controlid, $stigid5, $ruleid5, $cci5, $datetime, ${RED}FAILED, Use of the semanage command is not configured correctly${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${BLD}$file5 not found${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity5, $controlid, $stigid5, $ruleid5, $cci5, $datetime, ${RED}FAILED, $file5 not found${NORMAL}"
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

file6="/etc/audit/audit.rules"
fail=0

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file6 ]]
then
   aurules="$(grep -w '/usr/sbin/setsebool' $file6 | grep -v '^#')"
   if [[ $aurules ]]
   then
      for rule in ${aurules[@]}
      do
         echo -e "${NORMAL}RESULT:    ${BLD}$rule${NORMAL}"
         if [[ ! $rule =~ '-a always,exit' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-a always,exit'${NORMAL}"
         fi
         if [[ ! $rule =~ '-F path=/usr/sbin/' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-F path=/usr/sbin/'${NORMAL}"
         fi
         if [[ ! $rule =~ '-F perm=x' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-F perm=x'${NORMAL}"
         fi
         if ! [[ $rule =~ 'privileged' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing 'privileged-priv_change'${NORMAL}"
         fi

         IFS=' ' read -a fieldvals <<< "${rule}"

         for field in ${fieldvals[@]}
         do
            if [[ $field =~ 'auid>=' ]]
            then
               auidval="$(echo $field | awk -F'>=' '{print $2}')"
               if (( $auidval > 1000 ))
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid>=' cannot be greater than 1000${NORMAL}"
                  fail=1
               fi
            elif [[ $field =~ 'auid!=' ]]
            then
               auidval="$(echo $field | awk -F'!=' '{print $2}')"
               if (( $auidval != 4294967295 && $auidval != 'unset' ))
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid!=' must be either 4294967295 or 'unset'.${NORMAL}"
                  fail=1
               fi
            fi
         done
      done
   else
      echo -e "${NORMAL}RESULT:    ${RED}missing a rule for 'setsebool'${NORMAL}"
      fail=2
   fi

   if [[ $fail == 0 ]]
   then
      echo -e "${NORMAL}$hostname, $severity6, $controlid, $stigid6, $ruleid6, $cci6, $datetime, ${GRN}PASSED, Use of the setsebool command is audited${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity6, $controlid, $stigid6, $ruleid6, $cci6, $datetime, ${RED}FAILED, Use of the setsebool command is not audited${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${BLD}$file6 not found${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity6, $controlid, $stigid6, $ruleid6, $cci6, $datetime, ${RED}FAILED, $file6 not found${NORMAL}"
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

file7="/etc/audit/audit.rules"
fail=0

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file7 ]]
then
   aurules="$(grep -w '/usr/bin/chcon' $file7 | grep -v '^#')"
   if [[ $aurules ]]
   then
      for rule in ${aurules[@]}
      do
         echo -e "${NORMAL}RESULT:    ${BLD}$rule${NORMAL}"
         if [[ ! $rule =~ '-a always,exit' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-a always,exit'${NORMAL}"
            fail=1
         fi
         if [[ ! $rule =~ '-F path=/usr/bin/' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-F path=/usr/sbin/'${NORMAL}"
         fi
         if [[ ! $rule =~ '-F perm=x' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-F perm=x'${NORMAL}"
         fi
         if ! [[ $rule =~ 'privileged' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing 'privileged-priv_change'${NORMAL}"
         fi

         IFS=' ' read -a fieldvals <<< "${rule}"

         for field in ${fieldvals[@]}
         do
            if [[ $field =~ 'auid>=' ]]
            then
               auidval="$(echo $field | awk -F'>=' '{print $2}')"
               if (( $auidval > 1000 ))
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid>=' cannot be greater than 1000${NORMAL}"
                  fail=1
               fi
            elif [[ $field =~ 'auid!=' ]]
            then
               auidval="$(echo $field | awk -F'!=' '{print $2}')"
               if (( $auidval != 4294967295 && $auidval != 'unset' ))
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid!=' must be either 4294967295 or 'unset'.${NORMAL}"
                  fail=1
               fi
            fi
         done
      done
   else
      echo -e "${NORMAL}RESULT:    ${RED}missing a rule for 'chcon'${NORMAL}"
      fail=1
   fi

   if [[ $fail == 0 ]]
   then
      echo -e "${NORMAL}$hostname, $severity7, $controlid, $stigid7, $ruleid7, $cci7, $datetime, ${GRN}PASSED, Use of the chcon command is audited${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity7, $controlid, $stigid7, $ruleid7, $cci7, $datetime, ${RED}FAILED, Use of the chcon command is not audited${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${BLD}$file7 not found${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity7, $controlid, $stigid7, $ruleid7, $cci7, $datetime, ${RED}FAILED, $file7 not found${NORMAL}"
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

file8="/etc/audit/audit.rules"
fail=0

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file8 ]]
then
   aurules="$(grep -w '/usr/sbin/setfiles' $file8 | grep -v '^#')"
   if [[ $aurules ]]
   then
      for rule in ${aurules[@]}
      do
         echo -e "${NORMAL}RESULT:    ${BLD}$rule${NORMAL}"
         if [[ ! $rule =~ '-a always,exit' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-a always,exit'${NORMAL}"
         fi
         if [[ ! $rule =~ '-F path=/usr/sbin/' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-F path=/usr/sbin/'${NORMAL}"
         fi
         if [[ ! $rule =~ '-F perm=x' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-F perm=x'${NORMAL}"
         fi
         if ! [[ $rule =~ 'privileged' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing 'privileged-priv_change'${NORMAL}"
         fi

         IFS=' ' read -a fieldvals <<< "${rule}"

         for field in ${fieldvals[@]}
         do
            if [[ $field =~ 'auid>=' ]]
            then
               auidval="$(echo $field | awk -F'>=' '{print $2}')"
               if (( $auidval > 1000 ))
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid>=' cannot be greater than 1000${NORMAL}"
                  fail=1
               fi
            elif [[ $field =~ 'auid!=' ]]
            then
               auidval="$(echo $field | awk -F'!=' '{print $2}')"
               if (( $auidval != 4294967295 && $auidval != 'unset' ))
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid!=' must be either 4294967295 or 'unset'.${NORMAL}"
                  fail=1
               fi
            fi
         done
      done
   else
      echo -e "${NORMAL}RESULT:    ${RED}missing a rule for 'setfiles'${NORMAL}"
      fail=1
   fi

   if [[ $fail == 0 ]]
   then
      echo -e "${NORMAL}$hostname, $severity8, $controlid, $stigid8, $ruleid8, $cci8, $datetime, ${GRN}PASSED, Use of the setfiles command is audited${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity8, $controlid, $stigid8, $ruleid8, $cci8, $datetime, ${RED}FAILED, Use of the setfiles command is not audited${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${BLD}$file8 not found${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity8, $controlid, $stigid8, $ruleid8, $cci8, $datetime, ${RED}FAILED, $file8 not found${NORMAL}"
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

file9="/etc/audit/audit.rules"
fail=0

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file9 ]]
then
   aurules="$(grep -i /var/run/faillock $file9 | grep -v '^#')"
   if [[ $aurules ]]
   then
      for rule in ${aurules[@]}
      do
         echo -e "${NORMAL}RESULT:    ${BLD}$rule${NORMAL}"
         if [[ ! $rule =~ -w ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-w '${NORMAL}"
         fi
         if [[ ! $rule =~ '-p wa ' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-p wa '${NORMAL}"
         fi
         if [[ ! $rule =~ '-k logins' &&
               ! $rule =~ '-F key=logins'
            ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-k logins'${NORMAL}"
            fail=1
         fi
      done
   else
      echo -e "${NORMAL}RESULT:    ${RED}missing a rule for '/var/run/faillock'${NORMAL}"
      fail=1
   fi

   if [[ $fail == 0 ]]
   then
      echo -e "${NORMAL}$hostname, $severity9, $controlid, $stigid9, $ruleid9, $cci9, $datetime, ${GRN}PASSED, The operating system generates audit records for all unsuccessful account access events${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity9, $controlid, $stigid9, $ruleid9, $cci9, $datetime, ${RED}FAILED, The operating system does not generate audit records for all unsuccessful account access events${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${BLD}$file9 not found${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity9, $controlid, $stigid9, $ruleid9, $cci9, $datetime, ${RED}FAILED, $file9 not found${NORMAL}"
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

file10="/etc/audit/audit.rules"
fail=0

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file10 ]]
then
   aurules="$(grep -i '/var/log/lastlog' $file10 | grep -v '^#')"
   if [[ $aurules ]]
   then
      for rule in ${aurules[@]}
      do
         echo -e "${NORMAL}RESULT:    ${BLD}$rule${NORMAL}"
         if [[ ! $rule =~ -w ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-w '${NORMAL}"
         fi
         if [[ ! $rule =~ '-p wa ' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-p wa '${NORMAL}"
         fi
         if [[ ! $rule =~ '-k logins' &&
               ! $rule =~ '-F key=logins'
            ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-k logins'${NORMAL}"
            fail=1
         fi
      done
   else
      echo -e "${NORMAL}RESULT:    ${RED}missing a rule for '/var/log/lastlog'${NORMAL}"
      fail=1
   fi

   if [[ $fail == 0 ]]
   then
      echo -e "${NORMAL}$hostname, $severity10, $controlid, $stigid10, $ruleid10, $cci10, $datetime, ${GRN}PASSED, The operating system generates audit records for all successful account access events${NORMAL}"
   else (( $fail == 2 ))
      echo -e "${NORMAL}$hostname, $severity10, $controlid, $stigid10, $ruleid10, $cci10, $datetime, ${RED}FAILED, The operating system does not generate audit records for all successful account access events${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${BLD}$file10 not found${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity10, $controlid, $stigid10, $ruleid10, $cci10, $datetime, ${RED}FAILED, $file10 not found${NORMAL}"
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

file11="/etc/audit/audit.rules"
fail=0

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file11 ]]
then
   aurules="$(grep -i /usr/bin/passwd $file11 | grep -v '^#')"
   if [[ $aurules ]]
   then
      for rule in ${aurules[@]}
      do
         echo -e "${NORMAL}RESULT:    ${BLD}$rule${NORMAL}"
         if [[ ! $rule =~ '-a always,exit' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-a always,exit'${NORMAL}"
         fi
         if [[ ! $rule =~ '-F path=/usr/bin/' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-F path=/usr/bin/'${NORMAL}"
         fi
         if [[ ! $rule =~ '-F perm=x' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-F perm=x'${NORMAL}"
         fi
         if [[ ! $rule =~ '-F key=privileged' && ! $rule =~ '-F key=special-' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing 'key=privileged' or 'key=special-'.${NORMAL}"
         fi

         IFS=' ' read -a fieldvals <<< "${rule}"

         for field in ${fieldvals[@]}
         do
            if [[ $field =~ 'auid>=' ]]
            then
               auidval="$(echo $field | awk -F'>=' '{print $2}')"
               if (( $auidval > 1000 ))
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid>=' cannot be greater than 1000${NORMAL}"
                  fail=1
               fi
            elif [[ $field =~ 'auid!=' ]]
            then
               auidval="$(echo $field | awk -F'!=' '{print $2}')"
               if (( $auidval != 4294967295 && $auidval != 'unset' ))
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid!=' must be either 4294967295 or 'unset'.${NORMAL}"
                  fail=1
               fi
            fi
         done
      done
   else
      echo -e "${NORMAL}RESULT:    ${RED}missing a rule for 'setfiles'${NORMAL}"
      fail=1
   fi

   if [[ $fail == 0 ]]
   then
      echo -e "${NORMAL}$hostname, $severity11, $controlid, $stigid11, $ruleid11, $cci11, $datetime, ${GRN}PASSED, Use of the passwd command is audited${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity11, $controlid, $stigid11, $ruleid11, $cci11, $datetime, ${RED}FAILED, Use of the passwd command is not audited${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${BLD}$file11 not found${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity11, $controlid, $stigid11, $ruleid11, $cci11, $datetime, ${RED}FAILED, $file11 not found${NORMAL}"
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

file12="/etc/audit/audit.rules"
fail=0

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file12 ]]
then
   aurules="$(grep -i '/usr/sbin/unix_chkpwd' $file12 | grep -v '^#')"
   if [[ $aurules ]]
   then
      for rule in ${aurules[@]}
      do
         echo -e "${NORMAL}RESULT:    ${BLD}$rule${NORMAL}"
         if [[ ! $rule =~ '-F path=/usr/sbin/' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-F path=/sbin/'${NORMAL}"
         fi
         if [[ ! $rule =~ '-F perm=x' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-F perm=x'${NORMAL}"
         fi
         if [[ ! $rule =~ 'privileged' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing 'key=privileged'${NORMAL}"
         fi

         IFS=' ' read -a fieldvals <<< "${rule}"

         for field in ${fieldvals[@]}
         do
            if [[ $field =~ 'auid>=' ]]
            then
               auidval="$(echo $field | awk -F'>=' '{print $2}')"
               if (( $auidval > 1000 ))
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid>=' cannot be greater than 1000${NORMAL}"
                  fail=1
               fi
            elif [[ $field =~ 'auid!=' ]]
            then
               auidval="$(echo $field | awk -F'!=' '{print $2}')"
               if (( $auidval != 4294967295 && $auidval != 'unset' ))
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid!=' must be either 4294967295 or 'unset'.${NORMAL}"
                  fail=1
               fi
            fi
         done
      done
   else
      echo -e "${NORMAL}RESULT:    ${RED}missing a rule for 'unix_chkpwd'${NORMAL}"
      fail=1
   fi

   if [[ $fail == 0 ]]
   then
      echo -e "${NORMAL}$hostname, $severity12, $controlid, $stigid12, $ruleid12, $cci12, $datetime, ${GRN}PASSED, Use of the unix_chkpwd command is audited${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity12, $controlid, $stigid12, $ruleid12, $cci12, $datetime, ${RED}FAILED, Use of the unix_chkpwd command is not audited${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${BLD}$file12 not found${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity12, $controlid, $stigid12, $ruleid12, $cci12, $datetime, ${RED}FAILED, $file12 not found${NORMAL}"
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

file13="/etc/audit/audit.rules"
fail=0

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file13 ]]
then
   aurules="$(grep -i /usr/bin/gpasswd $file13 | grep -v '^#')"
   if [[ $aurules ]]
   then
      for rule in ${aurules[@]}
      do
         echo -e "${NORMAL}RESULT:    ${BLD}$rule${NORMAL}"
         if [[ ! $rule =~ '-a always,exit' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-a always,exit'${NORMAL}"
         fi
         if [[ ! $rule =~ '-F path=/usr/bin/' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-F path=/usr/bin/'${NORMAL}"
         fi
         if [[ ! $rule =~ '-F perm=x' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-F perm=x'${NORMAL}"
         fi
         if [[ ! $rule =~ 'privileged' && ! $rule =~ 'special' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing 'privileged or special'${NORMAL}"
         fi

         IFS=' ' read -a fieldvals <<< "${rule}"

         for field in ${fieldvals[@]}
         do
            if [[ $field =~ 'auid>=' ]]
            then
               auidval="$(echo $field | awk -F'>=' '{print $2}')"
               if (( $auidval > 1000 ))
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid>=' cannot be greater than 1000${NORMAL}"
                  fail=1
               fi
            elif [[ $field =~ 'auid!=' ]]
            then
               auidval="$(echo $field | awk -F'!=' '{print $2}')"
               if (( $auidval != 4294967295 && $auidval != 'unset' ))
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid!=' must be either 4294967295 or 'unset'${NORMAL}"
                  fail=1
               fi
            fi
         done
      done
   else
      echo -e "${NORMAL}RESULT:    ${RED}missing a rule for 'gpasswd'${NORMAL}"
      fail=1
   fi

   if [[ $fail == 0 ]]
   then
      echo -e "${NORMAL}$hostname, $severity13, $controlid, $stigid13, $ruleid13, $cci13, $datetime, ${GRN}PASSED, Use of the gpasswd command is audited${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity13, $controlid, $stigid13, $ruleid13, $cci13, $datetime, ${RED}FAILED, Use of the gpasswd command is not audited${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${BLD}$file13 not found${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity13, $controlid, $stigid13, $ruleid13, $cci13, $datetime, ${RED}FAILED, $file13 not found${NORMAL}"
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

file14="/etc/audit/audit.rules"
fail=0

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file14 ]]
then
   aurules="$(grep -i /usr/bin/chage $file14 | grep -v '^#')"
   if [[ $aurules ]]
   then
      for rule in ${aurules[@]}
      do
         echo -e "${NORMAL}RESULT:    ${BLD}$rule${NORMAL}"
         if [[ ! $rule =~ '-a always,exit' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-a always,exit'${NORMAL}"
         fi
         if [[ ! $rule =~ '-F path=/usr/bin/' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-F path=/usr/bin/'${NORMAL}"
         fi
         if [[ ! $rule =~ '-F perm=x' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-F perm=x'${NORMAL}"
         fi
         if [[ ! $rule =~ 'privileged' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-k privileged-passwd'${NORMAL}"
         fi

         IFS=' ' read -a fieldvals <<< "${rule}"

         for field in ${fieldvals[@]}
         do
            if [[ $field =~ 'auid>=' ]]
            then
               auidval="$(echo $field | awk -F'>=' '{print $2}')"
               if (( $auidval > 1000 ))
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid>=' cannot be greater than 1000${NORMAL}"
                  fail=1
               fi
            elif [[ $field =~ 'auid!=' ]]
            then
               auidval="$(echo $field | awk -F'!=' '{print $2}')"
               if (( $auidval != 4294967295 && $auidval != 'unset' ))
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid!=' must be either 4294967295 or 'unset'${NORMAL}"
                  fail=1
               fi
            fi
         done
      done
   else
      echo -e "${NORMAL}RESULT:    ${RED}missing a rule for 'chage'${NORMAL}"
      fail=1
   fi

   if [[ $fail == 0 ]]
   then
      echo -e "${NORMAL}$hostname, $severity14, $controlid, $stigid14, $ruleid14, $cci14, $datetime, ${GRN}PASSED, Use of the chage command is audited${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity14, $controlid, $stigid14, $ruleid14, $cci14, $datetime, ${RED}FAILED, Use of the chage command is not audited${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${BLD}$file14 not found${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity14, $controlid, $stigid14, $ruleid14, $cci14, $datetime, ${RED}FAILED, $file14 not found${NORMAL}"
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

file15="/etc/audit/audit.rules"
fail=0

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file15 ]]
then
   aurules="$(grep -w '/usr/sbin/userhelper' $file15 | grep -v '^#')"
   if [[ $aurules ]]
   then
      for rule in ${aurules[@]}
      do
         echo -e "${NORMAL}RESULT:    ${BLD}$rule${NORMAL}"
         if [[ ! $rule =~ '-a always,exit' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-a always,exit'${NORMAL}"
         fi
         if [[ ! $rule =~ '-F path=/usr/sbin/' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-F path=/usr/sbin/'${NORMAL}"
         fi
         if [[ ! $rule =~ '-F perm=x' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-F perm=x'${NORMAL}"
         fi
         if [[ ! $rule =~ 'privileged' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing 'privileged'${NORMAL}"
         fi

         IFS=' ' read -a fieldvals <<< "${rule}"

         for field in ${fieldvals[@]}
         do
            if [[ $field =~ 'auid>=' ]]
            then
               auidval="$(echo $field | awk -F'>=' '{print $2}')"
               if (( $auidval > 1000 ))
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid>=' cannot be greater than 1000${NORMAL}"
                  fail=1
               fi
            elif [[ $field =~ 'auid!=' ]]
            then
               auidval="$(echo $field | awk -F'!=' '{print $2}')"
               if (( $auidval != 4294967295 && $auidval != 'unset' ))
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid!=' must be either 4294967295 or 'unset'${NORMAL}"
                  fail=1
               fi
            fi
         done
      done
   else
      echo -e "${NORMAL}RESULT:    ${RED}missing a rule for 'userhelper'${NORMAL}"
      fail=1
   fi

   if [[ $fail == 0 ]]
   then
      echo -e "${NORMAL}$hostname, $severity15, $controlid, $stigid15, $ruleid15, $cci15, $datetime, ${GRN}PASSED, Use of the userhelper command is audited${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity15, $controlid, $stigid15, $ruleid15, $cci15, $datetime, ${RED}FAILED, Use of the userhelper command is not audited${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${BLD}$file15 not found${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity15, $controlid, $stigid15, $ruleid15, $cci15, $datetime, ${RED}FAILED, $file15 not found${NORMAL}"
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

file16="/etc/audit/audit.rules"
fail=0

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file16 ]]
then
   aurules="$(grep -i '/usr/bin/su\ '  $file16 | grep -v '^#')"
   if [[ $aurules ]]
   then
      for rule in ${aurules[@]}
      do
         echo -e "${NORMAL}RESULT:    ${BLD}$rule${NORMAL}"
         if [[ ! $rule =~ '-a always,exit' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-a always,exit'${NORMAL}"
         fi
         if [[ ! $rule =~ '-F path=/usr/bin/' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-F path=/usr/bin/'${NORMAL}"
         fi
         if [[ ! $rule =~ '-F perm=x' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-F perm=x'${NORMAL}"
         fi
         if ! [[ $rule =~ 'privileged' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing 'privileged'${NORMAL}"
         fi

         IFS=' ' read -a fieldvals <<< "${rule}"

         for field in ${fieldvals[@]}
         do
            if [[ $field =~ 'auid>=' ]]
            then
               auidval="$(echo $field | awk -F'>=' '{print $2}')"
               if (( $auidval > 1000 ))
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid>=' cannot be greater than 1000${NORMAL}"
                  fail=1
               fi
            elif [[ $field =~ 'auid!=' ]]
            then
               auidval="$(echo $field | awk -F'!=' '{print $2}')"
               if (( $auidval != 4294967295 && $auidval != 'unset' ))
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid!=' must be either 4294967295 or 'unset'${NORMAL}"
                  fail=1
               fi
            fi
         done
      done
   else
      echo -e "${NORMAL}RESULT:    ${RED}missing a rule for 'su'${NORMAL}"
      fail=1
   fi

   if [[ $fail == 0 ]]
   then
      echo -e "${NORMAL}$hostname, $severity16, $controlid, $stigid16, $ruleid16, $cci16, $datetime, ${GRN}PASSED, Use of the su command is audited${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity16, $controlid, $stigid16, $ruleid16, $cci16, $datetime, ${RED}FAILED, Use of the su command is not audited${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${BLD}$file16 not found${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity16, $controlid, $stigid16, $ruleid16, $cci16, $datetime, ${RED}FAILED, $file16 not found${NORMAL}"
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

file17="/etc/audit/audit.rules"
fail=0

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file17 ]]
then
   aurules="$(grep -i '/usr/bin/sudo '  $file17 | grep -v '^#')"
   if [[ $aurules ]]
   then
      for rule in ${aurules[@]}
      do
         echo -e "${NORMAL}RESULT:    ${BLD}$rule${NORMAL}"
         if [[ ! $rule =~ '-a always,exit' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-a always,exit'${NORMAL}"
         fi
         if [[ ! $rule =~ '-F path=/usr/bin/' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-F path=/usr/bin/'${NORMAL}"
         fi
         if [[ ! $rule =~ '-F perm=x' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-F perm=x'${NORMAL}"
         fi
         if ! [[ $rule =~ 'privileged' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing 'privileged-priv_change'${NORMAL}"
         fi

         IFS=' ' read -a fieldvals <<< "${rule}"

         for field in ${fieldvals[@]}
         do
            if [[ $field =~ 'auid>=' ]]
            then
               auidval="$(echo $field | awk -F'>=' '{print $2}')"
               if (( $auidval > 1000 ))
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid>=' cannot be greater than 1000${NORMAL}"
                  fail=1
               fi
            elif [[ $field =~ 'auid!=' ]]
            then
               auidval="$(echo $field | awk -F'!=' '{print $2}')"
               if (( $auidval != 4294967295 && $auidval != 'unset' ))
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid!=' must be either 4294967295 or 'unset'${NORMAL}"
                  fail=1
               fi
            fi
         done
      done
   else
      echo -e "${NORMAL}RESULT:    ${RED}missing a rule for 'sudo'${NORMAL}"
      fail=1
   fi

   if [[ $fail == 0 ]]
   then
      echo -e "${NORMAL}$hostname, $severity17, $controlid, $stigid17, $ruleid17, $cci17, $datetime, ${GRN}PASSED, Use of the sudo command is audited${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity17, $controlid, $stigid17, $ruleid17, $cci17, $datetime, ${RED}FAILED, Use of the sudo command is not audited${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${BLD}$file17 not found${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity17, $controlid, $stigid17, $ruleid17, $cci17, $datetime, ${RED}FAILED, $file17 not found${NORMAL}"
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

file18="/etc/audit/audit.rules"
fail=0

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file18 ]]
then
   aurules="$(grep -i /etc/sudoers $file18 | grep -v '^#')"
   if [[ $aurules ]]
   then
      for rule in ${aurules[@]}
      do
         echo -e "${NORMAL}RESULT:    ${BLD}$rule${NORMAL}"
         if [[ ! $rule =~ -w ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-w '${NORMAL}"
         fi
         if [[ ! $rule =~ '-p wa ' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-p wa '${NORMAL}"
         fi
         if [[ ! $rule =~ 'privileged' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-k privileged-actions'${NORMAL}"
         fi
      done
   else
      echo -e "${NORMAL}RESULT:    ${RED}missing a rule for 'sudoers'${NORMAL}"
      fail=1
   fi

   if [[ $fail == 0 ]]
   then
      echo -e "${NORMAL}$hostname, $severity18, $controlid, $stigid18, $ruleid18, $cci18, $datetime, ${GRN}PASSED, Use of the sudoers command is audited${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity18, $controlid, $stigid18, $ruleid18, $cci18, $datetime, ${RED}FAILED, Use of the sudoers command is not audited${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${BLD}$file18 not found${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity18, $controlid, $stigid18, $ruleid18, $cci18, $datetime, ${RED}FAILED, $file18 not found${NORMAL}"
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

file19="/etc/audit/audit.rules"
fail=0

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file19 ]]
then
   aurules="$(grep -i /usr/bin/newgrp  $file19 | grep -v '^#')"
   if [[ $aurules ]]
   then
      for rule in ${aurules[@]}
      do
         echo -e "${NORMAL}RESULT:    ${BLD}$rule${NORMAL}"
         if [[ ! $rule =~ '-a always,exit' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-a always,exit'${NORMAL}"
         fi
         if [[ ! $rule =~ '-F path=/usr/bin/' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-F path=/usr/bin/'${NORMAL}"
         fi
         if [[ ! $rule =~ '-F perm=x' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-F perm=x'${NORMAL}"
         fi
         if ! [[ $rule =~ 'privileged' || $rule =~ 'special' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing 'privileged' or 'special'${NORMAL}"
         fi

         IFS=' ' read -a fieldvals <<< "${rule}"

         for field in ${fieldvals[@]}
         do
            if [[ $field =~ 'auid>=' ]]
            then
               auidval="$(echo $field | awk -F'>=' '{print $2}')"
               if (( $auidval > 1000 ))
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid>=' cannot be greater than 1000${NORMAL}"
                  fail=1
               fi
            elif [[ $field =~ 'auid!=' ]]
            then
               auidval="$(echo $field | awk -F'!=' '{print $2}')"
               if (( $auidval != 4294967295 && $auidval != 'unset' ))
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid!=' must be 4294967295 or 'unset'${NORMAL}"
                  fail=1
               fi
            fi
         done
      done
   else
      echo -e "${NORMAL}RESULT:    ${RED}missing a rule for 'newgrp'${NORMAL}"
      fail=1
   fi

   if [[ $fail == 0 ]]
   then
      echo -e "${NORMAL}$hostname, $severity19, $controlid, $stigid19, $ruleid19, $cci19, $datetime, ${GRN}PASSED, Use of the newgrp command is audited${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity19, $controlid, $stigid19, $ruleid19, $cci19, $datetime, ${RED}FAILED, Use of the newgrp command is not audited${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${BLD}$file19 not found${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity19, $controlid, $stigid19, $ruleid19, $cci19, $datetime, ${RED}FAILED, $file19 not found${NORMAL}"
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

file20="/etc/audit/audit.rules"
fail=0

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file20 ]]
then
   aurules="$(grep -i /usr/bin/chsh  $file20 | grep -v '^#')"
   if [[ $aurules ]]
   then
      for rule in ${aurules[@]}
      do
         echo -e "${NORMAL}RESULT:    ${BLD}$rule${NORMAL}"
         if [[ ! $rule =~ '-F path=/usr/bin/' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-F path=/usr/bin/'${NORMAL}"
         fi
         if [[ ! $rule =~ '-F perm=x' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-F perm=x'${NORMAL}"
         fi
         if ! [[ $rule =~ 'privileged' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing 'privileged'${NORMAL}"
         fi

         IFS=' ' read -a fieldvals <<< "${rule}"

         for field in ${fieldvals[@]}
         do
            if [[ $field =~ 'auid>=' ]]
            then
               auidval="$(echo $field | awk -F'>=' '{print $2}')"
               if (( $auidval > 1000 ))
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid>=' cannot be greater than 1000${NORMAL}"
                  fail=1
               fi
            elif [[ $field =~ 'auid!=' ]]
            then
               auidval="$(echo $field | awk -F'!=' '{print $2}')"
               if (( $auidval != 4294967295 && $auidval != 'unset' ))
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid!=' must be either 4294967295 or 'unset'${NORMAL}"
                  fail=1
               fi
            fi
         done
      done
   else
      echo -e "${NORMAL}RESULT:    ${RED}missing a rule for 'chsh'${NORMAL}"
      fail=1
   fi

   if [[ $fail == 0 ]]
   then
      echo -e "${NORMAL}$hostname, $severity20, $controlid, $stigid20, $ruleid20, $cci20, $datetime, ${GRN}PASSED, Use of the chsh command is audited${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity20, $controlid, $stigid20, $ruleid20, $cci20, $datetime, ${RED}FAILED, Use of the chsh command is not audited${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${BLD}$file20 not found${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity20, $controlid, $stigid20, $ruleid20, $cci20, $datetime, ${RED}FAILED, $file20 not found${NORMAL}"
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

file21="/etc/audit/audit.rules"
fail=0

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file21 ]]
then
   aurules="$(grep -i '/usr/libexec/openssh/ssh-keysign'  $file21 | grep -v '^#')"
   if [[ $aurules ]]
   then
      for rule in ${aurules[@]}
      do
         echo -e "${NORMAL}RESULT:    ${BLD}$rule${NORMAL}"
         if [[ ! $rule =~ '-F path=/usr/libexec/openssh/' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-F path=/usr/libexec/openssh/'${NORMAL}"
         fi
         if [[ ! $rule =~ '-F perm=x' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-F perm=x'${NORMAL}"
         fi
         if [[ ! $rule =~ 'privileged' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing 'privileged'${NORMAL}"
         fi

         IFS=' ' read -a fieldvals <<< "${rule}"

         for field in ${fieldvals[@]}
         do
            if [[ $field =~ 'auid>=' ]]
            then
               auidval="$(echo $field | awk -F'>=' '{print $2}')"
               if (( $auidval > 1000 ))
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid>=' cannot be greater than 1000${NORMAL}"
                  fail=1
               fi
            elif [[ $field =~ 'auid!=' ]]
            then
               auidval="$(echo $field | awk -F'!=' '{print $2}')"
               if (( $auidval != 4294967295 && $auidval != 'unset' ))
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid!=' must be either 4294967295 or 'unset'${NORMAL}"
                  fail=1
               fi
            fi
         done
      done
   else
      echo -e "${NORMAL}RESULT:    ${RED}missing a rule for 'ssh-keysign'${NORMAL}"
      fail=2
   fi

   if [[ $fail == 0 ]]
   then
      echo -e "${NORMAL}$hostname, $severity21, $controlid, $stigid21, $ruleid21, $cci21, $datetime, ${GRN}PASSED, Use of the ssh-keysign command is audited${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity21, $controlid, $stigid21, $ruleid21, $cci21, $datetime, ${RED}FAILED, Use of the ssh-keysign command is not audited${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${BLD}$file21 not found${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity21, $controlid, $stigid21, $ruleid21, $cci21, $datetime, ${RED}FAILED, $file21 not found${NORMAL}"
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

file22="/etc/audit/audit.rules"
fail=0

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file22 ]]
then
   aurules="$(grep -w '/usr/bin/crontab'  $file22 | grep -v '^#')"
   if [[ $aurules ]]
   then
      for rule in ${aurules[@]}
      do
         echo -e "${NORMAL}RESULT:    ${BLD}$rule${NORMAL}"
         if [[ ! $rule =~ '-F path=/usr/bin/' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-F path=/usr/bin/'${NORMAL}"
         fi
         if [[ ! $rule =~ '-F perm=x' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-F perm=x'${NORMAL}"
         fi
         if [[ ! $rule =~ 'privileged' && ! $rule =~ 'special' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing 'privileged' or 'special'${NORMAL}"
         fi

         IFS=' ' read -a fieldvals <<< "${rule}"

         for field in ${fieldvals[@]}
         do
            if [[ $field =~ 'auid>=' ]]
            then
               auidval="$(echo $field | awk -F'>=' '{print $2}')"
               if (( $auidval > 1000 ))
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid>=' cannot be greater than 1000${NORMAL}"
                  fail=1
               fi
            elif [[ $field =~ 'auid!=' ]]
            then
               auidval="$(echo $field | awk -F'!=' '{print $2}')"
               if (( $auidval != 4294967295 && $auidval != 'unset' ))
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid!=' must be either 4294967295 or 'unset'${NORMAL}"
                  fail=1
               fi
            fi
         done
      done
   else
      echo -e "${NORMAL}RESULT:    ${RED}missing a rule for 'crontab'${NORMAL}"
      fail=1
   fi

   if [[ $fail == 0 ]]
   then
      echo -e "${NORMAL}$hostname, $severity22, $controlid, $stigid22, $ruleid22, $cci22, $datetime, ${GRN}PASSED, Use of the crontab command is audited${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity22, $controlid, $stigid22, $ruleid22, $cci22, $datetime, ${RED}FAILED, Use of the crontab command is not audited${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${BLD}$file22 not found${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity22, $controlid, $stigid22, $ruleid22, $cci22, $datetime, ${RED}FAILED, $file22 not found${NORMAL}"
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

file23="/etc/audit/audit.rules"
fail=0

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file23 ]]
then
   aurules="$(grep -i '/sbin/pam_timestamp_check'  $file23 | grep -v '^#')"
   if [[ $aurules ]]
   then
      for rule in ${aurules[@]}
      do
         echo -e "${NORMAL}RESULT:    ${BLD}$rule${NORMAL}"
         if [[ ! $rule =~ '-a always,exit' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-a always,exit'${NORMAL}"
         fi
         if [[ ! $rule =~ '-F path=/usr/sbin/' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-F path=/usr/sbin/'${NORMAL}"
         fi
         if [[ ! $rule =~ '-F perm=x' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-F perm=x'${NORMAL}"
         fi
         if [[ ! $rule =~ 'privileged' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing 'privileged-pam'${NORMAL}"
         fi

         IFS=' ' read -a fieldvals <<< "${rule}"

         for field in ${fieldvals[@]}
         do
            if [[ $field =~ 'auid>=' ]]
            then
               auidval="$(echo $field | awk -F'>=' '{print $2}')"
               if (( $auidval > 1000 ))
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid>=' cannot be greater than 1000${NORMAL}"
               fi
            elif [[ $field =~ 'auid!=' ]]
            then
               auidval="$(echo $field | awk -F'!=' '{print $2}')"
               if (( $auidval != 4294967295 && $auidval != 'unset' ))
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid!=' must be either 4294967295 or 'unset'${NORMAL}"
                  fail=1
               fi
            fi
         done
      done
   else
      echo -e "${NORMAL}RESULT:    ${RED}missing a rule for 'pam_timestamp_check'${NORMAL}"
      fail=1
   fi

   if [[ $fail == 0 ]]
   then
      echo -e "${NORMAL}$hostname, $severity23, $controlid, $stigid23, $ruleid23, $cci23, $datetime, ${GRN}PASSED, Use of the pam_timestamp_check command is audited${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity23, $controlid, $stigid23, $ruleid23, $cci23, $datetime, ${RED}FAILED, Use of the pam_timestamp_check command is not audited${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${BLD}$file23 not found${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity23, $controlid, $stigid23, $ruleid23, $cci23, $datetime, ${RED}FAILED, $file23 not found${NORMAL}"
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

file24="/etc/audit/audit.rules"
fail=0

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file24 ]]
then
   aurules="$(grep -w 'create_module' $file24 | grep -v '^#')"
   if [[ $aurules ]]
   then
      for rule in ${aurules[@]}
      do
         echo -e "${NORMAL}RESULT:    ${BLD}$rule${NORMAL}"
         if [[ ! $rule =~ '-a always,exit' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-a always,exit'${NORMAL}"
         fi
         if [[ ! $rule =~ 'module-change' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing module-change${NORMAL}"
         fi
      done
   else
      echo -e "${NORMAL}RESULT:    ${RED}missing a rule for 'create_module'${NORMAL}"
      fail=1
   fi

   if [[ $fail == 0 ]]
   then
      echo -e "${NORMAL}$hostname, $severity24, $controlid, $stigid24, $ruleid24, $cci24, $datetime, ${GRN}PASSED, Use of the create_module command is audited${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity24, $controlid, $stigid24, $ruleid24, $cci24, $datetime, ${RED}FAILED, Use of the create_module command is not audited${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${BLD}$file24 not found${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity24, $controlid, $stigid24, $ruleid24, $cci24, $datetime, ${RED}FAILED, $file24 not found${NORMAL}"
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

file25="/etc/audit/audit.rules"
init32cnt=0
init64cnt=0
finit32cnt=0
finit64cnt=0
fail=0

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file25 ]]
then
   aurules="$(grep -w 'init_module' $file25 | grep -v '^#')"
   if [[ $aurules ]]
   then
      for rule in ${aurules[@]}
      do
         echo -e "${NORMAL}RESULT:    ${BLD}$rule${NORMAL}"
         if [[ ! $rule =~ '-a always,exit' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-a always,exit'${NORMAL}"
            fail=1
         fi
         if [[ ! $rule =~ 'key=module-' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing 'key=module-'${NORMAL}"
         fi
         IFS=' ' read -a fieldvals <<< "${rule}"
         for field in ${fieldvals[@]}
         do
            if [[ $field =~ 'init_module' ]]
            then
               IFS=',' read -r -a initarr <<< "$field"
               for element in ${initarr[@]}
               do
                  if [[ $rule =~ "arch=b32" ]]
                  then
                     case $element in
                        'init_module')
                            (( init32cnt++ ))
                            ;;
                        'finit_module')
                            (( finit32cnt++ ))
                            ;;
                     esac
                  elif [[ $rule =~ "arch=b64" ]]
                  then
                     case $element in
                        'init_module')
                            (( init64cnt++ ))
                            ;;
                        'finit_module')
                            (( finit64cnt++ ))
                            ;;
                     esac
                  fi
               done
            fi
         done
      done
      if [[ $init32cnt == 0 ]]
      then
         echo -e "${NORMAL}RESULT:    ${RED}missing a rule for 'init_module' for 'arch=b32'${NORMAL}"
         fail=1
      fi
      if [[ $finit32cnt == 0 ]]
      then
         echo -e "${NORMAL}RESULT:    ${RED}missing a rule for 'finit_module' for 'arch=b32'${NORMAL}"
         fail=1
      fi
      if [[ $init64cnt == 0 ]]
      then
         echo -e "${NORMAL}RESULT:    ${RED}missing a rule for 'init_module' for 'arch=b64'${NORMAL}"
         fail=1
      fi
      if [[ $finit64cnt == 0 ]]
      then
         echo -e "${NORMAL}RESULT:    ${RED}missing a rule for 'finit_module' for 'arch=b64'${NORMAL}"
         fail=1
      fi
   else
      echo -e "${NORMAL}RESULT:    ${RED}missing a rules for 'init_module' and 'finit_module'${NORMAL}"
      fail=1
   fi

   if [[ $fail == 0 ]]
   then
      echo -e "${NORMAL}$hostname, $severity25, $controlid, $stigid25, $ruleid25, $cci25, $datetime, ${GRN}PASSED, Use of the init_module and finit_module commands are all audited${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity25, $controlid, $stigid25, $ruleid25, $cci25, $datetime, ${RED}FAILED, Use of the init_module and finit_module commands are not all audited${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${BLD}$file25 not found${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity25, $controlid, $stigid25, $ruleid25, $cci25, $datetime, ${RED}FAILED, $file25 not found${NORMAL}"
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

file26="/etc/audit/audit.rules"
fail=0
del32cnt=0
del64cnt=0

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file26 ]]
then
   aurules="$(grep -w delete_module $file26 | grep -v '^#')"
   if [[ $aurules ]]
   then
      for rule in ${aurules[@]}
      do
         echo -e "${NORMAL}RESULT:    ${BLD}$rule${NORMAL}"
         if [[ ! $rule =~ '-a always,exit' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-a always,exit'${NORMAL}"
         fi
         if [[ ! $rule =~ 'key=module-' && ! $rule =~ '-k modules' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing 'key=module-' or '-k modules'${NORMAL}"
         fi
         IFS=' ' read -a fieldvals <<< "${rule}"
         for field in ${fieldvals[@]}
         do
            if [[ $field =~ 'delete_module' ]]
            then
               if [[ $rule =~ "arch=b32" ]]
               then
                  (( del32cnt++ ))
               elif [[ $rule =~ "arch=b64" ]]
               then
                  (( del64cnt++ ))
               fi
            fi
         done
      done
      if [[ $del32cnt == 0 ]]
      then
         echo -e "${NORMAL}RESULT:    ${RED}missing a rule for 'delete_module' for 'arch=b32'${NORMAL}"
         fail=1
      fi
      if [[ $del64cnt == 0 ]]
      then
         echo -e "${NORMAL}RESULT:    ${RED}missing a rule for 'delete_module' for 'arch=b64'${NORMAL}"
         fail=1
      fi
   else
      echo -e "${NORMAL}RESULT:    ${RED}missing a rule for 'delete_module'${NORMAL}"
      fail=1
   fi

   if [[ $fail == 0 ]]
   then
      echo -e "${NORMAL}$hostname, $severity26, $controlid, $stigid26, $ruleid26, $cci26, $datetime, ${GRN}PASSED, Use of the delete_module is audited${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity26, $controlid, $stigid26, $ruleid26, $cci26, $datetime, ${RED}FAILED, Use of the delete_module is not all audited${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${BLD}$file26 not found${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity26, $controlid, $stigid26, $ruleid26, $cci26, $datetime, ${RED}FAILED, $file26 not found${NORMAL}"
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

file27="/etc/audit/audit.rules"
fail=0

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file27 ]]
then
   aurules="$(grep -iw kmod $file27 | grep -v '^#')"
   if [[ $aurules ]]
   then
      for rule in ${aurules[@]}
      do
         echo -e "${NORMAL}RESULT:    ${BLD}$rule${NORMAL}"
         if [[ ! $rule =~ ^-w ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing -w ${NORMAL}"
         fi
         if [[ ! $rule =~ '-p x' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing -p x${NORMAL}"
         fi
         if [[ ! $rule =~ '-F auid!=4294967295' && ! $rule =~ 'auid!=unset' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing -F auid!=4294967295 or auid!=unset${NORMAL}"
         fi
         if [[ ! $rule =~ 'module-' && ! $rule =~ 'k modules' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing 'k modules'${NORMAL}"
         fi
      done
   else
      echo -e "${NORMAL}RESULT:    ${RED}missing a rule for 'kmod'${NORMAL}"
      fail=1
   fi

   if [[ $fail == 0 ]]
   then
      echo -e "${NORMAL}$hostname, $severity27, $controlid, $stigid27, $ruleid27, $cci27, $datetime, ${GRN}PASSED, Use of the kmod command is audited${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity27, $controlid, $stigid27, $ruleid27, $cci27, $datetime, ${RED}FAILED, Use of the kmod command is not audited${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${BLD}$file27 not found${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity27, $controlid, $stigid27, $ruleid27, $cci27, $datetime, ${RED}FAILED, Audit use of kmod: $file27 not found${NORMAL}"
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

file28="/etc/audit/audit.rules"
fail=0

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file28 ]]
then
   aurules="$(grep '/etc/passwd' $file28 | grep -v '^#' | grep -v 'path=/etc/passwd')"
   if [[ $aurules ]]
   then
      for rule in ${aurules[@]}
      do
         echo -e "${NORMAL}RESULT:    ${BLD}$rule${NORMAL}"
         if [[ ! $rule =~ ^-w ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing -w ${NORMAL}"
         fi
         if [[ ! $rule =~ '-p wa' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing -p wa${NORMAL}"
         fi
         if [[ ! $rule =~ '-k identity'  && ! $rule =~ '-F key=identity' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing identity${NORMAL}"
         fi
      done
   else
      echo -e "${NORMAL}RESULT:    ${RED}missing a rule for '/etc/passwd'${NORMAL}"
      fail=1
   fi

   if [[ $fail == 0 ]]
   then
      echo -e "${NORMAL}$hostname, $severity28, $controlid, $stigid28, $ruleid28, $cci28, $datetime, ${GRN}PASSED, Use of the /etc/passwd command is audited${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity28, $controlid, $stigid28, $ruleid28, $cci28, $datetime, ${RED}FAILED, Use of the /etc/passwd command is not audited${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${BLD}$file28 not found${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity28, $controlid, $stigid28, $ruleid28, $cci28, $datetime, ${RED}FAILED, $file28 not found${NORMAL}"
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

file29="/etc/audit/audit.rules"
fail=0

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file29 ]]
then
   aurules="$(grep /etc/group $file29 | grep -v '^#' | grep -v 'path=/etc/group')"
   if [[ $aurules ]]
   then
      for rule in ${aurules[@]}
      do
         echo -e "${NORMAL}RESULT:    ${BLD}$rule${NORMAL}"
         if [[ ! $rule =~ ^-w ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing -w ${NORMAL}"
            fail=1
         fi
         if [[ ! $rule =~ '-p wa' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing -p wa${NORMAL}"
            fail=1
         fi
         if [[ ! $rule =~ 'identity' && ! $rule =~ 'audit_rules_usergroup_modification' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing 'identity' or 'audit_rules_usergroup_modification'${NORMAL}"
         fi
      done
   else
      echo -e "${NORMAL}RESULT:    ${RED}missing a rule for '/etc/group'${NORMAL}"
      fail=2
   fi

   if [[ $fail == 0 ]]
   then
      echo -e "${NORMAL}$hostname, $severity29, $controlid, $stigid29, $ruleid29, $cci29, $datetime, ${GRN}PASSED, The operating system generates audit records for all account creations modifications disabling and termination events that affect /etc/group${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity29, $controlid, $stigid29, $ruleid29, $cci29, $datetime, ${RED}FAILED, The operating system does not generate audit records for all account creations modifications disabling and termination events that affect /etc/group${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${BLD}$file29 not found${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity29, $controlid, $stigid29, $ruleid29, $cci29, $datetime, ${RED}FAILED, $file29 not found${NORMAL}"
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

file30="/etc/audit/audit.rules"
fail=0

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file30 ]]
then
   aurules="$(grep /etc/gshadow $file30 | grep -v '^#' | grep -v 'path=/etc/gshadow')"
   if [[ $aurules ]]
   then
      for rule in ${aurules[@]}
      do
         echo -e "${NORMAL}RESULT:    ${BLD}$rule${NORMAL}"
         if [[ ! $rule =~ ^-w ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing -w ${NORMAL}"
            fail=1
         fi
         if [[ ! $rule =~ '-p wa' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing -p wa${NORMAL}"
            fail=1
         fi
         if [[ ! $rule =~ 'identity' && ! $rule =~ 'usergroup_modification' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing identity${NORMAL}"
         fi
      done
   else
      echo -e "${NORMAL}RESULT:    ${RED}missing a rule for '/etc/gshadow'${NORMAL}"
      fail=1
   fi

   if [[ $fail == 0 ]]
   then
      echo -e "${NORMAL}$hostname, $severity30, $controlid, $stigid30, $ruleid30, $cci30, $datetime, ${GRN}PASSED, The operating system generates audit records for all account creations modifications disabling and termination events that affect /etc/gshadow${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity30, $controlid, $stigid30, $ruleid30, $cci30, $datetime, ${RED}FAILED, The operating system does not generate audit records for all account creations modifications disabling and termination events that affect /etc/gshadow${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${BLD}$file30 not found${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity30, $controlid, $stigid30, $ruleid30, $cci30, $datetime, ${RED}FAILED, $file30 not found${NORMAL}"
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

file31="/etc/audit/audit.rules"
fail=0

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file31 ]]
then
   aurules="$(grep /etc/shadow $file31 | grep -v '^#' | grep -v 'path=/etc/shadow')"
   if [[ $aurules ]]
   then
      for rule in ${aurules[@]}
      do
         echo -e "${NORMAL}RESULT:    ${BLD}$rule${NORMAL}"
         if [[ ! $rule =~ ^-w ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing -w ${NORMAL}"
            fail=1
         fi
         if [[ ! $rule =~ '-p wa' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing -p wa${NORMAL}"
            fail=1
         fi
         if [[ ! $rule =~ 'identity' && ! $rule =~ 'usergroup_modification' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing identity${NORMAL}"
         fi
      done
   else
      echo -e "${NORMAL}RESULT:    ${RED}missing a rule for '/etc/shadow'${NORMAL}"
      fail=1
   fi

   if [[ $fail == 0 ]]
   then
      echo -e "${NORMAL}$hostname, $severity31, $controlid, $stigid31, $ruleid31, $cci31, $datetime, ${GRN}PASSED, The operating system generates audit records for all account creations modifications disabling and termination events that affect /etc/shadow.${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity31, $controlid, $stigid31, $ruleid31, $cci31, $datetime, ${RED}FAILED, The operating system does not generate audit records for all account creations modifications disabling and termination events that affect /etc/shadow.${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${BLD}$file31 not found${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity31, $controlid, $stigid31, $ruleid31, $cci31, $datetime, ${RED}FAILED, $file31 not found${NORMAL}"
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
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity31${NORMAL}"

file32="/etc/audit/audit.rules"
fail=0

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file32 ]]
then
   aurules="$(grep -i '/etc/security/opasswd' $file32 | grep -v '^#')"
   if [[ $aurules ]]
   then
      for rule in ${aurules[@]}
      do
         echo -e "${NORMAL}RESULT:    ${BLD}$rule${NORMAL}"
         if [[ ! $rule =~ ^-w ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing -w ${NORMAL}"
            fail=1
         fi
         if [[ ! $rule =~ '-p wa' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing -p wa${NORMAL}"
            fail=1
         fi
         if [[ ! $rule =~ 'identity' && ! $rule =~ 'usergroup_modification' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing identity${NORMAL}"
         fi
      done
   else
      echo -e "${NORMAL}RESULT:    ${RED}missing a rule for '/etc/security/opasswd'${NORMAL}"
      fail=1
   fi

   if [[ $fail == 0 ]]
   then
      echo -e "${NORMAL}$hostname, $severity32, $controlid, $stigid32, $ruleid32, $cci32, $datetime, ${GRN}PASSED, The operating system generates audit records for all account creations modifications disabling and termination events that affect /etc/opasswd.${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity32, $controlid, $stigid32, $ruleid32, $cci32, $datetime, ${RED}FAILED, The operating system does not generate audit records for all account creations modifications disabling and termination events that affect /etc/opasswd.${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${BLD}$file32 not found${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity32, $controlid, $stigid32, $ruleid32, $cci32, $datetime, ${RED}FAILED, $file32 not found${NORMAL}"
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

file33="/etc/audit/audit.rules"

fail=0
unlink32=0
unlink64=0
unlinkat32=0
unlinkat64=0
rename32=0
rename64=0
renameat32=0
renameat64=0
rmdir32=0
rmdir64=0

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file33 ]]
then
   aurules="$(grep 'unlink\|rename\|rmdir' $file33 | grep -v '^#')"
   if [[ $aurules ]]
   then
      for rule in ${aurules[@]}
      do
         echo -e "${NORMAL}RESULT:    ${BLD}$rule${NORMAL}"
         if [[ ! $rule =~ '-a always,exit' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-a always,exit'${NORMAL}"
            fail=1
         fi
         if [[ ! $rule =~ 'unsuccesful' &&
               ! $rule =~ 'delete'
            ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing 'unsuccessful' or 'delete' key${NORMAL}"
         fi

         IFS=' ' read -a fieldvals <<< "${rule}"

         for field in ${fieldvals[@]}
         do
            if [[ $field =~ 'unlink' || $field =~ 'creat' || $field =~ 'rename' || $field =~ 'rmdir' ]]
            then
               IFS=',' read -r -a creatarr <<< "$field"
               for element in ${creatarr[@]}
               do
                  if [[ $rule =~ "arch=b32" ]]
                  then
                     case $element in
                        'unlink')
                           (( unlink32++ ))
                           ;;
                        'unlinkat')
                           (( unlinkat32++ ))
                           ;;
                        'rename')
                           (( rename32++ ))
                           ;;
                        'renameat')
                           (( renameat32++ ))
                           ;;
                        'rmdir')
                           (( rmdir32++ ))
                           ;;
                     esac
                  elif [[ $rule =~ "arch=b64" ]]
                  then
                     case $element in
                        'unlink')
                           (( unlink64++ ))
                           ;;
                        'unlinkat')
                           (( unlinkat64++ ))
                           ;;
                        'rename')
                           (( rename64++ ))
                           ;;
                        'renameat')
                           (( renameat64++ ))
                           ;;
                        'rmdir')
                           (( rmdir64++ ))
                           ;;
                     esac
                  fi
               done
            fi
            if [[ $field =~ 'auid>=' ]]
            then
               auidval="$(echo $field | awk -F'>=' '{print $2}')"
               if (( $auidval > 1000 ))
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid>=' cannot be greater than 1000${NORMAL}"
                  fail=1
               fi
            elif [[ $field =~ 'auid!=' ]]
            then
               auidval="$(echo $field | awk -F'!=' '{print $2}')"
               if (( $auidval != 4294967295 )) && [[ $auidval != "unset" ]]
               then
                  echo -e "${NORMAL}RESULT:    ${RED}\"auid!=\" must be \"4294967295\", or \"unset\".${NORMAL}"
                  fail=1
               fi
            fi
         done
      done
      if [[ $unlink32 == 0 ]]
      then
         echo -e "${NORMAL}RESULT:    ${RED}A rule for \"unlink\" was not found for \"arch=b32\".${NORMAL}"
         fail=1
      fi
      if [[ $unlinkat32 == 0 ]]
      then
         echo -e "${NORMAL}RESULT:    ${RED}A rule for \"unlinkat\" was not found for \"arch=b32\".${NORMAL}"
         fail=1
      fi
      if [[ $rename32 == 0 ]]
      then
         echo -e "${NORMAL}RESULT:    ${RED}A rule for \"rename\" was not found for \"arch=b32\".${NORMAL}"
         fail=1
      fi
      if [[ $renameat32 == 0 ]]
      then
         echo -e "${NORMAL}RESULT:    ${RED}A rule for \"renameat\" was not found for \"arch=b32\".${NORMAL}"
         fail=1
      fi
      if [[ $rmdir32 == 0 ]]
      then
         echo -e "${NORMAL}RESULT:    ${RED}A rule for \"rmdir\" was not found for \"arch=b32\".${NORMAL}"
         fail=1
      fi
      if [[ $unlink64 == 0 ]]
      then
         echo -e "${NORMAL}RESULT:    ${RED}A rule for \"unlink\" was not found for \"arch=b64\".${NORMAL}"
         fail=1
      fi
      if [[ $unlinkat64 == 0 ]]
      then
         echo -e "${NORMAL}RESULT:    ${RED}A rule for \"unlinkat\" was not found for \"arch=b64\".${NORMAL}"
         fail=1
      fi
      if [[ $rename64 == 0 ]]
      then
         echo -e "${NORMAL}RESULT:    ${RED}A rule for \"rename\" was not found for \"arch=b64\".${NORMAL}"
         fail=1
      fi
      if [[ $renameat64 == 0 ]]
      then
         echo -e "${NORMAL}RESULT:    ${RED}A rule for \"renameat\" was not found for \"arch=b64\".${NORMAL}"
         fail=1
      fi
      if [[ $rmdir64 == 0 ]]
      then
         echo -e "${NORMAL}RESULT:    ${RED}A rule for \"rmdir\" was not found for \"arch=b64\".${NORMAL}"
         fail=1
      fi
   else
      echo -e "${NORMAL}RESULT:    ${RED}missing rules for 'unlink', 'unlinkat', 'rename', 'renameat, and 'rmdir'.${NORMAL}"
      fail=1
   fi

   if [[ $fail == 0 ]]
   then
      echo -e "${NORMAL}$hostname, $severity33, $controlid, $stigid33, $ruleid33, $cci33, $datetime, ${GRN}PASSED, Use of the unlink unlinkat rename renameat and rmdir commands are all audited${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity33, $controlid, $stigid33, $ruleid33, $cci33, $datetime, ${RED}FAILED, Use of the unlink unlinkat rename renameat and rmdir commands are not all audited${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${BLD}$file33 not found${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity33, $controlid, $stigid33, $ruleid33, $cci33, $datetime, ${RED}FAILED, $file33 not found${NORMAL}"
fi

exit

