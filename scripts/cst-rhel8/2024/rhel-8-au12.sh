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

stig="Red Hat Enterprise Linux 8 Security Technical Implementation Guide :: Version 1, Release: 13 Benchmark Date: 24 Jan 2024" 

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

title1a="RHEL 8 must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/shadow."
title1b="Checking with 'grep /etc/shadow /etc/audit/audit.rules'."
title1c="Expecting: ${YLO}-w /etc/shadow -p wa -k identity.${BLD}
           NOTE: ${YLO}If the command does not return a line, or the line is commented out, this is a finding."${BLD}
cci1="CCI-000169"
stigid1="RHEL-08-030130"
severity1="CAT II"
ruleid1="SV-230404r627750_rule"
vulnid1="V-230404"

title2a="RHEL 8  must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/opasswd."
title2b="Checking with 'grep /etc/security/opasswd /etc/audit/audit.rules'."
title2c="Expecting: ${YLO}-w /etc/security/opasswd -p wa -k identity${BLD}
           NOTE: ${YLO}If the command does not return a line, or the line is commented out, this is a finding."${BLD}
cci2="CCI-000169"
stigid2="RHEL-08-030140"
severity2="CAT II"
ruleid2="SV-230405r627750_rule"
vulnid2="V-230405"

title3a="RHEL 8 must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/passwd."
title3b="Checking with 'grep /etc/passwd /etc/audit/audit.rules'."
title3c="Expecting: ${YLO}-w /etc/passwd -p wa -k identity${BLD}
           NOTE: ${YLO}If the command does not return a line, or the line is commented out, this is a finding."${BLD}
cci3="CCI-000169"
stigid3="RHEL-08-030150"
severity3="CAT II"
ruleid3="SV-230406r627750_rule"
vulnid3="V-230406"

title4a="RHEL 8 must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/gshadow."
title4b="Checking with 'grep /etc/gshadow /etc/audit/audit.rules'."
title4c="Expecting: ${YLO}-w /etc/gshadow -p wa -k identity${BLD}
           NOTE: ${YLO}If the command does not return a line, or the line is commented out, this is a finding."${BLD}
cci4="CCI-000169"
stigid4="RHEL-08-030160"
severity4="CAT II"
ruleid4="SV-230407r627750_rule"
vulnid4="V-230407"

title5a="RHEL 8 must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/group."
title5b="Checking with 'grep /etc/group /etc/audit/audit.rules'."
title5c="Expecting: ${YLO}-w /etc/group -p wa -k audit_rules_usergroup_modification.${BLD}
           NOTE: ${YLO}If the command does not return a line, or the line is commented out, this is a finding."${BLD}
cci5="CCI-000169"
stigid5="RHEL-08-030170"
severity5="CAT II"
ruleid5="SV-230408r627750_rule"
vulnid5="V-230408"

title6a="RHEL 8  must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/sudoers."
title6b="Checking with 'grep /etc/sudoers /etc/audit/audit.rules'."
title6c="Expecting: ${YLO}-w /etc/sudoers -p wa -k identity${BLD}
           NOTE: ${YLO}If the command does not return a line, or the line is commented out, this is a finding."${BLD}
cci6="CCI-000169"
stigid6="RHEL-08-030171"
severity6="CAT II"
ruleid6="SV-230409r627750_rule"
vulnid6="V-230409"

title7a="RHEL 8  must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/sudoers.d"
title7b="Checking with 'grep /etc/sudoers.d/ /etc/audit/audit.rules'."
title7c="Expecting: ${YLO}-w /etc/sudoers.d/ -p wa -k identity${BLD}
           NOTE: ${YLO}If the command does not return a line, or the line is commented out, this is a finding."${BLD}
cci7="CCI-000169"
stigid7="RHEL-08-030172"
severity7="CAT II"
ruleid7="SV-230410r627750_rule"
vulnid7="V-230410"

title8a="The RHEL 8 audit package must be installed."
title8b="Checking with 'yum list installed audit'"
title8c="Expecting: ${YLO}audit.x86_64 3.0-0.17.20191104git1c2f876.el8 @anaconda${BLD}
           NOTE: ${YLO}If the \"audit\" package is not installed, this is a finding."${BLD}
cci8="CCI-000169"
stigid8="RHEL-08-030180"
severity8="CAT II"
ruleid8="SV-230411r744000_rule"
vulnid8="V-230411"

title9a="Successful/unsuccessful uses of the su command in RHEL 8 must generate an audit record."
title9b="Checking with 'grep -w /usr/bin/su /etc/audit/audit.rules'"
title9c="Expecting: ${YLO}-a always,exit -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=unset -k privileged-priv_change${BLD}
           NOTE: ${YLO}If the command does not return any output, this is a finding."${BLD}
cci9="CCI-000169"
stigid9="RHEL-08-030190"
severity9="CAT II"
ruleid9="SV-230412r627750_rule"
vulnid9="V-230412"

title10a="The RHEL 8 audit system must be configured to audit any usage of the setxattr, fsetxattr, lsetxattr, removexattr, fremovexattr, and lremovexattr system calls."
title10b="Checking with 'grep -w xattr /etc/audit/audit.rules'."
title10c="Expecting: ${YLO}
           -a always,exit -F arch=b32 -S setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr -F auid>=1000 -F auid!=unset -k perm_mod
           -a always,exit -F arch=b64 -S setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr -F auid>=1000 -F auid!=unset -k perm_mod
           
           -a always,exit -F arch=b32 -S setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr -F auid=0 -k perm_mod
           -a always,exit -F arch=b64 -S setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr -F auid=0 -k perm_mod
           NOTE: If the command does not return an audit rule for \"setxattr\", \"fsetxattr\", \"lsetxattr\", \"removexattr\", \"fremovexattr\", and \"lremovexattr\" or any of the lines returned are commented out, this is a finding."${BLD}
cci10="CCI-000169"
stigid10="RHEL-08-030200"
severity10="CAT II"
ruleid10="SV-230413r810463_rule"
vulnid10="V-230413"

title11a="The RHEL 8 system must audit all successful/unsuccessful uses of the chage command."
title11b="Checking with 'grep -w chage /etc/audit/audit.rules'."
title11c="Expecting: i${YLO}-a always,exit -F path=/usr/bin/chage -F perm=x -F auid>=1000 -F auid!=unset -k privileged-chage${BLD}
           NOTE: ${YLO}If the command does not return a line, or the line is commented out, this is a finding."${BLD}
cci11="CCI-000169"
stigid11="RHEL-08-030250"
severity11="CAT II"
ruleid11="SV-230418r627750_rule"
vulnid11="V-230418"

title12a="The RHEL 8 system must audit all successful/unsuccessful uses of the chcon command."
title12b="Checking with 'grep -iw chcon /etc/audit/audit.rules'."
title12c="Expecting: ${YLO}-a always,exit -F path=/usr/bin/chcon -F perm=x -F auid>=1000 -F auid!=unset -k privileged-priv_change${BLD}
           NOTE: ${YLO}If the command does not return a line, or the line is commented out, this is a finding."${BLD}
cci12="CCI-000169"
stigid12="RHEL-08-030260"
severity12="CAT II"
ruleid12="SV-230419r627750_rule"
vulnid12="V-230419"

title13a="Successful/unsuccessful uses of the ssh-agent in RHEL 8 must generate an audit record."
title13b="Checking with 'grep ssh-agent /etc/audit/audit.rules'."
title13c="Expecting: ${YLO}-a always,exit -F path=/usr/bin/ssh-agent -F perm=x -F auid>=1000 -F auid!=unset -k privileged-ssh${BLD}
           NOTE: ${YLO}If the command does not return a line, or the line is commented out, this is a finding."${BLD}
cci13="CCI-000169"
stigid13="RHEL-08-030280"
severity13="CAT II"
ruleid13="SV-230421r627750_rule"
vulnid13="V-230421"

title14a="Successful/unsuccessful uses of the passwd command in RHEL 8 must generate an audit record."
title14b="Checking with 'grep -w passwd /etc/audit/audit.rules'."
title14c="Expecting: ${YLO}-a always,exit -F path=/usr/bin/passwd -F perm=x -F auid>=1000 -F auid!=unset -k privileged-passwd${BLD}
           NOTE: ${YLO}If the command does not return a line, or the line is commented out, this is a finding."${BLD}
cci14="CCI-000169"
stigid14="RHEL-08-030290"
severity14="CAT II"
ruleid14="SV-230422r627750_rule"
vulnid14="V-230422"

title15a="Successful/unsuccessful uses of the mount command in RHEL 8 must generate an audit record."
title15b="Checking with 'grep -w /usr/bin/mount /etc/audit/audit.rules'."
title15c="Expecting: ${YLO}-a always,exit -F path=/usr/bin/mount -F perm=x -F auid>=1000 -F auid!=unset -k privileged-mount${BLD}
           NOTE: ${YLO}If the command does not return a line, or the line is commented out, this is a finding."${BLD}
cci15="CCI-000169"
stigid15="RHEL-08-030300"
severity15="CAT II"
ruleid15="SV-230423r627750_rule"
vulnid15="V-230423"

title16a="Successful/unsuccessful uses of the umount command in RHEL 8 must generate an audit record."
title16b="Checking with 'grep -w /usr/bin/umount /etc/audit/audit.rules'."
title16c="Expecting: ${YLO}-a always,exit -F path=/usr/bin/umount -F perm=x -F auid>=1000 -F auid!=unset -k privileged-mount${BLD}
           NOTE: ${YLO}If the command does not return a line, or the line is commented out, this is a finding."${BLD}
cci16="CCI-000169"
stigid16="RHEL-08-030301"
severity16="CAT II"
ruleid16="SV-230424r627750_rule"
vulnid16="V-230424"

title17a="Successful/unsuccessful uses of the mount syscall in RHEL 8 must generate an audit record."
title17b="Checking with 'grep -w \"\-S mount\" /etc/audit/audit.rules'."
title17c="Expecting: 
           ${YLO}-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=unset -k privileged-mount${BLD}
           ${YLO}-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=unset -k privileged-mount${BLD}
           NOTE: ${YLO}If the command does not return a line, or the line is commented out, this is a finding."${BLD}
cci17="CCI-000169"
stigid17="RHEL-08-030302"
severity17="CAT II"
ruleid17="SV-230425r627750_rule"
vulnid17="V-230425"

title18a="Successful/unsuccessful uses of the unix_update syscall in RHEL 8 must generate an audit record."
title18b="Checking with 'grep -w 'unix_update' /etc/audit/audit.rules'."
title18c="Expecting: ${YLO}-a always,exit -F path=/usr/sbin/unix_update -F perm=x -F auid>=1000 -F auid!=unset -k privileged-unix-update${BLD}
           NOTE: ${YLO}If the command does not return a line, or the line is commented out, this is a finding."${BLD}
cci18="CCI-000169"
stigid18="RHEL-08-030310"
severity18="CAT II"
ruleid18="SV-230426r627750_rule"
vulnid18="V-230426"

title19a="Successful/unsuccessful uses of postdrop in RHEL 8 must generate an audit record."
title190b="Checking with 'grep -w 'postdrop' /etc/audit/audit.rules'."
title19c="Expecting: ${YLO}-a always,exit -F path=/usr/sbin/postdrop -F perm=x -F auid>=1000 -F auid!=unset -k privileged-unix-update${BLD}
           NOTE: ${YLO}If the command does not return a line, or the line is commented out, this is a finding."${BLD}
cci19="CCI-000169"
stigid19="RHEL-08-030311"
severity19="CAT II"
ruleid19="SV-230427r627750_rule"
vulnid19="V-230427"

title20a="Successful/unsuccessful uses of postqueue in RHEL 8 must generate an audit record."
title20b="Checking with 'grep -w 'postqueue' /etc/audit/audit.rules'."
title20c="Expecting: ${YLO}-a always,exit -F path=/usr/sbin/postqueue -F perm=x -F auid>=1000 -F auid!=unset -k privileged-unix-update${BLD}
           NOTE: ${YLO}If the command does not return a line, or the line is commented out, this is a finding."${BLD}
cci20="CCI-000169"
stigid20="RHEL-08-030312"
severity20="CAT II"
ruleid20="SV-230428r627750_rule"
vulnid20="V-230428"

title21a=" Successful/unsuccessful uses of semanage in RHEL 8 must generate an audit record."
title21b="Checking with 'grep -w 'semanage' /etc/audit/audit.rules'."
title21c="Expecting: ${YLO}-a always,exit -F path=/usr/sbin/semanage -F perm=x -F auid>=1000 -F auid!=unset -k privileged-unix-update${BLD}
           NOTE: ${YLO}If the command does not return a line, or the line is commented out, this is a finding."${BLD}
cci21="CCI-000169"
stigid21="RHEL-08-030313"
severity21="CAT II"
ruleid21="SV-230429r627750_rule"
vulnid21="V-230429"

title22a="Successful/unsuccessful uses of setfiles in RHEL 8 must generate an audit record."
title22b="Checking with 'grep -w 'setfiles' /etc/audit/audit.rules'."
title22c="Expecting: ${YLO}-a always,exit -F path=/usr/sbin/setfiles -F perm=x -F auid>=1000 -F auid!=unset -k privileged-unix-update${BLD}
      f     NOTE: ${YLO}If the command does not return any output, this is a finding."${BLD}
cci22="CCI-000169"
stigid22="RHEL-08-030314"
severity22="CAT II"
ruleid22="SV-230430r627750_rule"
vulnid22="V-230430"

title23a="Successful/unsuccessful uses of userhelper in RHEL 8 must generate an audit record."
title23b="Checking with 'grep -w userhelper /etc/audit/audit.rules'."
title23c="Expecting: ${YLO}-a always,exit -F path=/usr/sbin/userhelper -F perm=x -F auid>=1000 -F auid!=unset -k privileged-unix-update${BLD}
           NOTE: ${YLO}If the command does not return any output, this is a finding."${BLD}
cci23="CCI-000169"
stigid23="RHEL-08-030315"
severity23="CAT II"
ruleid23="SV-230431r627750_rule"
vulnid23="V-230431"

title24a="Successful/unsuccessful uses of setsebool in RHEL 8 must generate an audit record."
title24b="Checking with 'grep -w setsebool /etc/audit/audit.rules'."
title24c="Expecting: ${YLO}-a always,exit -F path=/usr/sbin/setsebool -F perm=x -F auid>=1000 -F auid!=unset -k privileged-unix-update${BLD}
           NOTE: ${YLO}If the command does not return any output, this is a finding."${BLD}
cci24="CCI-000169"
stigid24="RHEL-08-030316"
severity24="CAT II"
ruleid24="SV-230432r627750_rule"
vulnid24="V-230432"

title25a="Successful/unsuccessful uses of the ssh-keysign in RHEL 8 must generate an audit record."
title25b="Checking with 'grep -w unix_chkpwd /etc/audit/audit.rules'."
title25c="Expecting: ${YLO}-a always,exit -F path=/usr/sbin/unix_chkpwd -F perm=x -F auid>=1000 -F auid!=unset -k privileged-unix-update${BLD}
           NOTE: ${YLO}If the command does not return any output, this is a finding."${BLD}
cci25="CCI-000169"
stigid25="RHEL-08-030317"
severity25="CAT II"
ruleid25="SV-230433r627750_rule"
vulnid25="V-230433"

title26a="The Red Hat Enterprise Linux operating system must audit all uses of the ssh-keysign command."
title26b="Checking with 'grep -i /usr/libexec/openssh/ssh-keysign /etc/audit/audit.rules'."
title26c="Expecting: ${YLO}-a always,exit -F path=/usr/libexec/openssh/ssh-keysign -F perm=x -F auid>=1000 -F auid!=unset -k privileged-ssh${BLD} 
           NOTE: ${YLO}If the command does not return any output, this is a finding."${BLD}
cci26="CCI-000169"
stigid26="RHEL-08-030320"
severity26="CAT II"
ruleid26="SV-230434r744002_rule"
vulnid26="V-230434"

title27a="Successful/unsuccessful uses of the setfacl command in RHEL 8 must generate an audit record."
title27b="Checking with 'grep -w 'setfacl' /etc/audit/audit.rules'."
title27c="Expecting: ${YLO}-a always,exit -F path=/usr/sbin/setfacl -F perm=x -F auid>=1000 -F auid!=unset -k perm_mod${BLD}
           NOTE: ${YLO}If the command does not return a line, or the line is commented out, this is a finding."${BLD}
cci27="CCI-000169"
stigid27="RHEL-08-030330"
severity27="CAT II"
ruleid27="SV-230435r627750_rule"
vulnid27="V-230435"

title28a="Successful/unsuccessful uses of the pam_timestamp_check command in RHEL 8 must generate an audit record."
title28b="Checking with 'grep -w 'pam_timestamp_check' /etc/audit/audit.rules'."
title28c="Expecting: ${YLO}-a always,exit -F path=/usr/sbin/pam_timestamp_check -F perm=x -F auid>=1000 -F auid!=unset -k privileged-pam_timestamp_check${BLD}
           NOTE: ${YLO}If the command does not return any output, this is a finding."${BLD}
cci28="CCI-000169"
stigid28="RHEL-08-030340"
severity28="CAT II"
ruleid28="SV-230436r627750_rule"
vulnid28="V-230436"

title29a="The Red Hat Enterprise Linux operating system must audit all uses of the newgrp command."
title29b="Checking with 'grep -w newgrp /etc/audit/audit.rules'."
title29c="Expecting: ${YLO}-a always,exit -F path=/usr/bin/newgrp -F perm=x -F auid>=1000 -F auid!=unset -k priv_cmd${BLD}
           NOTE: ${YLO}If the command does not return any output, this is a finding."${BLD}
cci29="CCI-000169"
stigid29="RHEL-08-030350"
severity29="CAT II"
ruleid29="SV-230437r627750_rule"
vulnid29="V-230437"

title30a="Successful/unsuccessful uses of the init_module command in RHEL 8 must generate an audit record."
title30b="Checking with 'grep -w init_module /etc/audit/audit.rules'."
title30c="Expecting:
           ${YLO}-a always,exit -F arch=b32 -S init_module -F auid>=1000 -F auid!=unset -k module_chng${BLD}
           ${YLO}-a always,exit -F arch=b64 -S init_module -F auid>=1000 -F auid!=unset -k module_chng${BLD}
           NOTE: ${YLO}If the command does not return a line, or the line is commented out, this is a finding."${BLD}
cci30="CCI-000169"
stigid30="RHEL-08-030360"
severity30="CAT II"
ruleid30="SV-230438r627750_rule"
vulnid30="V-230438"

title31a="Successful/unsuccessful uses of the rename, unlink, rmdir, renameat, and unlinkat system calls in RHEL 8 must generate an audit record."
title31b="Checking with 'grep rename\|unlink\|rmdir /etc/audit/audit.rules'."
title31c="Expecting: 
           ${YLO}-a always,exit -F arch=b32 -S rename -F auid>=1000 -F auid!=unset -k delete${BLD}
           ${YLO}-a always,exit -F arch=b64 -S rename -F auid>=1000 -F auid!=unset -k delete${BLD}
           NOTE: ${YLO}If the command does not return a line, or the line is commented out, this is a finding."${BLD}
cci31="CCI-000169"
stigid31="RHEL-08-030361"
severity31="CAT II"
ruleid31="SV-230439r627750_rule"
vulnid31="V-230439"

title32a="Successful/unsuccessful uses of the gpasswd command in RHEL 8 must generate an audit record."
title32b="Checking with 'grep -w gpasswd /etc/audit/audit.rules'."
title32c="Expecting: 
           ${YLO}-a always,exit -F path=/usr/bin/gpasswd -F perm=x -F auid>=1000 -F auid!=unset -k privileged-gpasswd${BLD}
           NOTE: If the command does not return a line, or the line is commented out, this is a finding."
cci32="CCI-000169"
stigid32="RHEL-08-030370"
severity32="CAT II"
ruleid32="SV-230444r627750_rule"
vulnid32="V-230444"

title33a="Successful/unsuccessful uses of the delete_module command in RHEL 8 must generate an audit record."
title33b="Checking with 'grep -w delete_module /etc/audit/audit.rules'."
title33c="Expecting: 
           ${YLO}-a always,exit -F arch=b32 -S delete_module -F auid>=1000 -F auid!=unset -k module_chng${BLD}
           ${YLO}-a always,exit -F arch=b64 -S delete_module -F auid>=1000 -F auid!=unset -k module_chng${BLD}
           NOTE: ${YLO}If the command does not return a line, or the line is commented out, this is a finding."${BLD}
cci33="CCI-000169"
stigid33="RHEL-08-030390"
severity33="CAT II"
ruleid33="SV-230446r627750_rule"
vulnid33="V-230446"

title34a="Successful/unsuccessful uses of the crontab command in RHEL 8 must generate an audit record."
title34b="Checking with 'grep -w crontab /etc/audit/audit.rules'."
title34c="Expecting: ${YLO}-a always,exit -F path=/usr/bin/crontab -F perm=x -F auid>=1000 -F auid!=unset -k privileged-crontab${BLD}
           NOTE: ${YLO}If the command does not return a line, or the line is commented out, this is a finding."${BLD}
cci34="CCI-000169"
stigid34="RHEL-08-030400"
severity34="CAT II"
ruleid34="SV-230447r627750_rule"
vulnid34="V-230447"

title35a="Successful/unsuccessful uses of the chsh command in RHEL 8 must generate an audit record."
title35b="Checking with 'grep -w chsh /etc/audit/audit.rules'."
title35c="Expecting: ${YLO}-a always,exit -F path=/usr/bin/chsh -F perm=x -F auid>=1000 -F auid!=unset -k priv_cmd${BLD}
           NOTE: ${YLO}If the command does not return a line, or the line is commented out, this is a finding."${BLD}
cci35="CCI-000169"
stigid35="RHEL-08-030410"
severity35="CAT II"
ruleid35="SV-230448r627750_rule"
vulnid35="V-230448"

title36a="Successful/unsuccessful uses of the truncate, ftruncate, creat, open, openat, and open_by_handle_at system calls in RHEL 8 must generate an audit record."
title36b="Checking with 'grep 'open\|truncate\|creat' /etc/audit/audit.rules'."
title36c="Expecting:${YLO}
           -a always,exit -F arch=b32 -S truncate,ftruncate,creat,open,openat,open_by_handle_at -F exit=-EPERM -F auid>=1000 -F auid!=unset -k perm_access
           -a always,exit -F arch=b64 -S truncate,ftruncate,creat,open,openat,open_by_handle_at -F exit=-EPERM -F auid>=1000 -F auid!=unset -k perm_access
           
           -a always,exit -F arch=b32 -S truncate,ftruncate,creat,open,openat,open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=unset -k perm_access
           -a always,exit -F arch=b64 -S truncate,ftruncate,creat,open,openat,open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=unset -k perm_access
           NOTE: If the output does not produce rules containing \"-F exit=-EPERM\", this is a finding.
	   NOTE: If the output does not produce rules containing \"-F exit=-EACCES\", this is a finding.
	   NOTE: If the output does not produce rules containing \"-F exit=-EACCES\", this is a finding."${BLD}
cci36="CCI-000169"
stigid36="RHEL-08-030420"
severity36="CAT II"
ruleid36="SV-230449r810455_rule"
vulnid36="V-230449"

title37a="Successful/unsuccessful uses of the chown command in RHEL 8 must generate an audit record."
title37b="Checking with 'grep chown /etc/audit/audit.rules'."
title37c="Expecting: ${YLO}
           -a always,exit -F arch=b32 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=unset -k perm_mod
           -a always,exit -F arch=b64 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=unset -k perm_mod
           NOTE: If the command does not return all lines, or the lines are commented out, this is a finding."${BLD}
cci37="CCI-000169"
stigid37="RHEL-08-030480"
severity37="CAT II"
ruleid37="SV-230455r627750_rule"
vulnid37="V-230455"

title38a="Successful/unsuccessful uses of the chmod command in RHEL 8 must generate an audit record."
title38b="Checking with 'grep chmod /etc/audit/audit.rules'."
title38c="Expecting: i${YLO}
           -a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=unset -k perm_mod
           -a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=unset -k perm_mod
           NOTE: ${YLO}If the command does not return all lines, or the lines are commented out, this is a finding."${BLD}
cci38="CCI-000169"
stigid38="RHEL-08-030490"
severity38="CAT II"
ruleid38="SV-230456r810462_rule"
vulnid38="V-230456"

title39a="Successful/unsuccessful uses of the sudo command in RHEL 8 must generate an audit record."
title39b="Checking with 'grep -w sudo /etc/audit/audit.rules'."
title39c="Expecting: 
           ${YLO}-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=unset -k priv_cmd${BLD}
           NOTE: ${YLO}If the command does not return any output, this is a finding."${BLD}
cci39="CCI-000169"
stigid39="RHEL-08-030550"
severity39="CAT II"
ruleid39="SV-230462r627750_rule"
vulnid39="V-230462"

title40a="Successful/unsuccessful uses of the usermod command in RHEL 8 must generate an audit record."
title40b="Checking with 'grep -w usermod /etc/audit/audit.rules'."
title40c="Expecting: ${YLO}-a always,exit -F path=/usr/sbin/usermod -F perm=x -F auid>=1000 -F auid!=unset -k privileged-usermod${BLD}
           NOTE: ${YLO}If the command does not return a line, or the line is commented out, this is a finding."${BLD}
cci40="CCI-000169"
stigid40="RHEL-08-030560"
severity40="CAT II"
ruleid40="SV-230463r627750_rule"
vulnid40="V-230463"

title41a="Successful/unsuccessful uses of the chacl command in RHEL 8 must generate an audit record."
title41b="Checking with 'grep -w chacl /etc/audit/audit.rules'."
title41c="Expecting: ${YLO}-a always,exit -F path=/usr/bin/chacl -F perm=x -F auid>=1000 -F auid!=unset -k perm_mod${BLD}
           NOTE: ${YLO}If the command does not return a line, or the line is commented out, this is a finding."${BLD}
cci41="CCI-000169"
stigid41="RHEL-08-030570"
severity41="CAT II"
ruleid41="SV-230464r627750_rule"
vulnid41="V-230464"

title42a="Successful/unsuccessful uses of the kmod command in RHEL 8 must generate an audit record."
title42b="Checking with 'grep /usr/bin/kmod /etc/audit/audit.rules'."
title42c="Expecting: ${YLO}-a always,exit -F path=/usr/bin/kmod -F perm=x -F auid>=1000 -F auid!=unset -k modules${BLD}
           NOTE: DoD has defined the list of events for which RHEL 8 will provide an audit record generation capability as the following:

           1) Successful and unsuccessful attempts to access, modify, or delete privileges, security objects, security levels, or categories of information (e.g., classification levels);

           2) Access actions, such as successful and unsuccessful logon attempts, privileged activities or other system-level access, starting and ending time for user access to the system, concurrent logons from different workstations, successful and unsuccessful accesses to objects, all program initiations, and all direct access to the information system;

           3) All account creations, modifications, disabling, and terminations; and 

           4) All kernel module load, unload, and restart actions.
           NOTE: ${YLO}If the command does not return a line, or the line is commented out, this is a finding."${BLD}
cci42="CCI-000169"
stigid42="RHEL-08-030580"
severity42="CAT II"
ruleid42="SV-230465r627750_rule"
vulnid42="V-230465"

title43a="Successful/unsuccessful modifications to the faillock log file in RHEL 8 must generate an audit record."
title43b="Checking with
           a. (For RHEL 8.1 and older) 'grep -i pam_faillock.so /etc/pam.d/system-auth'
	   b. (For RHEL 8.2 and newer) 'grep dir /etc/security/faillock.conf'."
title43c="Expecting: ${YLO}
           a. auth required pam_faillock.so preauth dir=/var/log/faillock silent deny=3 fail_interval=900 even_deny_root
	   b. dir=/var/log/faillock${BLD}
           NOTE: DoD has defined the list of events for which RHEL 8 will provide an audit record generation capability as the following:

           1) Successful and unsuccessful attempts to access, modify, or delete privileges, security objects, security levels, or categories of information (e.g., classification levels);

           2) Access actions, such as successful and unsuccessful logon attempts, privileged activities or other system-level access, starting and ending time for user access to the system, concurrent logons from different workstations, successful and unsuccessful accesses to objects, all program initiations, and all direct access to the information system;

           3) All account creations, modifications, disabling, and terminations; and

           4) All kernel module load, unload, and restart actions.

           From \"Pam_Faillock man\" pages: Note the default directory that pam_faillock uses is usually cleared on system boot so the access will be reenabled after system reboot. If that is undesirable a different tally directory must be set with the \"dir\" option.
           NOTE: ${YLO}If the command does not return any output, this is a finding."${BLD}
cci43="CCI-000169"
stigid43="RHEL-08-030590"
severity43="CAT II"
ruleid43="SV-230466r627750_rule"
vulnid43="V-230466"

title44a="Successful/unsuccessful modifications to the lastlog file in RHEL 8 must generate an audit record."
title44b="Checking with 'grep -w lastlog /etc/audit/audit.rules'."
title44c="Expecting: ${YLO}-w /var/log/lastlog -p wa -k logins${BLD}
           NOTE: DoD has defined the list of events for which RHEL 8 will provide an audit record generation capability as the following:

           1) Successful and unsuccessful attempts to access, modify, or delete privileges, security objects, security levels, or categories of information (e.g., classification levels);

           2) Access actions, such as successful and unsuccessful logon attempts, privileged activities or other system-level access, starting and ending time for user access to the system, concurrent logons from different workstations, successful and unsuccessful accesses to objects, all program initiations, and all direct access to the information system;

           3) All account creations, modifications, disabling, and terminations; and

           4) All kernel module load, unload, and restart actions.
           NOTE: ${YLO}If the command does not return any output, this is a finding."${BLD}
cci44="CCI-000169"
stigid44="RHEL-08-030600"
severity44="CAT II"
ruleid44="SV-230467r627750_rule"
vulnid44="V-230467"

title45a="RHEL 8 must enable auditing of processes that start prior to the audit daemon."
title45b="Checking with 'grub2-editenv list | grep audit'."
title45c="Expecting: ${YLO}kernelopts=root=/dev/mapper/rhel-root ro crashkernel=auto resume=/dev/mapper/rhel-swap rd.lvm.lv=rhel/root rd.lvm.lv=rhel/swap rhgb quiet fips=1 ${GRN}audit=1${YLO} audit_backlog_limit=8192 boot=UUID=8d171156-cd61-421c-ba41-1c021ac29e82${BLD}
           NOTE: DoD has defined the list of events for which RHEL 8 will provide an audit record generation capability as the following:

           1) Successful and unsuccessful attempts to access, modify, or delete privileges, security objects, security levels, or categories of information (e.g., classification levels);

           2) Access actions, such as successful and unsuccessful logon attempts, privileged activities or other system-level access, starting and ending time for user access to the system, concurrent logons from different workstations, successful and unsuccessful accesses to objects, all program initiations, and all direct access to the information system;

           3) All account creations, modifications, disabling, and terminations; and

           4) All kernel module load, unload, and restart actions.${BLD}
           NOTE: ${YLO}If the \"audit\" entry does not equal \"1\", is missing, or the line is commented out, this is a finding."${BLD}
cci45="CCI-000169"
stigid45="RHEL-08-030601"
severity45="CAT III"
ruleid45="SV-230468r792904_rule"
vulnid45="V-230468"

title46a="RHEL 8 must enable Linux audit logging for the USBGuard daemon."
title46b="Checking with 'grep -i auditbackend /etc/usbguard/usbguard-daemon.conf'."
title46c="Expecting: ${YLO}AuditBackend=LinuxAudit${BLD}
           NOTE: DoD has defined the list of events for which RHEL 8 will provide an audit record generation capability as the following:

           1) Successful and unsuccessful attempts to access, modify, or delete privileges, security objects, security levels, or categories of information (e.g., classification levels);

           2) Access actions, such as successful and unsuccessful logon attempts, privileged activities or other system-level access, starting and ending time for user access to the system, concurrent logons from different workstations, successful and unsuccessful accesses to objects, all program initiations, and all direct access to the information system;

           3) All account creations, modifications, disabling, and terminations; and 

           4) All kernel module load, unload, and restart actions.${BLD}
           NOTE: ${YLO}If the \"AuditBackend\" entry does not equal \"LinuxAudit\", is missing, or the line is commented out, this is a finding."${BLD}
cci46="CCI-000169"
stigid46="RHEL-08-030603"
severity46="CAT III"
ruleid46="SV-230470r744006_rule"
vulnid46="V-230470"

title47a=" RHEL 8 must allow only the Information System Security Manager (ISSM) (or individuals or roles appointed by the ISSM) to select which auditable events are to be audited."
title47b="Checking with 'ls -al /etc/audit/rules.d/*.rules'"
title47c="Expecting: ${YLO}-rw-r----- 1 root root 621 Sep 22 17:19 auditd.conf${BLD}
           NOTE: ${YLO}If the files in the \"/etc/audit/rules.d/\" directory or the \"/etc/audit/auditd.conf\" file have a mode more permissive than \"0640\", this is a finding."${BLD}
cci47="CCI-000171"
stigid47="RHEL-08-030610"
severity47="CAT II"
ruleid47="SV-230471r627750_rule"
vulnid47="V-230471"

title48a="RHEL 8 audit records must contain information to establish what type of events occurred, the source of events, where events occurred, and the outcome of events."
title48b="Checking with 'systemctl status auditd.service'."
title48c="Expecting: 
           ${YLO}auditd.service - Security Auditing Service
           Loaded:loaded (/usr/lib/systemd/system/auditd.service; enabled; vendor preset: enabled)
           Active: active (running) since Tues 2020-12-11 12:56:56 EST; 4 weeks 0 days ago${BLD}
	   ${YLO}If the audit service is not \"active\" and \"running\", this is a finding."${BLD}
cci48="CCI-000366"
stigid48="RHEL-08-030181"
severity48="CAT II"
ruleid48="SV-244542r743875_rule"
vulnid48="V-244542"

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
fail=1

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file1 ]]
then
  aurules="$(grep -i /etc/shadow $file1 2>/dev/null | grep -v '^#')"
  if [[ $aurules ]]
  then
    for rule in ${aurules[@]}
    do
      if [[ $rule =~ '-w' && $rule =~ '-p wa -k' && 
	  ( $rule =~ 'identity' || $rule =~ 'audit_rules_usergroup_modification' )
         ]]
      then
        fail=0
        echo -e "${NORMAL}RESULT:    ${BLD}$rule${NORMAL}"
      else
        echo -e "${NORMAL}RESULT:    ${RED}$rule${NORMAL}"
      fi
    done
  else
    echo -e "${NORMAL}RESULT:    ${RED}a rule for \"/etc/shadow\" was not found.${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}$file1 not found${NORMAL}"
fi
if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${GRN}PASSED, RHEL 8 generates audit records for all account creations modifications disabling and termination events that affect /etc/shadow.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${RED}FAILED, RHEL 8 does not generate audit records for all account creations modifications disabling and termination events that affect /etc/shadow.${NORMAL}"
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
fail=1

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file2 ]]
then
  aurules="$(grep -i /etc/security/opasswd $file2 2>/dev/null | grep -v '^#')"
  if [[ $aurules ]]
  then
    for rule in ${aurules[@]}
    do
      if [[ $rule =~ '-w' && $rule =~ '-p wa -k' &&
	  ( $rule =~ 'identity' || $rule =~ 'audit_rules_usergroup_modification' )
         ]]
      then
        fail=0
        echo -e "${NORMAL}RESULT:    ${BLD}$rule${NORMAL}"
      else
        echo -e "${NORMAL}RESULT:    ${RED}$rule${NORMAL}"
      fi
    done
  else
    echo -e "${NORMAL}RESULT:    ${RED}a rule for \"/etc/security/opasswd\" was not found.${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}$file2 not found${NORMAL}"
fi
if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${GRN}PASSED, RHEL 8 generates audit records for all account creations modifications disabling and termination events that affect /etc/security/opasswd.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${RED}FAILED, RHEL 8 does not generate audit records for all account creations modifications disabling and termination events that affect /etc/security/opasswd.${NORMAL}"
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
fail=1

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file3 ]]
then
  aurules="$(grep -i /etc/passwd $file3 2>/dev/null | grep -v '^#')"
  if [[ $aurules ]]
  then
    for rule in ${aurules[@]}
    do
      if [[ $rule =~ '-w' && $rule =~ '-p wa -k' &&
          ( $rule =~ 'identity' || $rule =~ 'audit_rules_usergroup_modification' )
         ]]
      then
        fail=0
        echo -e "${NORMAL}RESULT:    ${BLD}$rule${NORMAL}"
      else
        echo -e "${NORMAL}RESULT:    ${RED}$rule${NORMAL}"
      fi
    done
  else
    echo -e "${NORMAL}RESULT:    ${RED}a rule for \"/etc/passwd\" was not found.${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}$file3 not found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${GRN}PASSED, RHEL 8 generates audit records for all account creations modifications disabling and termination events that affect /etc/passwd.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${RED}FAILED, RHEL 8 does not generate audit records for all account creations modifications disabling and termination events that affect /etc/passwd.${NORMAL}"
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
fail=1

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file4 ]]
then
  aurules="$(grep -i /etc/gshadow $file4 2>/dev/null | grep -v '^#')"
  if [[ $aurules ]]
  then
    for rule in ${aurules[@]}
    do
      if [[ $rule =~ '-w' && $rule =~ '-p wa -k' && 
	  ( $rule =~ 'identity' || $rule =~ 'audit_rules_usergroup_modification' )
         ]]
      then
        fail=0
        echo -e "${NORMAL}RESULT:    ${BLD}$rule${NORMAL}"
      else
        echo -e "${NORMAL}RESULT:    ${RED}$rule${NORMAL}"
      fi
    done
  else
    echo -e "${NORMAL}RESULT:    ${RED}a rule for \"/etc/gshadow\" was not found.${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}$file4 not found${NORMAL}"
fi
if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${GRN}PASSED, RHEL 8 generates audit records for all account creations modifications disabling and termination events that affect /etc/gshadow.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${RED}FAILED, RHEL 8 does not generate audit records for all account creations modifications disabling and termination events that affect /etc/gshadow.${NORMAL}"
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

file5="/etc/audit/audit.rules"
fail=1

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file5 ]]
then
  aurules="$(grep -i /etc/group $file5 2>/dev/null | grep -v '^#')"
  if [[ $aurules ]]
  then
    for rule in ${aurules[@]}
    do
      if [[ $rule =~ '-w' && $rule =~ '-p wa -k' &&
          ( $rule =~ 'audit_rules_usergroup_modification' ) ]]
      then
        fail=0
        echo -e "${NORMAL}RESULT:    ${BLD}$rule${NORMAL}"
      else
        echo -e "${NORMAL}RESULT:    ${RED}$rule${NORMAL}"
      fi
    done
  else
    echo -e "${NORMAL}RESULT:    ${RED}a rule for \"/etc/group\" was not found.${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}$file5 not found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity5, $controlid, $stigid5, $ruleid5, $cci5, $datetime, ${GRN}PASSED, RHEL 8 generates audit records for all account creations modifications disabling and termination events that affect /etc/group.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity5, $controlid, $stigid5, $ruleid5, $cci5, $datetime, ${RED}FAILED, RHEL 8 does not generate audit records for all account creations modifications disabling and termination events that affect /etc/group.${NORMAL}"
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

file6="/etc/audit/audit.rules"
fail=1

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file6 ]]
then
  aurules="$(grep -i /etc/sudoers $file6 2>/dev/null | grep -v '^#')"
  if [[ $aurules ]]
  then
    for rule in ${aurules[@]}
    do
      if [[ $rule =~ '-w' && $rule =~ '-p wa -k' &&
          ( $rule =~ 'identity' || $rule =~ 'audit_rules_usergroup_modification' )
         ]]
      then
        fail=0
        echo -e "${NORMAL}RESULT:    ${BLD}$rule${NORMAL}"
      else
        echo -e "${NORMAL}RESULT:    ${RED}$rule${NORMAL}"
      fi
    done
  else
    echo -e "${NORMAL}RESULT:    ${RED}a rule for \"/etc/sudoers\" was not found.${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}$file6 not found${NORMAL}"
fi
if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity6, $controlid, $stigid6, $ruleid6, $cci6, $datetime, ${GRN}PASSED, RHEL 8 generates audit records for all account creations modifications disabling and termination events that affect /etc/sudoers.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity6, $controlid, $stigid6, $ruleid6, $cci6, $datetime, ${RED}FAILED, RHEL 8 does not generate audit records for all account creations modifications disabling and termination events that affect /etc/sudoers.${NORMAL}"
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

file7="/etc/audit/audit.rules"
fail=1

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file7 ]]
then
  aurules="$(grep -i /etc/sudoers.d/ $file7 2>/dev/null | grep -v '^#')"
  if [[ $aurules ]]
  then
    for rule in ${aurules[@]}
    do
      if [[ $rule =~ '-w' && $rule =~ '-p wa -k' &&
          ( $rule =~ 'identity' || $rule =~ 'audit_rules_usergroup_modification' )
         ]]
      then
        fail=0
        echo -e "${NORMAL}RESULT:    ${BLD}$rule${NORMAL}"
      else
        echo -e "${NORMAL}RESULT:    ${RED}$rule${NORMAL}"
      fi
    done
  else
    echo -e "${NORMAL}RESULT:    ${RED}a rule for \"/etc/sudoers.d/\" was not found.${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}$file7 not found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity7, $controlid, $stigid7, $ruleid7, $cci7, $datetime, ${GRN}PASSED, RHEL 8 generates audit records for all account creations modifications disabling and termination events that affect /etc/sudoers.d/.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity7, $controlid, $stigid7, $ruleid7, $cci7, $datetime, ${RED}FAILED, RHEL 8 does not generate audit records for all account creations modifications disabling and termination events that affect /etc/sudoers.d/.${NORMAL}"
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

aurpm="$(yum list installed audit 2>/dev/null | grep audit)"

datetime="$(date +%FT%H:%M:%S)"

if [[ $aurpm ]]
then
  fail=0
  for file in ${aurpm[@]}
  do
    echo -e "${NORMAL}RESULT:    ${BLD}$file${NORMAL}"
  done
else
  echo -e "${NORMAL}RESULT:    ${RED}The \"audit\" package is not installed${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity8, $controlid, $stigid8, $ruleid8, $cci8, $datetime, ${GRN}PASSED, The RHEL 8 audit package is installed.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity8, $controlid, $stigid8, $ruleid8, $cci8, $datetime, ${RED}FAILED, The RHEL 8 audit package is not installed.${NORMAL}"
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
   aurules="$(grep -i '/usr/bin/su\ '  $file9 | grep -v '^#')"
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
            echo -e "${NORMAL}RESULT:    ${RED}missing '-F path=/usr/bin/'${NORMAL}"
            fail=1
         fi
         if [[ ! $rule =~ '-F perm=x' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-F perm=x'${NORMAL}"
            fail=1
         fi
         if ! [[ $rule =~ 'privileged-priv_change' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing 'privileged-priv_change'${NORMAL}"
         fi

         IFS=' ' read -a fieldvals <<< "${rule}"

         for field in ${fieldvals[@]}
         do
            if [[ $field =~ 'auid>=' ]]
            then
               auidval="$(echo $field | awk -F'>=' '{print $2}')"
               if [[ $auidval > 1000 ]]
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid>=' cannot be greater than 1000${NORMAL}"
                  fail=1
               fi
            elif [[ $field =~ 'auid=' ]]
            then
               auidval="$(echo $field | awk -F= '{print $2}')"
               if (( $auidval != 0 ))
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid=' cannot be a value other than '0'${NORMAL}"
                  fail=1
               fi
            elif [[ $field =~ 'auid!=' ]]
            then
               auidval="$(echo $field | awk -F'!=' '{print $2}')"
               if (( $auidval != 'unset' ))
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid!=' must be unset${NORMAL}"
                  fail=1
               fi
            fi
         done
      done
   else
      echo -e "${NORMAL}RESULT:    ${RED}$file9 is missing a rule for '/usr/bin/su'${NORMAL}"
      fail=2
   fi
   if (( $fail == 0 ))
   then
      echo -e "${NORMAL}$hostname, $severity9, $controlid, $stigid9, $ruleid9, $cci9, $datetime, ${GRN}PASSED, Use of the su command is audited${NORMAL}"
   elif (( $fail == 2 ))
   then
      echo -e "${NORMAL}$hostname, $severity9, $controlid, $stigid9, $ruleid9, $cci9, $datetime, ${RED}FAILED, Use of the su command is not audited${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity9, $controlid, $stigid9, $ruleid9, $cci9, $datetime, ${RED}FAILED, Use of the su command is not configured correctly${NORMAL}"
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

setxattr=0
fsetxattr=0
lsetxattr=0
removexattr=0
fremovexattr=0
lremovexattr=0

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file10 ]]
then
   aurules="$(grep xattr $file10 | grep -v '^#')"
   if [[ $aurules ]]
   then
      for rule in ${aurules[@]}
      do
         echo -e "${NORMAL}RESULT:    ${BLD}$rule${NORMAL}"
         if [[ ! $rule =~ '-a always,exit' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-a always,exit'${NORMAL}"
         fi
         if [[ ! $rule =~ 'perm_mod' ]]
	 then
            echo -e "${NORMAL}RESULT:    ${RED}missing 'perm_mod'${NORMAL}"
         fi

         IFS=' ' read -a fieldvals <<< "${rule}"

         for field in ${fieldvals[@]}
         do
	    if [[ $field =~ 'b32' ]]
	    then
	      b32=1
	    elif [[ $field =~ 'b64' ]]
            then
	      b64=1
            elif [[ $field =~ 'auid>=' ]]
            then
               auidval="$(echo $field | awk -F'>=' '{print $2}')"
               if [[ $auidval > 1000 ]]
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid>=' cannot be greater than 1000${NORMAL}"
		  fail=1
               fi
            elif [[ $field =~ 'auid=' ]]
            then
               auidval="$(echo $field | awk -F= '{print $2}')"
               if (( $auidval != 0 ))
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid=' cannot be a value other than '0'${NORMAL}"
		  fail=1
               fi
            elif [[ $field =~ 'auid!=' ]]
            then
               auidval="$(echo $field | awk -F'!=' '{print $2}')"
               if (( $auidval != 'unset' ))
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid!=' must be unset${NORMAL}"
		  fail=1
               fi
	    fi
	    if [[ $field =~ 'setxattr' ]]
	    then
	      setxattr=1
	    fi
            if [[ $field =~ 'fsetxattr' ]]
            then
              fsetxattr=1
            fi
            if [[ $field =~ 'lsetxattr' ]]
            then
              lsetxattr=1
            fi
            if [[ $field =~ 'removexattr' ]]
            then
              removexattr=1
            fi
            if [[ $field =~ 'fremovexattr' ]]
            then
              fremovexattr=1
            fi
            if [[ $field =~ 'lremovexattr' ]]
            then
              lremovexattr=1
            fi    
         done
         if [[ $setxattr == 0 || $fsetxattr == 0 || $lsetxattr == 0 || $removexattr == 0 || $fremeovexattr == 0 || $lremovexattr == 0 ]]
         then
	   fail=2
         fi	 
      done
   fi

   if (( $fail == 0 ))
   then
      echo -e "${NORMAL}$hostname, $severity10, $controlid, $stigid10, $ruleid10, $cci10, $datetime, ${GRN}PASSED, Use of the xattr commands are audited${NORMAL}"
   elif (( $fail == 2 ))
   then
      echo -e "${NORMAL}$hostname, $severity10, $controlid, $stigid10, $ruleid10, $cci10, $datetime, ${RED}FAILED, Use of some or all of the xattr commands are not audited${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity10, $controlid, $stigid10, $ruleid10, $cci10, $datetime, ${RED}FAILED, Use of some or all of the xattr commands are not configured correctly${NORMAL}"
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
found=0
fail=0

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file11 ]]
then
   aurules="$(grep -w /usr/bin/chage $file11 | grep -v '^#')"
   if [[ $aurules ]]
   then
      for rule in ${aurules[@]}
      do
         if [[ $rule =~ '-a always,exit' ]] &&
            [[ $rule =~ '-F perm=x' && $rule =~ 'privileged-chage' ]]
         then
            found=1
         fi
         echo -e "${NORMAL}RESULT:    ${BLD}$rule${NORMAL}"
         if [[ ! $rule =~ '-a always,exit' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-a always,exit'${NORMAL}"
            fail=1
         fi
         if [[ ! $rule =~ '-F path=/usr/bin/' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-F path=/usr/bin/'${NORMAL}"
            fail=1
         fi
         if [[ ! $rule =~ '-F perm=x' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-F perm=x'${NORMAL}"
            fail=1
         fi
         if [[ ! $rule =~ 'privileged-chage' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing 'privileged-passwd'${NORMAL}"
         fi

         IFS=' ' read -a fieldvals <<< "${rule}"

         for field in ${fieldvals[@]}
         do
            if [[ $field =~ 'auid>=' ]]
            then
               auidval="$(echo $field | awk -F'>=' '{print $2}')"
               if [[ $auidval > 1000 ]]
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid>=' cannot be greater than 1000${NORMAL}"
                  fail=1
               fi
            elif [[ $field =~ 'auid=' ]]
            then
               auidval="$(echo $field | awk -F= '{print $2}')"
               if (( $auidval != 0 ))
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid=' cannot be a value other than '0'${NORMAL}"
                  fail=1
               fi
            elif [[ $field =~ 'auid!=' ]]
            then
               auidval="$(echo $field | awk -F'!=' '{print $2}')"
               if (( $auidval != 'unset' ))
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid!=' must be unset${NORMAL}"
                  fail=1
               fi
            fi
         done
      done
   else
      echo -e "${NORMAL}RESULT:    ${RED}$file11 is missing a rule for 'chage'${NORMAL}"
      fail=2
   fi
   if (( $fail == 0 || $found == 1 ))
   then
      echo -e "${NORMAL}$hostname, $severity11, $controlid, $stigid11, $ruleid11, $cci11, $datetime, ${GRN}PASSED, Use of the chage command is audited${NORMAL}"
   elif (( $fail == 2 ))
   then
      echo -e "${NORMAL}$hostname, $severity11, $controlid, $stigid11, $ruleid11, $cci11, $datetime, ${RED}FAILED, Use of the chage command is not audited${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity11, $controlid, $stigid11, $ruleid11, $cci11, $datetime, ${RED}FAILED, Use of the chage command is not configured correctly${NORMAL}"
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
found=0

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file12 ]]
then
   aurules="$(grep -w chcon $file12 | grep -v '^#')"
   if [[ $aurules ]]
   then
      for rule in ${aurules[@]}
      do
         if [[ $rule =~ '-a always,exit' && $rule =~ '/sbin' ]] &&
            [[ $rule =~ '-F perm=x' && $rule =~ 'perm_mod' ]]
         then
            found=1
         fi
         echo -e "${NORMAL}RESULT:    ${BLD}$rule${NORMAL}"
         if [[ ! $rule =~ '-a always,exit' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-a always,exit'${NORMAL}"
            fail=1
         fi
         if [[ ! $rule =~ '-F path=/usr/bin/' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-F path=/usr/sbin/'${NORMAL}"
            fail=1
         fi
         if [[ ! $rule =~ '-F perm=x' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-F perm=x'${NORMAL}"
            fail=1
         fi
         if ! [[ $rule =~ 'perm_mod' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing 'perm_mod'${NORMAL}"
         fi

         IFS=' ' read -a fieldvals <<< "${rule}"

         for field in ${fieldvals[@]}
         do
            if [[ $field =~ 'auid>=' ]]
            then
               auidval="$(echo $field | awk -F'>=' '{print $2}')"
               if [[ $auidval > 1000 ]]
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid>=' cannot be greater than 1000${NORMAL}"
                  fail=1
               fi
            elif [[ $field =~ 'auid=' ]]
            then
               auidval="$(echo $field | awk -F= '{print $2}')"
               if (( $auidval != 0 ))
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid=' cannot be a value other than '0'${NORMAL}"
                  fail=1
               fi
            elif [[ $field =~ 'auid!=' ]]
            then
               auidval="$(echo $field | awk -F'!=' '{print $2}')"
               if (( $auidval != 'unset' ))
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid!=' must be unset${NORMAL}"
                  fail=1
               fi
            fi
         done
      done
   else
      echo -e "${NORMAL}RESULT:    ${RED}$file12 is missing a rule for 'chcon'${NORMAL}"
      fail=2
   fi
   if (( $fail == 0 || $found == 1 ))
   then
      echo -e "${NORMAL}$hostname, $severity12, $controlid, $stigid12, $ruleid12, $cci12, $datetime, ${GRN}PASSED, Use of the chcon command is audited${NORMAL}"
   elif (( $fail == 2 ))
   then
      echo -e "${NORMAL}$hostname, $severity12, $controlid, $stigid12, $ruleid12, $cci12, $datetime, ${RED}FAILED, Use of the chcon command is not audited${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity12, $controlid, $stigid12, $ruleid12, $cci12, $datetime, ${RED}FAILED, Use of the chcon command is not configured correctly${NORMAL}"
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
   aurules="$(grep ssh-agent  $file13 | grep -v '^#')"
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
            echo -e "${NORMAL}RESULT:    ${RED}missing '-F path=/usr/bin/'${NORMAL}"
            fail=1
         fi
         if [[ ! $rule =~ '-F perm=x' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-F perm=x'${NORMAL}"
            fail=1
         fi
         if ! [[ $rule =~ '-k privileged-ssh' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing 'privileged-ssh'${NORMAL}"
         fi

         IFS=' ' read -a fieldvals <<< "${rule}"

         for field in ${fieldvals[@]}
         do
            if [[ $field =~ 'auid>=' ]]
            then
               auidval="$(echo $field | awk -F'>=' '{print $2}')"
               if [[ $auidval != 1000 && $auidval != 0 ]]
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid>=' cannot be greater than 1000${NORMAL}"
                  fail=1
               fi
            elif [[ $field =~ 'auid=' ]]
            then
               auidval="$(echo $field | awk -F= '{print $2}')"
               if (( $auidval != 0 ))
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid=' cannot be a value other than '0'${NORMAL}"
                  fail=1
               fi
            elif [[ $field =~ 'auid!=' ]]
            then
               auidval="$(echo $field | awk -F'!=' '{print $2}')"
               if (( $auidval != 'unset' ))
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid!=' must be unset${NORMAL}"
                  fail=1
               fi
            fi
         done
      done
   else
      echo -e "${NORMAL}RESULT:    ${RED}$file13 is missing a rule for 'ssh-agent'${NORMAL}"
      fail=2
   fi
   if (( $fail == 0 ))
   then
      echo -e "${NORMAL}$hostname, $severity13, $controlid, $stigid13, $ruleid13, $cci13, $datetime, ${GRN}PASSED, Use of the ssh-agent command is audited${NORMAL}"
   elif (( $fail == 2 ))
   then
      echo -e "${NORMAL}$hostname, $severity13, $controlid, $stigid13, $ruleid13, $cci13, $datetime, ${RED}FAILED, Use of the ssh-agent command is not audited${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity13, $controlid, $stigid13, $ruleid13, $cci13, $datetime, ${RED}FAILED, Use of the ssh-agent command is not configured correctly${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${BLD}$file13 not found${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity13, $controlid, $stigid13, $ruleid13, $cci13, $datetime, ${RED}FAILED, $file55 not found${NORMAL}"
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
found=0
fail=0

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file14 ]]
then
   aurules="$(grep -w passwd $file14 | grep -v '^#')"
   if [[ $aurules ]]
   then
      for rule in ${aurules[@]}
      do
         echo -e "${NORMAL}RESULT:    ${BLD}$rule${NORMAL}"
         if [[ $rule =~ '-a always,exit' && $rule =~ '/bin' ]] &&
            [[ $rule =~ '-F perm=x' && $rule =~ 'privileged' ]]
         then
            found=1
         fi
         if [[ ! $rule =~ '-a always,exit' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-a always,exit'${NORMAL}"
            fail=1
         fi
         if [[ ! $rule =~ '-F path=/usr/bin/' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-F path=/usr/bin/'${NORMAL}"
            fail=1
         fi
         if [[ ! $rule =~ '-F perm=x' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-F perm=x'${NORMAL}"
            fail=1
         fi
         if [[ ! $rule =~ 'privileged-passwd' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing 'privileged-passwd'${NORMAL}"
         fi

         IFS=' ' read -a fieldvals <<< "${rule}"

         for field in ${fieldvals[@]}
         do
            if [[ $field =~ 'auid>=' ]]
            then
               auidval="$(echo $field | awk -F'>=' '{print $2}')"
               if [[ $auidval != 1000 && $auidval != 0 ]]
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid>=' cannot be greater than 1000${NORMAL}"
                  fail=1
               fi
            elif [[ $field =~ 'auid=' ]]
            then
               auidval="$(echo $field | awk -F= '{print $2}')"
               if (( $auidval != 0 ))
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid=' cannot be a value other than '0'${NORMAL}"
                  fail=1
               fi
            elif [[ $field =~ 'auid!=' ]]
            then
               auidval="$(echo $field | awk -F'!=' '{print $2}')"
               if (( $auidval != 'unset' ))
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid!=' must be unset${NORMAL}"
                  fail=1
               fi
            fi
         done
      done
   else
      echo -e "${NORMAL}RESULT:    ${RED}$file14 is missing a rule for 'passwd'${NORMAL}"
      fail=2
   fi
   if (( $fail == 0 || $found == 1 ))
   then
      echo -e "${NORMAL}$hostname, $severity14, $controlid, $stigid14, $ruleid14, $cci14, $datetime, ${GRN}PASSED, Use of the passwd command is audited${NORMAL}"
   elif (( $fail == 2 ))
   then
      echo -e "${NORMAL}$hostname, $severity14, $controlid, $stigid14, $ruleid14, $cci14, $datetime, ${RED}FAILED, Use of the passwd command is not audited${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity14, $controlid, $stigid14, $ruleid14, $cci14, $datetime, ${RED}FAILED, Use of the passwd command is not configured correctly${NORMAL}"
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
   aurules="$(grep -w /usr/bin/mount $file15 | grep -v '^#')"
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
            echo -e "${NORMAL}RESULT:    ${RED}missing '-F path=/usr/bin/'${NORMAL}"
            fail=1
         fi
         if [[ ! $rule =~ '-F perm=x' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-F perm=x'${NORMAL}"
            fail=1
         fi
         if ! [[ $rule =~ '-k privileged-mount' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing 'privileged-mount'${NORMAL}"
         fi

         IFS=' ' read -a fieldvals <<< "${rule}"

         for field in ${fieldvals[@]}
         do
            if [[ $field =~ 'auid>=' ]]
            then
               auidval="$(echo $field | awk -F'>=' '{print $2}')"
               if [[ $auidval != 1000 && $auidval != 0 ]]
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid>=' cannot be greater than 1000${NORMAL}"
                  fail=1
               fi
            elif [[ $field =~ 'auid=' ]]
            then
               auidval="$(echo $field | awk -F= '{print $2}')"
               if (( $auidval != 0 ))
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid=' cannot be a value other than '0'${NORMAL}"
                  fail=1
               fi
            elif [[ $field =~ 'auid!=' ]]
            then
               auidval="$(echo $field | awk -F'!=' '{print $2}')"
               if (( $auidval != 'unset' ))
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid!=' must be unset${NORMAL}"
                  fail=1
               fi
            fi
         done
      done
   else
      echo -e "${NORMAL}RESULT:    ${RED}$file15 is missing a rule for '/usr/bin/mount'${NORMAL}"
      fail=2
   fi
   if (( $fail == 0 ))
   then
      echo -e "${NORMAL}$hostname, $severity15, $controlid, $stigid15, $ruleid15, $cci15, $datetime, ${GRN}PASSED, Use of the mount command is audited${NORMAL}"
   elif (( $fail == 2 ))
   then
      echo -e "${NORMAL}$hostname, $severity15, $controlid, $stigid15, $ruleid15, $cci15, $datetime, ${RED}FAILED, Use of the mount command is not audited${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity15, $controlid, $stigid15, $ruleid15, $cci15, $datetime, ${RED}FAILED, Use of the mount command is not configured correctly${NORMAL}"
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
   aurules="$(grep -w /usr/bin/umount $file16 | grep -v '^#')"
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
            echo -e "${NORMAL}RESULT:    ${RED}missing '-F path=/usr/bin/'${NORMAL}"
            fail=1
         fi
         if [[ ! $rule =~ '-F perm=x' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-F perm=x'${NORMAL}"
            fail=1
         fi
         if ! [[ $rule =~ '-k privileged-mount' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing 'privileged-mount'${NORMAL}"
         fi

         IFS=' ' read -a fieldvals <<< "${rule}"

         for field in ${fieldvals[@]}
         do
            if [[ $field =~ 'auid>=' ]]
            then
               auidval="$(echo $field | awk -F'>=' '{print $2}')"
               if [[ $auidval != 1000 && $auidval != 0 ]]
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid>=' cannot be greater than 1000${NORMAL}"
                  fail=1
               fi
            elif [[ $field =~ 'auid=' ]]
            then
               auidval="$(echo $field | awk -F= '{print $2}')"
               if (( $auidval != 0 ))
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid=' cannot be a value other than '0'${NORMAL}"
                  fail=1
               fi
            elif [[ $field =~ 'auid!=' ]]
            then
               auidval="$(echo $field | awk -F'!=' '{print $2}')"
               if (( $auidval != 'unset' ))
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid!=' must be unset${NORMAL}"
                  fail=1
               fi
            fi
         done
      done
   else
      echo -e "${NORMAL}RESULT:    ${RED}$file16 is missing a rule for '/usr/bin/umount'${NORMAL}"
      fail=2
   fi
   if (( $fail == 0 ))
   then
      echo -e "${NORMAL}$hostname, $severity16, $controlid, $stigid16, $ruleid16, $cci16, $datetime, ${GRN}PASSED, Use of the umount command is audited${NORMAL}"
   elif (( $fail == 2 ))
   then
      echo -e "${NORMAL}$hostname, $severity16, $controlid, $stigid16, $ruleid16, $cci16, $datetime, ${RED}FAILED, Use of the umount command is not audited${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity16, $controlid, $stigid16, $ruleid16, $cci16, $datetime, ${RED}FAILED, Use of the umount command is not configured correctly${NORMAL}"
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
   aurules="$(grep -w '\-S mount' $file17 | grep -v '^#')"
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
         if ! [[ $rule =~ '-k privileged-mount' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing 'privileged-mount'${NORMAL}"
            fail=1
         fi

         IFS=' ' read -a fieldvals <<< "${rule}"

         for field in ${fieldvals[@]}
         do
            if [[ $field =~ 'auid>=' ]]
            then
               auidval="$(echo $field | awk -F'>=' '{print $2}')"
               if [[ $auidval != 1000 && $auidval != 0 ]]
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid>=' cannot be greater than 1000${NORMAL}"
                  fail=1
               fi
            elif [[ $field =~ 'auid=' ]]
            then
               auidval="$(echo $field | awk -F= '{print $2}')"
               if (( $auidval != 0 ))
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid=' cannot be a value other than '0'${NORMAL}"
                  fail=1
               fi
            elif [[ $field =~ 'auid!=' ]]
            then
               auidval="$(echo $field | awk -F'!=' '{print $2}')"
               if (( $auidval != 'unset' ))
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid!=' must be unset${NORMAL}"
                  fail=1
               fi
            fi
         done
      done
   else
      echo -e "${NORMAL}RESULT:    ${RED}$file17 is missing a rule for 'mount'${NORMAL}"
      fail=2
   fi
   if (( $fail == 0 ))
   then
      echo -e "${NORMAL}$hostname, $severity17, $controlid, $stigid17, $ruleid17, $cci17, $datetime, ${GRN}PASSED, Use of the mount command is audited${NORMAL}"
   elif (( $fail == 2 ))
   then
      echo -e "${NORMAL}$hostname, $severity17, $controlid, $stigid17, $ruleid17, $cci17, $datetime, ${RED}FAILED, Use of the mount command is not audited${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity17, $controlid, $stigid17, $ruleid17, $cci17, $datetime, ${RED}FAILED, Use of the mount command is not configured correctly${NORMAL}"
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
   aurules="$(grep -w '/usr/sbin/unix_update' $file18 | grep -v '^#')"
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
         if [[ ! $rule =~ '-F path=/usr/sbin/' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-F path=/usr/sbin/'${NORMAL}"
            fail=1
         fi
         if [[ ! $rule =~ '-F perm=x' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-F perm=x'${NORMAL}"
            fail=1
         fi
         if ! [[ $rule =~ '-k privileged-unix-update' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing 'privileged-unix-update'${NORMAL}"
         fi

         IFS=' ' read -a fieldvals <<< "${rule}"

         for field in ${fieldvals[@]}
         do
            if [[ $field =~ 'auid>=' ]]
            then
               auidval="$(echo $field | awk -F'>=' '{print $2}')"
               if [[ $auidval != 1000 && $auidval != 0 ]]
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid>=' cannot be greater than 1000${NORMAL}"
                  fail=1
               fi
            elif [[ $field =~ 'auid=' ]]
            then
               auidval="$(echo $field | awk -F= '{print $2}')"
               if (( $auidval != 0 ))
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid=' cannot be a value other than '0'${NORMAL}"
                  fail=1
               fi
            elif [[ $field =~ 'auid!=' ]]
            then
               auidval="$(echo $field | awk -F'!=' '{print $2}')"
               if (( $auidval != 'unset' ))
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid!=' must be unset${NORMAL}"
                  fail=1
               fi
            fi
         done
      done
   else
      echo -e "${NORMAL}RESULT:    ${RED}$file18 is missing a rule for 'unix_update'${NORMAL}"
      fail=2
   fi
   if (( $fail == 0 ))
   then
      echo -e "${NORMAL}$hostname, $severity18, $controlid, $stigid18, $ruleid18, $cci18, $datetime, ${GRN}PASSED, Use of the unix_update syscall is audited${NORMAL}"
   elif (( $fail == 2 ))
   then
      echo -e "${NORMAL}$hostname, $severity18, $controlid, $stigid18, $ruleid18, $cci18, $datetime, ${RED}FAILED, Use of the unix_update syscall is not audited${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity18, $controlid, $stigid18, $ruleid18, $cci18, $datetime, ${RED}FAILED, Use of the unix_update syscall is not configured correctly${NORMAL}"
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
   aurules="$(grep -w 'postdrop' $file19 | grep -v '^#')"
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
         if [[ ! $rule =~ '-F path=/usr/sbin/' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-F path=/usr/sbin/'${NORMAL}"
            fail=1
         fi
         if [[ ! $rule =~ '-F perm=x' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-F perm=x'${NORMAL}"
            fail=1
         fi
         if ! [[ $rule =~ '-k privileged-unix-update' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing 'privileged-unix-update'${NORMAL}"
         fi

         IFS=' ' read -a fieldvals <<< "${rule}"

         for field in ${fieldvals[@]}
         do
            if [[ $field =~ 'auid>=' ]]
            then
               auidval="$(echo $field | awk -F'>=' '{print $2}')"
               if [[ $auidval != 1000 && $auidval != 0 ]]
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid>=' cannot be greater than 1000${NORMAL}"
                  fail=1
               fi
            elif [[ $field =~ 'auid=' ]]
            then
               auidval="$(echo $field | awk -F= '{print $2}')"
               if (( $auidval != 0 ))
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid=' cannot be a value other than '0'${NORMAL}"
                  fail=1
               fi
            elif [[ $field =~ 'auid!=' ]]
            then
               auidval="$(echo $field | awk -F'!=' '{print $2}')"
               if (( $auidval != 'unset' ))
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid!=' must be unset${NORMAL}"
                  fail=1
               fi
            fi
         done
      done
   else
      echo -e "${NORMAL}RESULT:    ${RED}$file19 is missing a rule for 'postdrop'${NORMAL}"
      fail=2
   fi
   if (( $fail == 0 ))
   then
      echo -e "${NORMAL}$hostname, $severity19, $controlid, $stigid19, $ruleid19, $cci19, $datetime, ${GRN}PASSED, Use of the postdrop syscall is audited${NORMAL}"
   elif (( $fail == 2 ))
   then
      echo -e "${NORMAL}$hostname, $severity19, $controlid, $stigid19, $ruleid19, $cci19, $datetime, ${RED}FAILED, Use of the postdrop syscall is not audited${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity19, $controlid, $stigid19, $ruleid19, $cci19, $datetime, ${RED}FAILED, Use of the postdrop syscall is not configured correctly${NORMAL}"
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
   aurules="$(grep -w 'postqueue' $file20 | grep -v '^#')"
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
         if [[ ! $rule =~ '-F path=/usr/sbin/' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-F path=/usr/sbin/'${NORMAL}"
            fail=1
         fi
         if [[ ! $rule =~ '-F perm=x' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-F perm=x'${NORMAL}"
            fail=1
         fi
         if ! [[ $rule =~ '-k privileged-unix-update' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing 'privileged-unix-update'${NORMAL}"
         fi

         IFS=' ' read -a fieldvals <<< "${rule}"

         for field in ${fieldvals[@]}
         do
            if [[ $field =~ 'auid>=' ]]
            then
               auidval="$(echo $field | awk -F'>=' '{print $2}')"
               if [[ $auidval != 1000 && $auidval != 0 ]]
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid>=' cannot be greater than 1000${NORMAL}"
                  fail=1
               fi
            elif [[ $field =~ 'auid=' ]]
            then
               auidval="$(echo $field | awk -F= '{print $2}')"
               if (( $auidval != 0 ))
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid=' cannot be a value other than '0'${NORMAL}"
                  fail=1
               fi
            elif [[ $field =~ 'auid!=' ]]
            then
               auidval="$(echo $field | awk -F'!=' '{print $2}')"
               if (( $auidval != 'unset' ))
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid!=' must be unset${NORMAL}"
                  fail=1
               fi
            fi
         done
      done
   else
      echo -e "${NORMAL}RESULT:    ${RED}$file20 is missing a rule for 'postqueue'${NORMAL}"
      fail=2
   fi
   if (( $fail == 0 ))
   then
      echo -e "${NORMAL}$hostname, $severity20, $controlid, $stigid20, $ruleid20, $cci20, $datetime, ${GRN}PASSED, Use of the postqueue syscall is audited${NORMAL}"
   elif (( $fail == 2 ))
   then
      echo -e "${NORMAL}$hostname, $severity20, $controlid, $stigid20, $ruleid20, $cci20, $datetime, ${RED}FAILED, Use of the postqueue syscall is not audited${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity20, $controlid, $stigid20, $ruleid20, $cci20, $datetime, ${RED}FAILED, Use of the postqueue syscall is not configured correctly${NORMAL}"
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
found=0

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file21 ]]
then
   aurules="$(grep -w semanage $file21 | grep -v '^#')"
   if [[ $aurules ]]
   then
      for rule in ${aurules[@]}
      do
         if [[ $rule =~ '-a always,exit' && $rule =~ '/sbin' ]] &&
            [[ $rule =~ '-F perm=x' && $rule =~ 'privileged' ]]
         then
            found=1
         fi
         echo -e "${NORMAL}RESULT:    ${BLD}$rule${NORMAL}"
         if [[ ! $rule =~ '-a always,exit' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-a always,exit'${NORMAL}"
            fail=1
         fi
         if [[ ! $rule =~ '-F path=/usr/sbin/' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-F path=/usr/sbin/'${NORMAL}"
            fail=1
         fi
         if [[ ! $rule =~ '-F perm=x' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-F perm=x'${NORMAL}"
            fail=1
         fi
         if ! [[ $rule =~ 'privileged-unix-update' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing 'privileged-unix-update'${NORMAL}"
         fi

         IFS=' ' read -a fieldvals <<< "${rule}"

         for field in ${fieldvals[@]}
         do
            if [[ $field =~ 'auid>=' ]]
            then
               auidval="$(echo $field | awk -F'>=' '{print $2}')"
               if [[ $auidval != 1000 && $auidval != 0 ]]
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid>=' cannot be greater than 1000${NORMAL}"
                  fail=1
               fi
            elif [[ $field =~ 'auid=' ]]
            then
               auidval="$(echo $field | awk -F= '{print $2}')"
               if (( $auidval != 0 ))
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid=' cannot be a value other than '0'${NORMAL}"
                  fail=1
               fi
            elif [[ $field =~ 'auid!=' ]]
            then
               auidval="$(echo $field | awk -F'!=' '{print $2}')"
               if (( $auidval != 'unset' ))
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid!=' must be unset${NORMAL}"
                  fail=1
               fi
            fi
         done
      done
   else
      echo -e "${NORMAL}RESULT:    ${RED}$file21 is missing a rule for 'semanage'${NORMAL}"
      fail=2
   fi
   if (( $fail == 0 || $found == 1 ))
   then
      echo -e "${NORMAL}$hostname, $severity21, $controlid, $stigid21, $ruleid21, $cci21, $datetime, ${GRN}PASSED, Use of the semanage command is audited${NORMAL}"
   elif (( $fail == 2 ))
   then
      echo -e "${NORMAL}$hostname, $severity21, $controlid, $stigid21, $ruleid21, $cci21, $datetime, ${RED}FAILED, Use of the semanage command is not audited${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity21, $controlid, $stigid21, $ruleid21, $cci21, $datetime, ${RED}FAILED, Use of the semanage command is not configured correctly${NORMAL}"
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
found=0

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file22 ]]
then
   aurules="$(grep -w setfiles $file22 | grep -v '^#')"
   if [[ $aurules ]]
   then
      for rule in ${aurules[@]}
      do
         if [[ $rule =~ '-a always,exit' && $rule =~ '/sbin' ]] &&
            [[ $rule =~ '-F perm=x' && $rule =~ 'privileged' ]]
         then
            found=1
         fi
         echo -e "${NORMAL}RESULT:    ${BLD}$rule${NORMAL}"
         if [[ ! $rule =~ '-a always,exit' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-a always,exit'${NORMAL}"
            fail=1
         fi
         if [[ ! $rule =~ '-F path=/usr/sbin/' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-F path=/usr/sbin/'${NORMAL}"
            fail=1
         fi
         if [[ ! $rule =~ '-F perm=x' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-F perm=x'${NORMAL}"
            fail=1
         fi
         if ! [[ $rule =~ 'privileged-unix-update' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing 'privileged-unix-update'${NORMAL}"
         fi

         IFS=' ' read -a fieldvals <<< "${rule}"

         for field in ${fieldvals[@]}
         do
            if [[ $field =~ 'auid>=' ]]
            then
               auidval="$(echo $field | awk -F'>=' '{print $2}')"
               if [[ $auidval != 1000 && $auidval != 0 ]]
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid>=' cannot be greater than 1000${NORMAL}"
                  fail=1
               fi
            elif [[ $field =~ 'auid=' ]]
            then
               auidval="$(echo $field | awk -F= '{print $2}')"
               if (( $auidval != 0 ))
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid=' cannot be a value other than '0'${NORMAL}"
                  fail=1
               fi
            elif [[ $field =~ 'auid!=' ]]
            then
               auidval="$(echo $field | awk -F'!=' '{print $2}')"
               if (( $auidval != 'unset' ))
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid!=' must be unset${NORMAL}"
                  fail=1
               fi
            fi
         done
      done
   else
      echo -e "${NORMAL}RESULT:    ${RED}$file22 is missing a rule for 'setfiles'${NORMAL}"
      fail=2
   fi
   if (( $fail == 0 || $found == 1 ))
   then
      echo -e "${NORMAL}$hostname, $severity22, $controlid, $stigid22, $ruleid22, $cci22, $datetime, ${GRN}PASSED, Use of the setfiles command is audited${NORMAL}"
   elif (( $fail == 2 ))
   then
      echo -e "${NORMAL}$hostname, $severity22, $controlid, $stigid22, $ruleid22, $cci22, $datetime, ${RED}FAILED, Use of the setfiles command is not audited${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity22, $controlid, $stigid22, $ruleid22, $cci22, $datetime, ${RED}FAILED, Use of the setfiles command is not configured correctly${NORMAL}"
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
found=0
fail=0

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file23 ]]
then
   aurules="$(grep -i /usr/sbin/userhelper $file23 | grep -v '^#')"
   if [[ $aurules ]]
   then
      for rule in ${aurules[@]}
      do
         if [[ $rule =~ '-a always,exit' && $rule =~ '/sbin' ]] &&
            [[ $rule =~ '-F perm=x' && $rule =~ 'privileged' ]]
         then
            found=1
         fi
         echo -e "${NORMAL}RESULT:    ${BLD}$rule${NORMAL}"
         if [[ ! $rule =~ '-a always,exit' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-a always,exit'${NORMAL}"
            fail=1
         fi
         if [[ ! $rule =~ '-F path=/usr/sbin/' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-F path=/usr/sbin/'${NORMAL}"
            fail=1
         fi
         if [[ ! $rule =~ '-F perm=x' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-F perm=x'${NORMAL}"
            fail=1
         fi
         if [[ ! $rule =~ 'privileged-usix-update' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing 'privileged-unix-update'${NORMAL}"
         fi

         IFS=' ' read -a fieldvals <<< "${rule}"

         for field in ${fieldvals[@]}
         do
            if [[ $field =~ 'auid>=' ]]
            then
               auidval="$(echo $field | awk -F'>=' '{print $2}')"
               if [[ $auidval != 1000 && $audidval != 0 ]]
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid>=' cannot be greater than 1000${NORMAL}"
                  fail=1
               fi
            elif [[ $field =~ 'auid=' ]]
            then
               auidval="$(echo $field | awk -F= '{print $2}')"
               if (( $auidval != 0 ))
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid=' cannot be a value other than '0'${NORMAL}"
                  fail=1
               fi
            elif [[ $field =~ 'auid!=' ]]
            then
               auidval="$(echo $field | awk -F'!=' '{print $2}')"
               if (( $auidval != 'unset' ))
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid!=' must be unset${NORMAL}"
                  fail=1
               fi
            fi
         done
      done
   else
      echo -e "${NORMAL}RESULT:    ${RED}$file23 is missing a rule for 'userhelper'${NORMAL}"
      fail=2
   fi
   if (( $fail == 0 || $found == 1 ))
   then
      echo -e "${NORMAL}$hostname, $severity23, $controlid, $stigid23, $ruleid23, $cci23, $datetime, ${GRN}PASSED, Use of the userhelper command is audited${NORMAL}"
   elif (( $fail == 2 ))
   then
      echo -e "${NORMAL}$hostname, $severity23, $controlid, $stigid23, $ruleid23, $cci23, $datetime, ${RED}FAILED, Use of the userhelper command is not audited${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity23, $controlid, $stigid23, $ruleid23, $cci23, $datetime, ${RED}FAILED, Use of the userhelper command is not configured correctly${NORMAL}"
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
found=0

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file24 ]]
then
   aurules="$(grep -w setsebool $file24 | grep -v '^#')"
   if [[ $aurules ]]
   then
      for rule in ${aurules[@]}
      do
         if [[ $rule =~ '-a always,exit' && $rule =~ '/sbin' ]] &&
            [[ $rule =~ '-F perm=x' && $rule =~ 'privileged' ]]
         then
            found=1
         fi
         echo -e "${NORMAL}RESULT:    ${BLD}$rule${NORMAL}"
         if [[ ! $rule =~ '-a always,exit' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-a always,exit'${NORMAL}"
            fail=1
         fi
         if [[ ! $rule =~ '-F path=/usr/sbin/' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-F path=/usr/sbin/'${NORMAL}"
            fail=1
         fi
         if [[ ! $rule =~ '-F perm=x' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-F perm=x'${NORMAL}"
            fail=1
         fi
         if ! [[ $rule =~ 'privileged-unix-update' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing 'privileged-unix-update'${NORMAL}"
         fi

         IFS=' ' read -a fieldvals <<< "${rule}"

         for field in ${fieldvals[@]}
         do
            if [[ $field =~ 'auid>=' ]]
            then
               auidval="$(echo $field | awk -F'>=' '{print $2}')"
               if [[ $auidval != 1000 && $auidval != 0 ]]
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid>=' cannot be greater than 1000${NORMAL}"
                  fail=1
               fi
            elif [[ $field =~ 'auid=' ]]
            then
               auidval="$(echo $field | awk -F= '{print $2}')"
               if (( $auidval != 0 ))
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid=' cannot be a value other than '0'${NORMAL}"
                  fail=1
               fi
            elif [[ $field =~ 'auid!=' ]]
            then
               auidval="$(echo $field | awk -F'!=' '{print $2}')"
               if (( $auidval != 'unset' ))
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid!=' must be unset${NORMAL}"
                  fail=1
               fi
            fi
         done
      done
   else
      echo -e "${NORMAL}RESULT:    ${RED}$file24 is missing a rule for 'setsebool'${NORMAL}"
      fail=2
   fi
   if (( $fail == 0 || $found == 1 ))
   then
      echo -e "${NORMAL}$hostname, $severity24, $controlid, $stigid24, $ruleid24, $cci24, $datetime, ${GRN}PASSED, Use of the setsebool command is audited${NORMAL}"
   elif (( $fail == 2 ))
   then
      echo -e "${NORMAL}$hostname, $severity24, $controlid, $stigid24, $ruleid24, $cci24, $datetime, ${RED}FAILED, Use of the setsebool command is not audited${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity24, $controlid, $stigid24, $ruleid24, $cci24, $datetime, ${RED}FAILED, Use of the setsebool command is not configured correctly${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${BLD}$file24 not found${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity24, $controlid, $stigid24, $ruleid21, $cci24, $datetime, ${RED}FAILED, $file24 not found${NORMAL}"
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
found=0
fail=0

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file25 ]]
then
   aurules="$(grep -w unix_chkpwd $file25 | grep -v '^#')"
   if [[ $aurules ]]
   then
      for rule in ${aurules[@]}
      do
         if [[ $rule =~ '-a always,exit' && $rule =~ '/sbin' &&  \
               $rule =~ '-F perm=x' && $rule =~ 'privileged' ]]
         then
            found=1
         fi
         echo -e "${NORMAL}RESULT:    ${BLD}$rule${NORMAL}"
         if [[ ! $rule =~ '-a always,exit' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-a always,exit'${NORMAL}"
            fail=1
         fi
         if [[ ! $rule =~ '-F path=/sbin/' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-F path=/sbin/'${NORMAL}"
            fail=1
         fi
         if [[ ! $rule =~ '-F perm=x' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-F perm=x'${NORMAL}"
            fail=1
         fi
         if [[ ! $rule =~ 'privileged-unix-update' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing 'privileged-unix-update'${NORMAL}"
         fi

         IFS=' ' read -a fieldvals <<< "${rule}"

         for field in ${fieldvals[@]}
         do
            if [[ $field =~ 'auid>=' ]]
            then
               auidval="$(echo $field | awk -F'>=' '{print $2}')"
               if [[ $auidval != 1000 && $auidval != 0 ]]
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid>=' cannot be greater than 1000${NORMAL}"
                  fail=1
               fi
            elif [[ $field =~ 'auid=' ]]
            then
               auidval="$(echo $field | awk -F= '{print $2}')"
               if (( $auidval != 0 ))
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid=' cannot be a value other than '0'${NORMAL}"
                  fail=1
               fi
            elif [[ $field =~ 'auid!=' ]]
            then
               auidval="$(echo $field | awk -F'!=' '{print $2}')"
               if (( $auidval != 'unset' ))
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid!=' must be unset${NORMAL}"
                  fail=1
               fi
            fi
         done
      done
   else
      echo -e "${NORMAL}RESULT:    ${RED}$file25 is missing a rule for 'unix_chkpwd'${NORMAL}"
      fail=2
   fi
   if (( $fail == 0 || $found == 1 ))
   then
      echo -e "${NORMAL}$hostname, $severity25, $controlid, $stigid25, $ruleid25, $cci25, $datetime, ${GRN}PASSED, Use of the unix_chkpwd command is audited${NORMAL}"
   elif (( $fail == 2 ))
   then
      echo -e "${NORMAL}$hostname, $severity25, $controlid, $stigid25, $ruleid25, $cci25, $datetime, ${RED}FAILED, Use of the unix_chkpwd command is not audited${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity25, $controlid, $stigid25, $ruleid25, $cci25, $datetime, ${RED}FAILED, Use of the unix_chkpwd command is not configured correctly${NORMAL}"
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

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file26 ]]
then
   aurules="$(grep -i /usr/libexec/openssh/ssh-keysign  $file26 | grep -v '^#')"
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
         if [[ ! $rule =~ '-F path=/usr/libexec/openssh/' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-F path=/usr/libexec/openssh/'${NORMAL}"
            fail=1
         fi
         if [[ ! $rule =~ '-F perm=x' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-F perm=x'${NORMAL}"
            fail=1
         fi
         if [[ ! $rule =~ 'privileged-ssh' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing 'privileged-ssh'${NORMAL}"
         fi

         IFS=' ' read -a fieldvals <<< "${rule}"

         for field in ${fieldvals[@]}
         do
            if [[ $field =~ 'auid>=' ]]
            then
               auidval="$(echo $field | awk -F'>=' '{print $2}')"
               if [[ $auidval != 1000 && $auidval != 0 ]]
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid>=' cannot be greater than 1000${NORMAL}"
                  fail=1
               fi
            elif [[ $field =~ 'auid=' ]]
            then
               auidval="$(echo $field | awk -F= '{print $2}')"
               if (( $auidval != 0 ))
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid=' cannot be a value other than '0'${NORMAL}"
                  fail=1
               fi
            elif [[ $field =~ 'auid!=' ]]
            then
               auidval="$(echo $field | awk -F'!=' '{print $2}')"
               if (( $auidval != 'unset' ))
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid!=' must be unset${NORMAL}"
                  fail=1
               fi
            fi
         done
      done
   else
      echo -e "${NORMAL}RESULT:    ${RED}$file26 is missing a rule for 'ssh-keysign'${NORMAL}"
      fail=2
   fi
   if (( $fail == 0 ))
   then
      echo -e "${NORMAL}$hostname, $severity26, $controlid, $stigid26, $ruleid26, $cci26, $datetime, ${GRN}PASSED, Use of the ssh-keysign command is audited${NORMAL}"
   elif (( $fail == 2 ))
   then
      echo -e "${NORMAL}$hostname, $severity26, $controlid, $stigid26, $ruleid26, $cci26, $datetime, ${RED}FAILED, Use of the ssh-keysign command is not audited${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity26, $controlid, $stigid26, $ruleid26, $cci26, $datetime, ${RED}FAILED, Use of the ssh-keysign command is not configured correctly${NORMAL}"
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
   aurules="$(grep -w 'setfacl' $file27 | grep -v '^#')"
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
            echo -e "${NORMAL}RESULT:    ${RED}missing '-F path=/usr/bin/'${NORMAL}"
            fail=1
         fi
         if [[ ! $rule =~ '-F perm=x' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-F perm=x'${NORMAL}"
            fail=1
         fi
         if ! [[ $rule =~ 'perm_mod' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing 'perm_mod'${NORMAL}"
         fi

         IFS=' ' read -a fieldvals <<< "${rule}"

         for field in ${fieldvals[@]}
         do
            if [[ $field =~ 'auid>=' ]]
            then
               auidval="$(echo $field | awk -F'>=' '{print $2}')"
               if [[ $auidval != 1000 && $auidval != 0 ]]
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid>=' cannot be greater than 1000${NORMAL}"
                  fail=1
               fi
            elif [[ $field =~ 'auid=' ]]
            then
               auidval="$(echo $field | awk -F= '{print $2}')"
               if (( $auidval != 0 ))
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid=' cannot be a value other than '0'${NORMAL}"
                  fail=1
               fi
            elif [[ $field =~ 'auid!=' ]]
            then
               auidval="$(echo $field | awk -F'!=' '{print $2}')"
               if (( $auidval != 'unset' ))
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid!=' must be unset${NORMAL}"
                  fail=1
               fi
            fi
         done
      done
   else
      echo -e "${NORMAL}RESULT:    ${RED}$file27 is missing a rule for 'setfacl'${NORMAL}"
      fail=2
   fi
   if (( $fail == 0 ))
   then
      echo -e "${NORMAL}$hostname, $severity27, $controlid, $stigid27, $ruleid27, $cci27, $datetime, ${GRN}PASSED, Use of the setfacl command is audited${NORMAL}"
   elif (( $fail == 2 ))
   then
      echo -e "${NORMAL}$hostname, $severity27, $controlid, $stigid27, $ruleid27, $cci27, $datetime, ${RED}FAILED, Use of the setfacl command is not audited${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity27, $controlid, $stigid27, $ruleid27, $cci27, $datetime, ${RED}FAILED, Use of the setfacl command is not configured correctly${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${BLD}$file27 not found${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity27, $controlid, $stigid27, $ruleid27, $cci27, $datetime, ${RED}FAILED, $file27 not found${NORMAL}"
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
found=0
fail=0

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file28 ]]
then
   aurules="$(grep -w pam_timestamp_check  $file28 | grep -v '^#')"
   if [[ $aurules ]]
   then
      for rule in ${aurules[@]}
      do
         if [[ $rule =~ '-a always,exit' && $rule =~ '/sbin' ]] &&
            [[ $rule =~ '-F perm=x' && $rule =~ 'privileged' ]]
         then
            found=1
         fi
         echo -e "${NORMAL}RESULT:    ${BLD}$rule${NORMAL}"
         if [[ ! $rule =~ '-a always,exit' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-a always,exit'${NORMAL}"
            fail=1
         fi
         if [[ ! $rule =~ '-F path=/sbin/' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-F path=/sbin/'${NORMAL}"
            fail=1
         fi
         if [[ ! $rule =~ '-F perm=x' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-F perm=x'${NORMAL}"
            fail=1
         fi
         if [[ ! $rule =~ 'privileged-pam_timestamp_check' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing 'privileged-pam_timestamp_check'${NORMAL}"
         fi

         IFS=' ' read -a fieldvals <<< "${rule}"

         for field in ${fieldvals[@]}
         do
            if [[ $field =~ 'auid>=' ]]
            then
               auidval="$(echo $field | awk -F'>=' '{print $2}')"
               if [[ $auidval != 1000 && $auidval != 0 ]]
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid>=' cannot be greater than 1000${NORMAL}"
                  fail=1
               fi
            elif [[ $field =~ 'auid=' ]]
            then
               auidval="$(echo $field | awk -F= '{print $2}')"
               if (( $auidval != 0 ))
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid=' cannot be a value other than '0'${NORMAL}"
                  fail=1
               fi
            elif [[ $field =~ 'auid!=' ]]
            then
               auidval="$(echo $field | awk -F'!=' '{print $2}')"
               if (( $auidval != 'unset' ))
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid!=' must be unset${NORMAL}"
                  fail=1
               fi
            fi
         done
      done
   else
      echo -e "${NORMAL}RESULT:    ${RED}$file28 is missing a rule for 'pam_timestamp_check'${NORMAL}"
      fail=2
   fi
   if (( $fail == 0 || $found == 1 ))
   then
      echo -e "${NORMAL}$hostname, $severity28, $controlid, $stigid28, $ruleid28, $cci28, $datetime, ${GRN}PASSED, Use of the pam_timestamp_check command is audited${NORMAL}"
   elif (( $fail == 2 ))
   then
      echo -e "${NORMAL}$hostname, $severity28, $controlid, $stigid28, $ruleid28, $cci28, $datetime, ${RED}FAILED, Use of the pam_timestamp_check command is not audited${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity28, $controlid, $stigid28, $ruleid28, $cci28, $datetime, ${RED}FAILED, Use of the pam_timestamp_check command is not configured correctly${NORMAL}"
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
found=0

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file29 ]]
then
   aurules="$(grep -i newgrp  $file29 | grep -v '^#')"
   if [[ $aurules ]]
   then
      for rule in ${aurules[@]}
      do
         if [[ $rule =~ '-w' && $rule =~ '-p wa ' && $rule =~ 'priv' ]]
         then
            found=1
         fi
         echo -e "${NORMAL}RESULT:    ${BLD}$rule${NORMAL}"
         if [[ ! $rule =~ '-a always,exit' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-a always,exit'${NORMAL}"
            fail=1
         fi
         if [[ ! $rule =~ '-F path=/usr/bin/' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-F path=/usr/bin/'${NORMAL}"
            fail=1
         fi
         if [[ ! $rule =~ '-F perm=x' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-F perm=x'${NORMAL}"
            fail=1
         fi
         if ! [[ $rule =~ 'priv_cmd' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing 'priv_cmd'${NORMAL}"
         fi

         IFS=' ' read -a fieldvals <<< "${rule}"

         for field in ${fieldvals[@]}
         do
            if [[ $field =~ 'auid>=' ]]
            then
               auidval="$(echo $field | awk -F'>=' '{print $2}')"
               if [[ $auidval != 1000 && $auidval != 0 ]]
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid>=' cannot be greater than 1000${NORMAL}"
                  fail=1
               fi
            elif [[ $field =~ 'auid=' ]]
            then
               auidval="$(echo $field | awk -F= '{print $2}')"
               if (( $auidval != 0 ))
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid=' cannot be a value other than '0'${NORMAL}"
                  fail=1
               fi
            elif [[ $field =~ 'auid!=' ]]
            then
               auidval="$(echo $field | awk -F'!=' '{print $2}')"
               if (( $auidval != 'unset' ))
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid!=' must be unset${NORMAL}"
                  fail=1
               fi
            fi
         done
      done
   else
      echo -e "${NORMAL}RESULT:    ${RED}$file29 is missing a rule for 'newgrp'${NORMAL}"
      fail=2
   fi
   if (( $fail == 0 || $found == 1 ))
   then
      echo -e "${NORMAL}$hostname, $severity29, $controlid, $stigid29, $ruleid29, $cci29, $datetime, ${GRN}PASSED, Use of the newgrp command is audited${NORMAL}"
   elif (( $fail == 2 ))
   then
      echo -e "${NORMAL}$hostname, $severity29, $controlid, $stigid29, $ruleid29, $cci29, $datetime, ${RED}FAILED, Use of the newgrp command is not audited${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity29, $controlid, $stigid29, $ruleid29, $cci29, $datetime, ${RED}FAILED, Use of the newgrp command is not configured correctly${NORMAL}"
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
found=0

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file30 ]]
then
  aurules="$(grep -w init_module $file30 | grep -v '^#')"
  if [[ $aurules ]]
  then
     if [[ $rule =~ '-a always,exit' && $rule =~ 'module' ]]
     then
        found=1
     fi
     for rule in ${aurules[@]}
     do
       echo -e "${NORMAL}RESULT:    ${BLD}$rule${NORMAL}"
       if [[ ! $rule =~ '-a always,exit' ]]
       then
          echo -e "${NORMAL}RESULT:    ${RED}missing '-a always,exit'${NORMAL}"
          fail=1
       fi
       if [[ ! $rule =~ 'module-chng' ]]
       then
          echo -e "${NORMAL}RESULT:    ${RED}missing module-chng${NORMAL}"
       fi
      if [[ $field =~ 'auid>=' ]]
      then
        auidval="$(echo $field | awk -F'>=' '{print $2}')"
        if [[ $auidval != 1000 && $auidval != 0 ]]
        then
          echo -e "${NORMAL}RESULT:    ${RED}'auid>=' cannot be greater than 1000${NORMAL}"
          fail=1
        fi
      elif [[ $field =~ 'auid=' ]]
      then
        auidval="$(echo $field | awk -F= '{print $2}')"
        if (( $auidval != 0 ))
        then
          echo -e "${NORMAL}RESULT:    ${RED}'auid=' cannot be a value other than '0'${NORMAL}"
          fail=1
        fi
      elif [[ $field =~ 'auid!=' ]]
      then
        auidval="$(echo $field | awk -F'!=' '{print $2}')"
        if (( $auidval != 'unset' ))
        then
          echo -e "${NORMAL}RESULT:    ${RED}'auid!=' must be unset${NORMAL}"
          fail=1
        fi
      fi
    done
  else
    echo -e "${NORMAL}RESULT:    ${RED}$file30 is missing a rule for 'init_module'${NORMAL}"
    fail=2
  fi
  if (( $fail == 0 || $found == 1 ))
  then
    echo -e "${NORMAL}$hostname, $severity30, $controlid, $stigid30, $ruleid30, $cci30, $datetime, ${GRN}PASSED, Use of the init_module command is audited${NORMAL}"
  elif (( $fail == 2 ))
  then
    echo -e "${NORMAL}$hostname, $severity30, $controlid, $stigid30, $ruleid30, $cci30, $datetime, ${RED}FAILED, Use of the init_module command is not audited${NORMAL}"
  else
    echo -e "${NORMAL}$hostname, $severity30, $controlid, $stigid30, $ruleid30, $cci30, $datetime, ${RED}FAILED, Use of the init_module command is not configured correctly${NORMAL}"
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
found=0

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file31 ]]
then
   aurules="$(grep rename\|unlink\|rmdir  $file31 | grep -v '^#')"
   if [[ $aurules ]]
   then
      for rule in ${aurules[@]}
      do
         if [[ $rule =~ '-a always,exit' && ( $rule =~ '-k delete' || $rule =~ 'key=delete' ) ]]
         then
            found=1
         fi
         echo -e "${NORMAL}RESULT:    ${BLD}$rule${NORMAL}"
         if [[ ! $rule =~ '-a always,exit' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-a always,exit'${NORMAL}"
            fail=1
         fi
         if [[ ! $rule =~ 'delete' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing 'delete'${NORMAL}"
         fi

         IFS=' ' read -a fieldvals <<< "${rule}"

         for field in ${fieldvals[@]}
         do
            if [[ $field =~ 'auid>=' ]]
            then
               auidval="$(echo $field | awk -F'>=' '{print $2}')"
               if [[ $auidval != 1000 && $auidval != 0 ]]
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid>=' cannot be greater than 1000${NORMAL}"
                  fail=1
               fi
            elif [[ $field =~ 'auid=' ]]
            then
               auidval="$(echo $field | awk -F= '{print $2}')"
               if (( $auidval != 0 ))
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid=' cannot be a value other than '0'${NORMAL}"
                  fail=1
               fi
            elif [[ $field =~ 'auid!=' ]]
            then
               auidval="$(echo $field | awk -F'!=' '{print $2}')"
               if (( $auidval != 'unset' ))
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid!=' must be unset${NORMAL}"
                  fail=1
               fi
            fi
            if [[ $field =~ 'rename' ]]
            then
              rename=1
            fi
            if [[ $field =~ 'renameat' ]]
            then
              renameat=1
            fi
            if [[ $field =~ 'unlink' ]]
            then
              unlink=1
            fi
            if [[ $field =~ 'unlinkat' ]]
            then
              unlinkat=1
            fi
            if [[ $field =~ 'rmdir' ]]
            then
              rmdir=1
            fi
         done
	 if [[ $rename == 0 || $renameat == 0 || $unlink == 0 || $unlinkat == 0 || $rmdir == 0 ]]
	 then
	   fail=2
	 fi
      done
   fi

   if (( $fail == 0 || $found == 1 ))
   then
      echo -e "${NORMAL}$hostname, $severity31, $controlid, $stigid31, $ruleid31, $cci31, $datetime, ${GRN}PASSED, Use of the rename command is audited${NORMAL}"
   elif (( $fail == 2 ))
   then
      echo -e "${NORMAL}$hostname, $severity31, $controlid, $stigid31, $ruleid31, $cci31, $datetime, ${RED}FAILED, Use of some or all of the commands are not audited${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity31, $controlid, $stigid31, $ruleid31, $cci31, $datetime, ${RED}FAILED, Use of the rename command is not configured correctly${NORMAL}"
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
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity32${NORMAL}"

file32="/etc/audit/audit.rules"
found=0
fail=0

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file32 ]]
then
   aurules="$(grep -w gpasswd $file32 | grep -v '^#')"
   if [[ $aurules ]]
   then
      for rule in ${aurules[@]}
      do
         if [[ $rule =~ '-a always,exit' && $rule =~ '/bin' ]] &&
            [[ $rule =~ '-F perm=x' && $rule =~ 'privileged' ]]
         then
            found=1
         fi
         echo -e "${NORMAL}RESULT:    ${BLD}$rule${NORMAL}"
         if [[ ! $rule =~ '-a always,exit' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-a always,exit'${NORMAL}"
            fail=1
         fi
         if [[ ! $rule =~ '-F path=/usr/bin/' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-F path=/usr/bin/'${NORMAL}"
            fail=1
         fi
         if [[ ! $rule =~ '-F perm=x' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-F perm=x'${NORMAL}"
            fail=1
         fi
         if [[ ! $rule =~ 'privileged-gpasswd' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-k privileged-gpasswd'${NORMAL}"
         fi

         IFS=' ' read -a fieldvals <<< "${rule}"

         for field in ${fieldvals[@]}
         do
            if [[ $field =~ 'auid>=' ]]
            then
               auidval="$(echo $field | awk -F'>=' '{print $2}')"
               if [[ $auidval != 1000 && $auidval != 0 ]]
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid>=' cannot be greater than 1000${NORMAL}"
                  fail=1
               fi
            elif [[ $field =~ 'auid=' ]]
            then
               auidval="$(echo $field | awk -F= '{print $2}')"
               if (( $auidval != 0 ))
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid=' cannot be a value other than '0'${NORMAL}"
                  fail=1
               fi
            elif [[ $field =~ 'auid!=' ]]
            then
               auidval="$(echo $field | awk -F'!=' '{print $2}')"
               if (( $auidval != 'unset' ))
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid!=' must be unset${NORMAL}"
                  fail=1
               fi
            fi
         done
      done
   else
      echo -e "${NORMAL}RESULT:    ${RED}$file32 is missing a rule for 'gpasswd'${NORMAL}"
      fail=2
   fi
   if (( $fail == 0 || $found == 1 ))
   then
      echo -e "${NORMAL}$hostname, $severity32, $controlid, $stigid32, $ruleid32, $cci32, $datetime, ${GRN}PASSED, Use of the gpasswd command is audited${NORMAL}"
   elif (( $fail == 2 ))
   then
      echo -e "${NORMAL}$hostname, $severity32, $controlid, $stigid32, $ruleid32, $cci32, $datetime, ${RED}FAILED, Use of the gpasswd command is not audited${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity32, $controlid, $stigid32, $ruleid32, $cci32, $datetime, ${RED}FAILED, Use of the gpasswd command is not configured correctly${NORMAL}"
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
found=0

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file33 ]]
then
   aurules="$(grep -w delete_module $file33 | grep -v '^#')"
   if [[ $aurules ]]
   then
     if [[ $rule =~ '-a always,exit' && $rule =~ 'module' ]]
     then
        found=1
     fi
     for rule in ${aurules[@]}
     do
       echo -e "${NORMAL}RESULT:    ${BLD}$rule${NORMAL}"
       if [[ ! $rule =~ '-a always,exit' ]]
       then
          echo -e "${NORMAL}RESULT:    ${RED}missing '-a always,exit'${NORMAL}"
          fail=1
       fi
       if [[ ! $rule =~ 'module-chng' ]]
       then
          echo -e "${NORMAL}RESULT:    ${RED}missing module-chng${NORMAL}"
       fi
       if [[ $field =~ 'auid>=' ]]
       then
         auidval="$(echo $field | awk -F'>=' '{print $2}')"
         if [[ $auidval != 1000 && $auidval != 0 ]]
         then
           echo -e "${NORMAL}RESULT:    ${RED}'auid>=' cannot be greater than 1000${NORMAL}"
           fail=1
         fi
       elif [[ $field =~ 'auid=' ]]
       then
         auidval="$(echo $field | awk -F= '{print $2}')"
         if (( $auidval != 0 ))
         then
           echo -e "${NORMAL}RESULT:    ${RED}'auid=' cannot be a value other than '0'${NORMAL}"
           fail=1
         fi
       elif [[ $field =~ 'auid!=' ]]
       then
         auidval="$(echo $field | awk -F'!=' '{print $2}')"
         if (( $auidval != 'unset' ))
         then
           echo -e "${NORMAL}RESULT:    ${RED}'auid!=' must be unset${NORMAL}"
           fail=1
         fi
       fi
     done
   else
      echo -e "${NORMAL}RESULT:    ${RED}$file33 is missing a rule for 'delete_module'${NORMAL}"
      fail=2
   fi
   if (( $fail == 0 || $found == 1 ))
   then
      echo -e "${NORMAL}$hostname, $severity33, $controlid, $stigid33, $ruleid33, $cci33, $datetime, ${GRN}PASSED, Use of the delete_module command is audited${NORMAL}"
   elif (( $fail == 2 ))
   then
      echo -e "${NORMAL}$hostname, $severity33, $controlid, $stigid33, $ruleid33, $cci33, $datetime, ${RED}FAILED, Use of the delete_module command is not audited${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity33, $controlid, $stigid33, $ruleid33, $cci33, $datetime, ${RED}FAILED, Use of the delete_module command is not configured correctly${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${BLD}$file33 not found${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity33, $controlid, $stigid33, $ruleid33, $cci33, $datetime, ${RED}FAILED, $file33 not found${NORMAL}"
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

file34="/etc/audit/audit.rules"
fail=0

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file34 ]]
then
   aurules="$(grep -w /crontab  $file34 | grep -v '^#')"
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
            echo -e "${NORMAL}RESULT:    ${RED}missing '-F path=/usr/bin/'${NORMAL}"
            fail=1
         fi
         if [[ ! $rule =~ '-F perm=x' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-F perm=x'${NORMAL}"
            fail=1
         fi
         if [[ ! $rule =~ 'privileged-crontab' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-k privileged-crontab'${NORMAL}"
         fi

         IFS=' ' read -a fieldvals <<< "${rule}"

         for field in ${fieldvals[@]}
         do
            if [[ $field =~ 'auid>=' ]]
            then
               auidval="$(echo $field | awk -F'>=' '{print $2}')"
               if [[ $auidval != 1000 && $auidval != 0 ]]
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid>=' cannot be greater than 1000${NORMAL}"
                  fail=1
               fi
            elif [[ $field =~ 'auid=' ]]
            then
               auidval="$(echo $field | awk -F= '{print $2}')"
               if (( $auidval != 0 ))
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid=' cannot be a value other than '0'${NORMAL}"
                  fail=1
               fi
            elif [[ $field =~ 'auid!=' ]]
            then
               auidval="$(echo $field | awk -F'!=' '{print $2}')"
               if (( $auidval != 'unset' ))
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid!=' must be unset${NORMAL}"
                  fail=1
               fi
            fi
         done
      done
   else
      echo -e "${NORMAL}RESULT:    ${RED}$file34 is missing a rule for 'crontab'${NORMAL}"
      fail=2
   fi
   if (( $fail == 0 ))
   then
      echo -e "${NORMAL}$hostname, $severity34, $controlid, $stigid34, $ruleid34, $cci34, $datetime, ${GRN}PASSED, Use of the crontab command is audited${NORMAL}"
   elif (( $fail == 2 ))
   then
      echo -e "${NORMAL}$hostname, $severity34, $controlid, $stigid34, $ruleid34, $cci34, $datetime, ${RED}FAILED, Use of the crontab command is not audited${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity34, $controlid, $stigid34, $ruleid34, $cci34, $datetime, ${RED}FAILED, Use of the crontab command is not configured correctly${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${BLD}$file34 not found${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity34, $controlid, $stigid34, $ruleid34, $cci34, $datetime, ${RED}FAILED, $file34 not found${NORMAL}"
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

file35="/etc/audit/audit.rules"
fail=0

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file35 ]]
then
   aurules="$(grep -w chsh  $file35 | grep -v '^#')"
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
            echo -e "${NORMAL}RESULT:    ${RED}missing '-F path=/usr/bin/'${NORMAL}"
            fail=1
         fi
         if [[ ! $rule =~ '-F perm=x' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-F perm=x'${NORMAL}"
            fail=1
         fi
         if ! [[ $rule =~ 'priv_cmd' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing 'priv_cmd'${NORMAL}"
         fi

         IFS=' ' read -a fieldvals <<< "${rule}"

         for field in ${fieldvals[@]}
         do
            if [[ $field =~ 'auid>=' ]]
            then
               auidval="$(echo $field | awk -F'>=' '{print $2}')"
               if [[ $auidval != 1000 && $audival != 0 ]]
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid>=' cannot be greater than 1000${NORMAL}"
                  fail=1
               fi
            elif [[ $field =~ 'auid=' ]]
            then
               auidval="$(echo $field | awk -F= '{print $2}')"
               if (( $auidval != 0 ))
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid=' cannot be a value other than '0'${NORMAL}"
                  fail=1
               fi
            elif [[ $field =~ 'auid!=' ]]
            then
               auidval="$(echo $field | awk -F'!=' '{print $2}')"
               if (( $auidval != 'unset' ))
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid!=' must be unset${NORMAL}"
                  fail=1
               fi
            fi
         done
      done
   else
      echo -e "${NORMAL}RESULT:    ${RED}$file35 is missing a rule for 'chsh'${NORMAL}"
      fail=2
   fi
   if (( $fail == 0 ))
   then
      echo -e "${NORMAL}$hostname, $severity35, $controlid, $stigid35, $ruleid35, $cci35, $datetime, ${GRN}PASSED, Use of the chsh command is audited${NORMAL}"
   elif (( $fail == 2 ))
   then
      echo -e "${NORMAL}$hostname, $severity35, $controlid, $stigid35, $ruleid35, $cci35, $datetime, ${RED}FAILED, Use of the chsh command is not audited${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity35, $controlid, $stigid35, $ruleid35, $cci35, $datetime, ${RED}FAILED, Use of the chsh command is not configured correctly${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${BLD}$file35 not found${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity35, $controlid, $stigid35, $ruleid35, $cci35, $datetime, ${RED}FAILED, $file35 not found${NORMAL}"
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

file36="/etc/audit/audit.rules"
fail=0

truncate=0
ftruncate=0
open=0
openat=0
openbyhandleat=0
creat=0

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file36 ]]
then
   aurules="$(grep 'open\|truncate\|creat' $file36 | grep -v '^#')"
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
         if [[ ! $rule =~ '-F exit=-EACCES' ]] &&
            [[ ! $rule =~ '-F exit=-EPERM' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-F exit=-EPERM'${NORMAL}"
            fail=1
         fi
         if [[ ! $rule =~ 'perm_access' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing 'perm_access'${NORMAL}"
         fi

         IFS=' ' read -a fieldvals <<< "${rule}"

         for field in ${fieldvals[@]}
         do
            if [[ $field =~ 'auid>=' ]]
            then
               auidval="$(echo $field | awk -F'>=' '{print $2}')"
               if [[ $auidval != 1000 && $auidval != 0 ]]
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid>=' cannot be greater than 1000${NORMAL}"
                  fail=1
               fi
            elif [[ $field =~ 'auid=' ]]
            then
               auidval="$(echo $field | awk -F= '{print $2}')"
               if (( $auidval != 0 ))
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid=' cannot be a value other than '0'${NORMAL}"
                  fail=1
               fi
            elif [[ $field =~ 'auid!=' ]]
            then
               auidval="$(echo $field | awk -F'!=' '{print $2}')"
               if (( $auidval != 'unset' ))
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid!=' must be unset${NORMAL}"
                  fail=1
               fi
            fi
	    if [[ $field =~ 'truncate' ]]
            then
              truncate=1
            fi
        if [[ $field =~ 'ftruncate' ]]
        then
            ftruncate=1
        fi
        if [[ $field =~ 'creat' ]]
        then
            creat=1
        fi
        if [[ $field =~ 'open' ]]
        then
            open=1
        fi
        if [[ $field =~ 'openat' ]]
        then
            openat=1
        fi
	    if [[ $field =~ 'open_by_handle_at' ]]
	    then
	        openbyhandleat=1
	    fi

         done
	 if [[ $truncate == 0 || $ftruncate == 0 || $creat == 0 || $open == 0 || $openat == 0 || $openbyhandleat == 0 ]]
	 then
	   fail=2
	 fi
      done
   else
      echo -e "${NORMAL}RESULT:    ${RED}$file36 is missing a rule for 'truncate'${NORMAL}"
      fail=2
   fi
   if (( $fail == 0 ))
   then
      echo -e "${NORMAL}$hostname, $severity36, $controlid, $stigid36, $ruleid36, $cci36, $datetime, ${GRN}PASSED, Use of the truncate command is audited${NORMAL}"
   elif (( $fail == 2 ))
   then
      echo -e "${NORMAL}$hostname, $severity36, $controlid, $stigid36, $ruleid36, $cci36, $datetime, ${RED}FAILED, Use of the truncate command is not audited${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity36, $controlid, $stigid36, $ruleid36, $cci36, $datetime, ${RED}FAILED, Use of the truncate command is not configured correctly${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${BLD}$file36 not found${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity36, $controlid, $stigid36, $ruleid36, $cci36, $datetime, ${RED}FAILED, $file36 not found${NORMAL}"
fi

echo
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

file37="/etc/audit/audit.rules"
fail=0
found=0

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file37 ]]
then
   aurules="$(grep chown $file37 | grep -v '^#')"
   if [[ $aurules ]]
   then
      for rule in ${aurules[@]}
      do
         if [[ $rule =~ '-a always,exit' && $rule =~ 'perm_mod' ]]
         then
            found=1
         fi
         echo -e "${NORMAL}RESULT:    ${BLD}$rule${NORMAL}"
         if [[ ! $rule =~ '-a always,exit' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-a always,exit'${NORMAL}"
            fail=1
         fi
         if [[ ! $rule =~ 'perm_mod' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing 'perm_mod'${NORMAL}"
         fi

         IFS=' ' read -a fieldvals <<< "${rule}"

         for field in ${fieldvals[@]}
         do
            if [[ $field =~ 'auid>=' ]]
            then
               auidval="$(echo $field | awk -F'>=' '{print $2}')"
               if [[ $auidval != 1000 && $auidval != 0 ]]
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid>=' cannot be greater than 1000${NORMAL}"
                  fail=1
               fi
            elif [[ $field =~ 'auid=' ]]
            then
               auidval="$(echo $field | awk -F= '{print $2}')"
               if (( $auidval != 0 ))
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid=' cannot be a value other than '0'${NORMAL}"
                  fail=1
               fi
            elif [[ $field =~ 'auid!=' ]]
            then
               auidval="$(echo $field | awk -F'!=' '{print $2}')"
               if (( $auidval != unset ))
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid!=' must be unset${NORMAL}"
                  fail=1
               fi
            fi
         done
      done
   else
      echo -e "${NORMAL}RESULT:    ${RED}$file37 is missing a rule for 'chown'${NORMAL}"
      fail=2
   fi
   if (( $fail == 0 || $found == 1 ))
   then
      echo -e "${NORMAL}$hostname, $severity37, $controlid, $stigid37, $ruleid37, $cci37, $datetime, ${GRN}PASSED, Use of the chown command is audited${NORMAL}"
   elif (( $fail == 2 ))
   then
      echo -e "${NORMAL}$hostname, $severity37, $controlid, $stigid37, $ruleid37, $cci37, $datetime, ${RED}FAILED, Use of the chown command is not audited${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity37, $controlid, $stigid37, $ruleid37, $cci37, $datetime, ${RED}FAILED, Use of the chown command is not configured correctly${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${BLD}$file37 not found${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity37, $controlid, $stigid37, $ruleid37, $cci37, $datetime, ${RED}FAILED, $file37 not found${NORMAL}"
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

file38="/etc/audit/audit.rules"
fail=0
found=0

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file38 ]]
then
   aurules="$(grep chmod $file38 | grep -v '^#')"
   if [[ $aurules ]]
   then
      for rule in ${aurules[@]}
      do
         if [[ $rule =~ '-a always,exit' && $rule =~ 'perm_mod' ]]
         then
            found=1
         fi
         echo -e "${NORMAL}RESULT:    ${BLD}$rule${NORMAL}"
         if [[ ! $rule =~ '-a always,exit' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-a always,exit'${NORMAL}"
            fail=1
         fi
         if [[ ! $rule =~ 'perm_mod' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing 'perm_mod'${NORMAL}"
         fi

         IFS=' ' read -a fieldvals <<< "${rule}"

         for field in ${fieldvals[@]}
         do
            if [[ $field =~ 'auid>=' ]]
            then
               auidval="$(echo $field | awk -F'>=' '{print $2}')"
               if [[ $auidval != 1000 && $auidval != 0 ]]
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid>=' cannot be greater than 1000${NORMAL}"
                  fail=1
               fi
            elif [[ $field =~ 'auid=' ]]
            then
               auidval="$(echo $field | awk -F= '{print $2}')"
               if (( $auidval != 0 ))
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid=' cannot be a value other than '0'${NORMAL}"
                  fail=1
               fi
            elif [[ $field =~ 'auid!=' ]]
            then
               auidval="$(echo $field | awk -F'!=' '{print $2}')"
               if (( $auidval != 'unset' ))
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid!=' must be unset${NORMAL}"
                  fail=1
               fi
            fi
         done
      done
   else
      echo -e "${NORMAL}RESULT:    ${RED}$file38 is missing a rule for 'chmod'${NORMAL}"
      fail=2
   fi
   if (( $fail == 0 || $found == 1 ))
   then
      echo -e "${NORMAL}$hostname, $severity38, $controlid, $stigid38, $ruleid38, $cci38, $datetime, ${GRN}PASSED, Use of the chmod command is audited${NORMAL}"
   elif (( $fail == 2 ))
   then
      echo -e "${NORMAL}$hostname, $severity38, $controlid, $stigid38, $ruleid38, $cci38, $datetime, ${RED}FAILED, Use of the chmod command is not audited${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity38, $controlid, $stigid38, $ruleid38, $cci38, $datetime, ${RED}FAILED, Use of the chmod command is not configured correctly${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${BLD}$file38 not found${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity38, $controlid, $stigid38, $ruleid38, $cci38, $datetime, ${RED}FAILED, $file38 not found${NORMAL}"
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
echo -e "${NORMAL}           ${BLD}$title392c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity39${NORMAL}"

file39="/etc/audit/audit.rules"
fail=0
found=0

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file39 ]]
then
   aurules="$(grep -w sudo   $file39 | grep -v '^#')"
   if [[ $aurules ]]
   then
      for rule in ${aurules[@]}
      do
         if [[ $rule =~ '-a always,exit' && $rule =~ '/bin/sudo ' && $rule =~ 'privileged' ]]
         then
            found=1
         fi
         echo -e "${NORMAL}RESULT:    ${BLD}$rule${NORMAL}"
         if [[ ! $rule =~ '-a always,exit' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-a always,exit'${NORMAL}"
            fail=1
         fi
         if [[ ! $rule =~ '-F path=/usr/bin/' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-F path=/usr/bin/'${NORMAL}"
            fail=1
         fi
         if [[ ! $rule =~ '-F perm=x' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-F perm=x'${NORMAL}"
            fail=1
         fi
         if ! [[ rule =~ 'priv_cmd' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing 'priv_cmd'${NORMAL}"
            fail=1
         fi

         IFS=' ' read -a fieldvals <<< "${rule}"

         for field in ${fieldvals[@]}
         do
            if [[ $field =~ 'auid>=' ]]
            then
               auidval="$(echo $field | awk -F'>=' '{print $2}')"
               if [[ $auidval != 1000 && $auidval != 0 ]]
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid>=' cannot be greater than 1000${NORMAL}"
                  fail=1
               fi
            elif [[ $field =~ 'auid=' ]]
            then
               auidval="$(echo $field | awk -F= '{print $2}')"
               if (( $auidval != 0 ))
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid=' cannot be a value other than '0'${NORMAL}"
                  fail=1
               fi
            elif [[ $field =~ 'auid!=' ]]
            then
               auidval="$(echo $field | awk -F'!=' '{print $2}')"
               if (( $auidval != 'unset' ))
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid!=' must be unset${NORMAL}"
                  fail=1
               fi
            fi
         done
      done
   else
      echo -e "${NORMAL}RESULT:    ${RED}$file39 is missing a rule for 'sudo'${NORMAL}"
      fail=2
   fi
   if (( $fail == 0 || $found == 1 ))
   then
      echo -e "${NORMAL}$hostname, $severity39, $controlid, $stigid39, $ruleid39, $cci39, $datetime, ${GRN}PASSED, Use of the sudo command is audited${NORMAL}"
   elif (( $fail == 2 ))
   then
      echo -e "${NORMAL}$hostname, $severity39, $controlid, $stigid39, $ruleid39, $cci39, $datetime, ${RED}FAILED, Use of the sudo command is not audited${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity39, $controlid, $stigid39, $ruleid39, $cci39, $datetime, ${RED}FAILED, Use of the sudo command is not configured correctly${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${BLD}$file39 not found${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity39, $controlid, $stigid39, $ruleid39, $cci39, $datetime, ${RED}FAILED, $file39 not found${NORMAL}"
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

file40="/etc/audit/audit.rules"
fail=0

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file40 ]]
then
   aurules="$(grep -w usermod $file40 | grep -v '^#')"
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
         if [[ ! $rule =~ '-F path=/usr/sbin/' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-F path=/usr/sbin/'${NORMAL}"
            fail=1
         fi
         if [[ ! $rule =~ '-F perm=x' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-F perm=x'${NORMAL}"
            fail=1
         fi
         if ! [[ $rule =~ 'privileged_usermod' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing 'privileged_usermod'${NORMAL}"
         fi

         IFS=' ' read -a fieldvals <<< "${rule}"

         for field in ${fieldvals[@]}
         do
            if [[ $field =~ 'auid>=' ]]
            then
               auidval="$(echo $field | awk -F'>=' '{print $2}')"
               if [[ $auidval != 1000 && $auidval != 0 ]]
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid>=' cannot be greater than 1000${NORMAL}"
                  fail=1
               fi
            elif [[ $field =~ 'auid=' ]]
            then
               auidval="$(echo $field | awk -F= '{print $2}')"
               if (( $auidval != 0 ))
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid=' cannot be a value other than '0'${NORMAL}"
                  fail=1
               fi
            elif [[ $field =~ 'auid!=' ]]
            then
               auidval="$(echo $field | awk -F'!=' '{print $2}')"
               if (( $auidval != 'unset' ))
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid!=' must be unset${NORMAL}"
                  fail=1
               fi
            fi
         done
      done
   else
      echo -e "${NORMAL}RESULT:    ${RED}$file40 is missing a rule for 'usermod'${NORMAL}"
      fail=2
   fi
   if (( $fail == 0 ))
   then
      echo -e "${NORMAL}$hostname, $severity40, $controlid, $stigid40, $ruleid40, $cci40, $datetime, ${GRN}PASSED, Use of the usermod command is audited${NORMAL}"
   elif (( $fail == 2 ))
   then
      echo -e "${NORMAL}$hostname, $severity40, $controlid, $stigid40, $ruleid40, $cci40, $datetime, ${RED}FAILED, Use of the usermod command is not audited${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity40, $controlid, $stigid40, $ruleid40, $cci40, $datetime, ${RED}FAILED, Use of the usermod command is not configured correctly${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${BLD}$file40 not found${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity40, $controlid, $stigid40, $ruleid40, $cci40, $datetime, ${RED}FAILED, $file40 not found${NORMAL}"
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

file41="/etc/audit/audit.rules"
fail=0

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file41 ]]
then
   aurules="$(grep -w chacl $file41 | grep -v '^#')"
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
            echo -e "${NORMAL}RESULT:    ${RED}missing '-F path=/usr/bin/'${NORMAL}"
            fail=1
         fi
         if [[ ! $rule =~ '-F perm=x' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-F perm=x'${NORMAL}"
            fail=1
         fi
         if ! [[ $rule =~ 'perm_mod' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing 'perm_mod'${NORMAL}"
         fi

         IFS=' ' read -a fieldvals <<< "${rule}"

         for field in ${fieldvals[@]}
         do
            if [[ $field =~ 'auid>=' ]]
            then
               auidval="$(echo $field | awk -F'>=' '{print $2}')"
               if [[ $auidval != 1000 && $auidval != 0 ]]
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid>=' cannot be greater than 1000${NORMAL}"
                  fail=1
               fi
            elif [[ $field =~ 'auid=' ]]
            then
               auidval="$(echo $field | awk -F= '{print $2}')"
               if (( $auidval != 0 ))
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid=' cannot be a value other than '0'${NORMAL}"
                  fail=1
               fi
            elif [[ $field =~ 'auid!=' ]]
            then
               auidval="$(echo $field | awk -F'!=' '{print $2}')"
               if (( $auidval != 'unset' ))
               then
                  echo -e "${NORMAL}RESULT:    ${RED}'auid!=' must be unset${NORMAL}"
                  fail=1
               fi
            fi
         done
      done
   else
      echo -e "${NORMAL}RESULT:    ${RED}$file41 is missing a rule for 'chacl'${NORMAL}"
      fail=2
   fi
   if (( $fail == 0 ))
   then
      echo -e "${NORMAL}$hostname, $severity41, $controlid, $stigid41, $ruleid41, $cci41, $datetime, ${GRN}PASSED, Use of the chacl command is audited${NORMAL}"
   elif (( $fail == 2 ))
   then
      echo -e "${NORMAL}$hostname, $severity41, $controlid, $stigid41, $ruleid41, $cci41, $datetime, ${RED}FAILED, Use of the chacl command is not audited${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity41, $controlid, $stigid41, $ruleid41, $cci41, $datetime, ${RED}FAILED, Use of the chacl command is not configured correctly${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${BLD}$file41 not found${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity41, $controlid, $stigid41, $ruleid41, $cci41, $datetime, ${RED}FAILED, $file41 not found${NORMAL}"
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

file42="/etc/audit/audit.rules"
fail=0
found=0

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file42 ]]
then
   aurules="$(grep '/usr/bin/kmod' $file42 | grep -v '^#')"
   if [[ $aurules ]]
   then
      if [[ $rule =~ '/usr/bin/kmod' ]]
      then
         found=1
      fi
      for rule in ${aurules[@]}
      do
         echo -e "${NORMAL}RESULT:    ${BLD}$rule${NORMAL}"
         if [[ ! $rule =~ ^-a ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing -a ${NORMAL}"
            fail=1
         fi
         if [[ ! $rule =~ 'always,exit' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing 'always,exit'${NORMAL}"
            fail=1
         fi
         if [[ ! $rule =~ '-F perm=x' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-F perm=x'${NORMAL}"
            fail=1
         fi
         if [[ ! $rule =~ 'module' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing 'module'${NORMAL}"
            fail=1
         fi
      done
   else
      echo -e "${NORMAL}RESULT:    ${RED}$file42 is missing a rule for 'kmod'${NORMAL}"
      fail=2
   fi
   if (( $fail == 0 || $found == 1 ))
   then
      echo -e "${NORMAL}$hostname, $severity42, $controlid, $stigid42, $ruleid42, $cci42, $datetime, ${GRN}PASSED, Use of the kmod command is audited${NORMAL}"
   elif (( $fail == 2 ))
   then
      echo -e "${NORMAL}$hostname, $severity42, $controlid, $stigid42, $ruleid42, $cci42, $datetime, ${RED}FAILED, Use of the kmod command is not audited${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity42, $controlid, $stigid42, $ruleid42, $cci42, $datetime, ${RED}FAILED, Use of the kmod command is not configured correctly${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${BLD}$file42 not found${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity42, $controlid, $stigid42, $ruleid42, $cci42, $datetime, ${RED}FAILED, Audit use of kmod: $file42 not found${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid43${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid43${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid43${NORMAL}"
echo -e "${NORMAL}CCI:       $cci434${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 43:   ${BLD}$title43a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title43b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title43c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity43${NORMAL}"

file43a="/etc/pam.d/system-auth"
file43b="/etc/security/faillock.conf"
fail=0
found=0

release="$(echo $os | awk '{print $6}')"

major="$(echo $release | awk -F. '{print $1}')"
minor="$(echo $release | awk -F. '{print $2}')"

datetime="$(date +%FT%H:%M:%S)"

if (( $major == 8  && $minor <= 1 ))
then
  if [[ -f $file43a ]]
  then
     aurules="$(grep -i pam_faillock.so $file43a | grep -v '^#')"
     if [[ $aurules ]]
     then
        for rule in ${aurules[@]}
        do
           if [[ $rule =~ '^auth required' ]]
           then
              found=1
           fi
           echo -e "${NORMAL}RESULT:    ${BLD}$rule${NORMAL}"
           if [[ ! $rule =~ 'preauth' ]]
           then
              echo -e "${NORMAL}RESULT:    ${RED}missing 'preauth'${NORMAL}"
              fail=1
           fi
           if [[ ! $rule =~ 'dir=/var/log/faillock' ]]
           then
              echo -e "${NORMAL}RESULT:    ${RED}missing 'dir=/var/log/faillock'${NORMAL}"
              fail=1
           fi
  	       if [[ ! $rule =~ 'silent' ]]
           then
              echo -e "${NORMAL}RESULT:    ${RED}missing 'silent'${NORMAL}"
              fail=1
           fi
           if [[ ! $rule =~ 'deny=3' ]]
           then
              echo -e "${NORMAL}RESULT:    ${RED}missing 'deny=3'${NORMAL}"
              fail=1
           fi
           if [[ ! $rule =~ 'fail_interval=900' ]]
           then
              echo -e "${NORMAL}RESULT:    ${RED}missing 'fail_interval=900'${NORMAL}"
              fail=1
           fi
           if [[ ! $rule =~ 'even_deny_root' ]]
           then
              echo -e "${NORMAL}RESULT:    ${RED}missing 'even_deny_root'${NORMAL}"
              fail=1
           fi
        done
     else
        echo -e "${NORMAL}RESULT:    ${RED}$file43a is missing a rule for '/var/run/faillock'${NORMAL}"
        fail=2
     fi
   else
      echo -e "${NORMAL}RESULT:    ${BLD}$file43a not found${NORMAL}"
      echo -e "${NORMAL}$hostname, $severity43, $controlid, $stigid43, $ruleid43, $cci43, ${RED}FAILED, $file43 not found${NORMAL}"
   fi
elif (( $major == 8  && $minor >= 2 ))
then
  if [[ -f $file43b ]]
  then
    #location="$(grep dir $file43b | grep '=' | grep -v "^#")"
    location="$(grep dir $file43b | grep '=')"
    if [[ $location ]]
    then
      if [[ ${location:0:1} != "#" ]]
      then
        echo -e "${NORMAL}RESULT:    ${BLD}$location${NORMAL}"
        found=1
      else
        echo -e "${NORMAL}RESULT:    ${RED}$location${NORMAL}"
        fail=1
      fi
    else
      echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
      fail=1
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}$file43b not found${NORMAL}"
    fail=1
  fi
fi

if (( $fail == 0 || $found == 1 ))
then
   echo -e "${NORMAL}$hostname, $severity43, $controlid, $stigid43, $ruleid43, $cci43, $datetime, ${GRN}PASSED, The operating system generates audit records for all unsuccessful account access events${NORMAL}"
elif (( $fail == 2 ))
then
   echo -e "${NORMAL}$hostname, $severity43, $controlid, $stigid43, $ruleid43, $cci43, $datetime, ${RED}FAILED, The operating system does not generate audit records for all unsuccessful account access events${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity43, $controlid, $stigid43, $ruleid43, $cci43, $datetime, ${RED}FAILED, Auditing of unsuccessful account access events is not configured correctly${NORMAL}"
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

file44="/etc/audit/audit.rules"
fail=0
found=0

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file44 ]]
then
   aurules="$(grep -i /var/log/lastlog $file44 | grep -v '^#')"
   if [[ $aurules ]]
   then
      for rule in ${aurules[@]}
      do
         if [[ $rule =~ '-w' && $rule =~ '-p wa ' && $rule =~ 'logins' ]]
         then
            found=1
         fi
         echo -e "${NORMAL}RESULT:    ${BLD}$rule${NORMAL}"
         if [[ ! $rule =~ -w ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-w '${NORMAL}"
            fail=1
         fi
         if [[ ! $rule =~ '-p wa ' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing '-p wa '${NORMAL}"
            fail=1
         fi
         if [[ ! $rule =~ 'logins' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing 'logins'${NORMAL}"
            fail=1
         fi
      done
   else
      echo -e "${NORMAL}RESULT:    ${RED}$file44 is missing a rule for '/var/log/lastlog'${NORMAL}"
      fail=2
   fi
   if (( $fail == 0 || $found == 1 ))
   then
      echo -e "${NORMAL}$hostname, $severity44, $controlid, $stigid44, $ruleid44, $cci44, $datetime, ${GRN}PASSED, The operating system generates audit records for all successsful account access events${NORMAL}"
   elif (( $fail == 2 ))
   then
      echo -e "${NORMAL}$hostname, $severity44, $controlid, $stigid44, $ruleid44, $cci44, $datetime, ${RED}FAILED, The operating system does not generate audit records for all successful account access events${NORMAL}"
   else
      echo -e "${NORMAL}$hostname, $severity44, $controlid, $stigid44, $ruleid44, $cci44, $datetime, ${RED}FAILED, Auditing of successful account access events is not configured correctly${NORMAL}"
   fi
else
   echo -e "${NORMAL}RESULT:    ${BLD}$file44 not found${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity44, $controlid, $stigid44, $ruleid44, $cci44, $datetime, ${RED}FAILED, $file44 not found${NORMAL}"
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

fail=0

datetime="$(date +%FT%H:%M:%S)"

aurules="$(grub2-editenv list | grep audit)"
if [[ $aurules ]]
then
   for rule in ${aurules[@]}
   do
      echo -e "${NORMAL}RESULT:    ${BLD}$rule${NORMAL}"
      if [[ $rule =~ 'kernelopts' && ! $rule =~ 'audit=1' ]]
      then
         echo -e "${NORMAL}RESULT:    ${RED}missing 'audit=1'${NORMAL}"
         fail=1
      fi
   done
else
   echo -e "${NORMAL}RESULT:    ${RED}nothing found${NORMAL}"
   fail=1
fi

if (( $fail == 0 ))
then
   echo -e "${NORMAL}$hostname, $severity45, $controlid, $stigid45, $ruleid45, $cci45, $datetime, ${GRN}PASSED, RHEL 8 enables auditing of processes that start prior to the audit daemon.${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity45, $controlid, $stigid45, $ruleid45, $cci45, $datetime, ${RED}FAILED, RHEL 8 does not enable auditing of processes that start prior to the audit daemon.${NORMAL}"
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

file46="/etc/usbguard/usbguard-daemon.conf"
fail=0

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file46 ]]
then
   aurules="$(grep -i auditbackend $file46)"
   if [[ $aurules ]]
   then
      for rule in ${aurules[@]}
      do
         echo -e "${NORMAL}RESULT:    ${BLD}$rule${NORMAL}"
         if [[ $rule =~ 'kernelopts' && ! $rule =~ 'audit=1' ]]
         then
            echo -e "${NORMAL}RESULT:    ${RED}missing 'audit=1'${NORMAL}"
            fail=1
         fi
      done
   else
      echo -e "${NORMAL}RESULT:    ${RED}nothing found${NORMAL}"
      fail=1
   fi
else
   echo -e "${NORMAL}RESULT:    ${RED}$file46 not found${NORMAL}"
   fail=1
fi

if (( $fail == 0 ))
then
   echo -e "${NORMAL}$hostname, $severity46, $controlid, $stigid46, $ruleid46, $cci46, $datetime, ${GRN}PASSED, RHEL 8 enables Linux audit logging for the USBGuard daemon.${NORMAL}"
else
   echo -e "${NORMAL}$hostname, $severity46, $controlid, $stigid46, $ruleid46, $cci46, $datetime, ${RED}FAILED, RHEL 8 does not enable Linux audit logging for the USBGuard daemon.${NORMAL}"
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
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 47:   ${BLD}$title47a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title47b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title47c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity47${NORMAL}"

IFS='
'

file47a="/etc/audit/auditd.conf"
file47b="/etc/audit/rules.d"
fail=0
found=0

datetime="$(date +%FT%H:%M:%S)"

if [[ -f $file47a ]]
then
  found=1
  file47amode="$(ls -l $file47a)"
  acfmode="$(stat -c %a $file47a)"
  if (( $acfmode <= 640 ))
  then
    echo -e "${NORMAL}RESULT:    ${BLD}$file47amode (mode:  $acfmode)${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}$file47amode (mode:  $acfmode)${NORMAL}"
    fail=1
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}$file47a not found${NORMAL}"
fi

aufiles="$(ls -l $file47b | grep -v '^total')"

if [[ $aufiles ]]
then
  echo "$file47b files -----------------------------------------"
  for file in ${aufiles[@]}
  do
    fname="$(echo $file | awk '{print $9}')"
    fmode="$(stat -c %a $file47b/$fname)"
    if (( $fmode <= 640 ))
    then
      echo -e "${NORMAL}RESULT:    ${BLD}$file (mode:  $fmode)${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${RED}$file (mode:  $fmode)${NORMAL}"
      fail=1
    fi
  done
  echo "------------------------------------------------------------------"
else
  echo -e "${NORMAL}RESULT:    ${BLD}no files found under $file47b${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity47, $controlid, $stigid47, $ruleid47, $cci47, $datetime, ${GRN}PASSED, RHEL 8 allows only the Information System Security Manager (ISSM) (or individuals or roles appointed by the ISSM) to select which auditable events are to be audited.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity47, $controlid, $stigid47, $ruleid47, $cci47, $datetime, ${RED}FAILED, RHEL 8 does not allow only the Information System Security Manager (ISSM) (or individuals or roles appointed by the ISSM) to select which auditable events are to be audited.${NORMAL}"
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
echo -e "${NORMAL}CONTROL:   $controlid${NORMAL}"
echo -e "${NORMAL}TEST 48:   ${BLD}$title48a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title48b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title48c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity48${NORMAL}"

IFS='
'

sysctlcmd="$(command -v systemctl)"
enabled=0
active=0
running=0
fail=1

datetime="$(date +%FT%H:%M:%S)"

if [[ $sysctlcmd ]]
then
  ausvc="$($sysctlcmd status auditd.service)"
  if [[ $ausvc ]]
  then
    for line in ${ausvc[@]}
    do
      line="$(echo $line | sed -e 's/^[[:space:]]*//')"
      if [[ $line =~ 'enabled' ]]
      then
        enabled=1
        echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
      elif [[ $line =~ 'Active' ]]
      then
        active=1
        if [[ $line =~ 'running' ]]
        then
          echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
          running=1
        else
          echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
        fi
      else
        echo -e "${NORMAL}RESULT:    $line${NORMAL}"
      fi
    done
  else
    echo -e "${NORMAL}RESULT:    ${BLD}The kdump service was not found${NORMAL}"
  fi
  if [[ $enabled == 1 && $active == 1 && $running == 1 ]]
  then
    fail=0
  fi

  if (( $fail == 0 ))
  then
    echo -e "${NORMAL}$hostname, $severity48, $controlid, $stigid48, $ruleid48, $cci48, $datetime, ${GRN}PASSED, The RHEL 8 audit service is configured to produce audit records.${NORMAL}"
  else
    echo -e "${NORMAL}$hostname, $severity48, $controlid, $stigid48, $ruleid48, $cci48, $datetime, ${RED}FAILED. The RHEL 8 audit service is not configured to produce audit records.${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${BLD}The 'systemctl' command was not found${NORMAL}"
  echo -e "${NORMAL}$hostname, $severity48, $controlid, $stigid48, $ruleid48, $cci48, $datetime, ${CYN}VERIFY, the 'systemctl' command was not found${NORMAL}"
fi

exit

