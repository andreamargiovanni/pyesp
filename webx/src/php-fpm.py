'''
Created on Jan 8, 2013

@author: martino

Licenza: GPLv3

ToDo: finire nagios, parte SIM (system integrity check) aggiungere demone NTP e logwatch
Consentire di richiedere le info dopo il riepilogo
Finire la rimozione dati di test mysql
Suggerimento del nomeutente in base al dominio
Suggerimento password generata in automatico
In caso di run ripetuto, restart dei servizi (nginx e php-fpm)
'''
from string import split
import string
import urllib2
import os

def printgreen(msg):
    print "\033[92m" + msg + "\033[0m"

def printred(msg):
    print "\033[91m" + msg + "\033[0m"

def infocondef(prompt,default):
    # Input con valore di default tra parentesi quadre
    tmpin = raw_input(prompt + '['+default+'] ')
    if len(tmpin) != 0:
        return tmpin
    else:
        return default

def filedownloaderwithprogress(url,filename):
    # This will print a nice progressbar as the file is downloading
    u = urllib2.urlopen(url)
    f = open(filename, 'wb')
    meta = u.info()
    file_size = int(meta.getheaders("Content-Length")[0])
    print "Scaricamento in corso: %s Bytes: %s" % (filename, file_size)
    
    file_size_dl = 0
    block_sz = 8192
    while True:
        buffer = u.read(block_sz)
        if not buffer:
            break
    
        file_size_dl += len(buffer)
        f.write(buffer)
        status = r"%10d  [%3.2f%%]" % (file_size_dl, file_size_dl * 100. / file_size)
        status = status + chr(8)*(len(status)+1)
        print status,
    
    f.close()

class nagiosinstaller():
    def __init__(self,**kwargs):
        self.nrpeconffile = '/etc/nagios/nrpe.conf'
        self.defaultconf = '''
#############################################################################
# NRPE Config File 
# Written by: Ethan Galstad (nagios@nagios.org)
# 
# Last Modified: 03-10-2013
# By Marcin Czupryniak (martino@turbohosting.it)
#############################################################################


# LOG FACILITY
# The syslog facility that should be used for logging purposes.

log_facility=daemon



# PID FILE
# The name of the file in which the NRPE daemon should write it's process ID
# number.  The file is only written if the NRPE daemon is started by the root
# user and is running in standalone mode.

pid_file=/var/run/nrpe.pid



# PORT NUMBER
# Port number we should wait for connections on.
# NOTE: This must be a non-priviledged port (i.e. > 1024).
# NOTE: This option is ignored if NRPE is running under either inetd or xinetd

server_port=5666



# SERVER ADDRESS
# Address that nrpe should bind to in case there are more than one interface
# and you do not want nrpe to bind on all interfaces.
# NOTE: This option is ignored if NRPE is running under either inetd or xinetd

#server_address=127.0.0.1



# NRPE USER
# This determines the effective user that the NRPE daemon should run as.  
# You can either supply a username or a UID.
# 
# NOTE: This option is ignored if NRPE is running under either inetd or xinetd

nrpe_user=nagios



# NRPE GROUP
# This determines the effective group that the NRPE daemon should run as.  
# You can either supply a group name or a GID.
# 
# NOTE: This option is ignored if NRPE is running under either inetd or xinetd

nrpe_group=nagios



# ALLOWED HOST ADDRESSES
# This is an optional comma-delimited list of IP address or hostnames 
# that are allowed to talk to the NRPE daemon.
#
# Note: The daemon only does rudimentary checking of the client's IP
# address.  I would highly recommend adding entries in your /etc/hosts.allow
# file to allow only the specified host to connect to the port
# you are running this daemon on.
#
# NOTE: This option is ignored if NRPE is running under either inetd or xinetd

allowed_hosts=151.1.96.10,5.134.122.5
 


# COMMAND ARGUMENT PROCESSING
# This option determines whether or not the NRPE daemon will allow clients
# to specify arguments to commands that are executed.  This option only works
# if the daemon was configured with the --enable-command-args configure script
# option.  
#
# *** ENABLING THIS OPTION IS A SECURITY RISK! *** 
# Read the SECURITY file for information on some of the security implications
# of enabling this variable.
#
# Values: 0=do not allow arguments, 1=allow command arguments

dont_blame_nrpe=0



# COMMAND PREFIX
# This option allows you to prefix all commands with a user-defined string.
# A space is automatically added between the specified prefix string and the
# command line from the command definition.
#
# *** THIS EXAMPLE MAY POSE A POTENTIAL SECURITY RISK, SO USE WITH CAUTION! ***
# Usage scenario: 
# Execute restricted commmands using sudo.  For this to work, you need to add
# the nagios user to your /etc/sudoers.  An example entry for alllowing 
# execution of the plugins from might be:
#
# nagios          ALL=(ALL) NOPASSWD: /usr/lib/nagios/plugins/
#
# This lets the nagios user run all commands in that directory (and only them)
# without asking for a password.  If you do this, make sure you don't give
# random users write access to that directory or its contents!

# command_prefix=/usr/bin/sudo 



# DEBUGGING OPTION
# This option determines whether or not debugging messages are logged to the
# syslog facility.
# Values: 0=debugging off, 1=debugging on

debug=0



# COMMAND TIMEOUT
# This specifies the maximum number of seconds that the NRPE daemon will
# allow plugins to finish executing before killing them off.

command_timeout=60



# CONNECTION TIMEOUT
# This specifies the maximum number of seconds that the NRPE daemon will
# wait for a connection to be established before exiting. This is sometimes
# seen where a network problem stops the SSL being established even though
# all network sessions are connected. This causes the nrpe daemons to
# accumulate, eating system resources. Do not set this too low.

connection_timeout=300



# WEEK RANDOM SEED OPTION
# This directive allows you to use SSL even if your system does not have
# a /dev/random or /dev/urandom (on purpose or because the necessary patches
# were not applied). The random number generator will be seeded from a file
# which is either a file pointed to by the environment valiable $RANDFILE
# or $HOME/.rnd. If neither exists, the pseudo random number generator will
# be initialized and a warning will be issued.
# Values: 0=only seed from /dev/[u]random, 1=also seed from weak randomness

#allow_weak_random_seed=1



# INCLUDE CONFIG FILE
# This directive allows you to include definitions from an external config file.

#include=<somefile.cfg>



# INCLUDE CONFIG DIRECTORY
# This directive allows you to include definitions from config files (with a
# .cfg extension) in one or more directories (with recursion).

#include_dir=<somedirectory>
#include_dir=<someotherdirectory>



# COMMAND DEFINITIONS
# Command definitions that this daemon will run.  Definitions
# are in the following format:
#
# command[<command_name>]=<command_line>
#
# When the daemon receives a request to return the results of <command_name>
# it will execute the command specified by the <command_line> argument.
#
# Unlike Nagios, the command line cannot contain macros - it must be
# typed exactly as it should be executed.
#
# Note: Any plugins that are used in the command lines must reside
# on the machine that this daemon is running on!  The examples below
# assume that you have plugins installed in a /usr/local/nagios/libexec
# directory.  Also note that you will have to modify the definitions below
# to match the argument format the plugins expect.  Remember, these are
# examples only!


# The following examples use hardcoded command arguments...


############################# Comandi base ########################################
#
#----------------------------STANDARD-----------------------------------------------------------------
command[check_users]=/usr/lib64/nagios/plugins/check_users -w 3 -c 5
command[check_load]=/usr/lib64/nagios/plugins/check_load -w 4,3,2 -c 6,5,4
command[check_zombie_procs]=/usr/lib64/nagios/plugins/check_procs -w 2 -c 5 -s Z
command[check_total_procs]=/usr/lib64/nagios/plugins/check_procs -w 150 -c 200
command[check_swap]=/usr/lib64/nagios/plugins/check_swap -w 30 -c 10
command[check_yum]=/usr/lib64/nagios/plugins/check_yum
#
#--------------------------NRPE Custom-----------------------------------------------------------------
#
command[check_mem]=/usr/lib64/nagios/plugins/check_mem -w 15 -c 5
command[check_disk_root]=/usr/lib64/nagios/plugins/check_disk -w 20% -c 10% -p /
command[check_ssh_service]=/usr/lib64/nagios/plugins/check_ssh -4 localhost
#
#-------------------------POSTFIX----------------------------------------------------------------------
command[check_smtp_connect]=/usr/lib64/nagios/plugins/check_smtp -H localhost -c 1 -w 5
command[check_postfix_mqueue]=/usr/lib64/nagios/plugins/check_postfix -w 100 -c 250
#
#--------------------------HTTP Port80-------------------------------------------------------------------
command[check_httpd_80]=/usr/lib64/nagios/plugins/check_http -H localhost -w 1 -c 5 -t 10
#
#
#---------------------------MYSQL-------------------------------------------------------------------------
command[check_mysql]=/usr/lib64/nagios/plugins/check_mysql -u nrpe-mysql
#




# The following examples allow user-supplied arguments and can
# only be used if the NRPE daemon was compiled with support for 
# command arguments *AND* the dont_blame_nrpe directive in this
# config file is set to '1'.  This poses a potential security risk, so
# make sure you read the SECURITY file before doing this.

#command[check_users]=/usr/lib64/nagios/plugins/check_users -w $ARG1$ -c $ARG2$
#command[check_load]=/usr/lib64/nagios/plugins/check_load -w $ARG1$ -c $ARG2$
#command[check_disk]=/usr/lib64/nagios/plugins/check_disk -w $ARG1$ -c $ARG2$ -p $ARG3$
#command[check_procs]=/usr/lib64/nagios/plugins/check_procs -w $ARG1$ -c $ARG2$ -s $ARG3$
'''
        self.checkmemplugin = '''#!/usr/bin/env python

"""

    Nagios plugin to report Memory usage by parsing /proc/meminfo
    
    by L.S. Keijser <keijser@stone-it.com>

    This script takes Cached memory into consideration by adding that
    to the total MemFree value.

"""

from optparse import OptionParser
import sys

checkmemver = '0.1'

# Parse commandline options:
parser = OptionParser(usage="%prog -w <warning threshold> -c <critical threshold> [ -h ]",version="%prog " + checkmemver)
parser.add_option("-w", "--warning",
    action="store", type="string", dest="warn_threshold", help="Warning threshold in percentage")
parser.add_option("-c", "--critical",
    action="store", type="string", dest="crit_threshold", help="Critical threshold in percentage")
(options, args) = parser.parse_args()


def readLines(filename):
    f = open(filename, "r")
    lines = f.readlines()
    return lines

def readMemValues():
    global memTotal, memCached, memFree
    for line in readLines('/proc/meminfo'):
        if line.split()[0] == 'MemTotal:':
            memTotal = line.split()[1]
        if line.split()[0] == 'MemFree:':
            memFree = line.split()[1]
        if line.split()[0] == 'Cached:':
            memCached = line.split()[1]

def percMem():
    readMemValues()
    return (((int(memFree) + int(memCached)) * 100) / int(memTotal))

def realMem():
    readMemValues()
    return (int(memFree) + int(memCached)) / 1024

def go():
    if not options.crit_threshold:
        print "UNKNOWN: Missing critical threshold value."
        sys.exit(3)
    if not options.warn_threshold:
        print "UNKNOWN: Missing warning threshold value."
        sys.exit(3)
    if int(options.crit_threshold) >= int(options.warn_threshold):
        print "UNKNOWN: Critical percentage can't be equal to or bigger than warning percentage."
        sys.exit(3)
    trueFree = percMem()
    trueMemFree = realMem()
    if int(trueFree) <= int(options.crit_threshold):
        print "CRITICAL: Free memory percentage is less than or equal to " + options.crit_threshold + "%: " + str(trueFree) + "% (" + str(trueMemFree) + " MiB)"
        sys.exit(2)
    if int(trueFree) <= int(options.warn_threshold):
        print "WARNING: Free memory percentage is less than or equal to " + options.warn_threshold + "%: " + str(trueFree) + "% (" + str(trueMemFree) + " MiB)"
        sys.exit(1)
    else:
        print "OK: Free memory percentage is " + str(trueFree) + "% (" + str(trueMemFree) +" MiB)"
        sys.exit(0)

if __name__ == '__main__':
    go()
        '''
        self.checkyumplugin = '''#!/usr/bin/python
# coding=utf-8

"""Nagios plugin to check the YUM package management system for package updates. Can optionally alert on any available updates as well as just security related updates."""

__title__ = "check_yum"
__version__ = "1.0.0"

#Standard Nagios return codes
OK = 0
WARNING = 1
CRITICAL = 2
UNKNOWN = 3

import os
import re
import sys
import signal
OLD_PYTHON = False
try:
    from subprocess import Popen, PIPE, STDOUT
except ImportError:
    OLD_PYTHON = True
    import commands
from optparse import OptionParser

DEFAULT_TIMEOUT = 55


def end(status, message, perfdata=""):
    """Exits the plugin with first arg as the return code and the second arg as the message to output."""
    
    if perfdata:
        print "%s | %s" % (message, perfdata)
    else:
        print "%s" % message
    
    if status == OK:
        sys.exit(OK)
    elif status == WARNING:
        sys.exit(WARNING)
    elif status == CRITICAL:
        sys.exit(CRITICAL)
    else:
        sys.exit(UNKNOWN)


YUM = "/usr/bin/yum"

def check_yum_usable():
    """Checks that the YUM program and path are correct and usable - that the program exists and is executable, otherwise exits with error."""
    
    if not os.path.exists(YUM):
        end(UNKNOWN, "%s cannot be found" % YUM)
    elif not os.path.isfile(YUM):
        end(UNKNOWN, "%s is not a file" % YUM)
    elif not os.access(YUM, os.X_OK):
        end(UNKNOWN, "%s is not executable" % YUM)


class YumTester:
    """Class to hold all portage test functions and state."""
    
    def __init__(self):
        """Initialize all object variables."""
        
        self.all_updates        = False
        self.no_cache_update    = False
        self.no_warn_on_lock    = False
        self.no_warn_on_updates = False
        self.enable_repo        = ""
        self.disable_repo       = ""
        self.timeout            = DEFAULT_TIMEOUT
        self.verbosity          = 0
        self.warn_on_any_update = False
    
    
    def validate_all_variables(self):
        """Validates all object variables to make sure the environment is sane."""
        
        if self.timeout == None:
            self.timeout = DEFAULT_TIMEOUT
        try:
            self.timeout = int(self.timeout)
        except ValueError:
            end(UNKNOWN, "Timeout must be an whole number, representing the timeout in seconds")
        
        if self.timeout < 1 or self.timeout > 3600:
            end(UNKNOWN, "Timeout must be a number between 1 and 3600 seconds")
        
        if self.verbosity == None:
            self.verbosity = 0
        try:
            self.verbosity = int(self.verbosity)
            if self.verbosity < 0:
                raise ValueError
        except ValueError:
            end(UNKNOWN, "Invalid verbosity type, must be positive numeric integer")
    
    
    def run(self, cmd):
        """Runs a system command and returns an array of lines of the output."""
        
        if cmd == "" or cmd == None:
            end(UNKNOWN, "Internal python error - no cmd supplied for run function")
        
        if self.no_cache_update:
            cmd += " -C"
        
        if self.enable_repo:
            for repo in self.enable_repo.split(","):
                cmd += " --enablerepo=%s" % repo
        if self.disable_repo:
            for repo in self.disable_repo.split(","):
                cmd += " --disablerepo=%s" % repo
        
        self.vprint(3, "running command: %s" % cmd)
        
        if OLD_PYTHON:
            self.vprint(3, "subprocess not available, probably old python version, using shell instead")
            returncode, stdout = commands.getstatusoutput(cmd)
            if returncode >= 256:
                returncode = returncode / 256
        else:
            try:
                process = Popen( cmd.split(), stdin=PIPE, stdout=PIPE, stderr=STDOUT )
            except OSError, error:
                error = str(error)
                if error == "No such file or directory":
                    end(UNKNOWN, "Cannot find utility '%s'" % cmd.split()[0])
                end(UNKNOWN, "Error trying to run utility '%s' - %s" % (cmd.split()[0], error))
            
            output = process.communicate()
            returncode = process.returncode
            stdout = output[0]
        
        if stdout == None or stdout == "":
            end(UNKNOWN, "No output from utility '%s'" % cmd.split()[0])
        
        self.vprint(3, "Returncode: '%s'\nOutput: '%s'" % (returncode, stdout))
        output = str(stdout).split("\n")
        self.check_returncode(returncode, output)
        
        return output
    
    
    def check_returncode(self, returncode, output):
        """Takes the returncode and output (as an array of lines) of the YUM program execution and tests for failures, exits with an appropriate message if any are found."""
        
        if returncode == 0:
            pass
        elif returncode == 100:
            #Updates Available
            pass
        elif returncode == 200:
            if "lock" in output[-2] or "another copy is running" in output[-2]:
                msg = "Cannot check for updates, another instance of YUM is running"
                if self.no_warn_on_lock:
                    end(OK, msg)
                else:
                    end(WARNING, msg)
            else:
                output = self.strip_output(output)
                end(UNKNOWN, "%s" % output)
        else:
            if not 'Loading "security" plugin' in output or "Command line error: no such option: --security" in output:
                end(UNKNOWN, "Security plugin for YUM is required. Try to 'yum install yum-security' and then re-run this plugin. Alternatively, to just alert on any update which does not require the security plugin, try --all-updates")
            else:
                output = self.strip_output(output)
                end(UNKNOWN, "%s" % output)
    
    
    def strip_output(self, output):
        """Cleans up the output from the plugin and returns it. Takes and returns an array of the lines of output and returns a single string."""
        
        self.vprint(3, "stripping output of 'Loading ... plugin' lines")
        re_loading_plugin = re.compile("^Loading .+ plugin$")
        output = [re_loading_plugin.sub("", line) for line in output]
        output = " ".join(output).strip()
        return output
    
    
    def set_timeout(self):
        """Sets an alarm to time out the test."""
        
        if self.timeout == 1:
            self.vprint(3, "setting plugin timeout to %s second" % self.timeout)
        else:
            self.vprint(3, "setting plugin timeout to %s seconds" % self.timeout)
        
        signal.signal(signal.SIGALRM, self.sighandler)
        signal.alarm(self.timeout)
    
    
    def sighandler(self, discarded, discarded2):
        """Function to be called by signal.alarm to kill the plugin."""
        
        #Nop for these variables
        discarded = discarded2
        discarded2 = discarded
        
        end(UNKNOWN, "YUM nagios plugin has self terminated after exceeding the timeout (%s seconds)" % self.timeout)
    
    
    def get_updates(self):
        """Checks for updates and returns a tuple containing the number of security updates and the number of total updates."""
        
        self.vprint(2, "checking for any security updates")
        
        if self.all_updates:
            number_security_updates, number_other_updates = self.get_all_updates()
        else:
            number_other_updates = self.get_security_updates()
            number_security_updates = 0
        
        return number_security_updates, number_other_updates
    
    
    def get_all_updates(self):
        """Gets all updates. Returns a single integer of the number of available updates."""
        
        cmd = "%s check-update" % YUM
        
        output = self.run(cmd)
        
        output2 = "\n".join(output).split("\n\n")
        if self.verbosity >= 4 :
            for section in output2:
                print "\nSection:\n%s\n" % section
        if len(output2) > 2 or not ( "Setting up repositories" in output2[0] or "Loaded plugins: " in output2[0] or re.search('Loading\s+".+"\s+plugin', output2[0]) ):
            end(WARNING, "YUM output signature does not match current known format. Please make sure you have upgraded to the latest version of this plugin. If the problem persists, please contact the author for a fix")
        if len(output2) == 1:
            #There are no updates but we have passed the loading and setting up of repositories
            number_packages = 0
        else:
            number_packages = len([x for x in output2[1].split("\n") if len(x.split()) > 1 ])
        
        try:
            number_packages = int(number_packages)
            if number_packages < 0:
                raise ValueError
        except ValueError:
            end(UNKNOWN, "Error parsing package information, invalid package number, YUM output may have changed. Please make sure you have upgraded to the latest version of this plugin. If the problem persists, then please contact the author for a fix")
        
        #Extra layer of checks. This is a security plugin so it's preferable to fail on error rather than pass silently leaving you with an insecure system
        count = 0
        re_package_format = re.compile("^.+\.(i[3456]86|x86_64|noarch)\s+.+\s+.+$")
        #This is to work around a YUM truncation issue effectively changing the package output format. Currently only very long kmod lines are seen to have caused this so we stick to what we know for safety and raise an unknown error on anything else for maximum security
        #re_package_format_truncated = re.compile("^[\w-]+-kmod-\d[\d\.-]+.*\s+.+\s+.+$")
        for line in output:
            if re_package_format.match(line):
                count += 1
        if count != number_packages:
            end(UNKNOWN, "Error parsing package information, inconsistent package count, YUM output may have changed. Please make sure you have upgraded to the latest version of this plugin. If the problem persists, then please contact the author for a fix")
        
        return number_packages
    
    
    def get_security_updates(self):
        """Gets all updates, but differentiates between security and normal updates. Returns a tuple of the number of security and normal updates."""
        
        cmd = "%s --security check-update" % YUM
        
        output = self.run(cmd)
        
        re_security_summary_rhel5 = re.compile("Needed \d+ of \d+ packages, for security")
        re_security_summary_rhel6 = re.compile("\d+ package\(s\) needed for security, out of \d+ available")
        re_no_security_updates_available_rhel5 = re.compile("No packages needed, for security, \d+ available")
        re_no_security_updates_available_rhel6 = re.compile("No packages needed for security; \d+ packages available")
        summary_line_found = False
        for line in output:
            if re_no_security_updates_available_rhel5.match(line):
                summary_line_found = True
                number_security_updates = 0
                number_total_updates = line.split()[5]
                break
            if re_no_security_updates_available_rhel6.match(line):
                summary_line_found = True
                number_security_updates = 0
                number_total_updates = line.split()[5]
                break
            if re_security_summary_rhel5.match(line):
                summary_line_found = True
                number_security_updates = line.split()[1]
                number_total_updates = line.split()[3]
                break
            if re_security_summary_rhel6.match(line):
                summary_line_found = True
                number_security_updates = line.split()[0]
                number_total_updates = line.split()[7]
                break
        
        if not summary_line_found:
            end(WARNING, "Cannot find summary line in YUM output. Please make sure you have upgraded to the latest version of this plugin. If the problem persists, please contact the author for a fix")
        
        try:
            number_security_updates = int(number_security_updates)
            number_total_updates = int(number_total_updates)
        except ValueError:
            end(WARNING, "Error parsing package information, YUM output may have changed. Please make sure you have upgraded to the latest version of this plugin. If the problem persists, the please contact the author for a fix")
        
        number_other_updates = number_total_updates - number_security_updates
        
        if len(output) > number_total_updates + 25:
            end(WARNING, "YUM output signature is larger than current known format, please make sure you have upgraded to the latest version of this plugin. If the problem persists, please contact the author for a fix")
        
        return number_security_updates, number_other_updates
    
    
    def test_yum_updates(self):
        """Starts tests and controls logic flow."""
        
        check_yum_usable()
        self.vprint(3, "%s - Version %s\n" % (__title__, __version__))
        
        self.validate_all_variables()
        self.set_timeout()
        
        if self.all_updates:
            return self.test_all_updates()
        else:
            return self.test_security_updates()
    
    
    def test_all_updates(self):
        """Tests for all updates, and returns a tuple of the status code and output."""
        
        status = UNKNOWN
        message = "code error - please contact author for a fix"
        
        number_updates = self.get_all_updates()
        if number_updates == 0:
            status = OK
            message = "0 Updates Available"
        else:
            if self.no_warn_on_updates:
                status = OK
            else:
                status = CRITICAL
            if number_updates == 1:
                message = "1 Update Available"
            else:
                message = "%s Updates Available" % number_updates
        
        return status, message
    
    
    def test_security_updates(self):
        """Tests for security updates and returns a tuple of the status code and output."""
        
        status = UNKNOWN
        message = "code error - please contact author for a fix"
        
        number_security_updates, number_other_updates = self.get_security_updates()
        if number_security_updates == 0:
            status = OK
            message = "0 Security Updates Available"
        else:
            if self.no_warn_on_updates:
                status = OK
            else:
                status = CRITICAL
            if number_security_updates == 1:
                message = "1 Security Update Available"
            elif number_security_updates > 1:
                message = "%s Security Updates Available" % number_security_updates
        
        if number_other_updates != 0:
            if self.warn_on_any_update and status != CRITICAL:
                if self.no_warn_on_updates:
                    status = OK
                else:
                    status = WARNING
            
            if number_other_updates == 1:
                message += ". 1 Non-Security Update Available"
            else:
                message += ". %s Non-Security Updates Available" % number_other_updates
        
        return status, message
    
    
    def vprint(self, threshold, message):
        """Prints a message if the first arg is numerically greater than the verbosity level."""
        
        if self.verbosity >= threshold:
            print "%s" % message


def main():
    """Parses command line options and calls the test function."""
    
    tester = YumTester()
    parser = OptionParser()
    
    parser.add_option("--all-updates",
                      action="store_true",
                      dest="all_updates",
                      help="Does not distinguish between security and non-security updates, but returns critical for any available update. This may be used if the YUM security plugin is absent or you want to maintain every single package at the latest version. You may want to use --warn-on-any-update instead of this option.")
    
    parser.add_option("--warn-on-any-update",
                      action="store_true",
                      dest="warn_on_any_update",
                      help="Warns if there are any (non-security) package updates available. By default only warns when security related updates are available. If --all-updates is used, then this option is redundant as --all-updates will return a critical result on any available update, whereas using this switch still allows you to differentiate between the severity of updates.")
    
    parser.add_option("-C", "--cache-only",
                      action="store_true",
                      dest="no_cache_update",
                      help="Run entirely from cache and do not update the cache when running YUM. Useful if you have 'yum makecache' cronned so that the nagios check itself doesn't have to do it, possibly speeding up execution (by 1-2 seconds in tests).")
    
    parser.add_option("--no-warn-on-lock",
                      action="store_true",
                      dest="no_warn_on_lock",
                      help="Return OK instead of WARNING when YUM is locked and fails to check for updates due to another instance running. This is not recommended from the security standpoint, but may be wanted to reduce the number of alerts that may intermittently pop up when someone is running YUM interactively for package management.")
    
    parser.add_option("--no-warn-on-updates",
                      action="store_true",
                      dest="no_warn_on_updates",
                      help="Return OK instead of WARNING even when updates are available. This is not recommended from the security standpoint, but may be wanted to disable alerts while the plugin output still shows the number of available updates.")
    
    parser.add_option("--enablerepo",
                      dest="repository_to_enable",
                      help="Explicitly enables a reposity when calling YUM. Can take a comma separated list of repositories. Note that enabling repositories can lead to unexpected results, for example when protected repositories are enabled.")
    
    parser.add_option("--disablerepo",
                      dest="repository_to_disable",
                      help="Explicitly disables a repository when calling YUM. Can take a comma separated list of repositories. Note that disabling repositories can lead to unexpected results, for example when protected repositories are disabled.")
    
    parser.add_option("-t", "--timeout",
                      dest="timeout",
                      help="Sets a timeout in seconds after which the plugin will exit (defaults to %s seconds)." % DEFAULT_TIMEOUT)
    
    parser.add_option("-v", "--verbose",
                      action="count",
                      dest="verbosity",
                      help="Verbose mode. Can be used multiple times to increase output. Use -vvv for debugging output. By default only one result line is printed as per Nagios standards.")
    
    parser.add_option("-V", "--version",
                      action="store_true",
                      dest="version",
                      help="Print version number and exit.")
    
    (options, args) = parser.parse_args()
    
    if args:
        parser.print_help()
        sys.exit(UNKNOWN)
    
    tester.all_updates        = options.all_updates
    tester.no_cache_update    = options.no_cache_update
    tester.no_warn_on_lock    = options.no_warn_on_lock
    tester.no_warn_on_updates = options.no_warn_on_updates
    tester.enable_repo        = options.repository_to_enable
    tester.disable_repo       = options.repository_to_disable
    tester.timeout            = options.timeout
    tester.verbosity          = options.verbosity
    tester.warn_on_any_update = options.warn_on_any_update
    
    if options.version:
        print "%s - Version %s\n" % (__title__, __version__)
        sys.exit(OK)
    
    result, output = tester.test_yum_updates()
    end(result, output)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print "Caught Control-C..."
        sys.exit(CRITICAL)

        
        '''
        self.mysqlrootpass = ''
        self.pkglist = 'nrpe nagios-plugins-disk nagios-plugins-load nagios-plugins-users nagios-plugins-procs nagios-plugins-http nagios-plugins-mysql nagios-plugins-ssh nagios-plugins-smtp nagios-plugins-tcp'
    
    def writeconf(self):
        conffile = open(self.nrpeconffile,'rw')
        conffile.write(self.defaultconf)
        conffile.close()
        printgreen('File di configurazione /etc/nagios/nrpe.conf scritto correttamente')
    
    def chiediinfo(self):
        if self.mysqlrootpass == '': self.mysqlrootpass = raw_input('Password MYSQL root (per la creazione account probe): ')
    
    def install(self):
        os.system('yum -y install ' + self.pkglist)
        self.writeplugins()
        printgreen("Abilito nrpe per l'avvio automatico")
        os.system('chkconfig nrpe on')
        os.system('service nrpe start')
        
    
    def writeplugins(self):
        self.checkmempluginfile = '/usr/lib64/nagios/plugins/check_mem'
        self.checkyumpluginfile = '/usr/lib64/nagios/plugins/check_yum'
        check_mem = open(self.checkmempluginfile,'rw')
        check_mem.write(self.checkmemplugin)
        check_mem.close()
        os.system('chmod 755 ' + self.checkmempluginfile)
        printgreen('Plugin check_mem scritto correttamente')
        check_yum = open(self.checkyumpluginfile,'rw')
        check_yum.write(self.checkyumplugin)
        check_yum.close()
        os.system('chmod 755 ' + self.checkyumpluginfile)
        printgreen('Plugin check_yum scritto correttamente')
    
class phpmyadmininstaller():
    def __init__(self,**kwargs):
        '''
        @keyword phpmyadminurl: Location from where to grab the phpMyAdmin package
        @keyword installdir: Location of the parent installation directory
        @keyword installname: Name of the directory (for URL mapping, ex. http://mydomain.com/installname)
        @keyword fileowner: Username for chown of the installdir
        @keyword filegroup: Groupname for chown of the installdir
        '''
        self.phpmyadminurl = kwargs.get('phpmyadminurl','http://downloads.sourceforge.net/project/phpmyadmin/phpMyAdmin/4.0.0-beta1/phpMyAdmin-4.0.0-beta1-all-languages.tar.gz')
        self.installdir = kwargs.get('installdir')
        self.fileowner = kwargs.get('fileowner')
        self.filegroup = kwargs.get('filegroup')
        self.installname = kwargs.get('installname','myadmin')
        self.domain = kwargs.get('domain')
        
    def askinfo(self):
        self.installdir = infocondef('Cartella di destinazione?',self.installdir)
        self.installname = infocondef("Nome dell'istanza (determina l'URL es. http://dominio.it/istanza/) ",self.installname)
        riep = '''
Riepilogo:
\033[92m    Cartella destinazione:\033[0m \t%s
\033[92m    Nome istanza:\033[0m \t\t%s
'''
        print riep % (self.installdir,self.installname)
        qst = raw_input("Procedere con l'installazione con i parametri specificati? (y/n) ")
        if qst == 'y':
            self.install()
        
    def install(self):
        import tarfile
        tempfile = 'phpmyadmin.tar.gz'
        filedownloaderwithprogress(self.phpmyadminurl, tempfile)
        printgreen('Download completato, procedo con la decompressione')
        tfile = tarfile.open(tempfile,'r:gz')
        tfile.extractall(self.installname)
        #Remove the top level directory
        os.system(('shopt -s dotglob; cd '+ self.installname +'/phpMyAdmin-4.0.0-beta1-all-languages/; mv * ../; rmdir ../phpMyAdmin-4.0.0-beta1-all-languages'))
        #Set proper ownership
        printgreen('Assegno il proprietario')
        os.system(('chown -R ' + self.fileowner + ':' + self.filegroup + ' ' + self.installname))
        #Move into the desired location
        printgreen('Installo nella cartella specificata: ' + self.installdir + '/' + self.installname)
        os.system(('mv ' + self.installname + ' ' + self.installdir))
        #Delete remporary file
        os.system('rm -f phpmyadmin.tar.gz')
        printgreen('Installazione di base terminata con successo!')
        printred('!!!ATTENZIONE!!! Devi completare la configurazione di phpMyAdmin manualmente!')
        printred("La documentazione necessaria: http://docs.phpmyadmin.net/en/latest/setup.html")
        printred("Non completando questa procedura ti esponi a rischi di sicurezza molto seri.")
        printgreen('Puoi comunque accedere al phpMyAdmin al seguente URL:')
        printgreen(('http://' + self.domain + '/' + self.installname + '/'))

class fail2baninstaller():
    def __init__(self,mailaddr = '',frommail = ''):
        self.mailaddr = mailaddr
        self.frommail = frommail
    
    def chiediinfo(self):
        self.mailaddr = raw_input('Indirizzo email a cui spedire le notifiche: ')
        self.frommail = raw_input('Indirizzo email del campo "da[from]": ')
    
    def replacemail(self):
        import ConfigParser
        conf = ConfigParser.ConfigParser()
        conffile = '/etc/fail2ban/jail.conf'
        conf.read(conffile)
        #Gets the action part of the ssh-iptables section
        act = conf.get('ssh-iptables', 'action')
        newact = act.replace('dest=root','dest=%s' % (self.mailaddr))
        newact2 = newact.replace('sender=fail2ban@example.com','sender=%s' % (self.frommail))
        conf.set('ssh-iptables', 'action', newact2)
        with open(conffile,'wb') as configfile:
            conf.write(configfile)
        printgreen('Configurazione completata')
        
    def install(self):
        printgreen('Installo Fail2ban')
        os.system('yum -y install fail2ban')
        printgreen("Configuro l'avvio automatico del demone")
        os.system('chkconfig fail2ban on')
        printgreen("Configuro le notifiche all'indirizzo impostato")
        self.replacemail()
        printgreen('Avvio fail2ban')
        os.system('service fail2ban start')
        printred('Fail2ban con la configurazione di default protegge solo dagli attacchi SSH')
        printgreen('Per proteggere ulteriori servizi modifica il file /etc/fail2ban/jail.conf')
    
class stringtpl(string.Template):
    delimiter = '$$'
    idpattern = r'[a-z][_a-z0-9]*'

class nginxconf():
    def __init__(self):
        self.errorlog = ''
        self.accesslog = ''
        self.dominio = ''
        self.alias = ''
        self.fpmsock = ''
        self.httpdir = ''
        self.baseconfigtemplate = '''
server {
    listen 80;
    server_name $$servername;

    access_log $$accesslog;
    error_log $$errorlog;

    gzip on;
    gzip_http_version 1.1;
    gzip_comp_level 6;
    gzip_min_length 1100;
    gzip_buffers 4 8k;
    gzip_types text/plain application/xhtml+xml text/css application/xml application/xml+rss text/javascript application/javascript application/x-javascr$
    gzip_proxied     any;
    gzip_disable     "MSIE [1-6]\.";

    client_max_body_size 50m;

    root $$docdir;
    index index.php index.htm index.html;

    location ~ \.php$ {
        try_files $uri =404;
        fastcgi_pass unix:$$fpmsock;
        fastcgi_index index.php;
        fastcgi_param   SCRIPT_FILENAME  $document_root$fastcgi_script_name;
        include        fastcgi_params;
    }
}
'''
        self.configtemplate = stringtpl(self.baseconfigtemplate)

        
    def writeconf(self,file):
        if os.path.exists(file): raise Exception('Un file di configurazione per NGNIX esista gia per questo dominio')
        f = open(file,'w+b')
        servernames = self.dominio
        for aliases in self.alias.split(' '):
            servernames = servernames + ' ' + aliases + '.' + self.dominio
        conf = self.configtemplate.safe_substitute(servername=servernames,
                                                   accesslog = self.accesslog,
                                                   errorlog = self.errorlog,
                                                   docdir = self.httpdir,
                                                   fpmsock = self.fpmsock
                                                   )
        f.write(conf)
        f.close()
        printgreen('File di configurazione di NGINX scritto correttamente')
    
class fpmconf():
    def __init__(self):
        self.baseconfigtemplate = '''
[$$poolname]

; The address on which to accept FastCGI requests.
; Valid syntaxes are:
;   'ip.add.re.ss:port'    - to listen on a TCP socket to a specific address on
;                            a specific port;
;   'port'                 - to listen on a TCP socket to all addresses on a
;                            specific port;
;   '/path/to/unix/socket' - to listen on a unix socket.
; Note: This value is mandatory.
listen = $$socketpath

; Set listen(2) backlog. A value of '-1' means unlimited.
; Default Value: -1
;listen.backlog = -1
 
; List of ipv4 addresses of FastCGI clients which are allowed to connect.
; Equivalent to the FCGI_WEB_SERVER_ADDRS environment variable in the original
; PHP FCGI (5.2.2+). Makes sense only with a tcp listening socket. Each address
; must be separated by a comma. If this value is left blank, connections will be
; accepted from any ip address.
; Default Value: any
;listen.allowed_clients = 127.0.0.1

; Set permissions for unix socket, if one is used. In Linux, read/write
; permissions must be set in order to allow connections from a web server. Many
; BSD-derived systems allow connections regardless of permissions. 
; Default Values: user and group are set as the running user
;                 mode is set to 0666
listen.owner = $$username
listen.group = $$group
listen.mode = 0666

; Unix user/group of processes
; Note: The user is mandatory. If the group is not set, the default user's group
;       will be used.
; RPM: apache Choosed to be able to access some dir as httpd
user = $$username
; RPM: Keep a group allowed to write in log dir.
group = $$group

; Choose how the process manager will control the number of child processes.
; Possible Values:
;   static  - a fixed number (pm.max_children) of child processes;
;   dynamic - the number of child processes are set dynamically based on the
;             following directives:
;             pm.max_children      - the maximum number of children that can
;                                    be alive at the same time.
;             pm.start_servers     - the number of children created on startup.
;             pm.min_spare_servers - the minimum number of children in 'idle'
;                                    state (waiting to process). If the number
;                                    of 'idle' processes is less than this
;                                    number then some children will be created.
;             pm.max_spare_servers - the maximum number of children in 'idle'
;                                    state (waiting to process). If the number
;                                    of 'idle' processes is greater than this
;                                    number then some children will be killed.
; Note: This value is mandatory.
pm = dynamic

; The number of child processes to be created when pm is set to 'static' and the
; maximum number of child processes to be created when pm is set to 'dynamic'.
; This value sets the limit on the number of simultaneous requests that will be
; served. Equivalent to the ApacheMaxClients directive with mpm_prefork.
; Equivalent to the PHP_FCGI_CHILDREN environment variable in the original PHP
; CGI.
; Note: Used when pm is set to either 'static' or 'dynamic'
; Note: This value is mandatory.
pm.max_children = 50

; The number of child processes created on startup.
; Note: Used only when pm is set to 'dynamic'
; Default Value: min_spare_servers + (max_spare_servers - min_spare_servers) / 2
pm.start_servers = 5

; The desired minimum number of idle server processes.
; Note: Used only when pm is set to 'dynamic'
; Note: Mandatory when pm is set to 'dynamic'
pm.min_spare_servers = 5

; The desired maximum number of idle server processes.
; Note: Used only when pm is set to 'dynamic'
; Note: Mandatory when pm is set to 'dynamic'
pm.max_spare_servers = 35
 
; The number of requests each child process should execute before respawning.
; This can be useful to work around memory leaks in 3rd party libraries. For
; endless request processing specify '0'. Equivalent to PHP_FCGI_MAX_REQUESTS.
; Default Value: 0
;pm.max_requests = 500

; The URI to view the FPM status page. If this value is not set, no URI will be
; recognized as a status page. By default, the status page shows the following
; information:
;   accepted conn    - the number of request accepted by the pool;
;   pool             - the name of the pool;
;   process manager  - static or dynamic;
;   idle processes   - the number of idle processes;
;   active processes - the number of active processes;
;   total processes  - the number of idle + active processes.
; The values of 'idle processes', 'active processes' and 'total processes' are
; updated each second. The value of 'accepted conn' is updated in real time.
; Example output:
;   accepted conn:   12073
;   pool:             www
;   process manager:  static
;   idle processes:   35
;   active processes: 65
;   total processes:  100
; By default the status page output is formatted as text/plain. Passing either
; 'html' or 'json' as a query string will return the corresponding output
; syntax. Example:
;   http://www.foo.bar/status
;   http://www.foo.bar/status?json
;   http://www.foo.bar/status?html
; Note: The value must start with a leading slash (/). The value can be
;       anything, but it may not be a good idea to use the .php extension or it
;       may conflict with a real PHP file.
; Default Value: not set 
;pm.status_path = /status
 
; The ping URI to call the monitoring page of FPM. If this value is not set, no
; URI will be recognized as a ping page. This could be used to test from outside
; that FPM is alive and responding, or to
; - create a graph of FPM availability (rrd or such);
; - remove a server from a group if it is not responding (load balancing);
; - trigger alerts for the operating team (24/7).
; Note: The value must start with a leading slash (/). The value can be
;       anything, but it may not be a good idea to use the .php extension or it
;       may conflict with a real PHP file.
; Default Value: not set
;ping.path = /ping

; This directive may be used to customize the response of a ping request. The
; response is formatted as text/plain with a 200 response code.
; Default Value: pong
;ping.response = pong
 
; The timeout for serving a single request after which the worker process will
; be killed. This option should be used when the 'max_execution_time' ini option
; does not stop script execution for some reason. A value of '0' means 'off'.
; Available units: s(econds)(default), m(inutes), h(ours), or d(ays)
; Default Value: 0
;request_terminate_timeout = 0
 
; The timeout for serving a single request after which a PHP backtrace will be
; dumped to the 'slowlog' file. A value of '0s' means 'off'.
; Available units: s(econds)(default), m(inutes), h(ours), or d(ays)
; Default Value: 0
;request_slowlog_timeout = 0
 
; The log file for slow requests
; Default Value: not set
; Note: slowlog is mandatory if request_slowlog_timeout is set
;slowlog = /var/log/php-fpm/www-slow.log
 
; Set open file descriptor rlimit.
; Default Value: system defined value
;rlimit_files = 1024
 
; Set max core size rlimit.
; Possible Values: 'unlimited' or an integer greater or equal to 0
; Default Value: system defined value
;rlimit_core = 0
 
; Chroot to this directory at the start. This value must be defined as an
; absolute path. When this value is not set, chroot is not used.
; Note: chrooting is a great security feature and should be used whenever 
;       possible. However, all PHP paths will be relative to the chroot
;       (error_log, sessions.save_path, ...).
; Default Value: not set
;chroot = 
 
; Chdir to this directory at the start. This value must be an absolute path.
; Default Value: current directory or / when chroot
;chdir = /var/www
 
; Redirect worker stdout and stderr into main error log. If not set, stdout and
; stderr will be redirected to /dev/null according to FastCGI specs.
; Default Value: no
;catch_workers_output = yes
 
; Limits the extensions of the main script FPM will allow to parse. This can
; prevent configuration mistakes on the web server side. You should only limit
; FPM to .php extensions to prevent malicious users to use other extensions to
; exectute php code.
; Note: set an empty value to allow all extensions.
; Default Value: .php
;security.limit_extensions = .php .php3 .php4 .php5

; Pass environment variables like LD_LIBRARY_PATH. All $VARIABLEs are taken from
; the current environment.
; Default Value: clean env
;env[HOSTNAME] = $HOSTNAME
;env[PATH] = /usr/local/bin:/usr/bin:/bin
;env[TMP] = /tmp
;env[TMPDIR] = /tmp
;env[TEMP] = /tmp

; Additional php.ini defines, specific to this pool of workers. These settings
; overwrite the values previously defined in the php.ini. The directives are the
; same as the PHP SAPI:
;   php_value/php_flag             - you can set classic ini defines which can
;                                    be overwritten from PHP call 'ini_set'. 
;   php_admin_value/php_admin_flag - these directives won't be overwritten by
;                                     PHP call 'ini_set'
; For php_*flag, valid values are on, off, 1, 0, true, false, yes or no.

; Defining 'extension' will load the corresponding shared extension from
; extension_dir. Defining 'disable_functions' or 'disable_classes' will not
; overwrite previously defined php.ini values, but will append the new value
; instead.

; Default Value: nothing is defined by default except the values in php.ini and
;                specified at startup with the -d argument
;php_admin_value[sendmail_path] = /usr/sbin/sendmail -t -i -f www@my.domain.com
;php_flag[display_errors] = off
;php_admin_value[error_log] = /var/log/php-fpm/www-error.log
;php_admin_flag[log_errors] = on
;php_admin_value[memory_limit] = 128M

; Set session path to a directory owned by process user
php_value[session.save_handler] = files
php_value[session.save_path] = $$sessiondir
'''
        self.configtemplate = stringtpl(self.baseconfigtemplate)
        self.poolname = ''
        self.sessiondir = ''
        self.user = ''
        self.group = ''
        self.socketpath = ''
        
    def writeconf(self,file):
        if os.path.exists(file): raise Exception('Un file di configurazione per FPM esiste gia per questo dominio')
        f = open(file,'w+b')
        conf = self.configtemplate.safe_substitute(poolname = self.poolname,
                                              socketpath = self.socketpath,
                                              username = self.user,
                                              group = self.group,
                                              sessiondir = self.sessiondir)
        f.write(conf)
        f.close
        printgreen('File di configurazione di php-fpm scritto correttamente')
        printgreen('Disabilito PHP-FPM pool di default (www)')
        os.system('mv /etc/php-fpm.d/www.conf /etc/php-fpm.d/www.conf.disabled')
    
class mysqlconf():
    def __init__(self):
        self.rootpass = ''
        self.dbname = ''
        self.dbuser = ''
        self.dbpass = ''
    
    def chiediinfo(self):
        qst = raw_input('Vuoi configurare adesso un DB MySQL?:(y/n) ')
        if qst == 'y':
            self.rootpass = raw_input('Password di root da impostare per mysql (consigliata): ')
            self.dbuser = raw_input('Nome utente per il nuovo DB: ')
            self.dbpass = raw_input('Password per il nuovo utente: ')
            self.dbname = raw_input('Nome per il nuovo database: ')
            riep = '''
Riepilogo:
\033[92m    Password mysql root:\033[0m \t%s
\033[92m    Utente DB:\033[0m \t\t\t%s
\033[92m    Password utente DB:\033[0m \t%s
\033[92m    Nome DB:\033[0m \t\t\t%s
'''
            print riep % (self.rootpass,self.dbuser,self.dbpass,self.dbname)
            qst = raw_input('Procedere alla configurazione? (y/n/r) ')
            if qst == 'y':
                self.configuremysql()
            if qst == 'r':
                self.chiediinfo()


    def configuremysql(self):
        os.system('yum -y install MySQL-python')
        import MySQLdb
        conn = MySQLdb.connect(host='localhost',user='root')
        cur = conn.cursor()
        cur.execute(("update mysql.user set password=PASSWORD('%s') where User='root';" % (self.rootpass)))
        cur.execute("create database %s" % self.dbname)
        cur.execute("create user '%s'@'localhost' identified by '%s';" % (self.dbuser,self.dbpass))
        cur.execute("grant all privileges on %s.* to '%s'@'localhost';" % (self.dbname,self.dbuser))
        printgreen("Elimino il database di test e l'utente test")
        cur.execute("drop database test;")
        cur.execute("flush privileges;")
        conn.close()
        printgreen('Database configurato correttamente!')
        
class Sysconfiguratore():
    def __init__(self):
        self.dominio = ''
        self.utenteweb = ''
        self.loginshell = ''
        self.gruppo = ''
        self.utentewebpass = ''
        self.aliases = 'www'
        self.homedir = ''
        self.httpdir = ''
        self.logdir = ''
        self.fpmsock = ''
        self.fpmlogs = ''
        self.phpsessiondir = ''
        self.nginxfile = ''
        self.errorlog = ''
        self.accesslog = ''
    
    def verificaselinux(self):
        out = os.popen('getenforce').readlines()
        if out[0].rstrip() != 'Disabled':
            print ("Sul sistema e' in esecuzione SELINUX, lo script potrebbe non funzionare correttamente.")
            q = raw_input('Disattivare SELINUX? [y]:')
            if q == 'y':
                f = open('/etc/sysconfig/selinux','w+b')
                tmp = f.read()
                selinux = tmp.replace('SELINUX=enforcing','SELINUX=disabled')
                f.write(selinux)
                f.close()
                os.system('setenforce permissive')
                printgreen('Selinux verra disattivato completamente al prossimo reboot, temporaneamente settato in permissive mode')
                
    def chiediinfo(self):
        self.dominio = raw_input('Dominio da configurare (es. test.com): ')
        self.aliases = infocondef('Alias da configurare (es. www.test.com)',self.aliases)
        self.utenteweb = raw_input('Utente web: ')
        self.passwordutente = raw_input('Password utente: ')
        self.loginshell = infocondef("Abilitare il login SSH per l'utente?: ",'y')
        self.gruppo = infocondef('Gruppo utente (se inesistente creato automaticamente): ', self.utenteweb)
        self.homedir = '/home/%s/' % self.utenteweb
        self.homedir = infocondef('Homedir: ',self.homedir) 
        self.httpdir = self.homedir + 'www/httpdocs'
        self.httpdir = infocondef('HTTP docs dir: ',self.httpdir)
        self.logdir = self.homedir + 'www/logs'
        self.logdir = infocondef('Log dir: ',self.logdir)
        self.phpsessiondir = self.homedir + 'www/sessions'
        self.phpsessiondir = infocondef('PHP session dir:',self.phpsessiondir)
        self.stampariepilogo()

    def abilitaremirepo(self):
        qst = raw_input('Vuoi abilitare di default la repo REMI (consigliato)? (y/n) ')
        if qst == 'y':
            printgreen('Abilitazione REMI repo')
            repofile = open('/etc/yum.repos.d/remi.repo','r+w')
            repoconf = repofile.read()
            rep = repoconf.replace("enabled=0", "enabled=1", 1)
            repofile.write(rep)
            repofile.close()
            printgreen('Remi REPO abilitata correttamente')

    def stampariepilogo(self):
        riep = '''
Riepilogo settaggi:
\033[92m    Dominio configurato:\033[0m \t%s
\033[92m    Utente HTTP:\033[0m \t\t%s
\033[92m    Password utente:\033[0m \t\t%s
\033[92m    Consenti login:\033[0m \t\t%s
\033[92m    Gruppo:\033[0m \t\t\t%s
\033[92m    Alias attivi:\033[0m \t\t%s
\033[92m    Directory Home HTTP:\033[0m \t%s
\033[92m    Directory HTTP:\033[0m \t\t%s
\033[92m    Log Directory:\033[0m \t\t%s
\033[92m    PHP Session Dir:\033[0m \t\t%s
        '''
        print riep % (self.dominio, self.utenteweb, self.passwordutente,
                      self.loginshell, self.gruppo,str(self.aliases),
                      self.homedir, self.httpdir,self.logdir,self.phpsessiondir)
        qst = raw_input('Procedi con queste impostazioni? (y/n/r) ')
        if qst == 'r':
            self.chiediinfo()
        if qst == 'n':
            exit()
        
    def updatesystem(self):
        qst = raw_input('Aggiorna il sistema prima di procedere? (y/n) ')
        if qst == 'y':
            printgreen('Invoco aggiornamento tramite YUM')
            os.system('yum -y update')
        
    def confrepinstallnginx(self):
        self.nginxrpmurl = 'http://nginx.org/packages/rhel/6/noarch/RPMS/nginx-release-rhel-6-0.el6.ngx.noarch.rpm'
        printgreen('Installo NGINX repo')
        os.system(('yum -y install ' + self.nginxrpmurl))
        printgreen('Installo NGINX')
        os.system('yum -y install nginx')
    
    def installapkg(self):
        epelurl = 'http://dl.fedoraproject.org/pub/epel/6/x86_64/epel-release-6-8.noarch.rpm'
        remiurl = 'http://rpms.famillecollet.com/enterprise/remi-release-6.rpm'
        pkglist = 'postfix php php-fpm php-gd mysql-server php-mysql php-mbstring php-mcrypt'
        printgreen('Installazione di EPEL')
        os.system(('yum -y install ' + epelurl))
        printgreen('Installazione di REMI')
        os.system(('yum -y install ' + remiurl))
        printgreen(('Installazione di pacchetti necessari: ' + pkglist))
        os.system(('yum --enablerepo=remi -y install ' + pkglist))
        
    def aggiungiutente(self):
        os.system(('groupadd ' + self.gruppo))
        if self.loginshell == 'y':
            printgreen("Procedo a creare l'utente con shell di login")
            os.system(('useradd -g '+ self.gruppo + ' ' + self.utenteweb))
        else:
            printgreen("Procedo a creare l'utente senza shell di login")
            os.system(('useradd -s /sbin/nologin -g '+ self.gruppo + ' ' + self.utenteweb))
        printgreen("Configuro password per l'utente")
        os.system(('echo ' + self.passwordutente +' | passwd ' + self.utenteweb + ' --stdin'))
        printgreen("Creo cartelle di base")
        os.system(('mkdir -p ' + self.httpdir))
        printgreen("Creata " + self.httpdir)
        os.system(('mkdir -p ' + self.logdir))
        printgreen("Creata " + self.logdir)
        os.system(('mkdir -p ' + self.phpsessiondir))
        printgreen("Creata " + self.phpsessiondir)
        printgreen("Rendo accessibile la home directory")
        os.system(('chmod 755 ' + self.homedir))
        printgreen("Rendo accessibile la cartella httpdocs")
        os.system(('chmod 755 ' + self.httpdir))
        os.system(('chmod 755 ' + self.homedir + 'www'))
        printgreen('Creo la cartella sessioni di php')
        os.system(('mkdir -p ' + self.phpsessiondir))
        printgreen('Rendo privata la cartella delle sessioni php')
        os.system(('chmod 700 ' + self.phpsessiondir))
        os.system(('chown -vR ' + self.utenteweb + ':' + self.gruppo + ' ' + self.homedir))
            
    def generanginxconfig(self):
        self.errorlog = self.logdir + '/' + self.dominio + '.error.log'
        self.accesslog = self.logdir + '/' + self.dominio + '.access.log'
        self.nginxconf = nginxconf()
        self.nginxconf.dominio = self.dominio
        self.nginxconf.httpdir = self.httpdir
        self.nginxconf.errorlog = self.errorlog
        self.nginxconf.accesslog = self.accesslog
        self.nginxconf.alias = self.aliases
        self.nginxconf.fpmsock = self.fpmsock
        self.nginxfile = '/etc/nginx/conf.d/' + self.dominio + '.conf'
        self.nginxconf.writeconf(self.nginxfile)
    
    def generaphpfpmconfig(self):
        self.fpmconf = fpmconf()
        self.fpmconf.user = self.utenteweb
        self.fpmconf.group = self.gruppo
        self.fpmconf.poolname = self.dominio
        self.fpmconf.sessiondir = self.phpsessiondir
        self.fpmsock = self.homedir + 'www/fpm.sock'
        self.fpmconf.socketpath = self.fpmsock
        self.fpmfile = '/etc/php-fpm.d/' + self.dominio + '.conf'
        self.fpmconf.writeconf(self.fpmfile)
        
    def configuraservizi(self):
        printgreen("Configuro l'avvio automatico dei servizi: nginx, php-fpm e mysql")
        os.system('chkconfig php-fpm on')
        os.system('chkconfig mysqld on')
        os.system('chkconfig nginx on')
        printgreen("Attivo i servizi: nginx, php-fpm, mysql")
        os.system('service php-fpm start')
        os.system('service mysqld start')
        os.system('service nginx start')
    
    def configurafirewall(self):
        self.regolebaseiptables = '''
# Automatically configured by Turbohosting script
*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
-A INPUT -p icmp -j ACCEPT
-A INPUT -i lo -j ACCEPT
-A INPUT -m state --state NEW -m tcp -p tcp --dport 22 -j ACCEPT
-A INPUT -m state --state NEW -m tcp -p tcp --dport 80 -j ACCEPT
#Monitoring Armada
-A INPUT -m state --state NEW -m tcp -p tcp -s 5.134.122.5 --dport 5666 -j ACCEPT
-A INPUT -j REJECT --reject-with icmp-host-prohibited
-A FORWARD -j REJECT --reject-with icmp-host-prohibited
COMMIT
'''
        qst = raw_input('Configurare ed avviare il firewall con impostazioni di base? (y/n): ')
        if qst == 'y':
            printgreen('Scrivo regole del firewall per porte: 22, 80')
            f = open('/etc/sysconfig/iptables','w+b')
            f.write(self.regolebaseiptables)
            f.close()
            os.system('service iptables restart')
            printgreen('Firewall configurato correttamente!')
        
sets = Sysconfiguratore()
sets.verificaselinux()
sets.chiediinfo()
sets.updatesystem()
sets.confrepinstallnginx()
sets.installapkg()
sets.abilitaremirepo()
sets.aggiungiutente()
sets.generaphpfpmconfig()
sets.generanginxconfig()
sets.configuraservizi()
sets.configurafirewall()
mysql = mysqlconf()
mysql.chiediinfo()
phpmyadmin = phpmyadmininstaller(installdir=sets.httpdir, fileowner=sets.utenteweb, 
                                 filegroup=sets.gruppo,domain=sets.dominio)
qst = raw_input('Vuoi installare adesso phpMyAdmin? (y/n) ')
if qst == 'y':
    phpmyadmin.askinfo()
    
fail2ban = fail2baninstaller()
qst = raw_input('Vuoi installare adesso fail2ban (consigliato)? (y/n) ')
if qst == 'y':
    fail2ban.chiediinfo()
    fail2ban.install()