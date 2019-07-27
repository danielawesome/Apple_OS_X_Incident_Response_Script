
#/usr/bin/python

################################################
##
##  Apple OS X Incident Response script
##
##  Written by: Daniel Cosio
##
##  Modified Date: 06/24/2019
##  Version: 1.75
##
################################################

import sys, time, datetime, socket
import subprocess
from subprocess import Popen, PIPE
import os
import glob
import xml.parsers.expat
import commands, re
import warnings
import traceback

fqdn = socket.gethostname()
sysName = fqdn.split('.')[0]
today = time.strftime("%Y-%m-%d_%H:%M:%S")
audi5000 = time.strftime("%Y-%m-%d at %H:%M:%S")
user = sys.argv[1]
appleEpoch = 978307200



# The following function captures System information
def sysConfig():
    f = open(sys.argv[2] + '/' + sysName +'_'+today+'.txt', 'w')
    print "\n***** Apple OS X Incident Response Script *****\n"
    print "OS X Incident Response script started on " + audi5000

    print "\nwhoami:"
    run('whoami')

    print "\n*** A list of binaries we plan to run to collect our data ***"
    print "*** Check the SHA-256 Hash values if you have any doubts ***\n"
    run(' shasum /usr/bin/whoami ; shasum /bin/date ; shasum /usr/bin/w ; shasum /bin/hostname ; shasum /usr/bin/hostinfo ; shasum /usr/bin/sw_vers ; shasum /sbin/mount ; shasum /bin/df ; shasum /sbin/ifconfig ; shasum /bin/ps ; shasum /usr/sbin/netstat ; shasum /bin/bash ; shasum /bin/ls ; shasum /usr/bin/plutil ')
    
    print "\n******** w ***************\n"
    run('w')

    print "\n****** Hostname *********\n"
    run('hostname')

    print "\n****** Hostinfo *********\n"
    run('hostinfo')
	
    print "\nOS X version:"
    run('sw_vers')
	
    print "\n**** Mount and Drive Info ****\n"
    print "mount:"
    run('mount')
    print"\ndf -k:"
    run('df -k')
    
# We check if Filevault2 exist. If the file is not found (Error Code 32512), we bail.
    print "\n****** Encryption Status *****\n"
    
    print "\nOS X 10.8 and above - FileVault2 status:"
    status, result = commands.getstatusoutput("fdesetup")
    if status == 32512:
        print ("Filevault2 commands are not supported. System is running OS X 10.7 or older.")
    else:
        run('sudo fdesetup status')

    print "\n******** ifconfig *********\n"
    run('ifconfig')

    print "\n***** Running Process *****\n"
    run('ps -ef')

    print "\n****** lsof Connections ******"
    run('lsof -i')

 # This plist file does not exist after OS X 10.8--> so we first test if it exist    
    status, result = commands.getstatusoutput('/Library/Preferences/SystemConfiguration/com.apple.network.identification.plist')
    if status == 32512:
        pass
    else:
    	print "\n***** Network and DNS config ******\n"
    	print "Location and Modified time:"
    	run('ls -lt /Library/Preferences/SystemConfiguration/com.apple.network.identification.plist')
        print"\n"
        run('plutil -convert xml1 -o - /Library/Preferences/SystemConfiguration/com.apple.network.identification.plist | grep -w "string\|key" |  sed -e "s/<string>//g" | sed -e "s/<key>//g" | sed -e "s/<\/string>//g" | sed -e "s/<\/key>//g" | sed -e "s/	//g" | sed "/^$/d"  |  sed -e "s/Timestamp/		/g" ')
        print "\n"

def userInfo():
    print "\n******* User's LoginItems  *********\n"
    print "Location and Modified time:"
    run('ls -lt /Users/' + user + '/Library/Preferences/com.apple.loginwindow.plist')
    
    print "\n"
    print "Startup Items at Login:"
    run('plutil -convert xml1 -o - /Users/' + user + '/Library/Preferences/com.apple.loginitems.plist | grep "<string>" |  sed -e "s/<string>//g" |  sed -e "s/<\/string>//g"')

    print "\n******* User's Recent Items  *********\n"
    print "Location and Modified time:"
    run('ls -lt /Users/' + user + '/Library/Preferences/com.apple.recentitems.plist')
    
    print "\n"
    print "Recent Items:"
    run('plutil -convert xml1 -o - /Users/' + user + '/Library/Preferences/com.apple.recentitems.plist | grep "<string>" |  sed -e "s/<string>//g" |  sed -e "s/<\/string>//g" ')
    
# Lauchd is the first process started in user-mode and is responsible for starting every other process on the system. It is the equivalent of UNIX's init or rc.d
# Lauchd runs as root and with a PID of 1. So of course we want to monitor its Daemons and Agents
    
    print "\n******* Launchd agents provided by the User (Executed for this user only) *********\n"
    print "Location: " + '/Users/' + user + '/Library/LaunchAgents/'
    print "\nModified time:"
    run('ls -ltrO /Users/' + user + '/Library/LaunchAgents/')
    
    print "\n****** Launchd agents provided by Administrator (Executed for this entire system) *******\n"
    print "Location: /Library/LaunchAgents/"
    print "\nModified time:"
    run('ls -ltrO /Library/LaunchAgents/')
    
    print "\n******* Launchd System-wide daemons provided by the Administrator (Third Party Daemons) *******\n"
    print "Location: /Library/LaunchDaemons/\n"
    print "Modified time:"
    run('ls -ltrO /Library/LaunchDaemons')
        
    print "\n******* Launchd Per-user agents provided by Mac OS X  (OS Agents) *******"
    print "             *******        Last Ten Entries      *********\n"
    print "Location: /System/Library/LaunchAgents/\n"
    print  "Modified time:"
    run('ls -ltrO /System/Library/LaunchAgents | tail -n 10')
    
    print "\n******* Launchd System-wide daemons provided by Mac OS X  (OS Daemons) *******"
    print "             *******        Last Ten Entries      *********\n"
    print "Location: /System/Library/LaunchDaemons/\n"
    print "Modified time: "
    run('ls -ltrO /System/Library/LaunchDaemons | tail -n 10')

# Crash dumps can be useful to reconstruct binaries and collect data that was stored in memory at the time of crash
    print "\n******* Recent Crash Dumps (User Only) *******\n"
    print "Location: " + '/Users/' + user + '/Library/Logs/CrashReporter/'
    print  "\nModified time: "
    if os.path.exists('/Users/' + user + '/Library/Logs/CrashReporter'):
        run('ls -ltrO /Users/' + user + '/Library/Logs/CrashReporter')
    else:
        print "Found no dump files in " + '/Users/' + user + '/Library/Logs/CrashReporter'

    print "\n******* Recent Crash Dumps (System Wide) *******\n"
    print "Location: /Library/Logs/CrashReporter/\n"
    print "Modified time:"
    if os.path.exists("/Library/Logs/CrashReporter"):
        run('ls -ltrO /Library/Logs/CrashReporter')
    else:
        print "Found no dump files in " + "/Library/Logs/CrashReporter"
    
    print "\n******* USB Data *******\n"
    print "Note: This only captures timestamps and Unique Identifiers \n"
    #try:
    if os.path.exists("/var/log/kernel.log"):
        run('cat /var/log/kernel.log | grep "USBMSC Identifier"')
    else:
        run('cat /var/log/system.log | grep "USBMSC Identifier"')


# Most browser data except for Safari is stored in a Sqlite3 DB.
# So if a user has FireFox or Chrome, the database is locked and we cannnot grab browser history :(
# Close the browser if you need their browser history.

def browserData():

    print "\n******** Download History ***********\n"
    print "|-- Timestamp --|-- URL--|-- URL Origin --|-- User Agent --|"
    run("""sqlite3 /Users/""" + user + """/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV* 'SELECT datetime(LSQuarantineTimestamp + 978307200,"unixepoch"), LSQuarantineDataURLString,  LSQuarantineOriginURLString, LSQuarantineAgentName FROM LSQuarantineEvent ORDER by LSQuarantineTimestamp asc'""")
    
    print "\n****** Firefox  History *******\n"
    print "|-- Timestamp --|-- URL--|"
    fireHist = glob.glob(os.path.expanduser("~" + user)+"/Library/Application Support/Firefox/Profiles/*.default/places.sqlite")
    statement = " " + "\"" + (", ".join(fireHist)) + "\"" + " " + """'SELECT datetime(moz_historyvisits.visit_date/1000000,"unixepoch", "localtime"), moz_places.url FROM moz_places, moz_historyvisits WHERE moz_places.id = moz_historyvisits.place_id ORDER by visit_date asc'"""
    args = ('sqlite3' + statement)
    run(args)
    
    print "\n****** Firefox  Cookies *******\n"
    print "|-- Timestamp --|-- Domain--|-- Host--|-- Path--|-- Value--|-- Expires --|"
    fireHist = glob.glob(os.path.expanduser("~" + user)+"/Library/Application Support/Firefox/Profiles/*.default/cookies.sqlite")
    statement = " " + "\"" + (", ".join(fireHist)) + "\"" + " " + """'SELECT datetime(moz_cookies.lastAccessed/1000000,"unixepoch", "localtime"), baseDomain, host, name, value, datetime(moz_cookies.expiry,"unixepoch", "localtime")  FROM moz_cookies ORDER by lastAccessed asc'"""
    args = ('sqlite3' + statement)
    run(args)
    
    print "\n****** Firefox Forms *******\n"
    print "|-- Last Used --|-- Field Name --|-- Value --|-- First Used --|"
    fireHist = glob.glob(os.path.expanduser("~" + user)+"/Library/Application Support/Firefox/Profiles/*.default/formhistory.sqlite")
    statement = " " + "\"" + (", ".join(fireHist)) + "\"" + " " + """'SELECT datetime(moz_formhistory.lastUsed/1000000,"unixepoch", "localtime"), fieldname, value, datetime(moz_formhistory.firstUsed/1000000,"unixepoch", "localtime")  FROM moz_formhistory ORDER by lastUsed asc'"""
    args = ('sqlite3' + statement)
    run(args)

    print "\n****** Firefox Extensions *******\n"
    print "|-- Install Date --|-- Install Location--|-- Version--|-- Source URI --|"
    fireHist = glob.glob(os.path.expanduser("~" + user)+"/Library/Application Support/Firefox/Profiles/*.default/extensions.sqlite")
    statement = " " + "\"" + (", ".join(fireHist)) + "\"" + " " + """'SELECT datetime(installDate/1000000,"unixepoch", "localtime"), descriptor, version, sourceURI FROM addon ORDER by installdate asc'"""

    try:
        altrun(args)
    except OSError:
        print ("Error: no such table: addon")
    
    print "\n****** Google Chrome History ******\n"
    print "|-- Timestamp --|-- URL--|-- URL Title --|"
    run("""sqlite3 /Users/""" + user + """/Library/Application\ Support/Google/Chrome/Default/History 'SELECT datetime(((visits.visit_time/1000000)-11644473600), "unixepoch", "localtime"), urls.url, urls.title FROM urls, visits WHERE urls.id = visits.url ORDER by visit_time asc'""")


    print "\n****** Google Chrome Cookies ******\n"
    print "|-- Last Accessed --|-- URL--|-- URL Name --|-- Path --|-- Value --|-- Expires --|"
    run("""sqlite3 /Users/""" + user + """/Library/Application\ Support/Google/Chrome/Default/Cookies h""")

    print "\n****** Google Chrome Forms ******\n"
    print "|-- Last Used --|-- Name--|-- Value --|-- Date Created --|"
    run("""sqlite3 /Users/""" + user + """/Library/Application\ Support/Google/Chrome/Default/Web\ Data 'SELECT  datetime( autofill.date_last_used, "unixepoch", "localtime"), name, value,  datetime( autofill.date_created, "unixepoch", "localtime") FROM autofill ORDER BY date_last_used asc;'""")

    
def appsAndKext():
    print "\n******** Installed Apps *********\n"
    print "*** Use <codesign -dvv /Applications/AppName.app> to gather info about an App ***"
    print "*********************************************************************************\n"
    run('ls -ltrO /Applications/')
    
    print "\n********* Kext Apps (Unsigned-Apps Requiring Kernel-Mode Access) *********"
    print "Note: This field should be empty... \n"
    print "Index Refs Address            Size       Wired      Name (Version) <Linked Against>"
    run('kextstat | grep -i unsigned')


def misc():
    print "\n***** User's CRON Jobs *****\n"
    try:
        run('crontab -l')
    except OSError:
        print  "no crontab for " + user

    print "\n***** User's History Commands *****\n"
    bashHist = 'bash -i -c "history -r; history"'
    run(bashHist)

    print "\n******** Last Login ***************\n"
    run('last')

    print "\n******* User's Trash Bin ********\n"
    try:
       run('ls -ltrO /Users/' + user + '/.Trash/')
    except OSError:
        print ("Trash Bin is Empty")


def elFin():
    print "\n\n******** The following data is written to another file **************"
    print "\nWriting lsof output to ./lsof_"+today+".txt directory\n"
    run('lsof > ' + sys.argv[2] + '/' + 'lsof_'+today+'.txt')
    run('netstat -an >> ' + sys.argv[2] + '/' + 'lsof_'+today+'.txt')

    print "Done"

    print "\n******* Additional OS X Resources *******\n"
    print "plutil -convert xml1 -o - <plist_location>" 
    print "Examine contents of a plist file.\n"
    print "codesign -dvv /Applications/AppName.app"
    print "Gather information about an installed App.\n"
    
    print "sudo /usr/bin/opensnoop"
    print "Will run as a low level debugger that can monitor network connections at the Kernel layer."
    print "Example, locate a rootkit process calling home."
    print "Press Command-Z when done.\n"
            
    print "*****************************\n"
    print "OS X Incident Response script completed on " + time.strftime("%Y-%m-%d at %H:%M:%S")
    print "\n******** Finished **********\n"


def main():
    sysConfig()
    userInfo()
    browserData()
    misc()
    appsAndKext()
    elFin()

def run(command):
    proc = subprocess.Popen(command, stdout=subprocess.PIPE, shell=True)
    (out, err) = proc.communicate()
    print out

def altrun(command):
    proc = subprocess.Popen(command, stdout=subprocess.PIPE, shell=False)
    (out, err) = proc.communicate()
    print out

if __name__ == '__main__':
    sys.stdout = open(sys.argv[2] + '/' + sysName +'_'+today+'.txt', 'w')
    main()

