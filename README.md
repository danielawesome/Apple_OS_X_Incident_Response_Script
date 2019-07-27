
Apple_OS_X_Incident_Response_Script


What is this?
----------------------

This is an incident response script for the Apple OS X Operating System.

The primary goal of the script is to help an Incident Responder quickly determine if a system has been compromised.
The script gathers user, system information, running process, 3rd party applications and browser history.


Note - The Apple OS X script requires a root/admin or the user’s password to run correctly. The Apple OS X script also creates a second file containing List of Open Files(LSOF) data.


Instructions
----------------------

1. Copy the Apple.py script to a USB or external hard drive.
2. When responding to an incident, plug in the USB or external hard drive to the infected or compromised  system.
3. Open a command line terminal and change directories to your USB or external hard drive where the script exists. 

4. Type the following command and enter the user’s password when prompted…


   For Apple OS X systems:
   -----------------------

   sudo python.exe apple.py <username> <directory location>

   
   For example, $ sudo python.exe apple.py jdoe .	
   
   This will collect IR data for username JDoe and save the results to your current working directory 
   
   Another one,  $ sudo python.exe apple.py jdoe /Volume/USB	  	
   
   This will collect IR data for username JDoe and save the results to an external USB Device



Now what?
---------------


Two files should be created, our IR script and our LSOF file…

1. MacBook-Pro_2019-07-25_19/56/22.txt 	 <— This is the IR script results. The filename is based on Hostname_Year-Month-Date_Hour/Minutes/Seconds

2. lsof_2019-07-25_17/52/12.txt			 <— This is the LSOF output results. This will give you more verbose data but may be helpful in your investigation 


Recommendation:
-----------------------

The best way to understand how this script works is to run it on your personal system and see what data the script can extract.


To Do List:
--------------

	•	Add Safari Browser History results
	•	Add Safari Form Values. Helpful for phishing incidents where the user still has Safari set as their default browser. We can usually confirm a user entered their credentials during a phishing incident by looking here
	
