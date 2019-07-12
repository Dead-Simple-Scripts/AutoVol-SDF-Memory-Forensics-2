#! /bin/bash
#SDF Memory Forensics 2
# Script to autorun volatility plugins
echo "SDF Memory Forensics 2"
echo "Volatility Script"
echo ""
echo "Usage: autovol.sh <Memory image> "
echo ""
echo "Example: ./autovol.sh memory_image.dat "
echo ""
# Start of Autovol script
echo "****************************"
echo "*  autovol script started  *"
echo "****************************"
echo ""
#
echo "Plugin results will be saved to the /results folder"
echo "Files extracted from memory will be saved to the /exports folder"
echo ""
# SETUP OPERATIONS
mkdir results
mkdir exports
res=results
exp=exports
echo ""
echo "Identiying the KDBG signature with imageinfo, results pending"
echo ""
date > $res/imageinfo_"$1"_.txt
vol.py -f $1 imageinfo | tee -a $res/imageinfo_"$1"\_.txt
echo ""
echo "Enter the KDBG signature to use for this memory image, example Win2008R2SP1"
read kdbg
echo ""
echo "The operating system profile selected is :  --profile="$kdbg

# SEND ALL ERRORS TO NULL
exec 2>/dev/null

# PART 1: PLUGINS TO FIND SUSPICIOUS PROCESSES
echo ""
echo "pslist plugin running, results pending"
echo ""
vol.py -f $1 --profile=$kdbg pslist > $res/pslist_$1\_.txt
echo ""
echo "pslist completed"
echo ""
#
echo ""
echo "psscan plugin running, results pending"
echo ""
vol.py -f $1 --profile=$kdbg psscan  1>$res/psscan_$1\_.txt
echo ""
echo "psscan completed"
echo ""
#
echo ""
echo "pstree plugin running, results pending"
echo ""
vol.py -f $1 --profile=$kdbg pstree > $res/pstree_$1\_.txt
echo ""
echo "pstree completed"
echo ""
#
echo ""
echo "psxview plugin running, results pending"
echo ""
vol.py -f $1 --profile=$kdbg psxview > $res/psxview_$1\_.txt
echo ""
echo "psxview completed"
echo ""
#  POST PROCESSING LOGIC - part 1
echo ""
echo "Searching psxview results, results pending"
echo ""
grep -E -i "false" $res/psxview_$1\_.txt > $res/psxview_false_$1\_.txt
echo ""
echo "psxview search completed"
echo ""
echo ""
#
echo ""
echo "Searching pslist results, results pending"
echo ""
grep -E -i "(system|wininit|lsass|lsaiso|lsm|services)" $res/pslist_$1\_.txt > $res/pslist_singletons_$1\_.txt
grep -E -i "(system|wininit|lsass|lsaiso|lsm|services|sms|taskhost|winlogon|iexplore|explorer|svchost|csrss)" $res/pslist_$1\_.txt > $res/pslist_windowscore_$1\_.txt
grep -E -i -v "(system|wininit|lsass|lsaiso|lsm|services|sms|taskhost|winlogon|iexplore|explorer|svchost|csrss)" $res/pslist_$1\_.txt > $res/pslist_exclude_windows_core_$1\_.txt
echo "pslist search completed"
echo ""
# taskhost triage for pslist and psscan
echo "Taskhost triage:
The taskhost file name is different depending on the OS version it is running on. Use the following guide to determine if there is a notable taskhost processing in memory.

- taskhost.exe for Win7
- taskhostex.exe for Win8
- taskhostw.exe for Win10

********************" >> $res/pslist_taskhostcheck_$1\_.txt
grep -E -i "taskhost" $res/pslist_$1\_.txt >> $res/pslist_taskhostcheck_$1\_.txt
echo ""
echo ""
#
echo "Taskhost triage:
The taskhost file name is different depending on the OS version it is running on. Use the following guide to determine if there is a notable taskhost processing in memory.

- taskhost.exe for Win7
- taskhostex.exe for Win8
- taskhostw.exe for Win10

********************" >> $res/psscan_taskhostcheck_$1\_.txt
grep -E -i "taskhost" $res/psscan_$1\_.txt >> $res/psscan_taskhostcheck_$1\_.txt


# PART 2: FINDING MALWARE LOADED IN MEMORY
#
echo ""
echo "malfind plugin running, results pending"
echo ""
vol.py -f $1 --profile=$kdbg malfind > $res/malfind_$1\_.txt
echo ""
echo "malfind completed"
echo ""
#
echo ""
echo "Using malfind to extract possible executables inside processes, results pending"
echo ""
vol.py -f $1 --profile=$kdbg malfind -D $exp
file $exp/* > $res/malfind_file_check_$1\_.txt
echo ""
echo "Malfind \export completed"
echo ""
echo ""
#
echo ""
echo "Dumping DLLs from memory, results pending"
echo ""
vol.py -f $1 --profile=$kdbg dlldump -D $exp
echo ""
echo "Dlldump completed"
echo ""
echo ""
#
echo ""
echo "Extracting executables from kernel memory, results pending"
echo ""
vol.py -f $1 --profile=$kdbg moddump -D $exp
echo ""
echo "Moddump completed"
echo ""
echo ""
#
echo ""
echo "Checking exported executables with Clamscan, results pending"
echo ""
clamscan $exp | grep -v ": OK$" > $res/clamscan_$1\_.txt
echo ""
echo "Clamscan completed"
echo ""
echo ""
#
echo ""
echo "Hashing MD5 exported files, results pending"
echo ""
md5sum $exp/* > $res/md5_exports_$1\_.txt
cut -d " " -f1 $res/md5_exports_$1\_.txt > $res/md5_exports_just_md5s_$1\_.txt
echo ""
echo "MD5 hashing completed"
echo ""
echo ""

# PART 3: OTHER USEFUL PLUGINS
#
echo ""
echo "dlllist plugin running, results pending"
echo ""
vol.py -f $1 --profile=$kdbg dlllist > $res/dlllist_$1\_.txt
echo ""
echo "dlllist completed"
echo ""
#
echo ""
echo "shimcache plugin running, results pending"
echo ""
vol.py -f $1 --profile=$kdbg shimcache > $res/shimcache_$1\_.txt
echo ""
echo "shimcache completed"
echo ""
#
echo ""
echo "shimcachemem plugin running, results pending"
echo ""
vol.py -f $1 --profile=$kdbg shimcachemem > $res/shimcachemem_$1\_.txt
echo ""
echo "shimcachemem completed"
echo ""
#
echo ""
echo "mftparser plugin running, results pending"
echo ""
vol.py -f $1 --profile=$kdbg mftparser > $res/mftparser_$1\_.txt
echo ""
echo "mftparser completed"
#
echo ""
echo "Running Mactime on mftparser results, UTC+0 offset being used, results pending"
echo ""
vol.py -f $1 --profile=$kdbg mftparser --output=body | mactime -d -z UTC-0 > $res/mftparser_mactime_$1\_.csv
echo ""
echo "Mactime conversion complete"
echo ""

#  POST PROCESSING LOGIC - part 3
#
echo ""
echo "Searching mftparser results for malware indicators, results pending"
echo ""
grep -E -o -i "[\\][a-z0-9A-Z]{1,4}\.(exe|bat|dll|py|txt|vbs)" $res/mftparser_$1\_.txt | sort | uniq -c | sort -n > $res/mftparser_notables_$1\_.txt
cut -d "," -f8 $res/mftparser_mactime_$1\_.txt | grep -E -o -i "[^ ]*[\\][a-z0-9A-Z]{1,4}\.(exe|bat|dll|py|txt|vbs)" | sort | uniq -c | sort -n > $res/mftparser_mactime_notables_$1\_.txt
echo ""
echo "MFTparser search completed"
echo ""
echo ""
#
echo ""
echo "Searching dlllist results for malware indicators, results pending"
echo ""
grep -E -i "[\\][a-z0-9A-Z]{1,4}\.(exe|bat|dll|py|txt|vbs)" $res/dlllist_$1\_.* | sort | uniq -c | sort -n > $res/dlllist_notables_$1\_.txt
echo ""
echo "dlllist search completed"
echo ""
echo ""
#
echo ""
echo "autovol script has completed"
