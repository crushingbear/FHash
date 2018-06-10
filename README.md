# FHash

FHash is a command line utility, written in Python, to hash a drive or directory. It produces a report of File name, path directory, size, date created, last date accessed and last date modified. You can chose between MD5, SHA1, SHA256 and SHA512 algorithms. The log file is that. It logs the paths of the files, start time, end time, user running the utility, the hash type chosen and if chosen, will log the hash of the report file.


**Usage:**
    C:> python fhash -d C:\\users\\joe smith\\pictures\\  -r c:\\temp\ -md5 -v -x

    -v, --verbose,  help="allows progress messages to be displayed"
    -x, --hashreport, help="hashes final CSV report and adds hash to log file with timestamp"
    -d, --rootPath
    -r, --reportPath
    -MD5, SHA1, SHA256 or SHA512, help="choose hashing method"
    
Log file is stored in same directory from where the script is run. 
    

**Log file contains all the information from the report as well as the following:**

1. Time and date report was generated 
2. Machine name and type from which script was run on 
3. Logged in user who ran the script  
4. Records keyboard interupt if script is stopped before finishing 





 
