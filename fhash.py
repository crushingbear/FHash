# 
# FHASH Python File System Hash Program
# Based on pyfish by C. Hosmer
# Originally found in Python Forensics Book
# 

import logging    
import time       
import sys        
import os         
import stat       
import time       
import hashlib    
import argparse   
import csv   
import platform  
import getpass   


#
# Name: ExceptionHook() Function
#
def except_hook(exctype, value, traceback):
    t = time.strftime("%a, %b %d %Y %I:%M:%S %p")
    if exctype == KeyboardInterrupt:
        print("\n")
        print ("Scan Cancled " + str(t))
        logging.warning(getpass.getuser() +' Escaped the program: ' + t)
    else:
        sys.__excepthook__(exctype, value, traceback)
sys.excepthook = except_hook


#
# Name: ParseCommand() Function
#
def ParseCommandLine():
	parser = argparse.ArgumentParser(
		add_help=True,
		description="""FHASH - Python file system hashing utility that supports MD5, SHA1, SHA256 and SHA512 with a CSV output report and log function.
		Log file is located in the same directory as the utlity is run""")
	group = parser.add_argument_group()
	group.add_argument('-v', "--verbose",  help="allows progress messages to be displayed", action='store_true')
	group.add_argument('-x', "--hashreport", help="hashes final CSV report and adds hash to log file with timestamp", action='store_true')

	group = parser.add_mutually_exclusive_group(required=True)
	group.add_argument('--md5',      help = 'specifies MD5 algorithm',      action='store_true')
	group.add_argument('--sha1',     help = 'specifies SHA1 algorithm',     action='store_true')    
	group.add_argument('--sha256',   help = 'specifies SHA256 algorithm',   action='store_true')    
	group.add_argument('--sha512',   help = 'specifies SHA512 algorithm',   action='store_true')   
   
	parser.add_argument('-d', '--rootPath',   type= ValidateDirectory, required=True, help="specify the root path for hashing.")
	parser.add_argument('-r', '--reportPath', type= ValidateDirectoryWritable, required=True, help="specify the path for reports will be written.")   
	
	global gl_args
	global gl_hashType
	#global gl_hashDict
	global gl_verbose
	global gl_hashreport

	gl_args = parser.parse_args()   

	if gl_args.verbose:
		gl_verbose = True
	else:
		gl_verbose = False
	if gl_args.hashreport:
		gl_hashreport = True
	else:
		gl_hashreport = False
	


	if gl_args.md5:
		gl_hashType = 'MD5'
	elif gl_args.sha1:
		gl_hashType = 'SHA1'            
	elif gl_args.sha256:
		gl_hashType = 'SHA256'   
	elif gl_args.sha512:
		gl_hashType = 'SHA512'
	else:
		gl_hashType = "Unknown"
		logging.error('Unknown Hash Type Specified')

	DisplayMessage("Command line processed: Successfully")

	return

#
# Name: ValidateDirectory Function
#
def ValidateDirectory(theDir):
	if not os.path.isdir(theDir):
		raise argparse.ArgumentTypeError('Directory does not exist')
	if os.access(theDir, os.R_OK):
		return theDir
	else:
		raise argparse.ArgumentTypeError('Directory is not readable')
	

#
# Name: ValidateDirectoryWritable Function
#
def ValidateDirectoryWritable(theDir):
	if not os.path.isdir(theDir):
		raise argparse.ArgumentTypeError('Directory does not exist')
	if os.access(theDir, os.W_OK):
		return theDir
	else:
		raise argparse.ArgumentTypeError('Directory is not writable')


#
# Name: ValidateFileReadable Function
#
def ValidateFileReadable(theFile):
	if not os.path.isfile(theFile):
		raise argparse.ArgumentTypeError('File does not exist')
	if os.access(theFile, os.R_OK):
		return theFile
	else:
		raise argparse.ArgumentTypeError('File is not readable')


#
# Name: WalkPath() Function
#
def WalkPath():
	processCount = 0
	errorCount = 0 
	reportPath = os.path.join(gl_args.reportPath, "fhash_report.csv")
	oCVS = _CSVWriter(reportPath, gl_hashType,)

	if gl_args.rootPath.endswith('\\') or gl_args.rootPath.endswith('/'):
		rootPath = gl_args.rootPath
	else:
		rootPath = gl_args.rootPath+'/'

	logging.info('Start Scan Path: ' + rootPath)   
	for root, dirs, files in os.walk(rootPath):
		for file in files:
			fname = os.path.join(root, file)
			result = HashFile(fname, file, oCVS)

			if result is True:
				processCount += 1
			else:
				errorCount += 1       
	oCVS.writerClose()
	return(processCount)


#
# Name: HashFile Function
#
def HashFile(theFile, simpleName, o_result):
	if os.path.exists(theFile):
		if not os.path.islink(theFile):
			if os.path.isfile(theFile):
				try:
					f = open(theFile, 'rb')
				except IOError:
					logging.warning('Open Failed: ' + theFile)
					return
				else:
					try:
						read_size = 2048
						theFileStats =  os.stat(theFile)
						(mode, ino, dev, nlink, uid, gid, size, atime, mtime, ctime) = os.stat(theFile)
						rd = f.read(read_size)
					except IOError:
						f.close()
						logging.warning('File Access Error: ' + theFile)
						return
					else:
						DisplayMessage("Processing File: " + theFile)
						logging.info("Processing File: " + theFile)
						fileSize = str(size)

						modifiedTime = time.ctime(mtime)
						accessTime   = time.ctime(atime)
						createdTime  = time.ctime(ctime)

						if gl_args.md5:
							hash = hashlib.md5()
							hash.update(rd)
							hexMD5 = hash.hexdigest()
							hashValue = hexMD5.upper()
						elif gl_args.sha1:
							hash = hashlib.sha1()
							hash.update(rd)
							hexSHA1 = hash.hexdigest()
							hashValue = hexSHA1.upper()	                         
						elif gl_args.sha256:
							hash = hashlib.sha256()
							hash.update(rd)
							hexSHA256 = hash.hexdigest()
							hashValue = hexSHA256.upper()
						elif gl_args.sha512:
							hash=hashlib.sha512()
							hash.update(rd)
							hexSHA512 = hash.hexdigest()
							hashValue = hexSHA512.upper()
						else:
							logging.error('Hash not Selected')

						resultList = [simpleName, theFile, fileSize, modifiedTime, accessTime, createdTime, hashValue]     
						o_result.writeCSVRow(resultList)

						DisplayMessage("================================")
						return True
			else:
				logging.warning('[' + repr(simpleName) + ', Skipped NOT a File' + ']')
				return False
		else:
			logging.warning('[' + repr(simpleName) + ', Skipped Link NOT a File' + ']')
			return False
	else:
		logging.warning('[' + repr(simpleName) + ', Path does NOT exist' + ']')        
	return False



#
# Name: DisplayMessage() Function
#
def  DisplayMessage(msg):
	if gl_verbose:
		print(msg)
	return   

# 
# Class: _CSVWriter 
#
class _CSVWriter:
	def __init__(self, fileName, hashType):
		try:
			if (sys.version_info > (3, 0)):
				self.csvFile = open(fileName, 'a',newline="\r\n")
			else:
				self.csvFile = open(fileName, 'a')
			tempList = ['File', 'Path', 'Size', 'Modified Time', 'Access Time', 'Created Time', hashType]
			outStr = ",".join(tempList)
			self.csvFile.write(outStr)
			self.csvFile.write("\n")
		except:
			logging.error('CSV File Open Failure')
			DisplayMessage("Error Opening CSV File")
			DisplayMessage("Make sure CSV File Location is Writable and Ensure the file is not open")
			quit()

	def writeCSVRow(self, outList):
		outStr = ",".join(outList)
		self.csvFile.write(outStr)
		self.csvFile.write("\n")

	def writerClose(self):
		self.csvFile.close()


#
# Name: HashReport() Function
#

def ReportHash():
	if gl_hashreport:
		reportPath = os.path.join(gl_args.reportPath, "fhash_report.csv")
		h = hashlib.sha256()
		with open(reportPath, 'rb') as f:
			for b in iter(lambda : f.read(128*1024), b''):
				h.update(b)
			return h.hexdigest()
	return

# ------------ MAIN SCRIPT STARTS HERE -----------------

if __name__ == '__main__':
	FHASH_VERSION = ' 1.0.1'
	ReleaseDate   = "February 8, 2018"
	logging.basicConfig(filename='FHASH.log',level=logging.DEBUG,format='%(asctime)s %(message)s')
	ParseCommandLine()
	startTime = time.time()
	logging.info('Welcome to FHASH Python hash tool')
	logging.info('Version'+ FHASH_VERSION)
	logging.info('Release Date: '+ ReleaseDate)
	logging.info('Starting Scan with ' + gl_hashType + ' hash')
	DisplayMessage('Wecome to FHASH; Version: '+ FHASH_VERSION + ' Release Date: ' + ReleaseDate + '\n')
	logging.info('System:  '+ platform.system() +' '+ platform.release() + ' ' + platform.machine())
	logging.info('Version: '+ platform.version())
	logging.info('Machine Analyst: '+ getpass.getuser())

	filesProcessed = WalkPath()
	reportProcessed = ReportHash()
	endTime = time.time()
	duration = endTime - startTime

	logging.info('Files Processed: ' + str(filesProcessed) )
	logging.info('Elapsed Time: ' + str(duration) + ' seconds')
	logging.info('Program Terminated Normally')
	DisplayMessage('Files Processed: ' + str(filesProcessed) )
	DisplayMessage('Elapsed Time: ' + str(duration) + ' seconds')
	DisplayMessage('')
	logging.info('Report Hash: ' + str(reportProcessed))
	DisplayMessage("Program End")
	logging.info('')


# The End!