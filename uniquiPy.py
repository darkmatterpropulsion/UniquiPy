import hashlib
from pathlib import Path
import os
import shutil
import argparse
import sys
import yaml


BLOCK_SIZE = 65536


def fingerPrint(path):
	hash_method = hashlib.sha256()
	with open(path,"rb") as input_file:
		buf = input_file.read(BLOCK_SIZE) 
		while len(buf) > 0: 
			hash_method.update(buf) 
			buf = input_file.read(BLOCK_SIZE)
	return hash_method.hexdigest()


def searchPath(basepath):
	paths = []
	pathlist= Path(basepath).glob("**/*")
	for path in pathlist:
		if os.path.isfile(path) == True:
			paths.append(str(path))
	return paths


	
def isUnique(path,hashes,key):
	hashToCheck = fingerPrint(path)
	if hashToCheck in hashes[key]:
		return False,hashes[key]
	else:
		hashes[key].append(hashToCheck)
		return True,hashes[key]

	
def getFileName(rootName):
	fileNamePieces = rootName.split("/")
	return fileNamePieces[len(fileNamePieces) - 1]
	
def generateFolderHash(path):
	hash = []
	paths = searchPath(path)
	for singlePath in paths:
		hash.append(fingerPrint(singlePath))
	return hash

def createDir(path):
	if os.path.exists(path) == False:
		try:
			os.mkdir(path)
			return []
		except PermissionError:
			print("it appears that you don't have the permission to access " + path + ". Skipping...")
			return []
		except FileExistsError:
			print("It appears that the file already exists but was not detected.")
			return []
	else:
		return generateFolderHash(path)

	
def main():

	pathsToCheck = []
	pathToWrite = []
	allThePaths = []
	hashes = {}
	
	with open("unique.yaml","r") as f:
		data = yaml.safe_load(f)
		pathsToCheck = data['sources']
		pathToWrite = data['destination']
		for item in data['extensions']:
			for key in item.keys():
				hash = []
				hash = createDir(''.join(map(str,pathToWrite)) + "/" + key)				
				hashes[key] = hash	
	print(hashes)	

	for path in pathsToCheck:
		allThePaths.extend(searchPath(path))
		

	for path in allThePaths:
		rootName, fileExtension = os.path.splitext(path)
		fileName = getFileName(rootName)
		for item in data['extensions']:
			for key,values in item.items():
				if fileExtension in values:
					unique, hashes[key] = isUnique(path,hashes,key)
					if unique == True:
						shutil.copyfile(path,''.join(map(str,pathToWrite)) + "/" + f"{key}" +"/" + fileName + fileExtension)
						print(("[+]" + " Writing " + ''.join(map(str,pathToWrite)) + "/" + f"{key}" +"/" + fileName + fileExtension).encode(encoding="UTF-8",errors="strict"))
					else:
						print(("[-]" + " " + ''.join(map(str,pathToWrite))  + "/" + f"{key}" +"/" + fileName + fileExtension + " is already presesent").encode(encoding="UTF-8",errors="strict"))

if __name__ == '__main__':
	main()
