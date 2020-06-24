#!/usr/bin/python
# -*- coding: UTF-8 -*-

import os
import subprocess
import shutil
import json
import sys
import logging
import hashlib
import filetype
from zipfile import ZipFile

from rarfile import  RarFile
from py7zr import SevenZipFile


DOWNLOADS = os.path.normpath('./.downloads/')
EXAMPLE_DIR = os.path.normpath('../example/')
JSON_DB = os.path.join(EXAMPLE_DIR, 'example.json')
AUTOIT3 = os.path.normpath('C:/Program Files (x86)/AutoIt3/AutoIt3.exe')

# json db key
FILE_DIR_KEY = 'file_dir'
INSTALL_SCRIPT_KEY = 'install_script'
RELEASE_PATH_KEY = 'release_path'
INSTALL_TYPE_KEY = 'install_type'


class NotInDbError(Exception):
    pass

class RepetInstallError(Exception):
    pass

class DownloadError(Exception):
    pass

class InstallEXEError(Exception):
    pass


def py2Download(url, filePath):
    import urllib2
    f = urllib2.urlopen(url)

    # Open our local file for writing
    with open(filePath, "wb") as local_file:
        local_file.write(f.read())


def py3Download(url, filePath):
    import urllib.request
    urllib.request.urlretrieve(url, filePath)


def downloader(url, filePath):

    if sys.version_info.major == 2:
        py2Download(url, filePath)
    else:
        py3Download(url, filePath)

    return filePath


def createDir(dirPath):
    if os.path.exists(dirPath) == False:
        os.makedirs(dirPath)

    return dirPath


def downloadEXE(url):
    dirPath = createDir(DOWNLOADS)
    fileName = os.path.basename(url)
    EXEPath = dirPath + '/' + fileName

    downloader(url, EXEPath)

    return EXEPath


def getFileMd5(filePath):
    with open(filePath, 'rb') as fp:
        data=fp.read()
    md5 = hashlib.md5(data).hexdigest()

    return md5


def checkExistsInDB(md5):
    with open(JSON_DB) as f:
        dictData = json.load(f)

    if md5 in dictData:
        return True

    return False


def getEXEInfoByMd5(md5):
    with open(JSON_DB) as f:
        dictData = json.load(f)

    return dictData[md5]


def unzipFileToDir(zipFilePath, dirPath):
    with ZipFile(zipFilePath, 'r') as zipObj:
        zipObj.extractall(dirPath)


def unrarFileToDir(rarFilePath, dirPath):
    with RarFile(rarFilePath) as rarObj:
        rarObj.extractall(dirPath)


def un7zipFileToDir(sevenZipFilePath, dirPath):
    with SevenZipFile(sevenZipFilePath, mode='r') as sevenZipObj:
        sevenZipObj.extractall(dirPath)


def getFileType(filePath):
    kind = filetype.guess(filePath)
    if kind is None:
        raise RuntimeError('Cannot guess file type!')

    return kind.extension


def installIndependEXE(EXEPath, installPath):
    shutil.copy(EXEPath, installPath)


def installCompressionEXE(EXEPath, installPath):
    zipFilePath = EXEPath
    unzipDirPath = installPath

    extension = getFileType(EXEPath)

    if 'zip' == extension:
        unzipFileToDir(zipFilePath, unzipDirPath)
    elif 'rar' == extension:
        unrarFileToDir(zipFilePath, unzipDirPath)
    elif '7z' == extension:
        un7zipFileToDir(zipFilePath, unzipDirPath)
    else:
        raise  RuntimeError('unprocessed compressed file!')


def installSetupExe(EXEPath, au3ScriptPath):
    installCommand = AUTOIT3 + ' ' + au3ScriptPath + ' ' + EXEPath
    logging.info('install command: %s' %installCommand)
    subprocess.call([AUTOIT3, au3ScriptPath, EXEPath])


def installEXE(EXEPath, md5):

    logging.info('---------- %s START ----------' %md5)


    EXEInfo = getEXEInfoByMd5(md5)
    installType = int(EXEInfo[INSTALL_TYPE_KEY])


    installPath = None

    if 0 == installType:
        independDir = EXEInfo[RELEASE_PATH_KEY]
        createDir(independDir)
        installIndependEXE(EXEPath, independDir)
        installPath = independDir
    elif 1 == installType:
        decompressDir = EXEInfo[RELEASE_PATH_KEY]
        createDir(decompressDir)
        installCompressionEXE(EXEPath, decompressDir)
        installPath = decompressDir

    elif 2 == installType:
        fileDir = EXEInfo[FILE_DIR_KEY]
        au3Script = EXEInfo[INSTALL_SCRIPT_KEY]
        au3ScriptPath = os.path.join(EXAMPLE_DIR, fileDir, au3Script)

        installSetupExe(EXEPath, au3ScriptPath)
        installPath = EXEInfo[RELEASE_PATH_KEY]

    logging.info('---------- %s  END ----------' %md5)
    return installPath


def getBinFiles(installPath):
    installAbsPath = os.path.abspath(installPath)
    if os.path.exists(installAbsPath) == False:
        raise RuntimeError('install path(%s) does not exist, perhaps the installation failed or the path provided was incorrect!')

    binFiles = []
    for root, dirs, files in os.walk(installAbsPath):
        for file in files:
            if '.exe' == file[-4:] or '.dll' == file[-4:] or '.sys' == file[-4:]:
                binFiles.append(os.path.join(root, file))

    return binFiles



def checkInstalled(md5):
    EXEinfo = getEXEInfoByMd5(md5)
    release_path = EXEinfo[RELEASE_PATH_KEY]


    return os.path.exists(release_path)



def autoInstall(url):
    try:
        EXEPath = downloadEXE(url)
    except Exception as e:
        logging.error(e)
        logging.error("download exe(%s) failed!" %url)
        raise DownloadError('Download failed')



    md5 = getFileMd5(EXEPath)
    if checkExistsInDB(md5) is True:
        pass
    elif checkExistsInDB(md5.upper()) is True:
        md5 = md5.upper()
    else:
        logging.error("Exe(%s) is not in db!"  %EXEPath)
        raise NotInDbError('Exe is not in db!')


    if checkInstalled(md5) == True:
        logging.error("Md5(%s): Exe(%s) is installed!"  %(md5, EXEPath))
        raise RepetInstallError('This exe is installed!')


    try:
        installPath = installEXE(EXEPath, md5)
    except Exception as e:
        logging.error(e)
        logging.error("Md5(%s): Exe(%s) installation failed!" %(md5, EXEPath))
        raise InstallEXEError('Install program failed!')

    binFiles = getBinFiles(installPath)

    return binFiles

