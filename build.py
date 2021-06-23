import os
import sys
import cryptoTools.build

import thirdparty.getBitpolymul as getBitpolymul


def getParallel(args):
    par = multiprocessing.cpu_count()
    for x in args:
        if x.startswith("--par="):
            val = x.split("=",1)[1]
            par = int(val)
            if par < 1:
                par = 1
    return par


def Setup(install, prefix, par):
    dir_path = os.path.dirname(os.path.realpath(__file__))
    os.chdir(dir_path + "/thirdparty")


    getBitpolymul.get(install,prefix, par)

    os.chdir(dir_path)




if __name__ == "__main__":
	
   
    (mainArgs, cmake) = cryptoTools.build.parseArgs()
    install, prefix = cryptoTools.build.getInstallArgs(mainArgs)
    par = cryptoTools.build.getParallel(mainArgs)

    bitpolymul = "--bitpolymul" in mainArgs
    setup = "--setup" in mainArgs
    if setup and bitpolymul:
        Setup(install, prefix, par)

    cryptoTools.build.main("libOTe")
