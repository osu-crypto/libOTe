import os
import sys
import cryptoTools.build

import thirdparty.getBitpolymul as getBitpolymul

def replace(argv, find, rep):
    return cryptoTools.build.replace(argv, find, rep)

    os.chdir(dir_path)




if __name__ == "__main__":
	
    argv = sys.argv
    replace(argv, "--bitpolymul", "-DENABLE_SILENTOT=ON")
    replace(argv, "--all", "-DENABLE_BITPOLYMUL=ON -DENABLE_SODIUM=ON -DENABLE_ALL_OT=ON")
    cryptoTools.build.main("libOTe", argv[1:])
