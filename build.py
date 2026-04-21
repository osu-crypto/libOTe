import os
import subprocess
import sys


folder = os.path.dirname(os.path.realpath(__file__))
if os.path.exists(folder+"/cryptoTools/CMakeLists.txt") == False:
    subprocess.check_call("git submodule update --init", shell=True)

import cryptoTools.build


def replace(argv, find, rep):
    return cryptoTools.build.replace(argv, find, rep)


if __name__ == "__main__":

    argv = sys.argv
    replace(argv, "--bitpolymul", "-DENABLE_SILENTOT=ON -DENABLE_BITPOLYMUL=ON")
    replace(argv, "--all", "-DENABLE_ALL_OT=ON")
    sys.exit(cryptoTools.build.main("libOTe", argv[1:]))
