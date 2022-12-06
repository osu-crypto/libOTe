import os
import sys


folder = os.path.dirname(os.path.realpath(__file__))
if os.path.exists(folder+"/cryptoTools/CMakeLists.txt") == False:
    os.system("git submodule update --init")

import cryptoTools.build


def replace(argv, find, rep):
    return cryptoTools.build.replace(argv, find, rep)


if __name__ == "__main__":

    argv = sys.argv
    replace(argv, "--bitpolymul", "-DENABLE_SILENTOT=ON -DENABLE_BITPOLYMUL=ON")
    replace(argv, "--all", "-DENABLE_ALL_OT=ON")
    cryptoTools.build.main("libOTe", argv[1:])
