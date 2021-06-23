
import os 
import sys 
import platform


def get(install, prefix, par):
    
    cwd = os.getcwd()
    #thirdparty = os.path.dirname(os.path.realpath(__file__))
    
    if os.path.isdir("bitpolymul") == False:
        os.system("git clone https://github.com/ladnir/bitpolymul.git")

    os.chdir(cwd + "/bitpolymul")
    os.system("git checkout 5ccd7c0aeffded477806b21d54a20ad3ef78b3fa")

    buildDir = cwd + "/bitpolymul/build"
        
    config = ""
    argStr = "-DCMAKE_BUILD_TYPE=Release"
    
    osStr = (platform.system())
    sudo = ""
    if(osStr == "Windows"):
        config = " --config Release "
        buildDir = buildDir + "_win"
        if not install:
            prefix = cwd + "/win"
    else:
        if install and "--sudo" in sys.argv:
            sudo = "sudo "
        buildDir = buildDir + "_linux"
        if not install:
            prefix = cwd + "/unix"


    
    parallel = ""
    if par != 1:
        parallel = "--parallel " + str(par)
        
    CMakeCmd = "cmake -S . -B {0} {1}".format(buildDir, argStr)
    BuildCmd = "cmake --build {0} {1} {2} ".format(buildDir, config, parallel)

    InstallCmd = "{0}cmake --install {1}".format(sudo, buildDir)
    if len(prefix):
        InstallCmd += " --prefix {0} ".format(prefix)
    
    print("\n\n=========== getBitpolymul.py ================")
    print("mkdir "+ buildDir)
    print(CMakeCmd)
    print(BuildCmd)
    print(InstallCmd)
    print("vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv\n\n")

    if not os.path.exists(buildDir):
        os.mkdir(buildDir)

    os.system(CMakeCmd)
    os.system(BuildCmd)
    
    if len(sudo):
        print ("Installing bitpolymul: {0}".format(InstallCmd))

    os.system(InstallCmd)



if __name__ == "__main__":
    getBitpolymul(False, "", 1)
