BINARYDIR := Debug

#Toolchain
CXX := g++
LD := $(CXX)
AR := ar
OBJCOPY := objcopy

#Additional flags
PREPROCESSOR_MACROS :=  
INCLUDE_DIRS := ./libOTe ./libOTe_Tests ./thirdparty/linux ./thirdparty/linux/boost/includes ./thirdparty/linux/miracl ./thirdparty/linux/ntl/include
LIBRARY_DIRS := ./thirdparty/linux/boost/stage/lib ./thirdparty/linux/cryptopp ./thirdparty/linux/miracl/miracl/source ./thirdparty/linux/ntl/src ./bin/
SHARED_LIBRARY_NAMES := pthread rt
STATIC_LIBRARY_NAMES := boost_system boost_filesystem boost_thread miracl cryptopp PSI PSITests ntl
ADDITIONAL_LINKER_INPUTS := 
MACOS_FRAMEWORKS := 
LINUX_PACKAGES := 


CXXFLAGS := -ggdb -ffunction-sections -O0 -Wall -std=c++11 -maes -msse2 -msse4.1 -mpclmul -Wfatal-errors -pthread
LDFLAGS := -Wl,-gc-sections
COMMONFLAGS := 

START_GROUP := -Wl,--start-group
END_GROUP := -Wl,--end-group

