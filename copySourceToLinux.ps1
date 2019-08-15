$RemoteUserName='rindalp'
$RemoteHostName='eve.eecs.oregonstate.edu'
$PrivateKey='C:/keys/key.ppk'
$SolutionDir=$PWD
$RemoteWorkingDir='/scratch/repo/libOTe'

# only files with these extensions will be copied
$FileMasks='**.cpp;**.c;**.h;*.bin,*.S,*.sh,*CMake*;*.in;*/KyberOT/keccak4x/KeccakP-1600-times4-SIMD256.o;*/Tools/*.txt;*/gsl/*;**/Makefile;**.data;thirdparty/linux/**.get;*/libOTe_Tests/testData/*.txt'

# everything in these folders will be skipped
$ExcludeDirs='.git/;thirdparty/;Debug/;Release/;x64/;ipch/;.vs/;CMakeFiles/;boost/'

C:\tools\WinSCP.com  /command `
    "open $RemoteUserName@$RemoteHostName -privatekey=""$PrivateKey"""`
    "call mkdir -p $RemoteWorkingDir"`
    "synchronize Remote $SolutionDir $RemoteWorkingDir -filemask=""$FileMasks|$ExcludeDirs;"" -transfer=binary"`
    "call mkdir -p $RemoteWorkingDir/cryptoTools/thirdparty/"`
    "call mkdir -p $RemoteWorkingDir/cryptoTools/thirdparty/linux/"`
    "synchronize remote $SolutionDir/cryptoTools/thirdparty/linux/ $RemoteWorkingDir/cryptoTools/thirdparty/linux/ -filemask=""**.get|$ExcludeDirs"" -transfer=binary"`
    "exit" 