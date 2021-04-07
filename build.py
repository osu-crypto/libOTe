import cryptoTools.build
import sys



if __name__ == "__main__":
	if(len(sys.argv) > 1 and sys.argv[1] == "setup"):
		cryptoTools.build.Setup()
	else:
		cryptoTools.build.Build()
