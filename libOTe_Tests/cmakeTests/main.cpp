

#include "libOTe/Tools/Tools.h"

int main()
{
	using namespace oc;
	MatrixView<u8> in, out;
	// call a function that requires linking...
	transpose(in , out);
	return 0;
}