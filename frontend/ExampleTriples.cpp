#include "cryptoTools/Common/CLP.h"
#include "libOTe/Config.h"

#include "libOTe/Triple/Foleage/FoleageTriple.h"
#include "libOTe/Triple/RingLpn/RingLpnTriple.h"

#include <iostream>
#include <iomanip>

#include "coproto/Socket/LocalAsyncSock.h"
#include "cryptoTools/Crypto/PRNG.h"    
#include "cryptoTools/Common/Timer.h"
#include "cryptoTools/Common/BitIterator.h"
#include "cryptoTools/Common/Matrix.h"
#include "libOTe/Tools/Field/Fp.h"


namespace osuCrypto
{
	bool Foleage_Example(const CLP& cmd)
	{

#ifdef ENABLE_FOLEAGE
		std::cout << "\n=== Foleage Binary Triple Tutorial ===\n\n";

		// Step 1: Parse command line parameters
		u64 numTriples = cmd.getOr("n", 1000);  // Number of binary triples to generate
		u64 logN = log3ceil(numTriples);         // log3 of polynomial size for efficiency
		bool verbose = cmd.isSet("v");          // Verbose output
		bool timing = cmd.isSet("t");           // Show timing information
		bool manualBaseOTs = cmd.isSet("manualBaseOts"); // Manual base OTs

		std::cout << "Tutorial: Generating " << numTriples << " binary triples using Foleage PCG\n";
		std::cout << "Parameters: log3(polySize)=" << logN << "\n\n";

		// Step 2: Initialize pseudo-random number generators for both parties
		// In a real application, these would be seeded by sysRandomSeed();
		PRNG prng0(block(0x1234567890ABCDEF, 0xFEDCBA0987654321)); // Party 0's PRNG
		PRNG prng1(block(0xABCDEF1234567890, 0x0987654321FEDCBA)); // Party 1's PRNG

		std::cout << "Step 1: Initializing Foleage instances for both parties...\n";

		// Step 3: Create Foleage instances for both parties
		std::array<FoleageTriple, 2> foleage;

		// Initialize both parties with their respective party indices (0 and 1)
		foleage[0].init(0, numTriples);  // Party 0
		foleage[1].init(1, numTriples);  // Party 1

		if (verbose)
		{
			std::cout << "  Party 0 initialized with " << numTriples << " triples\n";
			std::cout << "  Party 1 initialized with " << numTriples << " triples\n";
			std::cout << "  Polynomial parameters: N=" << foleage[0].mN << ", T=" << foleage[0].mT
				<< ", C=" << foleage[0].mC << "\n";
		}

		std::cout << "\nStep 2: Setting up base OTs (Oblivious Transfers)...\n";

		// Step 4: Setup base OTs
		// In the Foleage protocol, parties need base OTs to securely share random values.
		// These can optionally be generated externally and provided manually.
		if (manualBaseOTs)
		{
			auto otCount0 = foleage[0].baseOtCount();
			auto otCount1 = foleage[1].baseOtCount();

			if (verbose)
			{
				std::cout << "  Party 0 needs: " << otCount0.mSendCount << " send OTs, "
					<< otCount0.mRecvCount << " receive OTs\n";
				std::cout << "  Party 1 needs: " << otCount1.mSendCount << " send OTs, "
					<< otCount1.mRecvCount << " receive OTs\n";
			}

			// Verify that the OT counts are compatible
			if (otCount0.mRecvCount != otCount1.mSendCount ||
				otCount0.mSendCount != otCount1.mRecvCount)
			{
				std::cout << "Error: Incompatible OT counts between parties!\n";
				return false;
			}

			// Generate fake base OTs.
			// In practice, these would be generated through a secure protocol
			std::array<std::vector<std::array<block, 2>>, 2> baseSend;
			std::array<std::vector<block>, 2> baseRecv;
			std::array<BitVector, 2> baseChoice;

			baseSend[0].resize(otCount0.mSendCount);
			baseSend[1].resize(otCount1.mSendCount);

			for (u64 i = 0; i < 2; ++i)
			{
				// Generate random OT messages
				prng0.get(baseSend[i].data(), baseSend[i].size());

				// Setup receiver's side
				baseRecv[1 ^ i].resize(baseSend[i].size());
				baseChoice[1 ^ i].resize(baseSend[i].size());
				baseChoice[1 ^ i].randomize(prng0);

				// Simulate OT: receiver gets chosen messages
				for (u64 j = 0; j < baseSend[i].size(); ++j)
				{
					baseRecv[1 ^ i][j] = baseSend[i][j][baseChoice[1 ^ i][j]];
				}
			}

			// Set the base OTs for both parties
			foleage[0].setBaseOts(baseSend[0], baseRecv[0], baseChoice[0]);
			foleage[1].setBaseOts(baseSend[1], baseRecv[1], baseChoice[1]);

			std::cout << "  Base OTs configured successfully\n";
		}

		std::cout << "\nStep 3: Creating secure communication channel...\n";

		// Step 5: Setup communication channel
		// LocalAsyncSocket simulates a network connection between two parties.
		// use AsioSocket or other real sockets in production code.
		auto sockets = coproto::LocalAsyncSocket::makePair();

		std::cout << "\nStep 4: Generating binary triples...\n";

		// Step 6: Prepare output buffers
		// Each party will get shares of A, B, and C such that A ⊕ B = C
		u64 numBlocks = divCeil(numTriples, 128);  // Number of 128-bit blocks needed

		std::array<std::vector<block>, 2> A, B, C;  // [party][block]
		for (u64 i = 0; i < 2; ++i)
		{
			A[i].resize(numBlocks);
			B[i].resize(numBlocks);
			C[i].resize(numBlocks);
		}

		// Step 7: Run the Foleage protocol
		Timer timer;
		if (timing) timer.setTimePoint("start");

		// Execute the protocol in parallel for both parties
		// Real execution would just sync_wait one of these tasks.
		auto result = macoro::sync_wait(macoro::when_all_ready(
			foleage[0].expand(A[0], B[0], C[0], prng0, sockets[0]),  // Party 0
			foleage[1].expand(A[1], B[1], C[1], prng1, sockets[1])   // Party 1
		));

		// Check for any errors
		std::get<0>(result).result();
		std::get<1>(result).result();

		if (timing)
		{
			timer.setTimePoint("end");
			std::cout << "  Protocol execution time: " << timer << "\n";
		}

		std::cout << "  Triple generation completed successfully!\n";

		std::cout << "\nStep 5: Verifying correctness of generated triples...\n";

		// Step 8: Verify the correctness of generated triples
		u64 verificationCount = std::min(numTriples, 10ULL);  // Verify first 10 triples
		bool allCorrect = true;

		for (u64 blockIdx = 0; blockIdx < numBlocks && allCorrect; ++blockIdx)
		{
			// Reconstruct the secret values by XORing shares
			block a_reconstructed = A[0][blockIdx] ^ A[1][blockIdx];
			block b_reconstructed = B[0][blockIdx] ^ B[1][blockIdx];
			block c_reconstructed = C[0][blockIdx] ^ C[1][blockIdx];

			// Verify that a * b = c (in GF(2), multiplication is AND)
			block expected_c = a_reconstructed & b_reconstructed;

			if (c_reconstructed != expected_c)
			{
				std::cout << "  Verification failed at block " << blockIdx << "!\n";
				allCorrect = false;
				break;
			}
		}

		if (allCorrect)
		{
			std::cout << "  All verified triples are correct!\n";
		}

		// Step 9: Display sample results
		if (verbose && allCorrect)
		{
			std::cout << "\nStep 6: Sample triple shares (first few bits):\n";
			std::cout << std::setw(8) << "Triple#" << " | "
				<< std::setw(8) << "A0" << " " << std::setw(8) << "A1" << " | "
				<< std::setw(8) << "B0" << " " << std::setw(8) << "B1" << " | "
				<< std::setw(8) << "C0" << " " << std::setw(8) << "C1" << " | "
				<< "Verify\n";
			std::cout << std::string(80, '-') << "\n";

			for (u64 i = 0; i < verificationCount && i < numTriples; ++i)
			{
				u64 blockIdx = i / 128;
				u64 bitIdx = i % 128;

				bool a0 = bit(A[0][blockIdx].data(), bitIdx);
				bool a1 = bit(A[1][blockIdx].data(), bitIdx);
				bool b0 = bit(B[0][blockIdx].data(), bitIdx);
				bool b1 = bit(B[1][blockIdx].data(), bitIdx);
				bool c0 = bit(C[0][blockIdx].data(), bitIdx);
				bool c1 = bit(C[1][blockIdx].data(), bitIdx);

				bool a = a0 ^ a1;
				bool b = b0 ^ b1;
				bool c = c0 ^ c1;
				bool expected = a & b;

				std::cout << std::setw(8) << i << " | "
					<< std::setw(8) << (int)a0 << " " << std::setw(8) << (int)a1 << " | "
					<< std::setw(8) << (int)b0 << " " << std::setw(8) << (int)b1 << " | "
					<< std::setw(8) << (int)c0 << " " << std::setw(8) << (int)c1 << " | "
					<< (c == expected ? "✅" : "❌") << "\n";
			}
		}

		// Step 10: Usage recommendations
		std::cout << "\n=== Usage Summary ===\n";
		std::cout << "Generated: " << numTriples << " binary triples\n";
		std::cout << "Storage: " << numBlocks << " blocks (" << numBlocks * 16 << " bytes per party)\n";
		std::cout << "Security: Information-theoretic security against semi-honest adversaries\n";
		std::cout << "\nNext steps:\n";
		std::cout << "1. Use these triples in secure multiparty computation protocols\n";
		std::cout << "2. For multiplication gates: a ⊕ b = c reveals a * b when combined\n";
		std::cout << "3. Store shares securely and use them as needed in your protocol\n";

		std::cout << "\n=== Advanced Usage ===\n";
		std::cout << "Command line options:\n";
		std::cout << "  -n <number>    : Number of triples to generate (default: 1000)\n";
		std::cout << "  -v             : Verbose output\n";
		std::cout << "  -t             : Show timing information\n";
		std::cout << "\nExample: ./program -foleage -n 5000 -log 7 -v -t\n";

		return allCorrect;

#else
		std::cout << "❌ Foleage support not enabled in this build.\n";
		std::cout << "To enable Foleage:\n";
		std::cout << "1. Recompile with -DENABLE_FOLEAGE=ON\n";
		std::cout << "2. Ensure all dependencies are available\n";
		return false;
#endif

	}


	bool RingLpn_Example(const CLP& cmd)
	{


#ifdef ENABLE_RINGLPN
		std::cout << "\n=== Ring-LPN Binary Triple Tutorial ===\n\n";

		// Step 1: Parse command line parameters
		u64 numTriples = cmd.getOr("n", 1000);        // Number of binary triples to generate
		u64 logN = log2ceil(numTriples);               // log2 of polynomial size
		bool verbose = cmd.isSet("v");                // Verbose output
		bool timing = cmd.isSet("t");                 // Show timing information
		bool debug = cmd.isSet("debug");              // Enable debug checks
		bool manualCoeffs = cmd.isSet("manualCoeffs"); // Manual base correlations
		bool manualBaseCors = cmd.isSet("manualBaseCors"); // Manual base OTs
		auto dpf = cmd.getOr("dpf", 0); // Manual base OTs

		// Ensure numTriples is a power of 2 for efficiency
		u64 n = 1ull << logN;
		std::cout << "Tutorial: Generating " << numTriples << " binary triples using Ring-LPN PCG\n";

		// Step 2: Initialize pseudo-random number generators for both parties
		// In a real application, these would be seeded by sysRandomSeed();
		PRNG prng0(block(0x1234567890ABCDEF, 0xFEDCBA0987654321)); // Party 0's PRNG
		PRNG prng1(block(0xABCDEF1234567890, 0x0987654321FEDCBA)); // Party 1's PRNG

		std::cout << "Step 1: Initializing Ring-LPN instances for both parties...\n";

		// Step 3: Create Ring-LPN instances for both parties
		// We use a finite field F12289 which is efficient for NTT operations
		using F = F12289;
		std::array<RingLpnTriple<F>, 2> ringLpn;

		// Configure protocol parameters
		ringLpn[0].mDebug = ringLpn[1].mDebug = debug;

		std::cout << "\nStep 2: Setting up base correlations...\n";

		// Step 4: optionally setup base correlations
		// Ring-LPN requires base OTs and binary OLEs for the underlying protocols
		if (manualBaseCors)
		{
			// the protocol will require having w random coefficients
			// held by each party, as well as the tensor/outer product of 
			// those coefficients in a secret shared form. I.e.
			// 
			//  P0: c00,c01,...,c0w
			//  P1: c10,c11,...,c1w
			// 
			// and a sharing of
			// 
			//  [c0i * c1j]
			// 
			// for all i,j in [w]
			// 
			// If you choose to manually generate the base correlations, you have 
			// the option to have only base OTs as the base correlation or to have 
			// base OTs and coefficients distributed as above.
			auto baseCorType = manualCoeffs ?
				RingLpnTriple<F>::TensorBaseCorType::Precomputed :
				RingLpnTriple<F>::TensorBaseCorType::OtBased;

			// Initialize both parties with their respective party indices (0 and 1)
			ringLpn[0].init(0, numTriples, RingLpnTriple<F>::Mode::Triple, (RingLpnTriple<F>::DpfType)dpf, baseCorType);  // Party 0
			ringLpn[1].init(1, numTriples, RingLpnTriple<F>::Mode::Triple, (RingLpnTriple<F>::DpfType)dpf, baseCorType);  // Party 1

			auto corCount0 = ringLpn[0].baseCorCount();
			auto corCount1 = ringLpn[1].baseCorCount();

			if (verbose)
			{
				std::cout << "  Party 0 needs: " << corCount0.mSendOtCount << " send OTs, "
					<< corCount0.mRecvOtCount << " receive OTs\n";
				std::cout << "  Party 0 needs: " << corCount0.mOleCount << " binary OLEs\n";
				std::cout << "  Party 0 needs: " << corCount0.mCoeffCount << " coefficients\n";
				std::cout << "  Party 1 needs: " << corCount1.mSendOtCount << " send OTs, "
					<< corCount1.mRecvOtCount << " receive OTs\n";
				std::cout << "  Party 1 needs: " << corCount1.mOleCount << " binary OLEs\n";
				std::cout << "  Party 1 needs: " << corCount1.mCoeffCount << " coefficients\n";
			}

			// Verify that the correlation counts are compatible
			if (corCount0.mRecvOtCount != corCount1.mSendOtCount ||
				corCount0.mSendOtCount != corCount1.mRecvOtCount)
			{
				std::cout << "Error: Incompatible OT counts between parties!\n";
				return false;
			}

			// Generate base OTs (in practice, these would be generated through a secure protocol)
			std::array<std::vector<std::array<block, 2>>, 2> baseSend;
			std::array<std::vector<block>, 2> baseRecv, oleMult, oleAdd;
			std::array<BitVector, 2> baseChoice;

			baseSend[0].resize(corCount0.mSendOtCount);
			baseSend[1].resize(corCount1.mSendOtCount);

			for (u64 i = 0; i < 2; ++i)
			{
				// Generate random OT messages
				prng0.get(baseSend[i].data(), baseSend[i].size());

				// Setup receiver's side
				baseRecv[1 ^ i].resize(baseSend[i].size());
				baseChoice[1 ^ i].resize(baseSend[i].size());
				baseChoice[1 ^ i].randomize(prng0);

				// Simulate OT: receiver gets chosen messages
				for (u64 j = 0; j < baseSend[i].size(); ++j)
				{
					baseRecv[1 ^ i][j] = baseSend[i][j][baseChoice[1 ^ i][j]];
				}
			}

			// Generate binary OLEs (multiplication triples in binary field)
			std::array<std::vector<F>, 2> coeffs, tensor;
			coeffs[0].resize(corCount0.mCoeffCount);
			coeffs[1].resize(corCount1.mCoeffCount);
			tensor[0].resize(corCount0.mCoeffCount * corCount0.mCoeffCount);
			tensor[1].resize(corCount1.mCoeffCount * corCount1.mCoeffCount);

			// Generate random coefficients for the sparse polynomials
			for (u64 i = 0; i < coeffs[0].size(); ++i)
			{
				coeffs[0][i] = prng0.get();
				coeffs[1][i] = prng1.get();
			}

			// Generate tensor products (coeffs[0][i] * coeffs[1][j] for all i,j)
			for (u64 i = 0; i < coeffs[0].size(); ++i)
			{
				for (u64 j = 0; j < coeffs[0].size(); ++j)
				{
					auto idx = i * coeffs[0].size() + j;
					tensor[0][idx] = prng0.get();
					tensor[1][idx] = coeffs[0][i] * coeffs[1][j] - tensor[0][idx];

					// Verify correctness
					if ((tensor[0][idx] + tensor[1][idx]) != (coeffs[0][i] * coeffs[1][j]))
						throw RTE_LOC;
				}
			}

			// Generate binary OLEs for the GMW protocol
			oleMult[0].resize(divCeil(corCount0.mOleCount, 128));
			oleMult[1].resize(divCeil(corCount0.mOleCount, 128));
			oleAdd[0].resize(divCeil(corCount0.mOleCount, 128));
			oleAdd[1].resize(divCeil(corCount0.mOleCount, 128));

			prng0.get(oleMult[0].data(), oleMult[0].size());
			prng0.get(oleMult[1].data(), oleMult[1].size());
			prng0.get(oleAdd[0].data(), oleAdd[0].size());

			// OLE correctness: oleAdd[0] ⊕ oleAdd[1] = oleMult[0] ∧ oleMult[1]
			for (u64 i = 0; i < oleAdd[1].size(); ++i)
				oleAdd[1][i] = (oleMult[1][i] & oleMult[0][i]) ^ oleAdd[0][i];

			// Set the base correlations for both parties
			ringLpn[0].setBaseCors(baseSend[0], baseRecv[0], baseChoice[0],
				oleMult[0], oleAdd[0], coeffs[0], tensor[0]);
			ringLpn[1].setBaseCors(baseSend[1], baseRecv[1], baseChoice[1],
				oleMult[1], oleAdd[1], coeffs[1], tensor[1]);

			std::cout << "  Base correlations configured successfully\n";
		}
		else
		{
			// Initialize both parties with their respective party indices (0 and 1)
			ringLpn[0].init(0, numTriples);  // Party 0
			ringLpn[1].init(1, numTriples);  // Party 1
		}

		std::cout << "\nStep 3: Creating secure communication channel...\n";

		// Step 5: Setup communication channel
		// LocalAsyncSocket simulates a network connection between two parties
		// Use AsioSocket or other real sockets in production code
		auto sockets = coproto::LocalAsyncSocket::makePair();

		std::cout << "\nStep 4: Generating field OLEs (Oblivious Linear Evaluations)...\n";

		// Step 6: Prepare output buffers
		// Each party will get shares of A and C such that A[0] * A[1] = C[0] + C[1]
		std::vector<F> A0(n), A1(n), C0(n), C1(n);

		// Step 7: Run the Ring-LPN protocol
		Timer timer;
		if (timing) timer.setTimePoint("start");

		if (verbose) ringLpn[0].setTimer(timer);



#else

#endif

		return 0;

	}

}
