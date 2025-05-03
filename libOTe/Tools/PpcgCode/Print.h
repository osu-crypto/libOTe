#pragma once
#include "cryptoTools/Common/Defines.h"
#include "EnumeratorTools.h"
#include "cryptoTools/Common/CLP.h"
#include "cryptoTools/Common/Log.h"
#include "cryptoTools/Common/Matrix.h"

#include <iostream>


namespace osuCrypto
{


	static bool print_timings = false;

	template<typename R>
	void print_distribution(
		span<R> D1,
		span<R> D2) {
		std::cout << "Printing  count distribution: " << std::endl;
		if (D1.size() != D2.size())
			throw RTE_LOC;
		for (u64 i = 0; i < D1.size(); ++i) {
			std::cout << Float(D1[i]) << " " << Float(D2[i]) << std::endl;
		}
		std::cout << "------------" << std::endl;
	}

	template<typename R>
	void print_distribution(
		span<R> distribution,
		u64 numPoints,
		bool percent,
		std::ostream& out = std::cout,
		std::string name = {}
	) {
		auto n = distribution.size() - 1;

		if (name.size())
			out << name << std::endl;

		if (numPoints == 0)
		{
			u64 h = 0;
			for (const auto& d : distribution) {
				out << double(h++) / n << " " << log2_(d) << std::endl;
			}
		}
		else
		{
			for (u64 i = 0; i < numPoints; ++i)
			{
				try {

					double DS = distribution.size();
					auto IPS = static_cast<double>(i) / numPoints;// in [0,1)
					auto scaled = IPS * DS; // in [0,DS)
					u64 lowIdx = std::floor(scaled); // in [0,DS)
					u64 highIdx = std::min<u64>(std::ceil(scaled), distribution.size() - 1); // in [0,DS)

					Float DL = log2_(Float(distribution[lowIdx])) ;
					Float DH = log2_(Float(distribution[highIdx]));
					auto LDS = lowIdx / DS; // in [0,1)
					auto HDS = highIdx / DS;// in [0,1)

					Float slope = 0;
					auto d = (HDS - LDS);
					if (d)
						slope = (DH - DL) / d;

					auto diff = IPS - LDS;
					auto val = DL + diff * slope;
					try {
						if (percent)
							out << double(i) / numPoints << " " << Float(val) << std::endl;
						else
							out << Float(val) << std::endl;
					}
					catch (...)
					{
						auto p = [](auto v) {
							std::stringstream ss;
							try {
								ss << v;
							}
							catch (...)
							{
								ss << "NaN";
							}
							return ss.str();
							};
						out << p(val) << " = " << p(DL) << " + " << p(diff) << " * " << p(slope)
							<< ", DL = " << p(distribution[lowIdx]) << std::endl;
					}
				}
				catch (...)
				{
					out << "error" << std::endl;
				}
			}
		}
		out << "------------" << std::endl;
	}


	template<typename R>
	void print_enumerator(
		MatrixView<R> E,
		span<R> dist,
		u64 numPoints,
		std::ostream& out = std::cout) {
		auto n = E.cols() - 1;
		auto k = E.rows() - 1;
		auto e = n / k;

		if (numPoints == 0)
		{
			u64 h = 0;
			for (u64 w = 0; w <= k; ++w)
			{
				for (u64 h = 0; h <= n; ++h)
				{
					if (E(w, h) == 0)
						out << "-inf,";
					else
						out << log2_(E(w, h)) << ",";
				}
				out << std::endl;
			}
			out << std::endl;
			out << "-303" << std::endl;// checksum
			out << log2_(dist[h]-1) << ",";
			for (u64 h = 1; h <= n; ++h)
			{
				out << log2_(dist[h]) << ",";
			}
			out << std::endl;			
			R sum = 0;
			out << ",";
			for (u64 h = 1; h <= n; ++h)
			{
				sum += dist[h];
				out << log2_(sum) << ",";
			}
			out << std::endl;
		}
		else
		{
			u64 wNumPoints = double(numPoints) / e;
			auto wStep = k / double(numPoints);
			for (u64 w = 1; w <= wNumPoints; ++w)
			{
				auto ww = u64(w * wStep);
				if (ww > k)
					continue;
				out << double(w) / wNumPoints << ": ";
				auto distribution = E[ww];
				for (u64 i = 0; i < numPoints; ++i)
				{
					try {

						double DS = E.size();
						auto IPS = static_cast<double>(i) / numPoints;// in [0,1)
						auto scaled = IPS * DS; // in [0,DS)
						u64 lowIdx = std::floor(scaled); // in [0,DS)
						u64 highIdx = std::min<u64>(std::ceil(scaled), distribution.size() - 1); // in [0,DS)

						Float DL = log2_(Float(distribution[lowIdx]));
						Float DH = log2_(Float(distribution[highIdx]));
						auto LDS = lowIdx / DS; // in [0,1)
						auto HDS = highIdx / DS;// in [0,1)

						Float slope = 0;
						auto d = (HDS - LDS);
						if (d)
							slope = (DH - DL) / d;

						auto diff = IPS - LDS;
						auto val = DL + diff * slope;
						try {

							out << Float(val) << std::endl;
						}
						catch (...)
						{
							auto p = [](auto v) {
								std::stringstream ss;
								try {
									ss << v;
								}
								catch (...)
								{
									ss << "NaN";
								}
								return ss.str();
								};
							out << p(val) << " = " << p(DL) << " + " << p(diff) << " * " << p(slope)
								<< ", DL = " << p(distribution[lowIdx]) << std::endl;
						}
					}
					catch (...)
					{
						out << "error" << std::endl;
					}
				}

				out << std::endl;
			}
		}
	}
}