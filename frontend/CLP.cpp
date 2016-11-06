#include "CLP.h"
#include <sstream>
#include <iostream>



void CLP::parse(int argc, char** argv)
{
	if (argc > 0)
	{
		std::stringstream ss;
		while (*argv[0] != 0)
			ss << *argv[0]++;
		mProgramName = ss.str();
	}

	for (int i = 1; i < argc;)
	{
		if (*argv[i]++ != '-')
		{
			throw CommandLineParserError();
		}

		std::stringstream ss;

		while (*argv[i] != 0)
			ss << *argv[i]++;

		++i;

		std::pair<std::string, std::list<std::string>> keyValues;
		keyValues.first = ss.str();;

		while (i < argc && argv[i][0] != '-')
		{
			ss.str("");

			while (*argv[i] != 0)
				ss << *argv[i]++;

			keyValues.second.push_back(ss.str());

			++i;
		}

		mKeyValues.emplace(keyValues);
	}
}

void CLP::setDefault(std::string key, std::string value)
{
	if (hasValue(key) == false)
	{
		mKeyValues.emplace(std::make_pair(key, std::list<std::string>{ value }));
	}

}
void CLP::setDefault(std::vector<std::string> keys, std::string value)
{
	if (hasValue(keys) == false)
	{
		setDefault(keys[0], value);
	}

}

bool CLP::isSet(std::string name)
{
	return mKeyValues.find(name) != mKeyValues.end();
}
bool CLP::isSet(std::vector<std::string> names)
{
	for (auto name : names)
	{
		if (isSet(name))
		{
			return true;
		}
	}
	return false;
}

bool CLP::hasValue(std::string name)
{
	return mKeyValues.find(name) != mKeyValues.end() && mKeyValues[name].size();
}
bool CLP::hasValue(std::vector<std::string> names)
{
	for (auto name : names)
	{
		if (hasValue(name))
		{
			return true;
		}
	}
	return false;
}

int CLP::getInt(std::string name)
{
	std::stringstream ss;
	ss << *mKeyValues[name].begin();

	int ret;
	ss >> ret;

	return ret;
}

int CLP::getInt(std::vector<std::string> names, std::string failMessage)
{
	for (auto name : names)
	{
		if (hasValue(name))
		{
			return getInt(name);
		}
	}

	if (failMessage != "")
		std::cout << failMessage << std::endl;

	throw CommandLineParserError();
}

std::string CLP::getString(std::string name)
{
	return *mKeyValues[name].begin();
}

std::list<std::string> CLP::getStrings(std::string name)
{
	return mKeyValues[name];
}

std::list<std::string> CLP::getStrings(std::vector<std::string> names, std::string failMessage)
{
	for (auto name : names)
	{
		if (hasValue(name))
		{
			return getStrings(name);
		}
	}

	if (failMessage != "")
		std::cout << failMessage << std::endl;

	throw CommandLineParserError();
}


std::string CLP::getString(std::vector<std::string> names, std::string failMessage)
{
	for (auto name : names)
	{
		if (hasValue(name))
		{
			return getString(name);
		}
	}

	if (failMessage != "")
		std::cout << failMessage << std::endl;

	throw CommandLineParserError();
}

