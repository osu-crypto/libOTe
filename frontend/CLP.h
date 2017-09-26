#pragma once

#include <unordered_map>
#include <set>
#include <list>
#include <vector>
#include <string>

class CommandLineParserError : public std::exception
{

};

class CLP
{
public:

	std::string mProgramName;
	std::unordered_map<std::string, std::list<std::string>> mKeyValues;

	void parse(int argc, char** argv);

	void setDefault(std::string key, std::string value);
	void setDefault(std::vector<std::string> keys, std::string value);

	bool isSet(std::string name);
	bool isSet(std::vector<std::string> names);

	bool hasValue(std::string name);
	bool hasValue(std::vector<std::string> names);

	int getInt(std::string name);
	int getInt(std::vector<std::string> names, std::string failMessage = "");

	std::string getString(std::string name);
	std::list<std::string> getStrings(std::string name);

	std::string getString(std::vector<std::string> names, std::string failMessage = "");
	std::list<std::string> getStrings(std::vector<std::string> names, std::string failMessage = "");
};

