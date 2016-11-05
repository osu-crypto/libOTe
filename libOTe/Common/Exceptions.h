#pragma once
// This file and the associated implementation has been placed in the public domain, waiving all copyright. No restrictions are placed on its use. 

#include <exception>
#include <string>
#include <sstream>
#include <iostream>

namespace osuCrypto {

  //class RepeatedOTException : public std::runtime_error
  //    {
  //    public:
  //        RepeatedOTException()
  //            : std::runtime_error("Can not make repeated queries to the same OT")
  //        {
  //        }
  //    };
    class not_implemented : public std::exception
    {
        virtual const char* what() const throw()
        {
            return "Case not implemented";
        }
    };
    class division_by_zero : public std::exception
    {
        virtual const char* what() const throw()
        {
            return "Division by zero";
        }
    };
    class invalid_plaintext : public std::exception
    {
        virtual const char* what() const throw()
        {
            return "Inconsistent plaintext space";
        }
    };
    class rep_mismatch : public std::exception
    {
        virtual const char* what() const throw()
        {
            return "Representation mismatch";
        }
    };
    class pr_mismatch : public std::exception
    {
        virtual const char* what() const throw()
        {
            return "Prime mismatch";
        }
    };
    class params_mismatch : public std::exception
    {
        virtual const char* what() const throw()
        {
            return "FHE params mismatch";
        }
    };
    class field_mismatch : public std::exception
    {
        virtual const char* what() const throw()
        {
            return "Plaintext Field mismatch";
        }
    };
    class level_mismatch : public std::exception
    {
        virtual const char* what() const throw()
        {
            return "Level mismatch";
        }
    };
    class invalid_length : public std::exception
    {
        virtual const char* what() const throw()
        {
            return "Invalid length";
        }
    };
    class invalid_commitment : public std::exception
    {
        std::string mWhat;
    public:
        invalid_commitment(std::string wht) : mWhat("Invalid Commitment" + wht) {}
        invalid_commitment() : mWhat("Invalid Commitment") {}
    private:
        virtual const char* what() const throw()
        {
            return mWhat.c_str();
        }
    };
    class IO_Error : public std::exception
    {
        std::string msg;
    public:
        IO_Error(std::string m) : msg(m) {}
        ~IO_Error()throw() { }
        virtual const char* what() const throw()
        {
            std::string ans = "IO-Error : ";
            ans += msg;
            return ans.c_str();
        }
    };
    class broadcast_invalid : public std::exception
    {
        virtual const char* what() const throw()
        {
            return "Inconsistent broadcast at some point";
        }
    };
    class bad_keygen : public std::exception
    {
        std::string msg;
    public:
        bad_keygen(std::string m) : msg(m) {}
        ~bad_keygen()throw() { }
        virtual const char* what() const throw()
        {
            std::string ans = "KeyGen has gone wrong: " + msg;
            return ans.c_str();
        }
    };
    class bad_enccommit : public std::exception
    {
        virtual const char* what() const throw()
        {
            return "Error in EncCommit";
        }
    };
    class invalid_params : public std::exception
    {
        virtual const char* what() const throw()
        {
            return "Invalid Params";
        }
    };
    class bad_value : public std::exception
    {
        virtual const char* what() const throw()
        {
            return "Some value is wrong somewhere";
        }
    };
    class Offline_Check_Error : public std::exception
    {
        std::string msg;
    public:
        Offline_Check_Error(std::string m) : msg(m) {}
        ~Offline_Check_Error()throw() { }
        virtual const char* what() const throw()
        {
            std::string ans = "Offline-Check-Error : ";
            ans += msg;
            return ans.c_str();
        }
    };
    class mac_fail : public std::exception
    {
        virtual const char* what() const throw()
        {
            return "MacCheck Failure";
        }
    };
    class invalid_program : public std::exception
    {
        virtual const char* what() const throw()
        {
            return "Invalid Program";
        }
    };
    class file_error : public std::exception
    {
        std::string filename;
    public:
        file_error(std::string m = "") : filename(m) {}
        ~file_error()throw() { }
        virtual const char* what() const throw()
        {
            std::string ans = "File Error : ";
            ans += filename;
            return ans.c_str();
        }
    };
    class end_of_file : public std::exception
    {
        virtual const char* what() const throw()
        {
            return "End of file reached";
        }
    };
    class Processor_Error : public std::exception
    {
        std::string msg;
    public:
        Processor_Error(std::string m) : msg(m) {}
        ~Processor_Error()throw() { }
        virtual const char* what() const throw()
        {
            std::string ans = "Processor-Error : ";
            ans += msg;
            return ans.c_str();
        }
    };
    class max_mod_sz_too_small : public std::exception
    {
        int len;
    public:
        max_mod_sz_too_small(int len) : len(len) {}
        ~max_mod_sz_too_small() throw() {}
        virtual const char* what() const throw()
        {
            std::stringstream out;
            out << "MAX_MOD_SZ too small for desired bit length of p, "
                << "must be at least ceil(len(p)/len(u64))+1, "
                << "in this case: " << len;
            return out.str().c_str();
        }
    };
    class crash_requested : public std::exception
    {
        virtual const char* what() const throw()
        {
            return "Crash requested by program";
        }
    };

}
