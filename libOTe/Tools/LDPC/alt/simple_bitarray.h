#include <cstddef>
#include <cstring>
#include <cassert>
#include <cstdint>
#ifndef __BIT_ARRAY_H
#define __BIT_ARRAY_H

#define __BIT_ARRAY_CHECK


#if 0
class simple_bit_array_t{
private:
	int len;
	bool* buffer;
	simple_bit_array_t(int _len, bool* _buffer) :len(_len), buffer(_buffer){}
public:
	simple_bit_array_t() :len(0), buffer(NULL){}
	simple_bit_array_t(int _len) :len(_len), buffer(new bool[_len]){}
	~simple_bit_array_t(){
		if (buffer != NULL)delete[] buffer; buffer = NULL;
	}
	simple_bit_array_t(simple_bit_array_t& arr){
		this->len = arr.len;
		this->buffer = new bool[len];
		memcpy(buffer, arr.buffer, sizeof(bool)*len);
	}
	simple_bit_array_t(bool* arr, int _len) :len(_len), buffer(new bool[_len]){
		memcpy(buffer, arr, sizeof(bool)*len);
	}
	int size() const{ return len; }
	simple_bit_array_t& operator=(const simple_bit_array_t& arr){
		this->len = arr.len;
		if (this->buffer != NULL)delete[] this->buffer;
		this->buffer = new bool[len];
		memcpy(buffer, arr.buffer, sizeof(bool)*len);
		return *this;
	}
	void clear(bool value = false){
		if (!value)memset(buffer, 0, sizeof(bool)*(len));
		else memset(buffer, true, sizeof(bool)*(len));
	}
	inline bool get(int index) const{
		return buffer[index];
	}
	simple_bit_array_t operator |(const simple_bit_array_t& arr){
		simple_bit_array_t res(len);
		for (int i = 0; i < len; i++)
			res.buffer[i] = arr.buffer[i] | buffer[i];
		return res;
	}

	simple_bit_array_t operator ^(const simple_bit_array_t& arr){
		simple_bit_array_t res(len);
		for (int i = 0; i < len; i++)
			res.buffer[i] = arr.buffer[i] ^ buffer[i];
		return res;
	}
	simple_bit_array_t operator &(const simple_bit_array_t& arr){
		simple_bit_array_t res(len);
		for (int i = 0; i < len; i++)
			res.buffer[i] = arr.buffer[i] & buffer[i];
		return res;
	}
	simple_bit_array_t operator !(){
		simple_bit_array_t res(len);
		for (int i = 0; i < len; i++)
			res.buffer[i] = !buffer[i];
		return res;
	}

	simple_bit_array_t& operator |=(const simple_bit_array_t& arr){
		for (int i = 0; i < len; i++)
			buffer[i] |= arr.buffer[i];
		return *this;
	}

	simple_bit_array_t& operator &=(const simple_bit_array_t& arr){
		for (int i = 0; i < len; i++)
			buffer[i] &= arr.buffer[i];
		return *this;
	}
	simple_bit_array_t& operator ^=(const simple_bit_array_t& arr){
		for (int i = 0; i < len; i++)
			buffer[i] ^= arr.buffer[i];
		return *this;
	}
	inline void set(int index, bool val){
		buffer[index] = val;
	}
	inline void xor(int index, bool val){
		buffer[index] ^= val;
	}
	inline bool operator [](int id) const{
		return get(id);
	}
};
typedef simple_bit_array_t bit_array_t;

#else
class bit_array_t{
private:
	typedef char uint8_t;
	int len;
	char* buffer;
	bit_array_t(int _len, char* _buffer) :len(_len), buffer(_buffer){}
public:
	bit_array_t() :len(0), buffer(NULL){}
	bit_array_t(int _len) :len(_len), buffer(new char[(_len + 7) / 8]){}
	~bit_array_t(){ if (buffer != NULL)delete[] buffer; buffer = NULL; }
	bit_array_t(bit_array_t& arr){
		this->len = arr.len;
		this->buffer = new char[(len + 7) / 8];
		memcpy(buffer, arr.buffer, sizeof(char)*((len + 7) / 8));
	}
	bit_array_t(bool* arr, int _len) :len(_len), buffer(new char[(_len + 7) / 8]){
		for (int i = 0; i < len; i++)
			set(i, arr[i]);
	}
	int size() const{ return len; }
	bit_array_t& operator=(const bit_array_t& arr){
		this->len = arr.len;
		if (this->buffer != NULL)delete[] this->buffer;
		this->buffer = new char[(len + 7) / 8];
		memcpy(buffer, arr.buffer, sizeof(char)*((len + 7) / 8));
		return *this;
	}
	void clear(bool value = false){
		if (!value)memset(buffer, 0, sizeof(char)*((len + 7) / 8));
		else memset(buffer, 255, sizeof(char)*((len + 7) / 8));
	}
	inline bool get(int index) const{
#ifdef __BIT_ARRAY_CHECK
		assert(index < len);
#endif
		return (buffer[index / 8] >> (index % 8)) & 1;
	}
	bit_array_t operator |(const bit_array_t& arr){
		assert(arr.len == len);
		bit_array_t res(len);
		for (int i = 0; i < (len + 7) / 8; i++)
			res.buffer[i] = arr.buffer[i] | buffer[i];
		return res;
	}

	bit_array_t operator ^(const bit_array_t& arr){
		assert(arr.len == len);
		bit_array_t res(len);
		for (int i = 0; i < (len + 7) / 8; i++)
			res.buffer[i] = arr.buffer[i] ^ buffer[i];
		return res;
	}
	bit_array_t operator &(const bit_array_t& arr){
		assert(arr.len == len);
		bit_array_t res(len);
		for (int i = 0; i < (len + 7) / 8; i++)
			res.buffer[i] = arr.buffer[i] & buffer[i];
		return res;
	}
	bit_array_t operator !(){
		bit_array_t res(len);
		for (int i = 0; i < (len + 7) / 8; i++)
			res.buffer[i] = !buffer[i];
		return res;
	}

	bit_array_t& operator |=(const bit_array_t& arr){
		for (int i = 0; i < (len + 7) / 8; i++)
			buffer[i] |= arr.buffer[i];
		return *this;
	}

	bit_array_t& operator &=(const bit_array_t& arr){
		for (int i = 0; i < (len + 7) / 8; i++)
			buffer[i] &= arr.buffer[i];
		return *this;
	}
	bit_array_t& operator ^=(const bit_array_t& arr){
		for (int i = 0; i < (len + 7) / 8; i++)
			buffer[i] ^= arr.buffer[i];
		return *this;
	}
	inline void set(int index, bool val){
#ifdef __BIT_ARRAY_CHECK
		assert(index < len);
#endif
		if (val)
			buffer[index / 8] |= (char)(1 << (index % 8));
		else
			buffer[index / 8] &= (char)~(1 << (index % 8));
	}
	inline void Xor(int index, bool val){
#ifdef __BIT_ARRAY_CHECK
		assert(index < len);
#endif
		if (val)
			buffer[index / 8] ^= (char)(1 << (index % 8));
	}
	inline bool operator [](int id) const{
		return get(id);
	}
};
#endif
#endif
