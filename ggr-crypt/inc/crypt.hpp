#pragma once

#include <stdint.h>
#include <string>
#include <assert.h>

static uint64_t defKey1 = 0xA1B3'4F58'CAD7'05B2;
static uint64_t defKey2 = 0xcde723a5;
static uint64_t defKey3 = 0x5851f42d4c957f2d;


uint64_t new_decrypt() {
	uint64_t key = defKey3;
	uint32_t multiplier = 0x3E;




	return 0;
}

uint64_t weird(uint64_t _pointer, uint8_t _in, uint8_t* _array, uint8_t* _data) {
	uint64_t key = 0xCBF29CE484222325;
	uint64_t multiplier = 0x100000001B3;

	uint8_t* r9;
	uint64_t r8, r10, r11, rcx, rdx, rax, rbp, r14;

	r9 = _data;
	r8 = _in;
	r14 = key;
	rbp = multiplier;
	r8 *= rbp;
	rax = _array[0];
	r8 ^= rax;
	r8 *= rbp;
	rax = _array[1];
	r8 ^= rax;
	r8 *= rbp;
	rax = _array[2];
	r8 ^= rax;
	r8 *= rbp;
	rax = r9[0x30];
	rax &= r8;
	rax >>= 4;
	r10 = r9[0x18];
	//r8 = ((uint8_t*)r10)[rax];
	//rcx = r8;
	r11 = rax + 8;
	rdx = r9[8];

	//cmp rcx, r8
	return rax;

	/*uint64_t curr = _in;
	curr ^= key;
	curr *= _in;
	
	//curr ^= */
	return 0;
}

uint64_t calculateKeyFromName_fast(const char* _name, const uint64_t _startKey) {
	uint64_t nkey = _startKey;
	while(_name[0] != 0) {
		nkey += (_name[0] & 0x80) ? (_name[0] | 0xFFFF'FFFF'FFFF'FF00) : (_name[0]); //sign-extend
		nkey *= 141;
		_name++;
	}
	return nkey;
}

uint64_t calculateKeyFromName(const std::string& _name, const uint64_t _startKey) {
	uint64_t nkey = _startKey;
	for (const auto& it : _name) {
		nkey += (it & 0x80) ? (it | 0xFFFF'FFFF'FFFF'FF00) : (it); //sign-extend
		nkey *= 141;
	}
	return nkey;
}


//returns the new key
uint64_t decryptBuffer(uint8_t* _in, uint8_t* _out, uint64_t key, size_t _size) {
	assert(_in);
	assert(_out);

	for (size_t i = 0; i < _size; i++) {
		uint8_t xormask = key >> (i & 0x1F); //key shifted by i mod 32
		key += _in[i];
		key *= 141;
		_out[i] = _in[i] ^ xormask;
	}

	return key;
}