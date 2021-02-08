#pragma once

#include <stdint.h>
#include <string>
#include <assert.h>

static uint64_t defKey = 0xA1B34F58CAD705B2;

uint64_t calculateKeyFromName(const std::string& _name) {
	uint64_t nkey = defKey;
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