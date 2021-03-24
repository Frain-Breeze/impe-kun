#include "../inc/crypt.hpp"
#include <stdio.h>
#include <functional>
#include <thread>
#include <string>
#include <fstream>
#include <unordered_map>

int modInverse(int a, int m) {
	for (int i = 1; i < m; i++) {
		if (((a % m) * (i * m)) % m == 1) {
			return i;
		}
	}
	return -1;
}

/*void nvm() {

	int64_t* plVar1, *plVar4, *plVar5, *plVar6, *param_3;
	int64_t* par3and = plVar4;

	plVar4 = (int64_t*)((uint64_t)param_3 | 0xf);
	plVar6 = (int64_t*)0x7fffffffffffffff;
	if (((plVar4 < (int64_t*)0x8000000000000000) &&
		(plVar1 <= (int64_t*)(0x7fffffffffffffff - ((uint64_t)plVar1 >> 1)))) &&
		(plVar5 = (int64_t*)(((uint64_t)plVar1 >> 1) + (int64_t)plVar1), plVar6 = plVar4, plVar4 < plVar5)) {

		plVar6 = plVar5;
	}
	static_assert(sizeof(uint64_t) == 8, "");

	par3and = (int64_t*)((uint64_t)param_3 | 0xF);
	plVar6 = (int64_t*)0x7fffffffffffffff;
	//if(true && )
}*/

/*

    plVar4 = (longlong *)((ulonglong)param_3 | 0xf);
    plVar6 = (longlong *)0x7fffffffffffffff;
    if (((plVar4 < (longlong *)0x8000000000000000) &&
		(plVar1 <= (longlong *)(0x7fffffffffffffff - ((ulonglong)plVar1 >> 1)))) &&
		(plVar5 = (longlong *)(((ulonglong)plVar1 >> 1) + (longlong)plVar1), plVar6 = plVar4, plVar4 < plVar5)) {

		plVar6 = plVar5;
    }

*/

int main(int argc, char* argv[]) {

	printf("usage:\n"
	"enc [keyString]\n"
	"match [infile].txt [outfile].csv //takes a file from the ggr patcher for dumping keys\n"
	"brute [wanted hash] [string to start with] //if you don't have a string to start with, use _ instead\n"
	"dec [file to decrypt] [output file] [offset] [keyString]\n\n");

	for (int i = 0; i < argc; i++) {
		printf("arg %d: %s\n", i, argv[i]);
	}

	if (argc > 2) {
		if((std::string)argv[1] == "enc") {
			uint64_t key1 = calculateKeyFromName(argv[2], defKey1);
			uint64_t key2 = calculateKeyFromName(argv[2], defKey2);
			printf("key1: %08lx, key2: %08lx\n", key1, key2);
			return 0;
		}
		else if ((std::string)argv[1] == "match") {
			//[logfile].txt
			struct MHANDLE {
				int handle = -1;
				std::string name;
			};
			std::vector<MHANDLE> handles;

			struct MREAD {
				int handle = -1;
				uint64_t size = 0;
				uint64_t offset = 0;
				uint64_t bytes = 0;
			};
			std::vector<MREAD> reads;

			struct MDEC {
				std::string password;
				uint64_t bytes = 0;
			};
			std::vector<MDEC> decs;


			if (argc == 4) {
				std::ifstream log(argv[2]);
				while (!log.eof()) {
					char line[2048];
					log.getline(line, 2048, '\n');
					if (line[0] == '[') {
						//printf("first character is [\n");
						{
							int handle;
							char nameBuf[2048];
							if (sscanf(line, "[fCreateW] handle: %d, name: %[^\n]", &handle, nameBuf) == 2) {
								//printf("handle %d with name %s\n", handle, nameBuf);
								MHANDLE h;
								for (const auto& b : handles) {
									if (b.handle == handle) {
										//printf("handle duplicate! not adding\n");
										goto do_not_add;
									}
								}
								h.name = nameBuf;
								h.handle = handle;
								handles.emplace_back(h);
								do_not_add:
								continue;
							}
						}
						{
							int handle, size, offset;
							uint64_t bytes;
							if (sscanf(line, "[fRead]: handle: %d, size: %d, offset: %d, bytes: %016llx", &handle, &size, &offset, &bytes) == 4) {
								const std::string* b = nullptr;
								for (const auto& a : handles) {
									b = &a.name;
								}
								//printf("read with handle %d, size %d, offset %d and bytes %016llx -> %s\n", handle, size, offset, bytes, b->c_str());
								MREAD r;
								r.bytes = bytes;
								r.handle = handle;
								r.offset = offset;
								r.size = size;
								reads.emplace_back(r);
								continue;
							}
						}
						{
							char nameBuf[2048];
							uint64_t bytes = 0;
							if (sscanf(line, "[decrypt] string: %[^,], bytes: %016llx", nameBuf, &bytes) == 2) {
								//printf("decrypt with name %s and bytes %016llx\n", nameBuf, bytes);
								MDEC d;
								d.bytes = bytes;
								d.password = nameBuf;
								decs.emplace_back(d);
								continue;
							}
						}
						
					}
				}

				FILE* ofp = fopen(argv[3], "wb");
				fprintf(ofp, "key,offset,size,path\n");


				for (const auto& d : decs) {
					const MREAD* match = nullptr;
					for (const auto& r : reads) {
						if (d.bytes == r.bytes) {
							match = &r;
							break;
						}
					}

					if (match) {
						for (const auto& h : handles) {
							if (h.handle == match->handle) {
								printf("key %s offs %-10d size %-10d on file %s\n", d.password.c_str(), match->offset, match->size, h.name.c_str());
								fprintf(ofp, "%s,%ld,%ld,%s\n", d.password.c_str(), match->offset, match->size, h.name.c_str());
								break;
							}
						}
					}
				}

			}
		}
		else if ((std::string)argv[1] == "brute") {
			if (argc == 4) {
				//bruteforce .exe [wanted hash] [garbage]
				uint64_t wanted = 0;
				sscanf(argv[2], "%08lx", &wanted);
				printf("wanted: %08lx\n", wanted);

				char name1[2048];
				memset(name1, 0, 2048);
				char name2[2048];
				memset(name2, 0, 2048);

				sscanf(argv[3], "%s", &name1);
				sscanf(argv[3], "%s", &name2);
				if (name1[0] == '_') {
					memset(name1, 0, 2048);
					memset(name2, 0, 2048);
				}

				int max_back = strlen(name1);

				int max_depth = 128;

				std::function<void(int)> func = [&](int depth) {
					name1[depth] = 0;
					name2[depth] = 0;
					uint64_t key1 = calculateKeyFromName_fast(name1, defKey1);
					uint64_t key2 = calculateKeyFromName_fast(name2, defKey2);
					//printf("\rtried: %s", name);
					if ((int)key1 == (int)wanted) {
						printf("found something: %s (key 1)\n", name1);
						return 0;
					}
					if ((int)key2 == (int)wanted) {
						printf("found something: %s (key 2)\n", name2);
						return 0;
					}
					if (depth > max_back)
						func(depth - 1);
					for (int a = 48; a < 127; a++) {
						name1[depth] = a;
						name2[depth] = a;
						//printf("\rtried: %s", name);
						uint64_t key1 = calculateKeyFromName_fast(name1, defKey1);
						uint64_t key2 = calculateKeyFromName_fast(name2, defKey2);
						if ((int)key1 == (int)wanted) {
							printf("found something: %s (key 1)\n", name1);
							return 0;
						}
						if ((int)key2 == (int)wanted) {
							printf("found something: %s (key 2)\n", name2);
							return 0;
						}
						if (depth > max_back)
							func(depth - 1);
					}
				};
				func(max_depth);
			}
		}
		else if (!strcmp(argv[1], "dec")) {
			if (argc == 6) {
				uint64_t key = calculateKeyFromName(argv[5], defKey1);
				FILE* ifp = fopen(argv[2], "rb");
				assert(ifp);

				int offset;
				sscanf(argv[4], "%d", &offset);

				fseek(ifp, 0, SEEK_END);
				size_t insize = ftell(ifp) - offset;
				uint8_t* buf = new uint8_t[insize];

				fseek(ifp, offset, SEEK_SET);

				fread(buf, 1, insize, ifp);
				fclose(ifp);

				decryptBuffer(buf, buf, key, insize);

				FILE* ofp = fopen(argv[3], "wb");
				assert(ofp);

				fwrite(buf, 1, insize, ofp);
				fclose(ofp);
			}
		}
	}
	return 0;


	/*if (argc == 6) {
		//weird decrypt thing

	}

	if (argc == 3) {
		//bruteforce .exe [wanted hash] [garbage]
		uint64_t wanted = 0;
		sscanf(argv[1], "%08x", &wanted);
		printf("wanted: %08x\n", wanted);

		char name[2048];
		memset(name, 0, 2048);

		sscanf(argv[2], "%s", &name);
		if (name[0] == '_') {
			memset(name, 0, 2048);
		}

		int max_back = strlen(name);


		//std::string name = "\x0\x0\x0\x0";
		//name.reserve(0xFFFF);

		

		int max_depth = 128;

		std::function<void(int)> func = [&](int depth) {
			name[depth] = 0;
			uint64_t key = calculateKeyFromName_fast(name);
			//printf("\rtried: %s", name);
			if ((int)key == (int)wanted) {
				printf("found something: %s", name);
				return 0;
			}
			if (depth > max_back)
				func(depth - 1);
			for (int a = 48; a < 127; a++) {
				name[depth] = a;
				//printf("\rtried: %s", name);
				uint64_t key = calculateKeyFromName_fast(name);
				if ((int)key == (int)wanted) {
					printf("\rfound something: %s\n", name);
					return 0;
				}
				if (depth > max_back)
					func(depth - 1);
			}
			
		};

	}

	printf("usage: ggrcrypt.exe [input file] [offset] [decrypt name] [output file]\n");
	if (argc == 5) {
		uint64_t key = calculateKeyFromName(argv[3]);
		FILE* ifp = fopen(argv[1], "rb");
		assert(ifp);

		int offset;
		sscanf(argv[2], "%d", &offset);

		fseek(ifp, 0, SEEK_END);
		size_t insize = ftell(ifp) - offset;
		uint8_t* buf = new uint8_t[insize];
		
		fseek(ifp, offset, SEEK_SET);

		fread(buf, 1, insize, ifp);
		fclose(ifp);

		decryptBuffer(buf, buf, key, insize);

		FILE* ofp = fopen(argv[4], "wb");
		assert(ofp);

		fwrite(buf, 1, insize, ofp);
		fclose(ofp);
	}
	else if (argc == 4) {
		//ggrcrypt.exe [input file] [decrypt name] [output file]
		FILE* ifp = fopen(argv[1], "rb");
		assert(ifp);

		fseek(ifp, 0, SEEK_END);
		size_t insize = ftell(ifp);
		fseek(ifp, 0, SEEK_SET);

		int nullCount = 0;
		for (size_t i = 0; i < insize; i++) {
			int curr = getc(ifp);
			if (curr == 0)
				nullCount++;
			else
				nullCount = 0;

			if (nullCount > 1)
				printf("nullcount %d or larger at position %d\n", nullCount, ftell(ifp));
		}
	}
	else if (argc == 2) {
		//ggrcrypt.exe [decrypt name]
		uint64_t key = calculateKeyFromName(argv[1]);
		printf("%08lx\n", key);
	}*/
	return 0;
}