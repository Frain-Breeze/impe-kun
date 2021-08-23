#include "../inc/crypt.hpp"
#include <stdio.h>
#include <functional>
#include <thread>
#include <string>
#include <fstream>
#include <filesystem>
#include <nlohmann/json.hpp>
#include <unordered_map>
#include <iostream>
#include <miniz.h>
#define STB_IMAGE_IMPLEMENTATION
#define STB_IMAGE_WRITE_IMPLEMENTATION
//#include <stb_image.h>
#include <stb_image_write.h>

using json = nlohmann::json;
namespace fs = std::filesystem;

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
	"enc_name [keyString]\n"
	"enc_match [data directory] [structure].json [password to check]\n"
	"match [infile].txt [outfile].json //takes a file from the ggr patcher for dumping keys\n"
	"brute [wanted hash] [string to start with] //if you don't have a string to start with, use _ instead\n"
	"dec_all [game directory] [json file with keys].json [output directory] //requires around ~20GB of free space in the output directory"
	"dec [file to decrypt] [output file] [offset] [keyString]\n\n");

	for (int i = 0; i < argc; i++) {
		printf("arg %d: %s\n", i, argv[i]);
	}

	if (argc > 2) {
		if ((std::string)argv[1] == "zlib_pack") {
			uint64_t key = calculateKeyFromName(argv[5], defKey1);
			FILE* ifp = fopen(argv[2], "rb");
			assert(ifp);

			int offset;
			sscanf(argv[4], "%d", &offset);

			fseek(ifp, 0, SEEK_END);
			size_t end = ftell(ifp);
			size_t insize = end - offset;
			uint8_t* buf = new uint8_t[insize];

			fseek(ifp, offset, SEEK_SET);

			fread(buf, 1, insize, ifp);
			fclose(ifp);

			uint8_t* bufout = new uint8_t[insize+4];

			mz_ulong outsize = insize;
			if (mz_compress(bufout + 4, &outsize, buf, insize) == MZ_OK) {
				delete[] buf;
				buf = bufout;
				*(uint32_t*)buf = insize;
				insize = outsize;
			}


			FILE* ofp = fopen(argv[3], "wb");
			assert(ofp);

			fwrite(buf, 1, insize, ofp);
			fclose(ofp);
		}
		if((std::string)argv[1] == "enc_name") {
			uint64_t key1 = calculateKeyFromName(argv[2], defKey1);
			uint64_t key2 = calculateKeyFromName(argv[2], defKey2);
			printf("key1: %08lx, key2: %08lx\n", key1, key2);
			return 0;
		}
		else if ((std::string)argv[1] == "dec_all") {
			if(argc == 5){
				//2 = game directory
				//3 = json file
				//4 = output directory
				std::ifstream jin(argv[3]);
				json js;
				jin >> js;
				jin.close();

				std::function<void(json&, fs::path, fs::path)> recurse_json = [&recurse_json](json& jsobj, fs::path in_path, fs::path out_path) -> void {
					if (jsobj.is_object()) {
						for (const auto& e : jsobj.items()) {
							if (e.key() == "keys") {
								for (const auto& a : e.value().items()) {
									std::string outpath = out_path.string();
									//outpath += "/";

									/*if (e.value().contains("humanName")) {
										outpath += e.value()["humanName"].get<std::string>();
									}
									else {
										outpath += e.key();
									}*/
									outpath += ".";

									outpath += std::to_string(a.value()["offset"].get<int>());
									outpath += ".bin";
									printf("decrypting with %s at %d to %s\n", a.value()["key"].get<std::string>().c_str(), a.value()["offset"].get<int>(), outpath.c_str());

									fs::create_directories(((fs::path)outpath).parent_path());

									uint64_t key = calculateKeyFromName(a.value()["key"].get<std::string>(), defKey1);
									FILE* ifp = fopen(in_path.string().c_str(), "rb");
									assert(ifp);

									int offset = a.value()["offset"].get<int>();

									fseek(ifp, 0, SEEK_END);
									size_t end = ftell(ifp);
									size_t insize = end - offset;
									if (insize > 40000000) {
										insize = 40000000;
									}
									uint8_t* buf = new uint8_t[insize];
									

									fseek(ifp, offset, SEEK_SET);

									fread(buf, 1, insize, ifp);
									fclose(ifp);

									decryptBuffer(buf, buf, key, insize);

									if (*(uint32_t*)buf < 1000000000) {
										mz_ulong out_len = *(uint32_t*)buf;
										uint8_t* buf2 = new uint8_t[out_len];
										mz_ulong actual_out_len = out_len;
										int status = mz_uncompress(buf2, &actual_out_len, &buf[4], insize - 4);
										if (status == Z_OK && out_len == actual_out_len) {
											delete[] buf;
											buf = buf2;
											outpath += ".decompressed.bin";
											insize = actual_out_len;
											printf("inflate succeeded: status: %d, len: %d, actual len: %d\n", status, out_len, actual_out_len);

											if (*(uint32_t*)buf == 108) { //tex file, it seems
												uint32_t dat_header_offset = *(uint32_t*)&buf[0x4C];
												uint32_t pixel_offset = *(uint32_t*)&buf[dat_header_offset];
												uint32_t width = *(uint32_t*)&buf[dat_header_offset + 12];
												uint32_t height = *(uint32_t*)&buf[dat_header_offset + 16];

												for (int i = 0; i < actual_out_len / 4; i++) {
													uint8_t temp_blue = buf[(i * 4) + 2];
													buf[(i * 4) + 2] = buf[(i * 4) + 0];
													buf[(i * 4) + 0] = temp_blue;
												}

												std::string pngpath = outpath;
												pngpath += ".png";
												stbi_write_png(pngpath.c_str(), width, height, 4, &buf[pixel_offset], width * 4);
											}
										}
										else {
											printf("inflate failed: status: %d, len: %d, actual len: %d\n", status, out_len, actual_out_len);
											delete[] buf2;
										}
									}

									FILE* ofp = fopen(outpath.c_str(), "wb");
									assert(ofp);

									fwrite(buf, 1, insize, ofp);
									fclose(ofp);

									delete[] buf;
								}
							}
							else if (e.key() == "humanName") {
								printf("name: %s\n", e.value().get<std::string>().c_str());
							}
							else if (e.key() == "encryptKey") {
								printf("encryptkey: %s\n", e.value().get<std::string>().c_str());
							}
							else {
								std::string name = e.key();
								if (e.value().contains("humanName")) {
									name += "__";
									name += e.value()["humanName"].get<std::string>();
								}
								if (e.key() == "c4f76749") {
									continue;
								}
								std::cout << in_path << "\n";
								recurse_json(e.value(), in_path / e.key(), out_path / name);
							}
							continue;
						}
					}
				};
				//printf("loli");
				recurse_json(js, argv[2], argv[4]);
			}
		}
		else if ((std::string)argv[1] == "enc_brute") {
			if (argc == 5) {
				//2 = game directory
				//3 = json file
				//4 = strings file
				std::ifstream jin(argv[3]);
				json js;
				jin >> js;
				jin.close();

				std::vector<uint32_t> files;
				for (const auto& e : fs::recursive_directory_iterator(argv[2])) {
					uint32_t fileName = 0;
					if (sscanf(e.path().filename().string().c_str(), "%08x", &fileName) == 1) {
						files.push_back(fileName);
					}
				}

				std::unordered_map<uint32_t, bool> found;

				std::ifstream lin(argv[4], std::ios::binary);
				while (!lin.eof()) {
					char lbuf[2048];
					lin.getline(lbuf, 2048);
					char curr[2048];
					int off = 2046;
					int firstunderscore = 0;
					curr[2047] = 0;
					//printf("processing new line %s\n", lbuf);
					for (int i = strlen(lbuf)-1; i >= 0; i--) {
						if (lbuf[i] == '_') {
							firstunderscore = off;
						}
						if (lbuf[i] == '\\') {
							off = 2046;
							continue;
						}
						uint64_t key1 = calculateKeyFromName(&curr[off], defKey1);
						uint64_t key2 = calculateKeyFromName(&curr[off], defKey2);
						curr[firstunderscore] = '.';
						uint64_t key1_dot = calculateKeyFromName(&curr[off], defKey1);
						uint64_t key2_dot = calculateKeyFromName(&curr[off], defKey2);
						curr[firstunderscore] = '_';

						for (int e = 0; e < files.size(); e++) {
							if (files[e] == (key1 & 0xFFFFFFFF)) {
								printf("found %08x matching %s with key 1\n", files[e], &curr[off]);
								off = 2046;
								files.erase(files.begin() + e);
								break;
							}
							else if (files[e] == (key2 & 0xFFFFFFFF)) {
								printf("found %08x matching %s with key 2\n", files[e], &curr[off]);
								off = 2046;
								files.erase(files.begin() + e);
								break;
							}
							else if (files[e] == (key1_dot & 0xFFFFFFFF)) {
								curr[firstunderscore] = '.';
								printf("found %08x matching %s with key 1 dotted\n", files[e], &curr[off]);
								off = 2046;
								files.erase(files.begin() + e);
								curr[firstunderscore] = '_';
								break;
							}
							else if (files[e] == (key2 & 0xFFFFFFFF)) {
								curr[firstunderscore] = '.';
								printf("found %08x matching %s with key 2 dotted\n", files[e], &curr[off]);
								off = 2046;
								files.erase(files.begin() + e);
								curr[firstunderscore] = '_';
								break;
							}
						}

						curr[off] = lbuf[i];
						off--;
						//printf("%d %s\n", i, &curr[off]);
					}
					/*for (int i = 0; i < strlen(lbuf) + 1; i++) {
						if ((lbuf[i] == '_' || lbuf[i] == '\\' || lbuf[i] == '/') && i != 0 && i != 1) {
							printf("new section: %s, from %s\n", curr.c_str(), lbuf);
							for (int depth = curr.size()-1; depth >= curr.size(); depth--) {
								uint64_t key1 = calculateKeyFromName(curr.c_str() + depth, defKey1);
								uint64_t key2 = calculateKeyFromName(curr.c_str() + depth, defKey2);
								printf("part %s from %s is depth %d\n", curr.c_str() + depth, curr.c_str(), depth);
							}
							uint64_t key1 = calculateKeyFromName(curr, defKey1);
							uint64_t key2 = calculateKeyFromName(curr, defKey2);
							for (int e = 0; e < files.size(); e++) {
								if (files[e] == (key1 & 0xFFFFFFFF)) {
									printf("found %08x matching %s with key 1\n", files[e], curr.c_str());
									curr = "";
									files.erase(files.begin() + e);
									break;
								}
								if (files[e] == (key2 & 0xFFFFFFFF)) {
									printf("found %08x matching %s with key 2\n", files[e], curr.c_str());
									curr = "";
									files.erase(files.begin() + e);
									break;
								}
								else {
									//printf("tried to match %s to %d (%s), didn't work\n", curr.c_str(), fileName, e.path().filename().string().c_str());
								}
							}
							//curr.clear();
							curr += lbuf[i];
						}
						else {
							curr += lbuf[i];
						}
						if (lbuf[i] == '\0') {
							break;
						}
						
					}*/
				}
			}
		}
		else if ((std::string)argv[1] == "enc_match") {
			if (argc == 5) {
				

				std::ifstream jin(argv[3]);
				json js;
				jin >> js;
				jin.close();

				char nbuf[2048];
				strcpy(nbuf, argv[4]);
				
				for (int aa = 0; aa < 200; aa++) {
					sprintf(nbuf, argv[4], aa);


					uint64_t key1 = calculateKeyFromName(nbuf, defKey1);
					uint64_t key2 = calculateKeyFromName(nbuf, defKey2);
					for (const auto& e : fs::recursive_directory_iterator(argv[2])) {
						uint32_t fileName = 0;
						if (sscanf(e.path().filename().string().c_str(), "%08x", &fileName) == 1) {
							if (fileName == (key2 & 0xFFFFFFFF)) {
								json* jss = &js;
								bool foundGame = false;
								for (const auto& p : e.path()) {
									if (p.string() == "GalGun Returns")
										foundGame = true;
									if (foundGame) {
										(*jss)[p.string().c_str()];
										jss = &(*jss)[p.string().c_str()];
										if ((*jss).contains("humanName")) {
											printf("%s ", (*jss)["humanName"].get<std::string>().c_str());
										}
										printf("%s\n", p.string().c_str());
									}
								}
								(*jss)["humanName"] = nbuf;
								(*jss)["encryptKey"] = "0xCDE723A5";
								printf("\n");
							}
							else if (fileName == (key1 & 0xFFFFFFFF)) {
								json* jss = &js;
								bool foundGame = false;
								for (const auto& p : e.path()) {
									if (p.string() == "GalGun Returns")
										foundGame = true;
									if (foundGame) {
										(*jss)[p.string().c_str()];
										jss = &(*jss)[p.string().c_str()];
										if ((*jss).contains("humanName")) {
											printf("%s\n", (*jss)["humanName"].get<std::string>().c_str());
										}
										printf("%s\n", p.string().c_str());
									}
								}
								if (foundGame) {
									(*jss)["humanName"] = nbuf;
									(*jss)["encryptKey"] = "0xA1B34F58CAD705B2";
								}
								printf("\n");
							}
						}
					}

					if (!strstr(argv[4], "%")) {
						break;
					}
				}
				

				std::ofstream jon(argv[3]);
				jon << js.dump(4);
				jon.close();
			}
			
		}
		else if ((std::string)argv[1] == "match") {
			std::ifstream log(argv[2]);

			struct READ {
				uint64_t bytes = 0;
				uint64_t size = 0;
				uint64_t offset = 0;
				size_t pathHash;
			};
			std::vector<READ> reads;

			std::unordered_map<int, std::string> handles;

			std::unordered_map<size_t, std::string> paths;
			std::hash<std::string> stringHasher;

			struct DEC {
				uint64_t bytes = 0;
				std::string password;
			};
			std::vector<DEC> decs;

			std::ifstream jin(argv[3]);
			json js;
			jin >> js;
			jin.close();

			int newKeys = 0;

			auto doDecs = [&]() {
				for (const auto& d : decs) {
					for (const auto& r : reads) {
						if (r.bytes == d.bytes) {
							//printf("%s %d %d %s\n", d.password.c_str(), r.offset, r.size, paths.at(r.pathHash).c_str());
							json* jss = &js;

							bool foundGame = false;
							for (const auto& p : ((fs::path)paths.at(r.pathHash).c_str())) {
								if (p.string() == "GalGun Returns")
									foundGame = true;
								if (foundGame) {
									//printf("%s\n", p.string().c_str());
									(*jss)[p.string().c_str()];
									jss = &(*jss)[p.string().c_str()];
								}
							}
							if (foundGame) {
								bool duplicate = false;
								for (const auto& e : (*jss)["keys"]) {
									if (e.contains("offset")) {
										if (e["offset"].get<int>() == r.offset) {
											duplicate = true;
											break;
										}
									}
								}
								if (!duplicate) {
									(*jss)["keys"].push_back({
										{ "key", d.password.c_str() },
										{ "size", r.size},
										{ "offset", r.offset } });
									printf("NEW key %s offs %-10d size %-10d file %s\n", d.password.c_str(), r.offset, r.size, paths.at(r.pathHash).c_str());
									newKeys++;
									break;
								}
								else {
									//printf("KNOWN key %s offs %-10d size %-10d on file %s\n", d.password.c_str(), r.offset, r.size, paths.at(r.pathHash).c_str());
									break;
								}

							}
						}
					}
				}
				decs.resize(0);
			};

			while (!log.eof()) {
				char line[2048];
				log.getline(line, 2048, '\n');
				if (line[0] == '[') {
					{
						int handle = -1;
						char nameBuf[2048];
						if (sscanf(line, "[fCreateW] handle: %d, name: %[^\n]", &handle, nameBuf) == 2) {
							//printf("handle %d with name %s\n", handle, nameBuf);
							if (handle == -1)
								continue;
							if (handles.find(handle) != handles.end()) { //if already present
								doDecs();
							}
							handles.insert_or_assign(handle, nameBuf);
							paths.insert_or_assign(stringHasher(nameBuf), nameBuf);
						}
					}
					{
						int handle, size, offset;
						uint64_t bytes;
						if (sscanf(line, "[fRead]: handle: %d, size: %d, offset: %d, bytes: %016llx", &handle, &size, &offset, &bytes) == 4) {
							//const std::string* b = nullptr;
							//for (const auto& a : handles) {
							//	b = &a.name;
							//}
							//printf("read with handle %d, size %d, offset %d and bytes %016llx\n", handle, size, offset, bytes);
							if (handle == -1)
								continue;

							READ r;
							r.bytes = bytes;
							r.offset = offset;
							r.size = size;
							const auto found = handles.find(handle);
							if (found != handles.end()) {
								r.pathHash = stringHasher(handles.at(handle));
								reads.emplace_back(r);
							}

							continue;
						}
					}
					{
						char nameBuf[2048];
						uint64_t bytes = 0;
						if (sscanf(line, "[decrypt] string: %[^,], bytes: %016llx", nameBuf, &bytes) == 2) {
							//printf("decrypt with name %s and bytes %016llx\n", nameBuf, bytes);

							DEC d;
							d.password = nameBuf;
							d.bytes = bytes;
							decs.push_back(d);

							continue;
						}
					}
				}
			}


			printf("new keys found: %d\n", newKeys);

			std::ofstream jon(argv[3]);
			jon << js.dump(4);
			jon.close();

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


			int newKeys = 0;

			if (argc == 4) {
				std::ifstream log(argv[2]);

				std::ifstream jin(argv[3]);
				json js;
				jin >> js;
				jin.close();

				auto doDecrypts = [&]() {
					for (const auto& d : decs) {
						const MREAD* match = nullptr;
						bool found = false;
						for (const auto& r : reads) {
							if (d.bytes == r.bytes) {
								if (found == true && r.offset != match->offset) {
									printf("BADDDDD %016llx duplicate\n", r.bytes);
									//return 0;
								}
								match = &r;
								found = true;
							}
						}

						if (match) {
							for (const auto& h : handles) {
								if (h.handle == match->handle) {
									
									json* jss = &js;

									bool foundGame = false;
									for (const auto& p : ((fs::path)h.name.c_str())) {
										if (p.string() == "GalGun Returns")
											foundGame = true;
										if (foundGame) {
											//printf("%s\n", p.string().c_str());
											(*jss)[p.string().c_str()];
											jss = &(*jss)[p.string().c_str()];
										}
									}
									if (foundGame) {
										bool duplicate = false;
										for (const auto& e : (*jss)["keys"]) {
											if (e.contains("offset")) {
												if (e["offset"].get<int>() == match->offset) {
													duplicate = true;
													break;
												}
											}
										}
										if (!duplicate) {
											(*jss)["keys"].push_back({
												{ "key", d.password.c_str() },
												{ "size", match->size},
												{ "offset", match->offset } });
											printf("NEW key %s offs %-10d size %-10d on %8d file %s\n", d.password.c_str(), match->offset, match->size, match->handle, h.name.c_str());
											newKeys++;
										}
										else {
											//printf("KNOWN key %s offs %-10d size %-10d on file %s\n", d.password.c_str(), match->offset, match->size, h.name.c_str());
										}

									}
								}
							}
						}
					}
					decs.resize(0);
				};

				while (!log.eof()) {
					char line[2048];
					log.getline(line, 2048, '\n');
					if (line[0] == '[') {
						{
							int handle = -1;
							char nameBuf[2048];
							if (sscanf(line, "[fCreateW] handle: %d, name: %[^\n]", &handle, nameBuf) == 2) {
								//printf("handle %d with name %s\n", handle, nameBuf);
								if (handle == -1)
									continue;

								

								MHANDLE h;
								bool dup = false;
								for (auto& b : handles) {
									if (b.handle == handle) {
										//printf("handle duplicate! not adding\n");

										if (nameBuf != b.name) {
											//printf("BAD DUPLICATE\n    %s\n    %s\n", nameBuf, b.name.c_str());
											doDecrypts();
											
										}

										b.handle = handle;
										b.name = nameBuf;
										dup = true;
										break;
									}
								}
								if (!dup) {
									h.name = nameBuf;
									h.handle = handle;
									handles.emplace_back(h);
									continue;
								}
								
							}
						}
						{
							int handle, size, offset;
							uint64_t bytes;
							if (sscanf(line, "[fRead]: handle: %d, size: %d, offset: %d, bytes: %016llx", &handle, &size, &offset, &bytes) == 4) {
								//const std::string* b = nullptr;
								//for (const auto& a : handles) {
								//	b = &a.name;
								//}
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

				printf("new keys: %d\n", newKeys);

				/*for (const auto& d : decs) {
					const MREAD* match = nullptr;
					bool found = false;
					for (const auto& r : reads) {
						if (d.bytes == r.bytes) {
							match = &r;
							if (found == true && r.offset != match->offset) {
								printf("BADDDDD\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n %016llx duplicate\n", r.bytes);
								//return 0;
							}
							found = true;
						}
					}

					if (match) {

						for (const auto& h : handles) {

							if (h.handle == match->handle) {
								printf("key %s offs %-10d size %-10d on file %s\n", d.password.c_str(), match->offset, match->size, h.name.c_str());
								//fprintf(ofp, "%s,%ld,%ld,%s\n", d.password.c_str(), match->offset, match->size, h.name.c_str());
								json* jss = &js;
								bool foundGame = false;
								for (const auto& p : ((fs::path)h.name.c_str())) {
									if (p.string() == "GalGun Returns")
										foundGame = true;
									if (foundGame) {
										//printf("%s\n", p.string().c_str());
										(*jss)[p.string().c_str()];
										jss = &(*jss)[p.string().c_str()];
									}
								}
								if (foundGame) {
									bool duplicate = false;
									for (const auto& e : (*jss)["keys"]) {
										if (e.contains("offset")) {
											if (e["offset"].get<int>() == match->offset) {
												duplicate = true;
												break;
											}
										}
									}
									if (!duplicate) {
										(*jss)["keys"].push_back({
											{ "key", d.password.c_str() },
											{ "size", match->size},
											{ "offset", match->offset } });
									}

								}

								break;
							}
						}
					}
				}*/

				std::ofstream jon(argv[3]);
				jon << js.dump(4);
				jon.close();
			}

			return 0;
			/*if (argc == 4) {
				std::ifstream log(argv[2]);
				while (!log.eof()) {
					char line[2048];
					log.getline(line, 2048, '\n');
					if (line[0] == '[') {
						//printf("first character is [\n");
						{
							int handle = -1;
							char nameBuf[2048];
							if (sscanf(line, "[fCreateW] handle: %d, name: %[^\n]", &handle, nameBuf) == 2) {
								//printf("handle %d with name %s\n", handle, nameBuf);
								if (handle == -1)
									continue;
								MHANDLE h;
								for (const auto& b : handles) {
									if (b.handle == handle) {
										//printf("handle duplicate! not adding\n");
										if (nameBuf != b.name) {
											printf("BAD DUPLICATE %s %s\n", nameBuf, b.name.c_str());
											return 0;
										}
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
								//const std::string* b = nullptr;
								//for (const auto& a : handles) {
								//	b = &a.name;
								//}
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

				//FILE* ofp = fopen(argv[3], "wb");
				//fprintf(ofp, "key,offset,size,path\n");
				std::ifstream jin(argv[3]);
				json js;
				jin >> js;
				jin.close();
				for (const auto& d : decs) {
					const MREAD* match = nullptr;
					bool found = false;
					for (const auto& r : reads) {
						if (d.bytes == r.bytes) {
							match = &r;
							if (found == true && r.offset != match->offset) {
								printf("BADDDDD\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n %016llx duplicate\n", r.bytes);
								//return 0;
							}
							found = true;
						}
					}

					if (match) {
						
						for (const auto& h : handles) {
							
							if (h.handle == match->handle) {
								printf("key %s offs %-10d size %-10d on file %s\n", d.password.c_str(), match->offset, match->size, h.name.c_str());
								//fprintf(ofp, "%s,%ld,%ld,%s\n", d.password.c_str(), match->offset, match->size, h.name.c_str());
								json* jss = &js;
								bool foundGame = false;
								for (const auto& p : ((fs::path)h.name.c_str())) {
									if (p.string() == "GalGun Returns")
										foundGame = true;
									if (foundGame) {
										//printf("%s\n", p.string().c_str());
										(*jss)[p.string().c_str()];
										jss = &(*jss)[p.string().c_str()];
									}
								}
								if (foundGame) {
									bool duplicate = false;
									for (const auto& e : (*jss)["keys"]) {
										if (e.contains("offset")) {
											if (e["offset"].get<int>() == match->offset) {
												duplicate = true;
												break;
											}
										}
									}
									if (!duplicate) {
										(*jss)["keys"].push_back({
											{ "key", d.password.c_str() },
											{ "size", match->size},
											{ "offset", match->offset } });
									}
									
								}
								
								break;
							}
						}
					}
				}

				std::ofstream jon(argv[3]);
				jon << js.dump(4);
				jon.close();

			}*/
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
		else if ((std::string)argv[1] == "dec" || (std::string)argv[1] == "enc") {
			if (argc == 6) {
				uint64_t key = calculateKeyFromName(argv[5], defKey1);
				FILE* ifp = fopen(argv[2], "rb");
				assert(ifp);

				int offset;
				sscanf(argv[4], "%d", &offset);

				fseek(ifp, 0, SEEK_END);
				size_t end = ftell(ifp);
				size_t insize = end - offset;
				uint8_t* buf = new uint8_t[insize];

				fseek(ifp, offset, SEEK_SET);

				fread(buf, 1, insize, ifp);
				fclose(ifp);

				if ((std::string)argv[1] == "dec") {
					decryptBuffer(buf, buf, key, insize);
				}
				else {
					encryptBuffer(buf, buf, key, insize);
				}

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