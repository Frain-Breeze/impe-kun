#include "../inc/crypt.hpp"
#include <stdio.h>

int main(int argc, char* argv[]) {

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
	return 0;
}