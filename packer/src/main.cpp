#include <stdio.h>
#include <miniz.h>

int main(int argc, char* argv[]) {

	printf("usage: ggrpack.exe [input file] [output file]\n");
	if (argc == 3) {
		FILE* ifp = fopen(argv[1], "rb");

		uint32_t size = 0;
		fread(&size, 1, 4, ifp);

		uint32_t magic_maybe = 0;
		fread(&magic_maybe, 1, 4, ifp);

		if (size == 0x10 && magic_maybe == 0x40) {
			printf("file with beeg header!\n");
			return 0;

			fseek(ifp, 220 - 4, SEEK_SET);
			uint32_t offsets[16];
			uint32_t prev_offset = 360;
			for (size_t i = 0; i < 16; i++) {
				fread(&offsets[i], 1, 4, ifp);

				prev_offset += offsets[i];
				offsets[i] = prev_offset;

				printf("offset %d: %d\n", i, offsets[i]);
			}
			for (size_t i = 0; i < 12; i++) {
				fseek(ifp, offsets[i] - 4, SEEK_SET);
				uint32_t sizeDec;
				fread(&sizeDec, 1, 4, ifp);

				fseek(ifp, 0, SEEK_END);
				size_t insize = ftell(ifp) - offsets[i];
				uint8_t* buf = new uint8_t[insize];

				fseek(ifp, offsets[i], SEEK_SET);

				fread(buf, 1, insize, ifp);

				uint8_t* datDecomp = new uint8_t[sizeDec];

				mz_ulong sizell = sizeDec;
				int res = uncompress(datDecomp, &sizell, buf, insize);

				printf("");

				char path[2048];
				snprintf(path, 2048, "%s_%d.dat", argv[2], offsets[i]);
				FILE* ofp = fopen(path, "wb");
				fwrite(datDecomp, 1, sizell, ofp);
				fclose(ofp);
			}

			return 0;
		}


		fseek(ifp, 0, SEEK_END);
		size_t insize = ftell(ifp) - 4;
		uint8_t* buf = new uint8_t[insize];
		fseek(ifp, 4, SEEK_SET);

		fread(buf, 1, insize, ifp);

		uint8_t* datDecomp = new uint8_t[size];

		mz_ulong sizeulong = size;

		int res = uncompress(datDecomp, &sizeulong, buf, insize);

		printf("res: %d\n", res);

		FILE* ofp = fopen(argv[2], "wb");

		fwrite(datDecomp, 1, sizeulong, ofp);
	}
}