#include "common.h"

void PrintHexData(PBYTE pByteArray, SIZE_T sSize) {
	for (int i = 0; i < sSize; i++) {
		printf("%0.2X ", pByteArray[i]);
		if (i % 16 == 15)
			putchar('\n');
	}
	putchar('\n');
}