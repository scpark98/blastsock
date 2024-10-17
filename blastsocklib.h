#ifndef BLASTSOCK_BLASTSOCKLIB_H
#define BLASTSOCK_BLASTSOCKLIB_H

#include <exception>
#include <string>
#include <ASSERT.H>

#pragma pack (push, 1)

typedef struct _RSAKey {
	char pvk[1300];
	char pbk[321];
} RSAKey;

class AIOBlock
{
public:
	size_t data_size;		// Data size in this block
	size_t data_sent;
	char *data_ptr;			// Beginning of the data buffer
	AIOBlock *next;			// Next block or NULL for the last block

	AIOBlock(int size, const char *data = NULL)
	{
		next = NULL;
		data_size = size;
		data_sent = 0;
		data_ptr = new char[size];
		if (data_ptr && data)
			memcpy(data_ptr, data, size);
	}

	~AIOBlock()
	{
		if (data_ptr)
		delete[] data_ptr;
	}
};

#pragma pack (pop)

#endif // #ifndef BLASTSOCK_BLASTSOCKLIB_H
