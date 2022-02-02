#pragma once
#include <ctype.h>

typedef struct st25taCC_t {
	uint8_t size[2];
	uint8_t vmapping;
	uint8_t nbread[2];
	uint8_t nbwrite[2];
	uint8_t tfield;
	uint8_t vfield;
	uint8_t id[2];
	uint8_t maxsize[2];
	uint8_t readaccess;
	uint8_t writeaccess;
} st25taCC;

typedef struct st25taSF_t {
	uint8_t size[2];
	uint8_t gpocfg;		// ST25TA02KB-D, ST25TA02KB-P only
	uint8_t countercfg; // ST25TA512B, ST25TA02KB, ST25TA02KB-D, ST25TA02KB-P only
	uint8_t counter[3]; // ST25TA512B, ST25TA02KB, ST25TA02KB-D, ST25TA02KB-P only
	uint8_t filenum;
	uint8_t uid[7];
	uint8_t memsize[2];
	uint8_t product;
} st25taSF;

