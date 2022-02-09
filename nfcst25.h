#pragma once
#include <ctype.h>

#define S_SUCCESS		0x9000	// Command completed successfully
#define E_OVERFLOW_E	0x6280	// File overflow (Le error)
#define E_EOF			0x6282	// End of file or record reached before reading Le bytes
#define E_PASSREQ		0x6300	// Password is required
#define E_BADPASS0		0x63c0	// Password is incorrect, 0 further retries allowed
#define E_BADPASS1		0x63c1	// Password is incorrect, 1 further retries allowed
#define E_BADPASS3		0x63c2	// Password is incorrect, 2 further retries allowed
#define E_UPDATEERR		0x6581	// Unsuccessful updating
#define E_WRONGLEN		0x6700	// Wrong length
#define E_CMDINCOMP		0x6981	// Command is incompatible with the file structure
#define E_NOTSEC		0x6982	// Security status not satisfied
#define E_DATAREF		0x6984	// Reference data not usable
#define E_BABCOND		0x6985	// The conditions of use are not satisfied
#define E_INCPARAM		0x6a80	// Incorrect parameters Le or Lc / CC file or System file selected
#define E_NOTFOUND		0x6a82	// File or application not found
#define E_OVERFLOW_C	0x6a84	// File overflow (Lc error)
#define E_BADP1P2		0x6a86	// Incorrect P1 or P2 values
#define E_NOINS			0x6d00	// INS field not supported
#define E_CLASS			0x6e00	// Class not supported

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

	uint8_t tfield1;
	uint8_t vfield1;
	uint8_t id1[2];
	uint8_t maxsize1[2];
	uint8_t readaccess1;
	uint8_t writeaccess1;

	uint8_t tfield2;
	uint8_t vfield2;
	uint8_t id2[2];
	uint8_t maxsize2[2];
	uint8_t readaccess2;
	uint8_t writeaccess2;

	uint8_t tfield3;
	uint8_t vfield3;
	uint8_t id3[2];
	uint8_t maxsize3[2];
	uint8_t readaccess3;
	uint8_t writeaccess3;

	uint8_t tfield4;
	uint8_t vfield4;
	uint8_t id4[2];
	uint8_t maxsize4[2];
	uint8_t readaccess4;
	uint8_t writeaccess4;

	uint8_t tfield5;
	uint8_t vfield5;
	uint8_t id5[2];
	uint8_t maxsize5[2];
	uint8_t readaccess5;
	uint8_t writeaccess5;

	uint8_t tfield6;
	uint8_t vfield6;
	uint8_t id6[2];
	uint8_t maxsize6[2];
	uint8_t readaccess6;
	uint8_t writeaccess6;

	uint8_t tfield7;
	uint8_t vfield7;
	uint8_t id7[2];
	uint8_t maxsize7[2];
	uint8_t readaccess7;
	uint8_t writeaccess7;
} st25taCC;

typedef struct st25taSF_t {
	uint8_t size[2];
	uint8_t gpocfg;			// ST25TA02KB-D, ST25TA02KB-P only
	uint8_t countercfg; 	// ST25TA512B, ST25TA02KB, ST25TA02KB-D, ST25TA02KB-P only
	uint8_t counter[3]; 	// ST25TA512B, ST25TA02KB, ST25TA02KB-D, ST25TA02KB-P only
	uint8_t ver_filenum;	// (ST25TA64K + ST25TA16K) = number of NDEF files    (ST25TA02KB-D + ST25TA02KB-P) = product version
	uint8_t uid[7];
	uint8_t memsize[2];
	uint8_t product;
} st25taSF;

static void sighandler(int sig);
int cardtransmit(nfc_device *pnd, uint8_t *capdu, size_t capdulen, uint8_t *rapdu, size_t *rapdulen);
int strcardtransmit(nfc_device *pnd, const char *line, uint8_t *rapdu, size_t *rapdulen);
static void print_hex(const uint8_t *pbtData, const size_t szBytes);
void failquit();
const char *strst25tastatus(uint16_t code);
const char *strproduct(uint8_t code);
const char *strGPOconfig(uint8_t code);
void printCC(st25taCC *cc, uint8_t numfile);
void printSF(st25taSF *sf);
int st25tagetCC(nfc_device *pnd, st25taCC *cc);
int st25tagetSF(nfc_device *pnd, st25taSF *sf);
int st25tagetndef(nfc_device *pnd, uint8_t **data, uint8_t *pass, int havepass);
int st25tacheck(nfc_target *nt);
int listdevices();
void printhelp(char *binname);
int hex2array(const char *line, uint8_t *passwd, size_t len);

