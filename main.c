#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <signal.h>
#include <unistd.h>
#include <nfc/nfc.h>

#include "nfcst25.h"
#include "color.h"

#define RAPDUMAXSZ 512
#define CAPDUMAXSZ 512
#define DEBUG        0

nfc_device *pnd;
nfc_context *context;
int optverb = 0;

// https://en.wikipedia.org/wiki/Smart_card_application_protocol_data_unit
// https://www.st.com/resource/en/datasheet/st25ta64k.pdf
// https://www.eftlab.com/knowledge-base/complete-list-of-apdu-responses/

// gestionnaire de signal
static void sighandler(int sig)
{
    printf("Caught signal %d\n", sig);
    if(pnd != NULL) {
        nfc_abort_command(pnd);
        nfc_close(pnd);
    }
    nfc_exit(context);
    exit(EXIT_FAILURE);
}

int cardtransmit(nfc_device *pnd, uint8_t *capdu, size_t capdulen, uint8_t *rapdu, size_t *rapdulen)
{
    int res;
	uint16_t status;
    size_t  szPos;

	if(DEBUG || optverb) {
		printf(YELLOW "=> ");
		for (szPos = 0; szPos < capdulen; szPos++) {
			printf("%02x ", capdu[szPos]);
		}
		printf(RESET "\n");
	}

    if((res = nfc_initiator_transceive_bytes(pnd, capdu, capdulen, rapdu, *rapdulen, -1)) < 0) {
        fprintf(stderr, "nfc_initiator_transceive_bytes error! %s\n", nfc_strerror(pnd));
        return(-1);
    }

	if(DEBUG || optverb) {
		printf(GREEN "<= ");
		for (szPos = 0; szPos < res; szPos++) {
			printf("%02x ", rapdu[szPos]);
		}
		printf(RESET "\n");
	}

	if(res < 2) {
		fprintf(stderr, "Bad response !\n");
		return(-1);
	}

	status = (rapdu[res-2] << 8) | rapdu[res-1];
	if(status != S_SUCCESS) {
		fprintf(stderr, "Bad response ! 0x%04x:%s\n", status, strst25tastatus(status));
		return(-1);
	}

	*rapdulen = (size_t)res;

	return(0);
}

// Transmit ADPU from hex string
int strcardtransmit(nfc_device *pnd, const char *line, uint8_t *rapdu, size_t *rapdulen)
{
    int res;
    size_t szPos;
	uint8_t *capdu = NULL;
	size_t capdulen = 0;
	*rapdulen = RAPDUMAXSZ;

	uint32_t temp;
	int indx = 0;
	char buf[5] = {0};

	uint16_t status;

	// linelen >0 & even
	if(!strlen(line) || strlen(line) > CAPDUMAXSZ*2)
		return(-1);

	if(!(capdu = malloc(strlen(line)/2))) {
		fprintf(stderr, "malloc list error: %s\n", strerror(errno));
		nfc_close(pnd);
		nfc_exit(context);
		exit(EXIT_FAILURE);
	}

    while (line[indx]) {
        if(line[indx] == '\t' || line[indx] == ' ') {
            indx++;
            continue;
        }

        if(isxdigit(line[indx])) {
            buf[strlen(buf) + 1] = 0x00;
            buf[strlen(buf)] = line[indx];
        } else {
            // if we have symbols other than spaces and hex
			free(capdu);
            return(-1);
        }

        if(strlen(buf) >= 2) {
            sscanf(buf, "%x", &temp);
            capdu[capdulen] = (uint8_t)(temp & 0xff);
            *buf = 0;
            capdulen++;
        }
        indx++;
    }

	// error if partial hex bytes
	if(strlen(buf) > 0) {
		free(capdu);
		return(-1);
	}

	if(DEBUG || optverb) {
		printf(YELLOW "=> " );
		for (szPos = 0; szPos < capdulen; szPos++) {
			printf("%02x ", capdu[szPos]);
		}
		printf(RESET "\n");
	}

    if((res = nfc_initiator_transceive_bytes(pnd, capdu, capdulen, rapdu, *rapdulen, -1)) < 0) {
        fprintf(stderr, "nfc_initiator_transceive_bytes error! %s\n", nfc_strerror(pnd));
		*rapdulen = 0;
        return(-1);
    }

	if(capdu) free(capdu);

	if(DEBUG || optverb) {
		printf(GREEN "<= ");
		for (szPos = 0; szPos < res; szPos++) {
			printf("%02x ", rapdu[szPos]);
		}
		printf(RESET "\n");
	}

	status = (rapdu[res-2] << 8) | rapdu[res-1];
	if(status != S_SUCCESS) {
		fprintf(stderr, "Bad response ! 0x%04x:%s\n", status, strst25tastatus(status));
		return(-1);
	}

	*rapdulen = (size_t)res;

	return(0);
}

static void print_hex(const uint8_t *pbtData, const size_t szBytes)
{
	size_t  szPos;

	for(szPos = 0; szPos < szBytes; szPos++) {
		printf("%02X", pbtData[szPos]);
	}
}

void failquit()
{
	if(pnd) nfc_close(pnd);
	if(context) nfc_exit(context);
	exit(EXIT_SUCCESS);
}

const char *strst25tastatus(uint16_t code) {
	switch(code) {
		case S_SUCCESS:
			return("Command completed successfully");
		case E_OVERFLOW_E:
			return("File overflow (Le error)");
		case E_EOF:
			return("End of file or record reached before reading Le bytes");
		case E_PASSREQ:
			return("Password is required");
		case E_BADPASS0:
			return("Password is incorrect, 0 further retries allowed");
		case E_BADPASS1:
			return("Password is incorrect, 1 further retries allowed");
		case E_BADPASS3:
			return("Password is incorrect, 2 further retries allowed");
		case E_UPDATEERR:
			return("Unsuccessful updating");
		case E_WRONGLEN:
			return("Wrong length");
		case E_CMDINCOMP:
			return("Command is incompatible with the file structure");
		case E_NOTSEC:
			return("Security status not satisfied");
		case E_DATAREF:
			return("Reference data not usable");
		case E_BABCOND:
			return("The conditions of use are not satisfied");
		case E_INCPARAM:
			return("Incorrect parameters Le/Lc or CC file or System file selected");
		case E_NOTFOUND:
			return("File or application not found");
		case E_OVERFLOW_C:
			return("File overflow (Lc error)");
		case E_BADP1P2:
			return("Incorrect P1 or P2 values");
		case E_NOINS:
			return("INS field not supported");
		case E_CLASS:
			return("Class not supported");
		default:
			return("Unknown error");
	}
}

const char *strproduct(uint8_t code) {
	switch(code) {
		case 0xc4: return("ST25TA64K");
		case 0xc5: return("ST25TA16K");
		case 0xe5: return("ST25TA512B");
		case 0xe2: return("ST25TA02KB");
		case 0xf2: return("ST25TA02KB-D");
		case 0xa2: return("ST25TA02KB-P");
		default: return("unknown");
	}
}

const char *strGPOconfig(uint8_t code) {
	switch(code >> 4) {
		case 0: return("Not used - unlocked");
		case 1: return("Session opened - unlocked");
		case 2: return("WIP (Writing In Progress) - unlocked");
		case 3: return("MIP (NDEF Message updating In Progress) - unlocked");
		case 4: return("Interrupt - unlocked");
		case 5: return("State Control - unlocked");
		case 6: return("RF Busy - unlocked");
		case 7: return("Field Detect - unlocked");
		case 0+8: return("Not used - locked");
		case 1+8: return("Session opened - locked");
		case 2+8: return("WIP (Writing In Progress) - locked");
		case 3+8: return("MIP (NDEF Message updating In Progress) - locked");
		case 4+8: return("Interrupt - locked");
		case 5+8: return("State Control - locked");
		case 6+8: return("RF Busy - locked");
		case 7+8: return("Field Detect - locked");
		default: return("unknown");
	}
}

const char *straccessbyte(uint8_t byte) {
	switch(byte) {
		case 0x00: return(GREEN "Unlocked" RESET);
		case 0x80: return(YELLOW "Locked" RESET);
		case 0xfe: return(RED "Permalocked" RESET);
		case 0xff: return(RED "Permalocked" RESET);
		default: return("????");
	}
}

void printCC(st25taCC *cc, uint8_t numfile) {
	printf("Capability Container file\n");
	printf("  Len:                      %u\n", (cc->size[0] << 8) | cc->size[1]);
	printf("  Version:                  %s\n", cc->vmapping == 0x20 ? "v2.0" : cc->vmapping == 0x10 ? "v1.0" : "??");
	printf("  MLe max R-APDU data size: %u\n", (cc->nbread[0] << 8) | cc->nbread[1]);
	printf("  MLc max C-APDU data size: %u\n", (cc->nbwrite[0] << 8) | cc->nbwrite[1]);
	printf("  NDEF file control TLV (Tag/Length/Value):\n");
	printf(CYAN "    file id:                %02x%02x" RESET "\n", cc->id[0], cc->id[1]);
	printf("    type of file:           %s (%02x)\n", cc->tfield==0x04 ? "NDEF" : cc->tfield==0x05 ? "Proprietary" : "????", cc->tfield);
	printf("    max ndef size:          %u\n", (cc->maxsize[0] << 8) | cc->maxsize[1]);
	printf("    read access:            %02x (%s)\n", cc->readaccess, straccessbyte(cc->readaccess));
	printf("    write access:           %02x (%s)\n", cc->writeaccess, straccessbyte(cc->writeaccess));

	if(numfile >= 1) {
		printf("  ----\n");
		printf(CYAN "    file id:                %02x%02x" RESET "\n", cc->id1[0], cc->id1[1]);
		printf("    type of file:           %s (%02x)\n", cc->tfield1==0x04 ? "NDEF" : cc->tfield1==0x05 ? "Proprietary" : "????", cc->tfield1);
		printf("    max ndef size:          %u\n", (cc->maxsize1[0] << 8) | cc->maxsize1[1]);
		printf("    read access:            %02x (%s)\n", cc->readaccess1, straccessbyte(cc->readaccess1));
		printf("    write access:           %02x (%s)\n", cc->writeaccess1, straccessbyte(cc->writeaccess1));
	}
	if(numfile >= 2) {
		printf("  ----\n");
		printf(CYAN "    file id:                %02x%02x" RESET "\n", cc->id2[0], cc->id2[1]);
		printf("    type of file:           %s (%02x)\n", cc->tfield2==0x04 ? "NDEF" : cc->tfield2==0x05 ? "Proprietary" : "????", cc->tfield2);
		printf("    max ndef size:          %u\n", (cc->maxsize2[0] << 8) | cc->maxsize2[1]);
		printf("    read access:            %02x (%s)\n", cc->readaccess2, straccessbyte(cc->readaccess2));
		printf("    write access:           %02x (%s)\n", cc->writeaccess2, straccessbyte(cc->writeaccess2));
	}
	if(numfile >= 3) {
		printf("  ----\n");
		printf(CYAN "    file id:                %02x%02x" RESET "\n", cc->id3[0], cc->id3[1]);
		printf("    type of file:           %s (%02x)\n", cc->tfield3==0x04 ? "NDEF" : cc->tfield3==0x05 ? "Proprietary" : "????", cc->tfield3);
		printf("    max ndef size:          %u\n", (cc->maxsize3[0] << 8) | cc->maxsize3[1]);
		printf("    read access:            %02x (%s)\n", cc->readaccess3, straccessbyte(cc->readaccess3));
		printf("    write access:           %02x (%s)\n", cc->writeaccess3, straccessbyte(cc->writeaccess3));
	}
	if(numfile >= 4) {
		printf("  ----\n");
		printf(CYAN "    file id:                %02x%02x" RESET "\n", cc->id4[0], cc->id4[1]);
		printf("    type of file:           %s (%02x)\n", cc->tfield4==0x04 ? "NDEF" : cc->tfield4==0x05 ? "Proprietary" : "????", cc->tfield4);
		printf("    max ndef size:          %u\n", (cc->maxsize4[0] << 8) | cc->maxsize4[1]);
		printf("    read access:            %02x (%s)\n", cc->readaccess4, straccessbyte(cc->readaccess4));
		printf("    write access:           %02x (%s)\n", cc->writeaccess4, straccessbyte(cc->writeaccess4));
	}
	if(numfile >= 5) {
		printf("  ----\n");
		printf(CYAN "    file id:                %02x%02x" RESET "\n", cc->id5[0], cc->id5[1]);
		printf("    type of file:           %s (%02x)\n", cc->tfield5==0x04 ? "NDEF" : cc->tfield5==0x05 ? "Proprietary" : "????", cc->tfield5);
		printf("    max ndef size:          %u\n", (cc->maxsize5[0] << 8) | cc->maxsize5[1]);
		printf("    read access:            %02x (%s)\n", cc->readaccess5, straccessbyte(cc->readaccess5));
		printf("    write access:           %02x (%s)\n", cc->writeaccess5, straccessbyte(cc->writeaccess5));
	}
	if(numfile >= 6) {
		printf("  ----\n");
		printf(CYAN "    file id:                %02x%02x" RESET "\n", cc->id6[0], cc->id6[1]);
		printf("    type of file:           %s (%02x)\n", cc->tfield6==0x04 ? "NDEF" : cc->tfield6==0x05 ? "Proprietary" : "????", cc->tfield6);
		printf("    max ndef size:          %u\n", (cc->maxsize6[0] << 8) | cc->maxsize6[1]);
		printf("    read access:            %02x (%s)\n", cc->readaccess6, straccessbyte(cc->readaccess6));
		printf("    write access:           %02x (%s)\n", cc->writeaccess6, straccessbyte(cc->writeaccess6));
	}
	if(numfile >= 7) {
		printf("  ----\n");
		printf(CYAN "    file id:                %02x%02x" RESET "\n", cc->id7[0], cc->id7[1]);
		printf("    type of file:           %s (%02x)\n", cc->tfield7==0x04 ? "NDEF" : cc->tfield7==0x05 ? "Proprietary" : "????", cc->tfield7);
		printf("    max ndef size:          %u\n", (cc->maxsize7[0] << 8) | cc->maxsize7[1]);
		printf("    read access:            %02x (%s)\n", cc->readaccess7, straccessbyte(cc->readaccess7));
		printf("    write access:           %02x (%s)\n", cc->writeaccess7, straccessbyte(cc->writeaccess7));
	}
}

void printSF(st25taSF *sf) {
	printf("ST System file\n");
	printf("  Len:                      %u\n", (sf->size[0] << 8) | sf->size[1]);
	printf("  UID:                      %02X%02X%02X%02X%02X%02X%02X\n", sf->uid[0], sf->uid[1], sf->uid[2], sf->uid[3], sf->uid[4], sf->uid[5], sf->uid[6]);
	printf("  Memory Size (-1):         %u\n", (sf->memsize[0] << 8) | sf->memsize[1]);
	printf("  Product:                  %s (0x%02X)\n", strproduct(sf->product), sf->product);
	if(sf->product == 0xc4 || sf->product == 0xc5)
		printf("  Number of NDEF file:      %u\n", sf->ver_filenum+1);

	if(sf->product == 0xf2 || sf->product == 0xa2) {
		printf("\nST25TA02KB-D or ST25TA02KB-P detected\n");
		printf("  GPO configuration:    %s (0x%02X)\n", strGPOconfig(sf->gpocfg), sf->gpocfg);
	}
}

int st25tagetCC(nfc_device *pnd, st25taCC *cc) {
	uint8_t resp[RAPDUMAXSZ] = {0};
	size_t respsz;
	uint8_t readccapdu[5] = { 0x00, 0xb0, 0x00, 0x00, 0x00 };

	if(!cc) return(-1);

	// Select App 0xD2760000850101
	if(strcardtransmit(pnd, "00a4 0400 07 d2760000850101 00", resp, &respsz) < 0) {
		fprintf(stderr, "cardtransmit error!\n");
		return(-1);
	}

	// Select CC file 0xE103
	if(strcardtransmit(pnd, "00a4 000c 02 e103", resp, &respsz) < 0) {
		fprintf(stderr, "cardtransmit error!\n");
		return(-1);
	}

	// Read 2 bytes from file (size of file)
	if(strcardtransmit(pnd, "00b0 0000 02", resp, &respsz) < 0) {
		fprintf(stderr, "cardtransmit error!\n");
		return(-1);
	}

	// 2 bytes + 0x9000
	if(respsz != 4)
		return(-1);

	// set number of bytes to read
	// only second byte since max CC file size = 15+(8*7) with 8 areas
	readccapdu[4] = resp[1];

	// Then read the file in full
	respsz = RAPDUMAXSZ;
	if(cardtransmit(pnd, readccapdu, 5, resp, &respsz) < 0) {
		fprintf(stderr, "cardtransmit error!\n");
		return(-1);
	}

	if(respsz == readccapdu[4]+2 && resp[0] == 0 && resp[1] == readccapdu[4])
		memcpy(cc, resp, readccapdu[4]);

	return(0);
}

int st25tagetSF(nfc_device *pnd, st25taSF *sf) {
	uint8_t resp[RAPDUMAXSZ] = {0};
	size_t respsz;

	if(!sf) return(-1);

	// Select App 0xD2760000850101
	if(strcardtransmit(pnd, "00a4 0400 07 d2760000850101 00", resp, &respsz) < 0) {
		fprintf(stderr, "cardtransmit error!\n");
		return(-1);
	}

	// Select ST file 0xE101
	if(strcardtransmit(pnd, "00a4 000c 02 e101", resp, &respsz) < 0) {
		fprintf(stderr, "cardtransmit error!\n");
		return(-1);
	}

	// Read
	if(strcardtransmit(pnd, "00b0 0000 12", resp, &respsz) < 0) {
		fprintf(stderr, "cardtransmit error!\n");
		return(-1);
	}

	if(respsz == 20 && resp[0] == 0 && resp[1] == 0x12)
		memcpy(sf, resp, 18);

	return(0);
}

int st25tagetndef(nfc_device *pnd, uint8_t **data, uint8_t *pass, int havepass) {
	int len = 0;
    uint8_t resp[RAPDUMAXSZ] = {0};
	size_t respsz = RAPDUMAXSZ;
	st25taCC tmpcc;
	uint16_t readsz;
	uint8_t selndefapdu[7] = { 0x00, 0xa4, 0x00, 0x0c, 0x02, 0x00, 0x00 };
	uint8_t verifapdu[21] = { 0x00, 0x20, 0x00, 0x01, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	unsigned int bytestoread;
	uint16_t pos;
	uint16_t end;
	uint8_t readndefapdu[5] = { 0x00, 0xb0, 0x00, 0x00, 0x00 };
	uint8_t *p;

	if(st25tagetCC(pnd, &tmpcc) != 0)
		return(-1);

	// get read max size
	readsz = (tmpcc.nbread[0] << 8) | tmpcc.nbread[1];

	// check read access right
	if(tmpcc.readaccess == 0xfe) {
		fprintf(stderr, "NDEF file permalocked!\n");
		return(-1);
	}

	// locked. Have password ?
	if(tmpcc.readaccess == 0x80 && !havepass) {
		fprintf(stderr, "NDEF file locked and no password given!\n");
		return(-1);
	}

	// select NDEF with ID from CC
	selndefapdu[5] = tmpcc.id[0];
	selndefapdu[6] = tmpcc.id[1];
	respsz = RAPDUMAXSZ;
	if(cardtransmit(pnd, selndefapdu, 7, resp, &respsz) < 0) {
		fprintf(stderr, "cardtransmit error!\n");
		return(-1);
	}

	// verify with password given
	if(tmpcc.readaccess == 0x80) {
		// try to unlock with password
		memcpy(verifapdu+5, pass, 16);
		if(cardtransmit(pnd, verifapdu, 21, resp, &respsz) < 0) {
			fprintf(stderr, "cardtransmit error!\n");
			return(-1);
		}
	}

	// read NDEF size
	if(strcardtransmit(pnd, "00b0 0000 02", resp, &respsz) < 0) {
		fprintf(stderr, "cardtransmit error!\n");
		return(-1);
	}

	// prepare loop read
	bytestoread = (resp[0] << 8) | resp[1];

	if(!(p = malloc(bytestoread))) {
		fprintf(stderr, "malloc error: %s\n", strerror(errno));
		return(-1);
	}

	pos = 2;
	end = bytestoread+pos;

	// loop read
	while(pos < end-1) {
		uint8_t nread = pos+readsz < end ? readsz : end-pos;

		readndefapdu[2] = (pos >> 8);
		readndefapdu[3] = pos & 255;
		readndefapdu[4] = nread;

		respsz = RAPDUMAXSZ;
		if(cardtransmit(pnd, readndefapdu, 5, resp, &respsz) < 0) {
			fprintf(stderr, "cardtransmit error!\n");
			return(-1);
		}

		memcpy(p+pos-2, resp, nread);
		pos=pos+nread;
	}

	len = bytestoread;
	*data = p;
	return(len);
}

int st25tacheck(nfc_target *nt) {
	if(nt->nti.nai.abtUid[0] != 0x02) {
		return(0);
	}

	// UID[1]!=productID
	// e4=ST25TA512B  e3=ST25TA02KB  f3=ST25TA02KB-D  a3=ST25TA02KB-P
	// c4=ST25TA16K  c5=ST25TA16K
	if(nt->nti.nai.abtUid[1] != 0xc4 && nt->nti.nai.abtUid[1] != 0xc5 &&
	   nt->nti.nai.abtUid[1] != 0xe4 && nt->nti.nai.abtUid[1] != 0xe3 &&
	   nt->nti.nai.abtUid[1] != 0xf3 && nt->nti.nai.abtUid[1] != 0xa3) {
		return(0);
	}

	return(1);
}

int listdevices() {
	size_t device_count;
	nfc_connstring devices[8];

	// Scan readers/devices
	device_count = nfc_list_devices(context, devices, sizeof(devices)/sizeof(*devices));
	if(device_count <= 0) {
		fprintf(stderr, "No NFC device found\n");
		return(0);
	}

	printf("Available readers/devices:\n");
	for(size_t d = 0; d < device_count; d++) {
		printf("  %lu: ", d);
		if(!(pnd = nfc_open (context, devices[d]))) {
			printf("nfc_open() failed\n");
		} else {
			printf("%s (connstring=\"%s\")\n", nfc_device_get_name(pnd), nfc_device_get_connstring(pnd));
			nfc_close(pnd);
		}
	}
	return(device_count);
}

void printhelp(char *binname)
{
	printf("ST25TA reader v0.0.1\n");
	printf("Copyright (c) 2022 - Denis Bodor\n\n");
	printf("Usage : %s [OPTIONS]\n", binname);
	printf(" -i              get info on tag\n");
	printf(" -r              read data from tag\n");
	printf(" -p password     use this read password\n");
//	printf(" -P password     use this write password\n"); // TODO
//	printf(" -q              be quiet, output nothing but data\n"); // TODO
//	printf(" -f ID           use this file ID when reading (default: use first file ID from CC)\n"); // TODO
	printf(" -d connstring   use this device (default: use the first available device)\n");
	printf(" -v              verbose mode\n");
	printf(" -h              show this help\n");
}

int str2pass128(const char *line, uint8_t *passwd, size_t len)
{
	size_t passlen = 0;
	uint32_t temp;
	int indx = 0;
	char buf[5] = {0};

	if(strlen(line) < 32 || len != 16)
		return(-1);

	while(line[indx]) {
		if(line[indx] == '\t' || line[indx] == ' ') {
			indx++;
			continue;
		}

		if(isxdigit(line[indx])) {
			buf[strlen(buf) + 1] = 0x00;
			buf[strlen(buf)] = line[indx];
		} else {
			// we have symbols other than spaces and hex
			return(-1);
		}

		if(strlen(buf) >= 2) {
			sscanf(buf, "%x", &temp);
			passwd[passlen] = (uint8_t)(temp & 0xff);
			*buf = 0;
			passlen++;
			if(passlen > len)
				return(-1);
		}

		indx++;
	}

	// no partial hex bytes and need exact match
	if(strlen(buf) > 0 || passlen != len) {
		return(-1);
	}

	return(0);
}

int main(int argc, char **argv)
{
	nfc_target nt;
	const nfc_modulation mod = {
		.nmt = NMT_ISO14443A,
		.nbr = NBR_106
	};

	st25taSF sf = { 0 };
	st25taCC cc = { 0 };
	uint8_t *ndef = NULL;
	int ndeflen = 0;
	uint8_t readpass[16] = { 0 };
//	uint8_t writepass[16] = { 0 }; // TODO

	int retopt;
	int opt = 0;
	int optinfo = 0;
	int optread = 0;
	int optreadpass = 0;
	int optlistdev = 0;
	char *optconnstring = NULL;

	while((retopt = getopt(argc, argv, "ivhrld:p:")) != -1) {
		switch (retopt) {
			case 'i':
				optinfo = 1;
				opt++;
				break;
			case 'r':
				optread = 1;
				opt++;
				break;
			case 'l':
				optlistdev = 1;
				opt++;
				break;
			case 'd':
				optconnstring = strdup(optarg);
				break;
			case 'p':
				if(str2pass128(optarg, readpass, 16) < 0) {
					fprintf(stderr, "Invalid password! Must be 16*hex (space allowed).\n");
					return(EXIT_FAILURE);
				}
				optreadpass = 1;
				break;
			case 'v':
				optverb = 1;
				break;
			case 'h':
				printhelp(argv[0]);
				return(EXIT_FAILURE);
			default:
				printhelp(argv[0]);
				return(EXIT_FAILURE);
		}
	}

	if(!opt) {
		printhelp(argv[0]);
		return(EXIT_FAILURE);
	}

    if(signal(SIGINT, &sighandler) == SIG_ERR) {
        printf("Can't catch SIGINT\n");
        return(EXIT_FAILURE);
    }

    if(signal(SIGTERM, &sighandler) == SIG_ERR) {
        printf("Can't catch SIGTERM\n");
        return(EXIT_FAILURE);
    }

	// Initialize libnfc and set the nfc_context
	nfc_init(&context);
	if(context == NULL) {
		printf("Unable to init libnfc (malloc)\n");
		exit(EXIT_FAILURE);
	}

	if(optlistdev) {
		listdevices();
		nfc_exit(context);
		return(EXIT_SUCCESS);
	}

	if(optconnstring) {
		// Open, using specified NFC device
		pnd = nfc_open(context, optconnstring);
	} else {
		// Open, using the first available NFC device which can be in order of selection:
		//   - default device specified using environment variable or
		//   - first specified device in libnfc.conf (/etc/nfc) or
		//   - first specified device in device-configuration directory (/etc/nfc/devices.d) or
		//   - first auto-detected (if feature is not disabled in libnfc.conf) device
		pnd = nfc_open(context, NULL);
	}

	if(pnd == NULL) {
		fprintf(stderr, "Unable to open NFC device!\n");
		exit(EXIT_FAILURE);
	}

	// Set opened NFC device to initiator mode
	if(nfc_initiator_init(pnd) < 0) {
		nfc_perror(pnd, "nfc_initiator_init");
		exit(EXIT_FAILURE);
	}

	printf("NFC reader: %s opened\n", nfc_device_get_name(pnd));

	if(nfc_initiator_select_passive_target(pnd, mod, NULL, 0, &nt) > 0) {
		printf("%s (%s) tag found. UID: " CYAN,
				str_nfc_modulation_type(mod.nmt), str_nfc_baud_rate(mod.nbr));
		print_hex(nt.nti.nai.abtUid, nt.nti.nai.szUidLen);
		printf(RESET "\n");
	} else {
		fprintf(stderr, "No ISO14443A tag found!\n");
		failquit();
	}

	if(st25tacheck(&nt) == 0) {
		fprintf(stderr, "Not a ST25TA* tag !\n");
		failquit();
	}

	if(optinfo) {
		if(st25tagetSF(pnd, &sf) != 0) {
			fprintf(stderr, "Unable to get ST System file!\n");
			failquit();
		}
		printf("\n");
		printSF(&sf);

		if(st25tagetCC(pnd, &cc) != 0) {
			fprintf(stderr, "unable to get CC file!\n");
			failquit();
		}
		printf("\n");

		if(sf.product == 0xc4 || sf.product == 0xc5)
			printCC(&cc, sf.ver_filenum);
		else
			printCC(&cc, 0);
	}

	if(optread) {
		if((ndeflen=st25tagetndef(pnd, &ndef, readpass, optreadpass)) < 0 ) {
			fprintf(stderr, "Unable to read file on tag!\n");
			failquit();
		}

		// display
		printf("\nNDEF data (%d):\n", ndeflen);
		if(ndeflen > 0) {
			for(int i=0; i < ndeflen; i++) {
				printf("%02x ", ndef[i]);
				if(!((i+1)%16))
					printf("\n");
			}
			printf("\n");
		} else {
			printf("No NDEF data\n");
		}

		if(ndef)
			free(ndef);
	}

	// Close NFC device
	nfc_close(pnd);
	// Release the context
	nfc_exit(context);
	exit(EXIT_SUCCESS);
}
