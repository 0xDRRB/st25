#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <signal.h>
#include <nfc/nfc.h>

#include "nfcst25.h"
#include "color.h"

#define RAPDUMAXSZ 512
#define CAPDUMAXSZ 512
#define DEBUG        0

nfc_device *pnd;
nfc_context *context;


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

int CardTransmit(nfc_device *pnd, uint8_t *capdu, size_t capdulen, uint8_t *rapdu, size_t *rapdulen)
{
    int res;
    size_t  szPos;

	if(DEBUG) {
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

	if(DEBUG) {
		printf(GREEN "<= ");
		for (szPos = 0; szPos < res; szPos++) {
			printf("%02x ", rapdu[szPos]);
		}
		printf(RESET "\n");
	}

	*rapdulen = (size_t)res;

	return(0);
}

// Transmit ADPU from hex string
int strCardTransmit(nfc_device *pnd, const char *line, uint8_t *rapdu, size_t *rapdulen)
{
    int res;
    size_t szPos;
	uint8_t *capdu = NULL;
	size_t capdulen = 0;
	*rapdulen = RAPDUMAXSZ;

	uint32_t temp;
	int indx = 0;
	char buf[5] = {0};

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

	if(DEBUG) {
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

	if(DEBUG) {
		printf(GREEN "<= ");
		for (szPos = 0; szPos < res; szPos++) {
			printf("%02x ", rapdu[szPos]);
		}
		printf(RESET "\n");
	}

	*rapdulen = (size_t)res;

	if(capdu) free(capdu);
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

void printCC(st25taCC *cc) {
	printf("Capability Container file\n");
	printf("  Len:                      %u\n", (cc->size[0] << 8) | cc->size[1]);
	printf("  Version:                  %s\n", cc->vmapping == 0x20 ? "v2.0" : cc->vmapping == 0x10 ? "v1.0" : "??");
	printf("  MLe max R-APDU data size: %u\n", (cc->nbread[0] << 8) | cc->nbread[1]);
	printf("  MLc max C-APDU data size: %u\n", (cc->nbwrite[0] << 8) | cc->nbwrite[1]);
	printf("  NDEF file control TLV (Tag/Length/Value):\n");
	printf("    type of file:           %02x\n", cc->tfield);
	printf("    L field:                %02x\n", cc->vfield);
	printf("    file id:                %02x%02x\n", cc->id[0], cc->id[1]);
	printf("    max ndef size:          %u\n", (cc->maxsize[0] << 8) | cc->maxsize[1]);
	printf("    -- access rights --\n");
	printf("    read:                   %02x (%s)\n", cc->readaccess, cc->readaccess == 0x00 ? "Unlocked" : cc->readaccess == 0x80 ? "Locked" : cc->readaccess == 0xfe ? "PerlLocked" : "?????");
	printf("    write:                  %02x (%s)\n", cc->writeaccess, cc->writeaccess == 0x00 ? "Unlocked" : cc->writeaccess == 0x80 ? "Locked" : cc->writeaccess == 0xff ? "PerlLocked" : "?????");
}

void printSF(st25taSF *sf) {
	printf("ST System file\n");
	printf("  Len:               %u\n", (sf->size[0] << 8) | sf->size[1]);
	printf("  UID:               %02X%02X%02X%02X%02X%02X%02X\n", sf->uid[0], sf->uid[1], sf->uid[2], sf->uid[3], sf->uid[4], sf->uid[5], sf->uid[6]);
	printf("  Memory Size (-1):  %u\n", (sf->memsize[0] << 8) | sf->memsize[1]);
	printf("  Product:           %s (0x%02X)\n", strproduct(sf->product), sf->product);

	if(sf->product == 0xf2 || sf->product == 0xa2) {
		printf("\nST25TA02KB-D or ST25TA02KB-P detected\n");
		printf("  GPO configuration:    %s (0x%02X)\n", strGPOconfig(sf->gpocfg), sf->gpocfg);
	}
}

int st25tagetCC(nfc_device *pnd, st25taCC *cc) {
	uint8_t resp[RAPDUMAXSZ] = {0};
	size_t respsz;

	if(!cc) return(-1);

	// Select App 0xD2760000850101
	if(strCardTransmit(pnd, "00 a4 04 00 07 d2 76 00 00 85 01 01 00", resp, &respsz) < 0) {
		fprintf(stderr, "CardTransmit error!\n");
		return(-1);
	}

	if(respsz < 2 || resp[respsz-2] != 0x90 || resp[respsz-1] != 0x00) {
		fprintf(stderr, "Application select. Bad response !\n");
		return(-1);
	}

	// Select CC file 0xE103
	if(strCardTransmit(pnd, "00 a4 00 0c 02 e1 03", resp, &respsz) < 0) {
		fprintf(stderr, "CardTransmit error!\n");
		return(-1);
	}

	if(respsz < 2 || resp[respsz-2] != 0x90 || resp[respsz-1] != 0x00) {
		fprintf(stderr, "Capability Container file select. Bad response !\n");
		return(-1);
	}

	// Read
	if(strCardTransmit(pnd, "00 b0 00 00 0f", resp, &respsz) < 0) {
		fprintf(stderr, "CardTransmit error!\n");
		return(-1);
	}

	if(respsz < 2 || resp[respsz-2] != 0x90 || resp[respsz-1] != 0x00) {
		fprintf(stderr, "Capability Container file read. Bad response !\n");
		return(-1);
	}

	if(respsz == 17 && resp[0] == 0 && resp[1] == 0x0f)
		memcpy(cc, resp, 15);

	return(0);
}

int st25tagetSF(nfc_device *pnd, st25taSF *sf) {
	uint8_t resp[RAPDUMAXSZ] = {0};
	size_t respsz;

	if(!sf) return(-1);

	// Select App 0xD2760000850101
	if(strCardTransmit(pnd, "00 a4 04 00 07 d2 76 00 00 85 01 01 00", resp, &respsz) < 0) {
		fprintf(stderr, "CardTransmit error!\n");
		return(-1);
	}

	if(respsz < 2 || resp[respsz-2] != 0x90 || resp[respsz-1] != 0x00) {
		fprintf(stderr, "Application select. Bad response !\n");
		return(-1);
	}

	// Select ST file 0xE101
	if(strCardTransmit(pnd, "00 a4 00 0c 02 e1 01", resp, &respsz) < 0) {
		fprintf(stderr, "CardTransmit error!\n");
		return(-1);
	}

	if(respsz < 2 || resp[respsz-2] != 0x90 || resp[respsz-1] != 0x00) {
		fprintf(stderr, "ST System file select. Bad response !\n");
		return(-1);
	}

	// Read
	if(strCardTransmit(pnd, "00 b0 00 00 12", resp, &respsz) < 0) {
		fprintf(stderr, "CardTransmit error!\n");
		return(-1);
	}

	if(respsz < 2 || resp[respsz-2] != 0x90 || resp[respsz-1] != 0x00) {
		fprintf(stderr, "ST System file read. Bad response !\n");
		return(-1);
	}

	if(respsz == 20 && resp[0] == 0 && resp[1] == 0x12)
		memcpy(sf, resp, 18);

	return(0);
}

int st25tagetndef(nfc_device *pnd, uint8_t **data) {
	int len = 0;
    uint8_t resp[RAPDUMAXSZ] = {0};
	size_t respsz = RAPDUMAXSZ;
	st25taCC tmpcc;
	uint16_t readsz;
	uint8_t selndefapdu[7] = { 0x00, 0xa4, 0x00, 0x0c, 0x02, 0x00, 0x00 };
	unsigned int bytestoread;
	uint16_t pos;
	uint16_t end;
	uint8_t rndefapdu[5] = { 0x00, 0xb0, 0x00, 0x00, 0x00 };
	uint8_t *p;

	if(st25tagetCC(pnd, &tmpcc) != 0)
		return(-1);

	// get read max size
	readsz = (tmpcc.nbread[0] << 8) | tmpcc.nbread[1];

	// check read access right
	if(tmpcc.readaccess != 0) {
		fprintf(stderr, "NDEF file locked!\n");
		return(-1);
	}

	// select NDEF with ID from CC
	selndefapdu[5] = tmpcc.id[0];
	selndefapdu[6] = tmpcc.id[1];

	if(CardTransmit(pnd, selndefapdu, 7, resp, &respsz) < 0) {
		fprintf(stderr, "CardTransmit error!\n");
		return(-1);
	}

	if(respsz < 2 || resp[respsz-2] != 0x90 || resp[respsz-1] != 0x00) {
		fprintf(stderr, "NDEF file select. Bad response !\n");
		return(-1);
	}

	// read NDEF size
	if(strCardTransmit(pnd, "00b0 0000 02", resp, &respsz) < 0) {
		fprintf(stderr, "CardTransmit error!\n");
		return(-1);
	}

	if(respsz < 2 || resp[respsz-2] != 0x90 || resp[respsz-1] != 0x00) {
		fprintf(stderr, "NDEF file select. Bad response !\n");
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

		rndefapdu[2] = (pos >> 8);
		rndefapdu[3] = pos & 255;
		rndefapdu[4] = nread;

		respsz = RAPDUMAXSZ;
		if(CardTransmit(pnd, rndefapdu, 5, resp, &respsz) < 0) {
			fprintf(stderr, "CardTransmit error!\n");
			return(-1);
		}

		if(respsz < 2 || resp[respsz-2] != 0x90 || resp[respsz-1] != 0x00) {
			fprintf(stderr, "NDEF file read. Bad response !\n");
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


int main(int argc, const char *argv[])
{
	nfc_target nt;
	st25taSF sf = { 0 };
	st25taCC cc = { 0 };
	uint8_t *ndef = NULL;
	size_t ndeflen = 0;
	const nfc_modulation mod = {
		.nmt = NMT_ISO14443A,
		.nbr = NBR_106
	};

	// Initialize libnfc and set the nfc_context
	nfc_init(&context);
	if(context == NULL) {
		printf("Unable to init libnfc (malloc)\n");
		exit(EXIT_FAILURE);
	}

    if(signal(SIGINT, &sighandler) == SIG_ERR) {
        printf("Can't catch SIGINT\n");
        return(EXIT_FAILURE);
    }

    if(signal(SIGTERM, &sighandler) == SIG_ERR) {
        printf("Can't catch SIGTERM\n");
        return(EXIT_FAILURE);
    }

	// Open, using the first available NFC device which can be in order of selection:
	//   - default device specified using environment variable or
	//   - first specified device in libnfc.conf (/etc/nfc) or
	//   - first specified device in device-configuration directory (/etc/nfc/devices.d) or
	//   - first auto-detected (if feature is not disabled in libnfc.conf) device
	pnd = nfc_open(context, NULL);

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

	if(st25tagetSF(pnd, &sf) != 0) {
		fprintf(stderr, "Unable to get ST System file!\n");
		failquit();
	}
	printf("\n");
	printSF(&sf);

	if(st25tagetCC(pnd, &cc) != 0) {
		fprintf(stderr, "unable to get st system file!\n");
		failquit();
	}
	printf("\n");
	printCC(&cc);

	if((ndeflen=st25tagetndef(pnd, &ndef)) < 0 ) {
		fprintf(stderr, "Unable to read NDEF file read !\n");
		failquit();
	}

	// display
	printf("\nNDEF data:\n");
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

	// Close NFC device
	nfc_close(pnd);
	// Release the context
	nfc_exit(context);
	exit(EXIT_SUCCESS);
}
