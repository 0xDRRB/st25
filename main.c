#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>
#include <math.h>
#include <regex.h>
#include <signal.h>

#include <nfc/nfc.h>

#include "color.h"

#define RESPMAXSZ 32

nfc_device *pnd;
nfc_context *context;

struct st25taCC_t {
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
};

// https://en.wikipedia.org/wiki/Smart_card_application_protocol_data_unit
// https://www.st.com/resource/en/datasheet/st25ta64k.pdf
// https://www.eftlab.com/knowledge-base/complete-list-of-apdu-responses/

int param_gethex_to_eol(const char *line, uint8_t *data, int maxdatalen, int *datalen) {
    uint32_t temp;
    char buf[5] = {0};

    *datalen = 0;

    int indx = 0;
    while (line[indx]) {
        if (line[indx] == '\t' || line[indx] == ' ') {
            indx++;
            continue;
        }

        if (isxdigit(line[indx])) {
            buf[strlen(buf) + 1] = 0x00;
            buf[strlen(buf)] = line[indx];
        } else {
            // if we have symbols other than spaces and hex
            return 1;
        }

        if (*datalen >= maxdatalen) {
            // if we don't have space in buffer and have symbols to translate
            return 2;
        }

        if (strlen(buf) >= 2) {
            sscanf(buf, "%x", &temp);
            data[*datalen] = (uint8_t)(temp & 0xff);
            *buf = 0;
            (*datalen)++;
        }

        indx++;
    }

    if (strlen(buf) > 0)
        //error when not completed hex bytes
        return 3;

    return 0;
}


// gestionnaire de signal
static void sighandler(int sig)
{
    printf("Caught signal %d\n", sig);
    if (pnd != NULL) {
        nfc_abort_command(pnd);
        nfc_close(pnd);
    }
    nfc_exit(context);
    exit(EXIT_FAILURE);
}

int strCardTransmit(nfc_device *pnd, const char *line, uint8_t *rapdu, size_t *rapdulen, int debug)
{
    int res;
    size_t szPos;
	uint8_t *capdu = NULL;
	size_t capdulen = 0;

	uint32_t temp;
	int indx = 0;
	char buf[5] = {0};

	// linelen >0 & even
	if(!strnlen(line, 64) || strnlen(line, 64) % 2)
		return -1;

	capdu = malloc(strnlen(line, 64) / 2);
	if(!capdu) {
		fprintf(stderr, "malloc list error: %s\n", strerror(errno));
		nfc_close(pnd);
		nfc_exit(context);
		exit(EXIT_FAILURE);
	}

    while (line[indx]) {
        if (line[indx] == '\t' || line[indx] == ' ') {
            indx++;
            continue;
        }

        if (isxdigit(line[indx])) {
            buf[strlen(buf) + 1] = 0x00;
            buf[strlen(buf)] = line[indx];
        } else {
            // if we have symbols other than spaces and hex
			free(capdu);
            return -1;
        }

        if (strlen(buf) >= 2) {
            sscanf(buf, "%x", &temp);
            capdu[capdulen] = (uint8_t)(temp & 0xff);
            *buf = 0;
            capdulen++;
        }
        indx++;
    }

    //error when not completed hex bytes
    if(strlen(buf) > 0) {
		free(capdu);
		return -1;
	}

	if(debug) {
		printf(YELLOW "=> " );
		for (szPos = 0; szPos < capdulen; szPos++) {
			printf("%02x ", capdu[szPos]);
		}
		printf(RESET "\n");
	}

    if((res = nfc_initiator_transceive_bytes(pnd, capdu, capdulen, rapdu, *rapdulen, 500)) < 0) {
        fprintf(stderr, "nfc_initiator_transceive_bytes error! %s\n", nfc_strerror(pnd));
        return -1;
    }

	if(debug) {
		printf(GREEN "<= ");
		for (szPos = 0; szPos < res; szPos++) {
			printf("%02x ", rapdu[szPos]);
		}
		printf(RESET "\n");
	}

	*rapdulen = (size_t)res;

	free(capdu);
	return 0;
}

static void print_hex(const uint8_t *pbtData, const size_t szBytes)
{
	size_t  szPos;

	for(szPos = 0; szPos < szBytes; szPos++) {
		printf("%02x  ", pbtData[szPos]);
	}
	printf("\n");
}

int main(int argc, const char *argv[])
{
	uint8_t resp[RESPMAXSZ] = {0};
	size_t respsz = RESPMAXSZ;

	nfc_target nt;

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
		printf("ERROR: %s\n", "Unable to open NFC device.");
		exit(EXIT_FAILURE);
	}

	// Set opened NFC device to initiator mode
	if (nfc_initiator_init(pnd) < 0) {
		nfc_perror(pnd, "nfc_initiator_init");
		exit(EXIT_FAILURE);
	}

	printf("NFC reader: %s opened\n", nfc_device_get_name(pnd));

	// Poll for a ISO14443A tag
	const nfc_modulation mod = {
		.nmt = NMT_ISO14443A,	// modulation / coding / protocol initialization
		.nbr = NBR_106,			// rate
	};

	if(nfc_initiator_select_passive_target(pnd, mod, NULL, 0, &nt) > 0) {
		printf("The following (NFC) ISO14443A tag was found:\n");
		printf("    ATQA (SENS_RES): ");
		print_hex(nt.nti.nai.abtAtqa, 2);
		printf("       UID (NFCID%c): ", (nt.nti.nai.abtUid[0] == 0x08 ? '3' : '1'));
		print_hex(nt.nti.nai.abtUid, nt.nti.nai.szUidLen);
		printf("      SAK (SEL_RES): ");
		print_hex(&nt.nti.nai.btSak, 1);
		if(nt.nti.nai.szAtsLen) {
			printf("          ATS (ATR): ");
			print_hex(nt.nti.nai.abtAts, nt.nti.nai.szAtsLen);
		}
	}

	respsz = RESPMAXSZ;
	//                  class   ins   P1    P2    Lc    1     2     3     4     5     6     6     Le
	if(strCardTransmit(pnd, "00 a4 04 00 07 d2 76 00 00 85 01 01 00", resp, &respsz, 1) < 0)
		fprintf(stderr, "CardTransmit error!\n");

	if(respsz < 2 || resp[respsz-2] != 0x90 || resp[respsz-1] != 0x00)
		fprintf(stderr, "Bad response !\n");
	else
		printf("Success! App selected.\n");

	respsz = RESPMAXSZ;
	if(strCardTransmit(pnd, "00 a4 00 0c 02 e1 03", resp, &respsz, 1) < 0)
		fprintf(stderr, "CardTransmit error!\n");

	if(respsz < 2 || resp[respsz-2] != 0x90 || resp[respsz-1] != 0x00)
		fprintf(stderr, "Bad response !\n");
	else
		printf("Success! Capability Container file selected.\n");

	respsz = RESPMAXSZ;
	if(strCardTransmit(pnd, "00 b0 00 00 0f", resp, &respsz, 1) < 0)
		fprintf(stderr, "CardTransmit error!\n");

	if(respsz < 2 || resp[respsz-2] != 0x90 || resp[respsz-1] != 0x00)
		fprintf(stderr, "Bad response !\n");
	else
		printf("Success! Capability Container file readed.\n");

	struct st25taCC_t cc = { 0 };

	if(respsz >= 16 && resp[0] == 0 && resp[1] == 0x0f)
		memcpy(&cc, resp, 15);


	printf("\nCapability Container file\n");
	printf("  Len:               %u\n", (cc.size[0] << 8) | cc.size[1]);
	printf("  Version:           %s\n", cc.vmapping == 0x20 ? "v2.0" : cc.vmapping == 0x10 ? "v1.0" : "??");
	printf("  max bytes read:    %u\n", (cc.nbread[0] << 8) | cc.nbread[1]);
	printf("  max bytes write:   %u\n", (cc.nbwrite[0] << 8) | cc.nbwrite[1]);
	printf("  NDEF file control TLV:\n");
	printf("    type of file:    %02x\n", cc.tfield);
	printf("    L field:         %02x\n", cc.vfield);
	printf("    file id:         %02x%02x\n", cc.id[0], cc.id[1]);
	printf("    max ndef size:   %u\n", (cc.maxsize[0] << 8) | cc.maxsize[1]);
	printf("    -- access rights --\n");
	printf("    read:            %02x\n", cc.readaccess);
	printf("    write:           %02x\n", cc.writeaccess);

	// Close NFC device
	nfc_close(pnd);
	// Release the context
	nfc_exit(context);
	exit(EXIT_SUCCESS);
}
