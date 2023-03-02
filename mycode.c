#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/cmac.h>

#define BLOCK_SIZE 16


/* function prototypes */
void print_hex(unsigned char *, size_t);
void print_string(unsigned char *, size_t); 
void usage(void);
void check_args(char *, char *, unsigned char *, int, int);
void keygen(unsigned char *, unsigned char *, unsigned char *, int);
void encrypt(unsigned char *, int, unsigned char *, unsigned char *, 
    unsigned char *, int );
int decrypt(unsigned char *, int, unsigned char *, unsigned char *, 
    unsigned char *, int);
void gen_cmac(unsigned char *, size_t, unsigned char *, unsigned char *, int);
int verify_cmac(unsigned char *, unsigned char *);



/* TODO Declare your function prototypes here... */
void file_control (unsigned char *, unsigned char *, int);


/*
 * Prints the hex value of the input
 * 16 values per line
 */
void
print_hex(unsigned char *data, size_t len)
{
	size_t i;

	if (!data)
		printf("NULL data\n");
	else {
		for (i = 0; i < len; i++) {
			if (!(i % 16) && (i != 0))
				printf("\n");
			printf("%02X ", data[i]);
		}
		printf("\n");
	}
}


/*
 * Prints the input as string
 */
void
print_string(unsigned char *data, size_t len)
{
	size_t i;

	if (!data)
		printf("NULL data\n");
	else {
		for (i = 0; i < len; i++)
			printf("%c", data[i]);
		printf("\n");
	}
}


/*
 * Prints the usage message
 * Describe the usage of the new arguments you introduce
 */
void
usage(void)
{
	printf(
	    "\n"
	    "Usage:\n"
	    "    assign_1 -i in_file -o out_file -p passwd -b bits" 
	        " [-d | -e | -s | -v]\n"
	    "    assign_1 -h\n"
	);
	printf(
	    "\n"
	    "Options:\n"
	    " -i    path    Path to input file\n"
	    " -o    path    Path to output file\n"
	    " -p    psswd   Password for key generation\n"
	    " -b    bits    Bit mode (128 or 256 only)\n"
	    " -d            Decrypt input and store results to output\n"
	    " -e            Encrypt input and store results to output\n"
	    " -s            Encrypt+sign input and store results to output\n"
	    " -v            Decrypt+verify input and store results to output\n"
	    " -h            This help message\n"
	);
	exit(EXIT_FAILURE);
}


/*
 * Checks the validity of the arguments
 * Check the new arguments you introduce
 */
void
check_args(char *input_file, char *output_file, unsigned char *password, 
    int bit_mode, int op_mode)
{
	if (!input_file) {
		printf("Error: No input file!\n");
		usage();
	}

	if (!output_file) {
		printf("Error: No output file!\n");
		usage();
	}

	if (!password) {
		printf("Error: No user key!\n");
		usage();
	}

	if ((bit_mode != 128) && (bit_mode != 256)) {
		printf("Error: Bit Mode <%d> is invalid!\n", bit_mode);
		usage();
	}

	if (op_mode == -1) {
		printf("Error: No mode\n");
		usage();
	}
}


/*
 * Generates a key using a password
 */
void
keygen(unsigned char *password, unsigned char *key, unsigned char *iv,
    int bit_mode)
{ 
	unsigned char *salt= NULL;
	int pwd_len= strlen((char *)password);
	int rounds = 2;
	
	if (bit_mode == 128)
	{ 
	EVP_BytesToKey(EVP_aes_128_ecb(), EVP_sha1(), salt, password, pwd_len, rounds, key, iv);
	}
	if (bit_mode == 256)
	{
	EVP_BytesToKey(EVP_aes_256_ecb(), EVP_sha1(), salt, password, pwd_len, rounds, key, iv);
	}

}


/*
 * Encrypts the data
 */
void
encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
    unsigned char *iv, unsigned char *ciphertext, int bit_mode)
{

	/* TODO Task B */
	int length;
	 EVP_CIPHER_CTX *cphr;

	 cphr = EVP_CIPHER_CTX_new();
	 EVP_EncryptInit_ex(cphr, EVP_aes_128_cbc(), NULL, key, iv);

	 EVP_EncryptUpdate(cphr, ciphertext, &length, plaintext, plaintext_len);

	 EVP_EncryptFinal_ex(cphr, ciphertext + length, &length);



}


/*
 * Decrypts the data and returns the plaintext size
 */
int
decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
    unsigned char *iv, unsigned char *plaintext, int bit_mode)
{
	int plaintext_len;

	plaintext_len = 0;

	/*TODO Task C */

	return plaintext_len;
}


/*
 * Generates a CMAC
 */
void
gen_cmac(unsigned char *data, size_t data_len, unsigned char *key, 
    unsigned char *cmac, int bit_mode)
{

	/* TODO Task D */

}


/*
 * Verifies a CMAC
 */
int
verify_cmac(unsigned char *cmac1, unsigned char *cmac2)
{
	int verify;

	verify = 0;

	/* TODO Task E */

	return verify;
}



/* TODO Develop your functions here... */

void file_control(unsigned char *input_file, unsigned char* input, int mode)
{
	int size=10, i=0, length=0;
	char ch;
	FILE *fp;
	input = realloc(NULL, sizeof(char)*size);

	fp = fopen(input_file, "r");
	if (fp == NULL)
   	{
      perror("Error while opening the input file.\n");
      exit(EXIT_FAILURE);
   	}
 

	if (mode == 0) /* read from input file */
	{
   		while((ch = fgetc(fp)) != EOF)
		{		
			input[length++]=ch;
				
			if( length == size)
			{			
				input = realloc(input, sizeof(char)* (size += 10));
				if(!input)
				return input;
			}
			input[length]='\0';
		}	
	}
	else if (mode ==1) /* write to output file */
	{

	}
}

/*
 * Encrypts the input file and stores the ciphertext to the output file
 *
 * Decrypts the input file and stores the plaintext to the output file
 *
 * Encrypts and signs the input file and stores the ciphertext concatenated with 
 * the CMAC to the output file
 *
 * Decrypts and verifies the input file and stores the plaintext to the output
 * file
 */
int
main(int argc, char **argv)
{
	int opt;			/* used for command line arguments */
	int bit_mode;			/* defines the key-size 128 or 256 */
	int op_mode;			/* operation mode */
	char *input_file;		/* path to the input file */
	char *output_file;		/* path to the output file */
	unsigned char *password;	/* the user defined password */

	/* Init arguments */
	input_file = NULL;
	output_file = NULL;
	password = NULL;
	bit_mode = -1;
	op_mode = -1;

	FILE *fin;
	FILE *fout;
	char ch;
	/*
	 * Get arguments
	 */
	while ((opt = getopt(argc, argv, "b:i:m:o:p:desvh:")) != -1) {
		switch (opt) {
		case 'b':
			bit_mode = atoi(optarg);
			break;
		case 'i':
			input_file = strdup(optarg);
			break;
		case 'o':
			output_file = strdup(optarg);
			break;
		case 'p':
			password = (unsigned char *)strdup(optarg);
			break;
		case 'd':
			/* if op_mode == 1 the tool decrypts */
			op_mode = 1;
			break;
		case 'e':
			/* if op_mode == 1 the tool encrypts */
			op_mode = 0;
			break;
		case 's':
			/* if op_mode == 1 the tool signs */
			op_mode = 2;
			break;
		case 'v':
			/* if op_mode == 1 the tool verifies */
			op_mode = 3;
			break;
		case 'h':
		default:
			usage();
		}
	}


	/* check arguments */
	check_args(input_file, output_file, password, bit_mode, op_mode);



	unsigned char *key;
	unsigned char *iv;
	/* TODO Develop the logic of your tool here... */
	if (bit_mode == 128)
	{
		key = malloc(16*(sizeof(char)));
		iv = malloc(16*(sizeof(char)));
	}
	else if (bit_mode == 256)
	{
		key = malloc(32*(sizeof(char)));
		iv = malloc(32*(sizeof(char)));
	}

	
/*	int length = strlen(plaintext);
	for (i=0; i < length; i++)
	{
	printf("%c", plaintext[i]);	
	}
	printf("ok\n");
/*

	/* Initialize the library */

	int length, i;
	/* read the input file */
	file_control(input_file, plaintext, 0);
	length = strlen(plaintext);
	for(i=0; i<length; i++)
	{
		printf("%c", plaintext[i]);
	}

	/* Keygen from password */
	keygen(password, key, iv, bit_mode);
	

	/* Operate on the data according to the mode */
	/* encrypt */
	
	/* decrypt */

	/* sign */

	/* verify */
		

	/* Clean up */
	free(input_file);
	free(output_file);
	free(password);
	free(key);
	free(iv);

	else if (mode == 2) /*read input bitstream */
	{
		fp = fopen(file, "rb+");
		fseek(fp, 0, SEEK_END);
		length = ftell(fp);
		rewind(fp);
		printf("\n %d length fseek", length);
		text = realloc(text, sizeof(char)*length);
		fread(text, sizeof(char), length, fp);
		text[length]='\0';
		printf("\nbitsream\n");
		print_hex(text, length);
		return text;
		fclose(fp);
	}
	else if (mode ==3) /*Write to output file plaintext */
	{
		fp = fopen(file, "w");
		fwrite(text, sizeof(char), length, fp);
	}
	/* END */
	return 0;
}
