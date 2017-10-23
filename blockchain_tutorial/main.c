#include "common.h"
#include "hash.h"
#include "varint.h"
#include "ec.h"
#include "base58.h"

typedef struct {
    uint16_t fixed1;
    uint64_t var2;
    uint32_t fixed3;
    uint8_t fixed4;
} foo_t;

int main() {

    printf("Tutorial 1 - Endianness and Serialization\n");

    tutorial_one();

    printf("----------------------------------------\n");

    printf("Tutorial 2 - Null Padded Strings\n");

    tutorial_two();

    printf("----------------------------------------\n");

    printf("Tutorial 3 - Hashes\n");

    tutorial_three();

    printf("----------------------------------------\n");

    printf("Tutorial 4 - Variable Integers\n");

    tutorial_four();

    printf("----------------------------------------\n");

    printf("Tutorial 5 - Variable Data\n");

    tutorial_five();

    printf("----------------------------------------\n");

    printf("Tutorial 6 - Elliptic Curves\n");

    tutorial_six();

    printf("----------------------------------------\n");

    printf("Tutorial 7 - Digital Signatures\n");

    tutorial_seven();

    printf("----------------------------------------\n");

    printf("Tutorial 8 - Wallet Import Format\n");

    tutorial_eight();

    printf("----------------------------------------\n");

    printf("Tutorial 9 - Addresses\n");

        tutorial_nine();

    printf("----------------------------------------\n");

    return 0;
}

void tutorial_one() {
    //we declare variables as hex pairs. each hex pair equates to a single ASCII character.
    //each hex pair as up to 8 bits (or 1 byte), hence why it is a uint8_t
    uint8_t n8 = 0x01;
    uint16_t n16 = 0x4523;
    uint32_t n32 = 0xcdab8967;
    uint64_t n64 = 0xdebc9a78563412ef;
    //this is declaring an array of 8-bit ints called ser. it could be called anything. the array is 15 long
    uint8_t ser[15];

    const char ser_exp[] = "0123456789abcdef123456789abcde";

    //*ser is a pointer to the ser array.
    //we say it is n8 as it will alot the 1st space of memory in ser with n8's value
    //so the next bit i am unclear on, but i think what is happening is we take the memory position at ser + n
    //(n being an open slot in the array) and we make a pointer to it using *(uint16_t*).
    //the * on the left is saying "make a pointer" (like in *ser), while the one in the brackets is saying
    //"you are pointing to this type"
    *ser = n8;
    *(uint16_t*)(ser + 1) = bbp_eint16(BBP_LITTLE, n16); //this calls the endian methods that will reverse the hex array
    *(uint32_t*)(ser + 3) = bbp_eint32(BBP_LITTLE, n32); //if it is little endian. this doesnt mean 6f becomes f6.
    *(uint64_t*)(ser + 7) = bbp_eint64(BBP_LITTLE, n64); //it means f6ed becomes edf6. thats why n8 can stay the same

    bbp_print_hex("ser      ", ser, sizeof(ser));
    printf("ser (exp): %s\n", ser_exp);
}

void tutorial_two() {

    //all up, these will add up to 12 bytes (6 for the FooBar string, 4 for prefix, 2 for postfix).
    //this is not enough for fixed length strings like FooBar to conform to the protocol. FooBar needs to be 8 bytes long.
    //so, we need it to be F o o B a r null null
    uint32_t n32 = 0x68f7a38b;
    char str[] = "FooBar";
    size_t str_len = 10;
    uint16_t n16 = 0xee12;
    uint8_t ser[16];

    const char ser_exp[] = "8ba3f768466f6f4261720000000012ee";

    //find out how much padding we need
    size_t str_real_len = strlen(str);
    size_t str_pad_len = str_len - str_real_len;

    //little endian the prefix into the first position in ser by creating a pointer for that area of the right type
    *(uint32_t *)(ser) = bbp_eint32(BBP_LITTLE, n32);

    //using memcpy we can copy the str into the spot at ser + 4 (4 because we already put a uint32_t in the first 4 spots)
    memcpy(ser + 4, str, str_real_len);
    if (str_pad_len > 0) {
        //if we need padding, we can then set the padding
        memset(ser + 4 + str_real_len, '\0', str_pad_len);
    }

    //little endian the postfix (which will always be done at spot 14 in the array because we have null padded)
    *(uint16_t *)(ser + 4 + str_len) = bbp_eint16(BBP_LITTLE, n16);

    bbp_print_hex("ser      ", ser, sizeof(ser));
    printf("ser (exp): %s\n", ser_exp);
}

void tutorial_three() {
    char message[] = "Hello Bitcoin!";
    uint16_t prefix = 0xd17f;
    uint8_t suffix = 0x8c;
    uint8_t digest[32];
    uint8_t ser[35];

    const char sha256_exp[] = "518ad5a375fa52f84b2b3df7933ad685eb62cf69869a96731561f94d10826b5c";
    const char hash256_exp[] = "90986ea4e28b847cc7f9beba87ea81b221ca6eaf9828a8b04c290c21d891bcda";
    const char ser_exp[] = "7fd190986ea4e28b847cc7f9beba87ea81b221ca6eaf9828a8b04c290c21d891bcda8c";

    /* */

    /* SHA-2 digest is big-endian */

    bbp_sha256(digest, (uint8_t *)message, strlen(message));
    bbp_print_hex("SHA256(message)      ", digest, 32);
    printf("SHA256(message) (exp): %s\n", sha256_exp);

    bbp_sha256(digest, digest, 32);
    bbp_print_hex("hash256(message)      ", digest, 32);
    printf("hash256(message) (exp): %s\n", hash256_exp);

    *(uint16_t *)(ser) = bbp_eint16(BBP_LITTLE, prefix);
    memcpy(ser + 2, digest, 32);
    *(ser + 2 + 32) = suffix;

    bbp_print_hex("ser      ", ser, sizeof(ser));
    printf("ser (exp): %s\n", ser_exp);
}

void tutorial_four() {

    uint8_t bytes[] = {
        0x13, 0x9c, 0xfd, 0x7d,
        0x80, 0x44, 0x6b, 0xa2,
        0x20, 0xcc
    };

    foo_t decoded;
    size_t varlen;

    const foo_t exp = {
        0x9c13,
        0x807d,
        0x20a26b44,
        0xcc
    };

    decoded.fixed1 = bbp_eint16(BBP_LITTLE, *(uint16_t *)bytes);
    decoded.var2 = bbp_varint_get(bytes + 2, &varlen);
    decoded.fixed3 = bbp_eint32(BBP_LITTLE, *(uint32_t *)(bytes + 2 + varlen));
    decoded.fixed4 = *(bytes + 2 + varlen + 4);

    printf("fixed1      : %x\n", decoded.fixed1);
    printf("fixed1 (exp): %x\n", exp.fixed1);
    printf("var2      : %llx\n", decoded.var2);
    printf("var2 (exp): %llx\n", exp.var2);
    printf("fixed3      : %x\n", decoded.fixed3);
    printf("fixed3 (exp): %x\n", exp.fixed3);
    printf("fixed4      : %x\n", decoded.fixed4);
    printf("fixed4 (exp): %x\n", exp.fixed4);
}

void tutorial_five() {
    uint8_t bytes[] = {
        0xfd, 0x0a, 0x00, 0xe3,
        0x03, 0x41, 0x8b, 0xa6,
        0x20, 0xe1, 0xb7, 0x83,
        0x60
    };

    size_t len;
    size_t varlen;
    uint8_t data[100] = { 0 };

    const char data_exp[] = "e303418ba620e1b78360";

    /* */

    len = bbp_varint_get(bytes, &varlen);
    printf("len: %lu, varlen: %lu\n", len, varlen);

    memcpy(data, bytes + varlen, len);

    bbp_print_hex("data      ", data, len);
    printf("data (exp): %s\n", data_exp);
}

void tutorial_six() {
	uint8_t priv_bytes[32] = {
	        0x16, 0x26, 0x07, 0x83, 0xe4, 0x0b, 0x16, 0x73,
	        0x16, 0x73, 0x62, 0x2a, 0xc8, 0xa5, 0xb0, 0x45,
	        0xfc, 0x3e, 0xa4, 0xaf, 0x70, 0xf7, 0x27, 0xf3,
	        0xf9, 0xe9, 0x2b, 0xdd, 0x3a, 0x1d, 0xdc, 0x42
	    };

	    EC_KEY *key;
	    uint8_t priv[32];
	    uint8_t *pub;
	    const BIGNUM *priv_bn;

	    point_conversion_form_t conv_forms[] = {
	        POINT_CONVERSION_UNCOMPRESSED,
	        POINT_CONVERSION_COMPRESSED
	    };
	    const char *conv_forms_desc[] = {
	        "uncompressed",
	        "compressed"
	    };
	    int i;

	    const char priv_exp[] = "16260783e40b16731673622ac8a5b045fc3ea4af70f727f3f9e92bdd3a1ddc42";
	    const char pub_exp[2][200] = {
	        "0482006e9398a6986eda61fe91674c3a108c399475bf1e738f19dfc2db11db1d28130c6b3b28aef9a9c7e7143dac6cf12c09b8444db61679abb1d86f85c038a58c",
	        "0282006e9398a6986eda61fe91674c3a108c399475bf1e738f19dfc2db11db1d28"
	    };

	    /* create keypair */

	    key = bbp_ec_new_keypair(priv_bytes);
	    if (!key) {
	        puts("Unable to create keypair");
	        return;
	    }
	    bbp_print_hex("priv #1   ", priv_bytes, sizeof(priv));

	    /* get private key back from EC_KEY */

	    priv_bn = EC_KEY_get0_private_key(key);
	    if (!priv_bn) {
	        puts("Unable to decode private key");
	        return;
	    }
	    BN_bn2bin(priv_bn, priv);
	    bbp_print_hex("priv #2   ", priv, sizeof(priv));

	    printf("priv (exp): %s\n", priv_exp);

	    /* get encoded public key from EC_KEY in all conversion forms */

	    for (i = 0; i < sizeof(conv_forms) / sizeof(point_conversion_form_t); ++i) {
	        size_t pub_len;
	        uint8_t *pub_copy;

	        EC_KEY_set_conv_form(key, conv_forms[i]);

	        pub_len = i2o_ECPublicKey(key, NULL);
	        pub = calloc(pub_len, sizeof(uint8_t));

	        /* pub_copy is needed because i2o_ECPublicKey alters the input pointer */
	        pub_copy = pub;
	        if (i2o_ECPublicKey(key, &pub_copy) != pub_len) {
	            puts("Unable to decode public key");
	            return;
	        }

	        printf("conversion form: %s\n", conv_forms_desc[i]);
	        bbp_print_hex("pub      ", pub, pub_len);
	        printf("pub (exp): %s\n", pub_exp[i]);

	        free(pub);
	    }

	    /* release keypair */

	    EC_KEY_free(key);

}

void tutorial_seven() {

    uint8_t priv_bytes[32] = {
        0x16, 0x26, 0x07, 0x83, 0xe4, 0x0b, 0x16, 0x73,
        0x16, 0x73, 0x62, 0x2a, 0xc8, 0xa5, 0xb0, 0x45,
        0xfc, 0x3e, 0xa4, 0xaf, 0x70, 0xf7, 0x27, 0xf3,
        0xf9, 0xe9, 0x2b, 0xdd, 0x3a, 0x1d, 0xdc, 0x42
    };

    const char message[] = "This is a very confidential message\n";

    EC_KEY *key;
    uint8_t digest[32];
    ECDSA_SIG *signature;
    uint8_t *der, *der_copy;
    size_t der_len;

    const char digest_exp[] = "4554813e91f3d5be790c7c608f80b2b00f3ea77512d49039e9e3dc45f89e2f01";

    /* */

    key = bbp_ec_new_keypair(priv_bytes);
    if (!key) {
        puts("Unable to create keypair");
        return;
    }

    bbp_sha256(digest, (uint8_t *)message, strlen(message));
    bbp_print_hex("digest      ", digest, 32);
    printf("digest (exp): %s\n", digest_exp);

    signature = ECDSA_do_sign(digest, sizeof(digest), key);
    printf("r: %s\n", BN_bn2hex(signature->r));
    printf("s: %s\n", BN_bn2hex(signature->s));

    der_len = ECDSA_size(key);
    der = calloc(der_len, sizeof(uint8_t));
    der_copy = der;
    i2d_ECDSA_SIG(signature, &der_copy);
    bbp_print_hex("DER-encoded", der, der_len);

    free(der);
    ECDSA_SIG_free(signature);
    EC_KEY_free(key);
}

void tutorial_eight() {
	uint8_t priv_bytes[32] = {
	        0x16, 0x26, 0x07, 0x83, 0xe4, 0x0b, 0x16, 0x73,
	        0x16, 0x73, 0x62, 0x2a, 0xc8, 0xa5, 0xb0, 0x45,
	        0xfc, 0x3e, 0xa4, 0xaf, 0x70, 0xf7, 0x27, 0xf3,
	        0xf9, 0xe9, 0x2b, 0xdd, 0x3a, 0x1d, 0xdc, 0x42
	    };
	    uint8_t wif_bytes[34];
	    char *wif;

	    const char wif_exp[] = "cNKkmrwHuShs2mvkVEKfXULxXhxRo3yy1cK6sq62uBp2Pc8Lsa76";

	    /* */

	    bbp_print_hex("priv", priv_bytes, sizeof(priv_bytes));

	    wif_bytes[0] = 0xef;
	    memcpy(wif_bytes + 1, priv_bytes, 32);
	    wif_bytes[33] = 0x01;

	    wif = bbp_base58check(wif_bytes, 34);
	    printf("WIF      : %s\n", wif);
	    printf("WIF (exp): %s\n", wif_exp);
	free(wif);
}

void tutorial_nine() {
	uint8_t pub_bytes[33] = {
	        0x02,
	        0x82, 0x00, 0x6e, 0x93, 0x98, 0xa6, 0x98, 0x6e,
	        0xda, 0x61, 0xfe, 0x91, 0x67, 0x4c, 0x3a, 0x10,
	        0x8c, 0x39, 0x94, 0x75, 0xbf, 0x1e, 0x73, 0x8f,
	        0x19, 0xdf, 0xc2, 0xdb, 0x11, 0xdb, 0x1d, 0x28
	    };
	    uint8_t address_bytes[21];
	    char *address;

	    const char address_exp[] = "mqMi3XYqsPvBWtrJTk8euPWDVmFTZ5jHuK";

	    /* */

	    bbp_print_hex("pub", pub_bytes, sizeof(pub_bytes));

	    address_bytes[0] = 0x6f;
	    bbp_hash160(address_bytes + 1, pub_bytes, 33);
	    bbp_print_hex("hash160", address_bytes + 1, 20);

	    address = bbp_base58check(address_bytes, 21);
	    printf("address      : %s\n", address);
	    printf("address (exp): %s\n", address_exp);
	free(address);
}



