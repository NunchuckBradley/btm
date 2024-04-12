#define SHA2_SHFR(x, n)    (x >> n)
#define SHA2_ROTR(x, n)   ((x >> n) | (x << ((sizeof(x) << 3) - n)))
#define SHA2_ROTL(x, n)   ((x << n) | (x >> ((sizeof(x) << 3) - n)))
#define SHA2_CH(x, y, z)  ((x & y) ^ (~x & z))
#define SHA2_MAJ(x, y, z) ((x & y) ^ (x & z) ^ (y & z))
#define SHA256_F1(x) (SHA2_ROTR(x,  2) ^ SHA2_ROTR(x, 13) ^ SHA2_ROTR(x, 22))
#define SHA256_F2(x) (SHA2_ROTR(x,  6) ^ SHA2_ROTR(x, 11) ^ SHA2_ROTR(x, 25))
#define SHA256_F3(x) (SHA2_ROTR(x,  7) ^ SHA2_ROTR(x, 18) ^ SHA2_SHFR(x,  3))
#define SHA256_F4(x) (SHA2_ROTR(x, 17) ^ SHA2_ROTR(x, 19) ^ SHA2_SHFR(x, 10))

__kernel void hash_header(__global const unsigned int* sha_k, __global const unsigned int* sha_h,
                          __global const unsigned int* target, __global const unsigned char* header,
                          __global unsigned int* nonce
//                          , __global const unsigned int* offset
//                          , __global unsigned int* output
                          ) {

    // Get the index of the current element to be processed
    int gid = get_global_id(0);
    unsigned int testNonce = 0xFFFFFFFF - gid; // to go backwards
//    nonce[0] = 333;


    int length = 80;
    int blocks = 2;
    int i = 0;
    unsigned int schedules_orig[2][64];

//     compression variables
    unsigned int sha256_h_buffer_orig[8] = {sha_h[0],sha_h[1],sha_h[2],sha_h[3],sha_h[4],sha_h[5],sha_h[6],sha_h[7]};
    unsigned int* sha256_h_buffer = sha256_h_buffer_orig;

    for(int bl = 0; bl < blocks; bl++) {
        unsigned int* schedules = schedules_orig[bl];
        // blank all fields
//        memset(&schedules[bl], 0x00, 64);
        for(i = 0; i < 64; i++) schedules[i] = 0;

        for(i = 0; i < 16; i++){
            if (bl > 0 && i > 3) {
                break;
            }
            // pack into 8 byte/32 bits array
            schedules[i] = (*(header + (i << 2) + (bl << 6)) << 24) + (*(header + (i << 2) + 1 + (bl << 6)) << 16) + (*(header + (i << 2) + 2 + (bl << 6)) << 8) + (*(header + (i << 2) + 3 + (bl << 6)));
        }

        if (bl == 1) {
            schedules[4] = 0x80000000;
            schedules[15] = length*8;

            // change nonce here
            unsigned int testNonceBigEndian = (testNonce << 24) + (((testNonce >> 8) << 24) >> 8) + (((testNonce >> 16) << 24) >> 16) + (testNonce >> 24);
            schedules[3] = testNonceBigEndian;
        }

        // compression
        // fill the schedule arrays
        for(i = 16; i < 64; i++) {
            unsigned int* s0v = &schedules[i-15];
            unsigned int* s1v = &schedules[i-2];
            unsigned int s0 = ((*s0v >> 7)|(*s0v << 25)) ^ ((*s0v >> 18)|(*s0v << 14)) ^ (*s0v >> 3);
            unsigned int s1 = ((*s1v >> 17)|(*s1v << 15)) ^ ((*s1v >> 19)|(*s1v << 13)) ^ (*s1v >> 10);
            schedules[i] = schedules[i-16] + s0 + schedules[i-7] + s1;
//                schedules[i] = schedules[i-16] + schedules[i-7] + SHA256_F4(schedules[i-2]) + SHA256_F3(schedules[i-15]);
        }

        unsigned int buf[8];
        for(i = 0; i < 8; i++) {
            buf[i] = sha256_h_buffer[i];
        }

        // COMPRESSION
        for(i = 0; i < 64; i++) {
            unsigned int f1 = ((buf[0] >> 2)|(buf[0] << 30)) ^ ((buf[0] >> 13)|(buf[0] << 19)) ^ ((buf[0] >> 22)|(buf[0] << 10));
            unsigned int maj = (buf[0] & buf[1]) ^ (buf[0] & buf[2]) ^ (buf[1] & buf[2]);
            unsigned int temp2 = f1 + maj;

            unsigned int f2 = ((buf[4] >> 6)|(buf[4] << 26)) ^ ((buf[4] >> 11)|(buf[4] << 21)) ^ ((buf[4] >> 25)|(buf[4] << 7));
            unsigned int ch = ((buf[4] & buf[5]) ^ (~buf[4] & buf[6]));
            unsigned int temp1 = buf[7] + f2 + ch + sha_k[i] + schedules[i];

//            unsigned int temp2 = SHA256_F1(buf[0]) + SHA2_MAJ(buf[0], buf[1], buf[2]);
//            unsigned int temp1 = buf[7] + SHA256_F2(buf[4]) + SHA2_CH(buf[4],buf[5],buf[6]) + sha256_k[i] + schedules2[i];
            buf[7] = buf[6];
            buf[6] = buf[5];
            buf[5] = buf[4];
            buf[4] = buf[3]+temp1;
            buf[3] = buf[2];
            buf[2] = buf[1];
            buf[1] = buf[0];
            buf[0] = temp1+temp2;
        }

        for(i = 0; i < 8; i++) {
            sha256_h_buffer[i] += buf[i];
        }
    }



    // SECOND RUNN
    // compression variables
    unsigned int sha256_h_buffer_orig2[8] = {sha_h[0],sha_h[1],sha_h[2],sha_h[3],sha_h[4],sha_h[5],sha_h[6],sha_h[7]};
    unsigned int* sha256_h_buffer2 = sha256_h_buffer_orig2;


    blocks = 1;
    unsigned int schedules2[64];
    // blank all fields
//    memset(&schedules2, 0x00, 64);
    for(i = 0; i < 64; i++) schedules2[i] = 0;

//        memcpy(&schedules2, &sha256_h_buffer_orig, 32);
//        for (i = 0; i < 8; i++) {
//            schedules2[i] = sha256_h_buffer_orig[i];
//        }
    schedules2[0] = sha256_h_buffer_orig[0];
    schedules2[1] = sha256_h_buffer_orig[1];
    schedules2[2] = sha256_h_buffer_orig[2];
    schedules2[3] = sha256_h_buffer_orig[3];
    schedules2[4] = sha256_h_buffer_orig[4];
    schedules2[5] = sha256_h_buffer_orig[5];
    schedules2[6] = sha256_h_buffer_orig[6];
    schedules2[7] = sha256_h_buffer_orig[7];

    // add a single bit to end of values
    schedules2[8] = 0x80000000;
    schedules2[15] = 32*8;


    // compression
    // fill the schedule arrays
    for(i = 16; i < 64; i++) {
            unsigned int* s0v = &schedules2[i-15];
            unsigned int* s1v = &schedules2[i-2];
            unsigned int s0 = ((*s0v >> 7)|(*s0v << 25)) ^ ((*s0v >> 18)|(*s0v << 14)) ^ (*s0v >> 3);
            unsigned int s1 = ((*s1v >> 17)|(*s1v << 15)) ^ ((*s1v >> 19)|(*s1v << 13)) ^ (*s1v >> 10);
            schedules2[i] = schedules2[i-16] + s0 + schedules2[i-7] + s1;
//            schedules2[i] = schedules2[i-16] + schedules2[i-7] + SHA256_F4(schedules2[i-2]) + SHA256_F3(schedules2[i-15]);
    }

    unsigned int buf2[8];
    unsigned int* buf = buf2;
    for(i = 0; i < 8; i++) {
        buf[i] = sha256_h_buffer2[i];
    }

    // COMPRESSION
    for(i = 0; i < 64; i++) {
        unsigned int f1 = ((buf[0] >> 2)|(buf[0] << 30)) ^ ((buf[0] >> 13)|(buf[0] << 19)) ^ ((buf[0] >> 22)|(buf[0] << 10));
        unsigned int maj = (buf[0] & buf[1]) ^ (buf[0] & buf[2]) ^ (buf[1] & buf[2]);
        unsigned int temp2 = f1 + maj;

        unsigned int f2 = ((buf[4] >> 6)|(buf[4] << 26)) ^ ((buf[4] >> 11)|(buf[4] << 21)) ^ ((buf[4] >> 25)|(buf[4] << 7));
        unsigned int ch = ((buf[4] & buf[5]) ^ (~buf[4] & buf[6]));
        unsigned int temp1 = buf[7] + f2 + ch + sha_k[i] + schedules2[i];

//        unsigned int temp2 = SHA256_F1(buf[0]) + SHA2_MAJ(buf[0], buf[1], buf[2]);
//        unsigned int temp1 = buf[7] + SHA256_F2(buf[4]) + SHA2_CH(buf[4],buf[5],buf[6]) + sha256_k[i] + schedules2[i];
        buf[7] = buf[6];
        buf[6] = buf[5];
        buf[5] = buf[4];
        buf[4] = buf[3]+temp1;
        buf[3] = buf[2];
        buf[2] = buf[1];
        buf[1] = buf[0];
        buf[0] = temp1+temp2;
    }

    for(i = 0; i < 8; i++) {
        sha256_h_buffer2[i] += buf[i];
    }

    unsigned int output[8];

    for (i = 0; i < 8; i++) {
        // reverse bytes needed for compare
        unsigned int b = sha256_h_buffer2[7-i];
        output[i] = (((b) >> 24)) + (((b << 8) >> 24) << 8) + (((b << 16) >> 24) << 16) + (((b << 24) >> 24) << 24);

        if(output[i] != 0 && target[i] != 0) {
            if (output[i] < target[i]) {
                // get header nonce
//                unsigned int headerNonce = 0;
//                for(int h = 0; h < 4; h++) {
//                    headerNonce += header[76+h] << (8*h);
//                }
                nonce[0] = testNonce;
                break;
            }
            break;
        }
        else if(output[i] != 0 && target[i] == 0) {
//            nonce[0] = 0;
            break;
        }
    }

}
