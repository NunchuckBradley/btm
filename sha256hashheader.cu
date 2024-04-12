#include <cstdlib>
#include <iostream>
#include <chrono>



// sha256 constants
const unsigned int sha256_k[64] = //UL = uint32
            {0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
             0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
             0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
             0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
             0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
             0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
             0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
             0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
             0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
             0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
             0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
             0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
             0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
             0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
             0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
             0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

const unsigned int sha256_h[8] =
            {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};



__global__
void hash_header(const unsigned int* sha_k, const unsigned int* sha_h, const unsigned int* target, const unsigned int* header, unsigned int* nonce) {

    // Get the index of the current element to be processed
    // int gid = get_global_id(0);
    // unsigned int threadsPerBlock  = blockDim.x * blockDim.y;
    // unsigned int threadNumInBlock = threadIdx.x + blockDim.x * threadIdx.y; // (alternatively: threadIdx.y + blockDim.y * threadIdx.x);
    // unsigned int blockNumInGrid   = blockIdx.x  + gridDim.x  * blockIdx.y; //  (alternatively: blockIdx.y  + gridDim.y  * blockIdx.x);
    // unsigned int gid = blockIdx.x*blockDim.x + threadIdx.x;
    // unique block index inside a 3D block grid
    const unsigned long long int blockId = blockIdx.x //1D
            + blockIdx.y * gridDim.x //2D
            + gridDim.x * gridDim.y * blockIdx.z; //3D

    // global unique thread index, block dimension uses only x-coordinate
    const unsigned long long int gid = blockId * blockDim.x + threadIdx.x;

    unsigned int testNonce = 0xFFFFFFFF - gid;
    testNonce = 4189752839;


    int length = 80;
    int i = 0;
    unsigned int schedules_orig[2][64];

//     compression variables
    unsigned int sha256_h_buffer_orig[8] = {sha_h[0],sha_h[1],sha_h[2],sha_h[3],sha_h[4],sha_h[5],sha_h[6],sha_h[7]};
    unsigned int* sha256_h_buffer = sha256_h_buffer_orig;

    unsigned int buf[8];

    // ================================================================================================================================
    // ================================================================================================================================
    // sha part 1: message one

    unsigned int* schedules = schedules_orig[0];
    for(i = 0; i < 16; i++){
        schedules[i] = header[i];
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
//        sha256_h_buffer[i] += buf[i];
        buf[i] += sha256_h_buffer[i];
    }

    // ================================================================================================================================
    // ================================================================================================================================
    // sha part 1: message two

    unsigned int* schedulesp2 = schedules_orig[1];
    // blank all fields, only part blank needed
    for(i = 3; i < 16; i++) schedulesp2[i] = 0;

    for(i = 16; i < 19; i++){
        schedulesp2[i] = header[i];
        // pack into 8 byte/32 bits array
        // schedules[i] = (*(header + (i << 2) + (bl << 6)) << 24) + (*(header + (i << 2) + 1 + (bl << 6)) << 16) + (*(header + (i << 2) + 2 + (bl << 6)) << 8) + (*(header + (i << 2) + 3 + (bl << 6)));
    }

    schedulesp2[4] = 0x80000000;
    schedulesp2[15] = length*8;

    // change nonce here
    unsigned int testNonceBigEndian = (testNonce << 24) + (((testNonce >> 8) << 24) >> 8) + (((testNonce >> 16) << 24) >> 16) + (testNonce >> 24);
    schedulesp2[3] = testNonceBigEndian;


    // compression
    // fill the schedule arrays
    for(i = 16; i < 64; i++) {
        unsigned int* s0v = &schedulesp2[i-15];
        unsigned int* s1v = &schedulesp2[i-2];
        unsigned int s0 = ((*s0v >> 7)|(*s0v << 25)) ^ ((*s0v >> 18)|(*s0v << 14)) ^ (*s0v >> 3);
        unsigned int s1 = ((*s1v >> 17)|(*s1v << 15)) ^ ((*s1v >> 19)|(*s1v << 13)) ^ (*s1v >> 10);
        schedulesp2[i] = schedulesp2[i-16] + s0 + schedulesp2[i-7] + s1;
//                schedules[i] = schedules[i-16] + schedules[i-7] + SHA256_F4(schedules[i-2]) + SHA256_F3(schedules[i-15]);
    }

//    for(i = 0; i < 8; i++) {
//        buf[i] = sha256_h_buffer[i];
//    }

    // COMPRESSION
    for(i = 0; i < 64; i++) {
        unsigned int f1 = ((buf[0] >> 2)|(buf[0] << 30)) ^ ((buf[0] >> 13)|(buf[0] << 19)) ^ ((buf[0] >> 22)|(buf[0] << 10));
        unsigned int maj = (buf[0] & buf[1]) ^ (buf[0] & buf[2]) ^ (buf[1] & buf[2]);
        unsigned int temp2 = f1 + maj;

        unsigned int f2 = ((buf[4] >> 6)|(buf[4] << 26)) ^ ((buf[4] >> 11)|(buf[4] << 21)) ^ ((buf[4] >> 25)|(buf[4] << 7));
        unsigned int ch = ((buf[4] & buf[5]) ^ (~buf[4] & buf[6]));
        unsigned int temp1 = buf[7] + f2 + ch + sha_k[i] + schedulesp2[i];

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

    // ================================================================================================================================
    // ================================================================================================================================
    // sha part 2: hashing the hash

    // SECOND RUNN
    // compression variables
    unsigned int sha256_h_buffer_orig2[8] = {sha_h[0],sha_h[1],sha_h[2],sha_h[3],sha_h[4],sha_h[5],sha_h[6],sha_h[7]};
    unsigned int* sha256_h_buffer2 = sha256_h_buffer_orig2;

    unsigned int schedules2[64];
    // blank all fields, only partial needed
    for(i = 8; i < 16; i++) schedules2[i] = 0;

//        memcpy(&schedules2, &sha256_h_buffer_orig, 32);
    for (i = 0; i < 8; i++) {
        schedules2[i] = sha256_h_buffer_orig[i];
    }
//    schedules2[0] = sha256_h_buffer_orig[0];
//    schedules2[1] = sha256_h_buffer_orig[1];
//    schedules2[2] = sha256_h_buffer_orig[2];
//    schedules2[3] = sha256_h_buffer_orig[3];
//    schedules2[4] = sha256_h_buffer_orig[4];
//    schedules2[5] = sha256_h_buffer_orig[5];
//    schedules2[6] = sha256_h_buffer_orig[6];
//    schedules2[7] = sha256_h_buffer_orig[7];

    // add a single bit to end of values
    schedules2[8] = 0x80000000;
    schedules2[15] = 256;


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
    for(i = 0; i < 8; i++) {
        buf2[i] = sha256_h_buffer2[i];
    }

    // COMPRESSION
    for(i = 0; i < 64; i++) {
        unsigned int f1 = ((buf2[0] >> 2)|(buf2[0] << 30)) ^ ((buf2[0] >> 13)|(buf2[0] << 19)) ^ ((buf2[0] >> 22)|(buf2[0] << 10));
        unsigned int maj = (buf2[0] & buf2[1]) ^ (buf2[0] & buf2[2]) ^ (buf2[1] & buf2[2]);
        unsigned int temp2 = f1 + maj;

        unsigned int f2 = ((buf2[4] >> 6)|(buf2[4] << 26)) ^ ((buf2[4] >> 11)|(buf2[4] << 21)) ^ ((buf2[4] >> 25)|(buf2[4] << 7));
        unsigned int ch = ((buf2[4] & buf2[5]) ^ (~buf2[4] & buf2[6]));
        unsigned int temp1 = buf2[7] + f2 + ch + sha_k[i] + schedules2[i];

//        unsigned int temp2 = SHA256_F1(buf[0]) + SHA2_MAJ(buf[0], buf[1], buf[2]);
//        unsigned int temp1 = buf[7] + SHA256_F2(buf[4]) + SHA2_CH(buf[4],buf[5],buf[6]) + sha256_k[i] + schedules2[i];
        buf2[7] = buf2[6];
        buf2[6] = buf2[5];
        buf2[5] = buf2[4];
        buf2[4] = buf2[3]+temp1;
        buf2[3] = buf2[2];
        buf2[2] = buf2[1];
        buf2[1] = buf2[0];
        buf2[0] = temp1+temp2;
    }

    for(i = 0; i < 8; i++) {
        sha256_h_buffer2[i] += buf2[i];
    }

    // ================================================================================================================================
    // ================================================================================================================================
    // comparing to the target

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


__host__
int hexToDec(char hex) {
  switch(hex){
        case 'F'|'f':
        return 15;
        break;
        case 'E'|'e':
        return 14;
        break;
        case 'D'|'d':
        return 13;
        break;
        case 'C'|'c':
        return 12;
        break;
        case 'B'|'b':
        return 11;
        break;
        case 'A'|'a':
        return 10;
        break;
        case '9':
        return 9;
        break;
        case '8':
        return 8;
        break;
        case '7':
        return 7;
        break;
        case '6':
        return 6;
        break;
        case '5':
        return 5;
        break;
        case '4':
        return 4;
        break;
        case '3':
        return 3;
        break;
        case '2':
        return 2;
        break;
        case '1':
        return 1;
        break;
        default:
        return 0;
    }
}


int main(int argc, char* argv[])
{
  if (argc == 3) {

    unsigned int header_int[20];
    for (int i = 0; i < 20; i++) {
      int startPos = i*8;
      int byteOne = (hexToDec(argv[2][startPos]) * 16) + hexToDec(argv[2][startPos+1]);
      int byteTwo = (hexToDec(argv[2][startPos+2]) * 16) + hexToDec(argv[2][startPos+3]);
      int byteTre = (hexToDec(argv[2][startPos+4]) * 16) + hexToDec(argv[2][startPos+5]);
      int byteFor = (hexToDec(argv[2][startPos+6]) * 16) + hexToDec(argv[2][startPos+7]);
      header_int[i] = (byteOne << 24) + (byteTwo << 16) + (byteTre << 8) + byteFor;
    }

    unsigned int target_int[8];
    for (int i = 0; i < 8; i++) {
      int startPos = i*8;
      int byteOne = (hexToDec(argv[1][startPos]) * 16) + hexToDec(argv[1][startPos+1]);
      int byteTwo = (hexToDec(argv[1][startPos+2]) * 16) + hexToDec(argv[1][startPos+3]);
      int byteTre = (hexToDec(argv[1][startPos+4]) * 16) + hexToDec(argv[1][startPos+5]);
      int byteFor = (hexToDec(argv[1][startPos+6]) * 16) + hexToDec(argv[1][startPos+7]);
      target_int[i] = (byteOne << 24) + (byteTwo << 16) + (byteTre << 8) + byteFor;
    }


    // prepare memory for sha256 constants
    unsigned int *sha256_kp, *sha256_hp;
    cudaMalloc(&sha256_kp, 64*sizeof(unsigned int));
    cudaMemcpy(sha256_kp, &sha256_k, 64*sizeof(unsigned int), cudaMemcpyHostToDevice);
    cudaMalloc(&sha256_hp, 8*sizeof(unsigned int));
    cudaMemcpy(sha256_hp, &sha256_h, 8*sizeof(unsigned int), cudaMemcpyHostToDevice);

    unsigned int *target, *header, *nonce;

    // prepare memory for header
    cudaMalloc(&header, 20*sizeof(unsigned int));
    cudaMemcpy(header, header_int, 20*sizeof(unsigned int), cudaMemcpyHostToDevice);

    // prepare memory for target
    cudaMalloc(&target, 8*sizeof(unsigned int));
    cudaMemcpy(target, target_int, 8*sizeof(unsigned int), cudaMemcpyHostToDevice);

    // prepare temporary nonce
    unsigned int *finalNonce;
    finalNonce = (unsigned int*)malloc(sizeof(unsigned int));
    cudaMalloc(&nonce, sizeof(unsigned int));
    // cudaMemcpy(nonce, finalNonce, sizeof(unsigned int), cudaMemcpyHostToDevice);

    // N = elements
    // Perform SAXPY on 1M elements
    // saxpy<<<(N+255)/256, 256>>>(N, 2.0f, d_x, d_y);
    // int blocks = 64;
    // hash_header<<<(0xFFFFFFFF+1)/blocks, blocks>>>(sha256_kp, sha256_hp, target, header, nonce);

    // for (int i = 0; i < 8; i++) {
    //   std::cout << "target " << i << ": " << target_int[i] << std::endl;
    //   std::cout << "header " << i << ": " << header_int[i] << std::endl;
    // }

    const auto p1 = std::chrono::system_clock::now();

    int blocks = 128;
//    hash_header<<<(0xFFFFFFFF/blocks+2), blocks>>>(sha256_kp, sha256_hp, target, header, nonce);
    hash_header<<<1,1>>>(sha256_kp, sha256_hp, target, header, nonce);
    // hash_header<<<1000,1000>>>(sha256_kp, sha256_hp, target, header, nonce);
    cudaMemcpy(finalNonce, nonce, sizeof(unsigned int), cudaMemcpyDeviceToHost);


    const auto p2 = std::chrono::system_clock::now();
    int finaltime = (std::chrono::duration_cast<std::chrono::seconds>(p2.time_since_epoch()).count() - std::chrono::duration_cast<std::chrono::seconds>(p1.time_since_epoch()).count());

    std::cout << "time taken: " << finaltime << std::endl;

    // float maxError = 0.0f;
    // for (int i = 0; i < N; i++)
    //   maxError = max(maxError, abs(y[i]-4.0f));
    // printf("Max error: %f\n", maxError);

    std::cout << "0xFFFFFFFF       : " << 0xFFFFFFFF << std::endl;
    std::cout << "Final nonce found: " << finalNonce[0] << std::endl;

    cudaFree(target);
    cudaFree(header);
    cudaFree(nonce);
    // free(target_int);
    // free(header_int);

  }
  else {
    return 0;
  }
  return 0;
}
