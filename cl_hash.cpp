#include <stdio.h>
#include <sstream>
#include <iostream>
#include <fstream>
#include <vector>
#include "uint_custom.h"
#include <algorithm>

//#ifdef __APPLE__
//#include <OpenCL/opencl.h>
//#else
////#include <CL/cl.h>
//#endif

#define MAX_SOURCE_SIZE (0xFFFFFFFF)

#include <CL/cl.h>
#include <CL/cl2.hpp>


int factorial(int n) {
    return (n <= 1) ? 1 : n * factorial(n-1);
}


// sha256 constants
const unsigned int ocl_sha256_k[64] = //UL = uint32
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

const unsigned int ocl_sha256_h[8] =
            {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};



unsigned int gpu_hashing(uint256<256>* target, unsigned char* header, bool verbose) {
    // ==================================================================================================================================
    // ==================================================================================================================================
    // pre-variables
    size_t local_item_size = 256; // Divide work items into groups of x
    unsigned int size = 0xFFFFFFFF - (local_item_size - 1); // to make multiple of loca_item_size otherwise it doesnt split
    // half workload
//    unsigned int size = 0x7FFFFFFF - (local_item_size - 1); // to make multiple of loca_item_size otherwise it doesnt split

    int chunks = 256;

//    unsigned int size = 1; // dev size
//    size_t local_item_size = 1; // dev size

    size_t global_item_size = size; // Process the entire lists

    const char kernelDir[] = "/home/martin/code/BitcoinTemplateMiner/bitcoin_hash_header.cl";
//    const char kernelFunction[] = "hash_header2";
    const char kernelFunction[] = "hash_header";
//    const char kernelFunction[] = "cl_testing";


    // ==================================================================================================================================
    // ==================================================================================================================================
    // Load the kernel source code into the array source_str
    if (verbose) std::cout << "Loading kernel.." << std::endl;
    FILE *fp;
    char *source_str;
    size_t source_size;

    fp = fopen(kernelDir, "r");
    if (!fp) {
        fprintf(stderr, "Failed to load kernel.\n");
        exit(1);
    }
    source_str = (char*)malloc(MAX_SOURCE_SIZE);
    source_size = fread( source_str, 1, MAX_SOURCE_SIZE, fp);
    fclose( fp );

    // ==================================================================================================================================
    // ==================================================================================================================================
    if (verbose) std::cout << "Finding device.." << std::endl;
    // Get platform and device information
    cl_platform_id platform_id = NULL;
    cl_device_id device_id = NULL;
    cl_uint ret_num_devices;
    cl_uint ret_num_platforms;
    cl_int ret = clGetPlatformIDs(1, &platform_id, &ret_num_platforms);
    ret = clGetDeviceIDs( platform_id, CL_DEVICE_TYPE_GPU, 1,
            &device_id, &ret_num_devices);

    // ==================================================================================================================================
    // ==================================================================================================================================
    if (verbose) std::cout << "Creating context.." << std::endl;
    // Create an OpenCL context
    cl_context context = clCreateContext( NULL, 1, &device_id, NULL, NULL, &ret);
    if (verbose) std::cout << "Creating command queue.." << std::endl;
    // Create a command queue
    cl_command_queue command_queue = clCreateCommandQueue(context, device_id, 0, &ret);


    // ==================================================================================================================================
    // ==================================================================================================================================
    if (verbose) std::cout << "Preparing variables for kernel.." << std::endl;
    // you HAVE to pass vectors through. it dont work uderwise

    // prepare target to beat
    unsigned int target_int[8];

    for(int i = 0; i < 8; i++) {
        // big endian
//           target_int[i] = (target->at(i << 2) << 24) + (target->at((i << 2) + 1) << 16) + (target->at((i << 2) + 2) << 8) + target->at((i << 2) + 3);
        // little endian
        target_int[7-i] = (target->at(i << 2)) + (target->at((i << 2) + 1) << 8) + (target->at((i << 2) + 2) << 16) + (target->at((i << 2) + 3) << 24);
    }

    cl_mem sha_k_obj = clCreateBuffer(context, CL_MEM_READ_ONLY, sizeof(unsigned int) * 64, NULL, &ret);
    cl_mem sha_h_obj = clCreateBuffer(context, CL_MEM_READ_ONLY, sizeof(unsigned int) * 8, NULL, &ret);
    cl_mem target_obj = clCreateBuffer(context, CL_MEM_READ_ONLY, sizeof(unsigned int) * 8, NULL, &ret);
    cl_mem header_obj = clCreateBuffer(context, CL_MEM_READ_ONLY, sizeof(unsigned char) * 80, NULL, &ret);

    cl_mem nonce_obj = clCreateBuffer(context, CL_MEM_WRITE_ONLY, sizeof(unsigned int), NULL, &ret);
//    cl_mem output_obj = clCreateBuffer(context, CL_MEM_WRITE_ONLY, sizeof(unsigned int) * 8, NULL, &ret);

    // Copy memory buffer values from host to device
    ret = clEnqueueWriteBuffer(command_queue, sha_k_obj, CL_TRUE, 0, sizeof(unsigned int) * 64, ocl_sha256_k, 0, NULL, NULL);
    ret = clEnqueueWriteBuffer(command_queue, sha_h_obj, CL_TRUE, 0, sizeof(unsigned int) * 8, ocl_sha256_h, 0, NULL, NULL);
    ret = clEnqueueWriteBuffer(command_queue, target_obj, CL_TRUE, 0, sizeof(unsigned int) * 8, target_int, 0, NULL, NULL);
    ret = clEnqueueWriteBuffer(command_queue, header_obj, CL_TRUE, 0, sizeof(unsigned char) * 80, header, 0, NULL, NULL);

//    for(int chunk = 0; chunk < chunks; chunk++)
//    {
//        int offset = (size / chunks) * chunk;
//        cl_mem offset_obj = clCreateBuffer(context, CL_MEM_WRITE_ONLY, sizeof(unsigned int), NULL, &ret);
//        ret = clEnqueueWriteBuffer(command_queue, offset_obj, CL_TRUE, 0, sizeof(unsigned int), &offset, 0, NULL, NULL);


        // ==================================================================================================================================
        // ==================================================================================================================================
        if (verbose) std::cout << "Creating program.." << std::endl;
        // Create a program from the kernel source
        cl_program program = clCreateProgramWithSource(context, 1, (const char **)&source_str, (const size_t *)&source_size, &ret);
        if (verbose) std::cout << "Building program.." << std::endl;
        // Build the program
        ret = clBuildProgram(program, 1, &device_id, NULL, NULL, NULL);
        if (verbose) std::cout << "Creating kernel.." << std::endl;
        // Create the OpenCL kernel
        cl_kernel kernel = clCreateKernel(program, kernelFunction, &ret);
        // ==================================================================================================================================
        // ==================================================================================================================================
        if (verbose) std::cout << "Setting kernel arguments.." << std::endl;
        // Set the arguments of the kernel
        ret = clSetKernelArg(kernel, 0, sizeof(cl_mem), (void *)&sha_k_obj);
        ret = clSetKernelArg(kernel, 1, sizeof(cl_mem), (void *)&sha_h_obj);
        ret = clSetKernelArg(kernel, 2, sizeof(cl_mem), (void *)&target_obj);
        ret = clSetKernelArg(kernel, 3, sizeof(cl_mem), (void *)&header_obj);
        ret = clSetKernelArg(kernel, 4, sizeof(cl_mem), (void *)&nonce_obj);
//        ret = clSetKernelArg(kernel, 5, sizeof(cl_mem), (void *)&offset_obj);
    //    ret = clSetKernelArg(kernel, 5, sizeof(cl_mem), (void *)&output_obj);


        const auto p1 = std::chrono::system_clock::now();

        // ==================================================================================================================================
        // ==================================================================================================================================
        if (verbose) std::cout << "Enqueue range.." << std::endl;

        // Execute the OpenCL kernel on the list
        ret = clEnqueueNDRangeKernel(command_queue, kernel, 1, NULL,
                &global_item_size, &local_item_size, 0, NULL, NULL);


        // ==================================================================================================================================
        // ==================================================================================================================================
        if (verbose) std::cout << "Reading buffer.." << std::endl;
        // Copy memory data from device to host
        unsigned int *nonce = (unsigned int*)malloc(sizeof(unsigned int));
        ret = clEnqueueReadBuffer(command_queue, nonce_obj, CL_TRUE, 0, sizeof(unsigned int), nonce, 0, NULL, NULL);

    //    unsigned int *output = (unsigned int*)malloc(sizeof(unsigned int) * 8);
    //    ret = clEnqueueReadBuffer(command_queue, output_obj, CL_TRUE, 0, sizeof(unsigned int) * 8, output, 0, NULL, NULL);

    //    for(int i = 0; i < 8; i++) {
    //        std::cout << "output " << i << ": " << Crypto::decToHex(output[i]) << std::endl;
    //    }


        const auto p2 = std::chrono::system_clock::now();
        int finaltime = (std::chrono::duration_cast<std::chrono::seconds>(p2.time_since_epoch()).count() - std::chrono::duration_cast<std::chrono::seconds>(p1.time_since_epoch()).count());
        unsigned int hashrate = (size / finaltime);
    //    std::cout << "hashrate: " << hashrate << std::endl;
    //    std::cout << "seconds : " << finaltime << std::endl;
        std::cout << "Mining info   hashrate: " << hashrate << "        time: " << finaltime << std::endl;

        // ==================================================================================================================================
        // ==================================================================================================================================

        // Clean up

//        ret = clReleaseMemObject(offset_obj);


//        if (nonce[0] > 0) {
//            return nonce[0];
//        }

//    }

    if (verbose) std::cout << "Clean up.." << std::endl;
    ret = clFlush(command_queue);
    ret = clFinish(command_queue);
    ret = clReleaseProgram(program);
    ret = clReleaseKernel(kernel);


    ret = clReleaseMemObject(sha_h_obj);
    ret = clReleaseMemObject(sha_k_obj);
    ret = clReleaseMemObject(target_obj);
    ret = clReleaseMemObject(header_obj);
    ret = clReleaseMemObject(nonce_obj);

    ret = clReleaseCommandQueue(command_queue);
    ret = clReleaseContext(context);
    return nonce[0];
}
