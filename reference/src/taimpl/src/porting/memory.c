/*
 * Copyright 2020-2023 Comcast Cable Communications Management, LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "porting/memory.h" // NOLINT
#include "log.h"
#include "porting/overflow.h"
#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

typedef struct MemoryNode {
    void* buffer;
    size_t size;
    struct MemoryNode* next;
} MemoryNode_t;

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

MemoryNode_t* g_memory_node = NULL;
size_t g_total_memory = 0;
size_t g_highest_memory = 0;

static void register_alloc(void* buffer, size_t size) {
    pthread_mutex_lock(&mutex);
    MemoryNode_t* node = malloc(sizeof(MemoryNode_t));
    node->next = g_memory_node;
    node->buffer = buffer;
    node->size = size;
    g_memory_node = node;
    g_total_memory += size;
    if (g_total_memory > g_highest_memory) {
        g_highest_memory = g_total_memory;
    }
    printf("Highest ever memory : %zu Total internal memory : %zu last allocated : %zu\n", g_highest_memory, g_total_memory, size);
    pthread_mutex_unlock(&mutex);
}

static void register_free(void* buffer) {
    if (buffer) {
        pthread_mutex_lock(&mutex);
        MemoryNode_t* prev = g_memory_node;
        MemoryNode_t* node = g_memory_node;
        while (node) {
            if (node->buffer == buffer) {
                break;
            }
            prev = node;
            node = node->next;
        }
        assert(node);
        if (node == g_memory_node) {
            g_memory_node = node->next;
        } else {
            prev->next = node->next;
        }
        g_total_memory -= node->size;
        printf("Highest ever memory : %zu Total internal memory : %zu last freed : %zu\n", g_highest_memory, g_total_memory, node->size);
        free(node);
        pthread_mutex_unlock(&mutex);
    }
}

void* memory_secure_alloc(size_t size) {
    return memory_internal_alloc(size);
}

void* memory_secure_realloc(void* buffer, size_t new_size) {
    return memory_internal_realloc(buffer, new_size);
}

void memory_secure_free(void* buffer) {
    memory_internal_free(buffer);
}

void* memory_internal_alloc(size_t size) {
    void* buffer = malloc(size);
    register_alloc(buffer, size);
    return buffer;
}

void* memory_internal_realloc(void* buffer, size_t new_size) {
    register_free(buffer);
    buffer = realloc(buffer, new_size);
    register_alloc(buffer, new_size);
    return buffer;
}

void memory_internal_free(void* buffer) {
    register_free(buffer);
    free(buffer);
}

int memory_memcmp_constant(const void* in1, const void* in2, size_t length) {
    uint8_t* a = (uint8_t*) in1;
    uint8_t* b = (uint8_t*) in2;

    int result = 0;
    for (size_t i = 0; i < length; ++i) {
        result |= a[i] ^ b[i];
    }

    return result;
}

void* memory_memset_unoptimizable(void* destination, uint8_t value, size_t size) {
    volatile uint8_t* pointer = (uint8_t*) destination;
    if (size == 0)
        return destination;

    while (size--)
        *pointer++ = value;
    return destination;
}

bool memory_is_valid_svp(
        void* memory_location,
        size_t size) {

    if (memory_location == NULL) {
        ERROR("Invalid memory");
        return false;
    }

    size_t temp;
    if (add_overflow((unsigned long) memory_location, size, &temp)) {
        ERROR("Integer overflow");
        return false;
    }

    // TODO: SoC vendor must verify that all bytes between memory_location and memory_location+size are within SVP
    // space.
    return true;
}

bool memory_is_valid_clear(
        void* memory_location,
        size_t size) {

    if (memory_location == NULL) {
        ERROR("Invalid memory");
        return false;
    }

    size_t temp;
    if (add_overflow((unsigned long) memory_location, size, &temp)) {
        ERROR("Integer overflow");
        return false;
    }

    // TODO: SoC vendor must verify that all bytes between memory_location and memory_location+size are not within SVP
    // space.
    return true;
}
