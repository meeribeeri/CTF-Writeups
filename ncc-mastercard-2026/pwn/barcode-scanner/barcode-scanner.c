#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "common.h"

#define BUFFER_SIZE 0x40
#define READ_SIZE (BUFFER_SIZE * 8)
#define NUM_BARCODES 5
#define BARCODE_LEN 40

typedef struct __attribute__((packed)) __barcode_info {
    char barcode[BARCODE_LEN];
    char product[BUFFER_SIZE];
} barcode_info;

barcode_info barcodes[NUM_BARCODES] = {
    {"3f1e2c4a-9b7d-4f2a-b8c3-1d2e3f4a5b6c", "Shoppy McShopface Classic Tee - Navy"},
    {"a2b3c4d5-6e7f-4a8b-9c0d-1e2f3a4b5c6d", "Shoppy McShopface Ceramic Mug (350ml)"},
    {"9f8e7d6c-5b4a-4c3d-8e9f-0a1b2c3d4e5f", "Shoppy Water Bottle - 750ml Stainless"},
    {"0f1e2d3c-4b5a-4a6b-8c9d-0e1f2a3b4c5d", "Shoppy Wireless Charger Pad"},
    {"fedcba98-7654-4f32-8abc-0123456789ab", "McShopface Hoodie - Charcoal, Size L"},
};

void win() {
    
    char contents[FLAG_SIZE] = {0};

    
    FILE *fd = fopen("flag.txt", "r");
    if (fd == NULL) {
        perror("failed to read flag from disk");
        exit(1);
    }

    
    fread(contents, 1, sizeof(contents), fd);

    
    printf("[ShoppyMcShopface] Found internal product: %s\n", contents);
}

void vuln() {
    
    char buffer[BARCODE_LEN] = {0};

    
    printf("[ShoppyMcShopface] enter barcode for lookup: ");
    fgets(buffer, READ_SIZE, stdin);

    
    int product_found = 0;
    for (int i = 0; i < NUM_BARCODES; ++i) {
        if (strncmp(barcodes[i].barcode, buffer, strlen(barcodes[i].barcode)) == 0) {
            printf("[ShoppyMcShopface] Found product: %s\n", barcodes[i].product);
            product_found = 1;
            break;
        }
    }

    
    if (product_found == 0) {
        printf("[ShoppyMcShopface] Product with barcode %64s couldn't be found.\n", buffer);
    }

    
    return;
}

int main() {
    vuln();
    return CODE_OK;
}
