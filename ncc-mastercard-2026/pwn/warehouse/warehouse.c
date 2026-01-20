#include "warehouse.h"

char products[PRODUCT_NUM][PRODUCT_LEN] = {
    "Shoppy McShopface Classic Tee - Navy",  "Shoppy McShopface Ceramic Mug (350ml)",
    "Shoppy Water Bottle - 750ml Stainless", "Shoppy Wireless Charger Pad",
    "McShopface Hoodie - Charcoal, Size L",  "Shoppy Sticker Pack (10 pcs)",
    "Shoppy Laptop Sleeve 13-inch",          "McShopface Enamel Pin - Limited",
    "Shoppy Reusable Tote Bag - Black",      "Shoppy Premium Headphones - Onyx",
};


sqlite3 *db = NULL;
char *err_msg = NULL;



int create_log(char *msg) {
    
    char *_buf = calloc(0x200, 1);
    if (_buf == NULL) {
        malloc_fail();
    }
    char *_fmt = calloc(0x200, 1);
    if (_fmt == NULL) {
        malloc_fail();
    }
    char *_time = calloc(0x80, 1);
    if (_time == NULL) {
        malloc_fail();
    }

    
    time_t now = time(NULL);              
    struct tm *tm_info = localtime(&now); 

    
    strftime(_time, 0x80, "%Y-%m-%d %H:%M:%S", tm_info);

    
    snprintf(_buf, 0x200, "INSERT INTO %%s (%%s, %%s) VALUES ('%s', '%s');", msg, _time);
    snprintf(_fmt, 0x200, _buf, TBL_ACCOUNTING, TBL_ACCOUNTING_MSG, TBL_ACCOUNTING_TIME);

    
    int rc = sqlite3_exec(db, _fmt, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        ERR("failed to insert accounting log");
        ERR(err_msg);
        sqlite3_free(err_msg);
        exit(CODE_SQLITE_FAIL);
    }

    
    free(_buf);
    free(_fmt);
    free(_time);

    
    return rc;
}


int create_product(char *name, int price, int qty) {
    
    char *sql = calloc(0x200, 1);
    if (sql == NULL) {
        malloc_fail();
    }

    
    char *sanitized = calloc(0x80, 1);
    if (sanitized == NULL) {
        malloc_fail();
    }

    
    strncpy(sanitized, name, 0x80);
    for (int i = 0; i < 0x80; ++i) {
        if (sanitized[i] == '\n') {
            sanitized[i] = '\0';
        }
    }

    
    snprintf(sql, 0x200, "INSERT INTO %s (%s, %s, %s) VALUES ('%s', %d, %d);", TBL_PRODUCTS,
             TBL_PRODUCTS_NAME, TBL_PRODUCTS_PRICE, TBL_PRODUCTS_QTY, sanitized, price, qty);

    
    int rc = sqlite3_exec(db, sql, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        ERR("failed to insert product");
        ERR(err_msg);
        sqlite3_free(err_msg);
        exit(CODE_SQLITE_FAIL);
    }

    
    snprintf(sql, 0x200, "Inserted product %s into the database", sanitized);
    create_log(sql);

    
    free(sql);
    free(sanitized);

    
    return rc;
}


int print_log(void *arg, int cols, char **vals, char **col_vals) {
    
    if (cols != 2) {
        ERR("invalid number of columns");
        exit(CODE_SQLITE_FAIL);
    }

    
    char *buf = calloc(0x200, 1);
    if (buf == NULL) {
        malloc_fail();
    }

    
    char *msg = vals[0];
    char *time = vals[1];

    
    snprintf(buf, 0x200, "Log [%s]: %s", time, msg);
    puts(buf);

    
    free(buf);

    
    return 0;
}


int print_product(void *arg, int cols, char **vals, char **col_vals) {
    
    if (cols != 3) {
        ERR("invalid number of columns");
        exit(CODE_SQLITE_FAIL);
    }

    
    char *buf = calloc(0x200, 1);
    if (buf == NULL) {
        malloc_fail();
    }

    
    char *name = vals[0];
    int price = 0;
    int qty = 0;

    
    if (sscanf(vals[1], "%d", &price) < 1) {
        ERR("failed to scan " TBL_PRODUCTS_PRICE);
        exit(CODE_OTHER);
    }
    if (sscanf(vals[2], "%d", &qty) < 1) {
        ERR("failed to scan " TBL_PRODUCTS_QTY);
        exit(CODE_OTHER);
    }

    
    snprintf(buf, 0x200, "Product: %s @ $%d (%d in stock)", name, price, qty);
    puts(buf);

    
    free(buf);

    
    return 0;
}


void view_logs() {
    
    char *sql = calloc(0x80, 1);
    if (sql == NULL) {
        malloc_fail();
    }

    
    strcpy(sql, "Viewed accounting logs");
    create_log(sql);

    
    strncpy(sql, "SELECT " TBL_ACCOUNTING_MSG ", " TBL_ACCOUNTING_TIME " FROM " TBL_ACCOUNTING,
            0x80);

    
    int rc = sqlite3_exec(db, sql, print_log, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        ERR("failed to pull accounting logs");
        ERR(err_msg);
        sqlite3_free(err_msg);
        exit(CODE_SQLITE_FAIL);
    }

    
    free(sql);
}


void view_products() {
    
    char *sql = calloc(0x80, 1);
    if (sql == NULL) {
        malloc_fail();
    }

    
    strcpy(sql, "Viewed products");
    create_log(sql);

    
    strncpy(sql,
            "SELECT " TBL_PRODUCTS_NAME ", " TBL_PRODUCTS_PRICE ", " TBL_PRODUCTS_QTY
            " FROM " TBL_PRODUCTS,
            0x80);

    
    int rc = sqlite3_exec(db, sql, print_product, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        ERR("failed to pull products");
        ERR(err_msg);
        sqlite3_free(err_msg);
        exit(CODE_SQLITE_FAIL);
    }

    
    free(sql);
}


void __attribute__((constructor(1000))) setup_db() {
    
    sqlite3_config(SQLITE_CONFIG_MULTITHREAD);
    sqlite3_initialize();

    
    if (sqlite3_open_v2("file::memory:", &db,
                        SQLITE_OPEN_URI | SQLITE_OPEN_CREATE | SQLITE_OPEN_MEMORY |
                            SQLITE_OPEN_READWRITE | SQLITE_OPEN_DELETEONCLOSE |
                            SQLITE_OPEN_FULLMUTEX,
                        NULL) != SQLITE_OK) {
        ERR("Couldn't create database");
        exit(CODE_OTHER);
    }

    
    int rc = sqlite3_exec(db, CREATE_ACCOUNTING_TABLE, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        ERR("couldn't create " TBL_ACCOUNTING " table");
        ERR(err_msg);
        sqlite3_free(err_msg);
        exit(CODE_SQLITE_FAIL);
    }

    
    rc = sqlite3_exec(db, CREATE_PRODUCT_TABLE, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        ERR("couldn't create " TBL_PRODUCTS " table");
        ERR(err_msg);
        sqlite3_free(err_msg);
        exit(CODE_SQLITE_FAIL);
    }
}


void __attribute__((constructor(1001))) populate_db() {
    
    for (int i = 0; i < PRODUCT_NUM; ++i) {
        create_product(products[i], 10, 10);
    }
}


void __attribute__((destructor)) cleanup() {
    
    sqlite3_close_v2(db);
}

void menu() {
    puts("1) Create product");
    puts("2) View Products");
    puts("3) Exit");
    printf("> ");
}

void vuln() {
    
    int choice = 0;
    int running = 1;
    int price = 0;
    int qty = 0;
    char input[0x40] = {0};

    
    while (running) {
        
        menu();

        
        fscanf(stdin, "%d", &choice);
        getchar();
        if (choice < 0 || choice > 4) {
            puts("Invalid input!");
            continue;
        }

        
        switch (choice) {
        case 1:
            
            printf("Enter product name: ");
            fgets(input, sizeof(input) * 8, stdin);

            
            printf("Enter price: ");
            fscanf(stdin, "%d", &price);

            
            printf("Enter qty: ");
            fscanf(stdin, "%d", &qty);

            
            create_product(input, price, qty);
            break;
        case 2:
            view_products();
            break;
        case 3:
            running = 0;
            break;
        case 4:
            view_logs();
            break;
        default:
            break;
        }
    }

    puts("Goodbye.");

    
    return;
}

int main() {
    
    puts("*********************************");
    puts("* SHOPPY MCSHOPFACE ENTERPRISES *");
    puts("*********************************\n");

    vuln();
    return CODE_OK;
}
