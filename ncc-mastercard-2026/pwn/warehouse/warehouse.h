#include <sqlite3.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

#include "common.h"

#ifndef __NCC_CTF_PRODUCT_MANAGER__
#define __NCC_CTF_PRODUCT_MANAGER__ 1


extern sqlite3 *db;


extern char *err_msg;


#define ERR(s) fputs(s, stderr)


#define PRODUCT_NUM 10
#define PRODUCT_LEN 128
#define CODE_SQLITE_FAIL 5


#define TBL_ACCOUNTING "accounting"
#define TBL_ACCOUNTING_TIME "time"
#define TBL_ACCOUNTING_MSG "msg"

#define TBL_PRODUCTS "products"
#define TBL_PRODUCTS_NAME "name"
#define TBL_PRODUCTS_PRICE "price"
#define TBL_PRODUCTS_QTY "qty"


#define CREATE_ACCOUNTING_TABLE                                                \
  "CREATE TABLE IF NOT EXISTS " TBL_ACCOUNTING "("                             \
  "id INTEGER PRIMARY KEY AUTOINCREMENT," TBL_ACCOUNTING_MSG                   \
  " TEXT NOT NULL," TBL_ACCOUNTING_TIME " TEXT NOT NULL"                       \
  ");"

#define CREATE_PRODUCT_TABLE                                                   \
  "CREATE TABLE IF NOT EXISTS " TBL_PRODUCTS "("                               \
  "id INTEGER PRIMARY KEY AUTOINCREMENT," TBL_PRODUCTS_NAME                    \
  " TEXT NOT NULL," TBL_PRODUCTS_PRICE " INTEGER NOT NULL," TBL_PRODUCTS_QTY   \
  " INTEGER NOT NULL"                                                          \
  ");"


int __attribute__((noinline)) create_log(char *msg);
int __attribute__((noinline)) create_product(char *name, int price, int qty);
int __attribute__((noinline)) print_log(void *arg, int cols, char **vals,
                                        char **col_vals);
int __attribute__((noinline)) print_product(void *arg, int cols, char **vals,
                                            char **col_vals);
void __attribute__((noinline)) view_logs();
void __attribute__((noinline)) view_products();

#endif 
