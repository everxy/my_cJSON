/*************************************************************************
	> File Name: cjson.h
	> Author: 
	> Mail: 
	> Created Time: 2017年05月01日 星期一 20时14分19秒
 ************************************************************************/

#ifndef _CJSON_H
#define _CJSON_H

#include <stddef.h>
typedef enum { LEPT_NULL, LEPT_FALSE, LEPT_TRUE, LEPT_NUMBER, LEPT_STRING, LEPT_ARRAY, LEPT_OBJECT } lept_type;

typedef struct lept_value lept_value;
typedef struct lept_member lept_member;

struct lept_value {
    union {
        double n;
        /*先用成员组成的数组形式 简单处理obj*/
        struct { lept_member *m;size_t size; } o;
        struct {char *s;size_t len;} s;
        struct { lept_value *e;size_t size; } a;/*array,size表示个数，e是指向元素类型为lept_value的数组的指针*/
    } u;
    lept_type   type;

};

/*obj的成员，键值对形式。*k是键，v是值*/
struct lept_member {
    char *k;size_t klen;
    lept_value v;
};

enum {
    LEPT_PARSE_OK = 0,
    LEPT_PARSE_EXPECT_VALUE,
    LEPT_PARSE_INVALID_VALUE,
    LEPT_PARSE_ROOT_NOT_SINGULAR,
    LEPT_PARSE_NUMBER_TOO_BIG,
    LEPT_PARSE_MISS_QUOTATION_MARK,
    LEPT_PARSE_INVALID_STRING_ESCAPE,
    LEPT_PARSE_INVALID_STRING_CHAR,
    LEPT_PARSE_INVALID_UNICODE_HEX,
    LEPT_PARSE_INVALID_UNICODE_SURROGATE,
    LEPT_PARSE_MISS_KEY,
    LEPT_PARSE_MISS_COLON,
    LEPT_PARSE_MISS_COMMA_OR_SQUARE_BRACKET,
    LEPT_PARSE_MISS_COMMA_OR_CURLY_BRACKET
};
#define lept_init(v)    do { (v)->type == LEPT_NULL; }while(0)

void lept_free(lept_value *v);

int lept_parse(lept_value* v, const char* json);
lept_type lept_get_type(const lept_value* v);

void lept_set_string(lept_value *v,const char *s,size_t len);
const char *lept_get_string(const lept_value *v);
size_t  lept_get_string_length(const lept_value *v);

double lept_get_number(const lept_value *v);
void lept_set_number(lept_value *v,double n);

int lept_get_boolean(const lept_value *v);
void lept_set_boolean(lept_value *v,int b);

size_t lept_get_array_size(const lept_value* v);
lept_value * lept_get_array_element(const lept_value *v,size_t index);

size_t lept_get_obj_size(const lept_value* v);
const char* lept_get_obj_key(const lept_value* v,size_t index);
size_t lept_get_obj_key_length(const lept_value* v,size_t index);
lept_value* lept_get_obj_value(const lept_value* v,size_t index);

char* lept_stringify(const lept_value *v,size_t *len);

#define lept_set_null(v) lept_free(v)


#endif
