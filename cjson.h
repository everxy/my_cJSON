/*************************************************************************
	> File Name: cjson.h
	> Author: 
	> Mail: 
	> Created Time: 2017年05月01日 星期一 20时14分19秒
 ************************************************************************/

#ifndef _CJSON_H
#define _CJSON_H
typedef enum { LEPT_NULL, LEPT_FALSE, LEPT_TRUE, LEPT_NUMBER, LEPT_STRING, LEPT_ARRAY, LEPT_OBJECT } lept_type;

typedef struct {
    lept_type type;
}lept_value;

enum {
    LEPT_PARSE_OK = 0,
    LEPT_PARSE_EXPECT_VALUE,
    LEPT_PARSE_INVALID_VALUE,
    LEPT_PARSE_ROOT_NOT_SINGULAR
};

int lept_parse(lept_value* v, const char* json);

lept_type lept_get_type(const lept_value* v);
#endif
