/*************************************************************************
	> File Name: test.c
	> Author: 
	> Mail: 
	> Created Time: 2017年05月01日 星期一 20时14分33秒
 ************************************************************************/

#include "cjson.h"
#include <assert.h>  /* assert() */
#include <stdlib.h>  /* NULL */
#include <errno.h>  /*errno,ERANGE*/
#include <math.h>   /* HUGE_VAL*/
#include <string.h>

#define EXPECT(c, ch)       do { assert(*c->json == (ch)); c->json++; } while(0)
#define ISDIGIT(ch)         ((ch) >= '0' && (ch) <= '9')
#define ISDIGIT1T9(ch)      ((ch) >= '1' && (ch) <= '9')
#define PUTC(c,ch)          do { *(char*)lept_context_push(c,sizeof(char)) = (ch); } while(0)

#ifndef LEPT_PARSE_STACK_INIT_SIZE
#define LEPT_PARSE_STACK_INIT_SIZE 256
#endif

typedef struct {
    const char* json;

    /*动态堆栈，size是当前容量，top是栈顶的位置。
    * 因为会扩展stack，所以不要将top用指针形式存储
    * */
    char *stack;
    size_t top,size;
}lept_context;

//实现堆栈的push和pop。
//这个堆是以字节存储，每次可有要求压如任意大小的数据，它会返回数据起始的指针
static void *lept_context_push(lept_context *c,size_t size) 
{
    void *ret;
    assert(size > 0);
    if(c->top + size >= c->size) {
        if(c->size == 0)
            c->size = LEPT_PARSE_STACK_INIT_SIZE;
        while(c->top + size >= c->size)
            c->size += c->size >> 1;  /*c->size * 1.5,并且是向下取整*/
        c->stack = (char *)realloc(c->stack,c->size); /*如果c->stack这里输入null，那么等同图malloc*/
    }
    ret = c->stack + c->top;
    c->top += size;
    return ret;
}

static void* lept_context_pop(lept_context* c,size_t size)
{
    assert(c->top >= size);
    return c->stack + (c->top -= size);
}

static void lept_parse_whitespace(lept_context* c) {
    const char *p = c->json;
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')
        p++;
    c->json = p;
}

static int lept_parse_literal(lept_context *c,lept_value *v,const char *literal,lept_type type)
{
    size_t  i;
    EXPECT(c,literal[0]);
    for(i = 0; literal[i + 1];i++)
        if(c->json[i] != literal[i + 1])
            return LEPT_PARSE_INVALID_VALUE;
    c->json += i;
    v->type = type;
    return LEPT_PARSE_OK;
}

static int lept_parse_number(lept_context *c,lept_value *v) {
    const char *p = c->json;
    if(*p == '-') p++;
    if(*p == '0') p++;
    else {
        if(!ISDIGIT1T9(*p)) return LEPT_PARSE_INVALID_VALUE;
        for(p++;ISDIGIT(*p);p++);
    }
        if(*p == 'e' || *p == 'E') {
            p++;
            if(*p == '+' || *p == '-') p++;
            for(p++;ISDIGIT(*p);p++);
        }
        if(*p == '.') {
            p++;
            if(!ISDIGIT(*p)) return LEPT_PARSE_INVALID_VALUE;
            for(p++;ISDIGIT(*p);p++);
        }
    errno = 0;
    v->u.n = strtod(c->json,NULL);
    if(errno == ERANGE && (v->u.n == HUGE_VAL || v->u.n == -HUGE_VAL)) return LEPT_PARSE_NUMBER_TOO_BIG;
    c->json = p;
    v->type = LEPT_NUMBER;
    return LEPT_PARSE_OK;
}

static int lept_parse_string(lept_context *c,lept_value *v)
{
    size_t head = c->top,len;
    const char *p;
    EXPECT(c,'\"');
    p = c->json;
    for(;;) {
        char ch = *p++;
        switch(ch) {
            case '\"' :
                len = c->top - head;
                lept_set_string(v,(const char *)lept_context_pop(c,len),len);
                c->json = p;
                return LEPT_PARSE_OK;
            case '\0':
                c->top = head;
                return LEPT_PARSE_MISS_QUOTATION_MARK;
            default:
                PUTC(c,ch);
        }
    }
}

static int lept_parse_value(lept_context* c, lept_value* v) {
    switch (*c->json) {
        case 'n':  return lept_parse_literal(c, v,"null",LEPT_NULL);
        case 't':  return lept_parse_literal(c, v,"true",LEPT_TRUE);
        case 'f':  return lept_parse_literal(c, v,"false",LEPT_FALSE);
        case '"':  return lept_parse_string(c, v);
        case '\0': return LEPT_PARSE_EXPECT_VALUE;
        default:   return lept_parse_number(c,v);
    }
}

void lept_free(lept_value *v)
{
    assert(v != NULL);
    if(v->type == LEPT_STRING)
        free(v->u.s.s);
    v->type = LEPT_NULL;
}

void lept_set_string(lept_value *v,const char *s,size_t len) {
    assert(v != NULL && (s != NULL || len == 0));
    lept_free(v);
    v->u.s.s = (char *)malloc(len + 1);
    memcpy(v->u.s.s,s,len);
    v->u.s.s[len] = '\0';
    v->u.s.len = len;
    v->type = LEPT_STRING;
}

int lept_parse(lept_value* v, const char* json) {
    lept_context c;
    int retcode;
    assert(v != NULL);
    c.json = json;

    //初始化stack
    c.stack = NULL;
    c.size = c.top = 0;
    
    lept_init(v);
    lept_parse_whitespace(&c);
    if((retcode = lept_parse_value(&c,v)) == LEPT_PARSE_OK) {
        lept_parse_whitespace(&c);
        if(*c.json != '\0'){
            v->type = LEPT_NULL;
            retcode = LEPT_PARSE_ROOT_NOT_SINGULAR;
        }
    }

    //确保所有的数据都被弹出
    assert(c.top == 0);
    free(c.stack);
    return retcode;
}

int lept_get_boolean(const lept_value *v)
{
    assert(v != NULL && (v->type == LEPT_TRUE || v->type == LEPT_FALSE));

    return v->type == LEPT_TRUE;
}

void lept_set_boolean(lept_value *v,int b )
{
    lept_free(v);
    v->type = b ? LEPT_TRUE:LEPT_FALSE;
}

double lept_get_number(const lept_value *v)
{
    assert(v != NULL && v->type == LEPT_NUMBER);
    return v->u.n;
}

void lept_set_number(lept_value *v,double n)
{
    lept_free(v);
    v->u.n = n;
    v->type = LEPT_NUMBER;
}

const char *lept_get_string(const lept_value *v)
{
    assert(v != NULL && v->type == LEPT_STRING);
    return v->u.s.s;
}

size_t lept_get_string_length(const lept_value *v)
{
    assert(v != NULL && v->type == LEPT_STRING);
    return v->u.s.len;
}

lept_type lept_get_type(const lept_value* v) {
    assert(v != NULL);
    return v->type;
}
