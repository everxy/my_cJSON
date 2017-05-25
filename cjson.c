/*************************************************************************
	> File Name: cjson.c
	> Author: 
	> Mail: 
	> Created Time: 三  5/24 09:39:49 2017
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

static int lept_parse_value(lept_context *c,lept_value *v);


/*实现堆栈的push和pop。*/
/*这个堆是以字节存储，每次可有要求压如任意大小的数据，它会返回数据起始的指针*/
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
        if(*p == '.') {
            p++;
            if(!ISDIGIT(*p)) return LEPT_PARSE_INVALID_VALUE;
            for(p++;ISDIGIT(*p);p++);
        }
        if(*p == 'e' || *p == 'E') {
            p++;
            if(*p == '+' || *p == '-') p++;
            for(p++;ISDIGIT(*p);p++);
        }
    errno = 0;
    v->u.n = strtod(c->json,NULL);
    if(errno == ERANGE && (v->u.n == HUGE_VAL || v->u.n == -HUGE_VAL)) return LEPT_PARSE_NUMBER_TOO_BIG;
    c->json = p;
    v->type = LEPT_NUMBER;
    return LEPT_PARSE_OK;
}
static const char* lept_parse_hex4(const char* p, unsigned* u)
{
    int i;
    *u = 0;
    for(i = 0;i < 4;i++) {
        char ch = *p++;
        *u <<= 4;
        if      (ch >= '0' && ch <= '9') *u |= ch -'0';
        /*将一个十六进制转换为10进制数字
        * F = F - 'A' + 10;--->F = 15;
        * */
        else if (ch >= 'A' && ch <= 'F') *u |= ch - ('A' - 10);
        else if (ch >= 'a' && ch <= 'f') *u |= ch - ('a' - 10);
        else return NULL;
    }
    return p;
}

static void lept_encode_utf8(lept_context *c,unsigned u)
{
    if (u <= 0x7F) 
        PUTC(c, u & 0xFF);
    else if (u <= 0x7FF) {
        PUTC(c, 0xC0 | ((u >> 6) & 0xFF));
        PUTC(c, 0x80 | ( u       & 0x3F));
    }
    else if (u <= 0xFFFF) {
        PUTC(c, 0xE0 | ((u >> 12) & 0xFF));
        PUTC(c, 0x80 | ((u >>  6) & 0x3F));
        PUTC(c, 0x80 | ( u        & 0x3F));
    }
    else {
        assert(u <= 0x10FFFF);
        PUTC(c, 0xF0 | ((u >> 18) & 0xFF));
        PUTC(c, 0x80 | ((u >> 12) & 0x3F));
        PUTC(c, 0x80 | ((u >>  6) & 0x3F));
        PUTC(c, 0x80 | ( u        & 0x3F));
    }
}

#define STRING_ERROR(ret)  do { c->top = head; return ret; } while(0)
/*处理字符串，将解析完成的字符串拷贝至v->u.s.s,返回处理的状态*/
static int lept_parse_string(lept_context *c,lept_value *v)
{
    size_t head = c->top,len;
    const char *p;
    unsigned u, u2;
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
            
            case '\\':
                switch(*p++) {
                    case '\"': PUTC(c,'\"');break;
                    case '\\':PUTC(c,'\\');break;
                    case '/': PUTC(c,'/');break;
                    case 'b': PUTC(c,'\b');break;
                    case 'f': PUTC(c,'\f');break;
                    case 'n': PUTC(c,'\n');break;
                    case 'r': PUTC(c,'\r');break;
                    case 't': PUTC(c,'\t');break;
                    case 'u':
                        if(!(p = lept_parse_hex4(p,&u)))
                            STRING_ERROR(LEPT_PARSE_INVALID_UNICODE_HEX);
                        if (u >= 0xD800 && u <= 0xDBFF) { /* surrogate pair */
                            if (*p++ != '\\')
                                STRING_ERROR(LEPT_PARSE_INVALID_UNICODE_SURROGATE);
                            if (*p++ != 'u')
                                STRING_ERROR(LEPT_PARSE_INVALID_UNICODE_SURROGATE);
                            if (!(p = lept_parse_hex4(p, &u2)))
                                STRING_ERROR(LEPT_PARSE_INVALID_UNICODE_HEX);
                            if (u2 < 0xDC00 || u2 > 0xDFFF)
                                STRING_ERROR(LEPT_PARSE_INVALID_UNICODE_SURROGATE);
                            u = (((u - 0xD800) << 10) | (u2 - 0xDC00)) + 0x10000;
                        }
                        lept_encode_utf8(c,u);
                        break;
                    default:
                        c->top = head;
                        return LEPT_PARSE_INVALID_STRING_ESCAPE;
                }
                break;
            case '\0':
                c->top = head;
                return LEPT_PARSE_MISS_QUOTATION_MARK;
            default:
                /*0x20是空格字符，asc码为32（十进制），小于它即是非法字符。
                * 32-126是所有的字符，127是删除
                * */
                if((unsigned char)ch < 0x20) {
                    c->top = head;
                    return LEPT_PARSE_INVALID_STRING_CHAR;
                }
                PUTC(c,ch);
        }
    }
}

static int lept_parse_array(lept_context* c,lept_value* v) {
    size_t size = 0;
    int ret;
    EXPECT(c,'[');
    lept_parse_whitespace(c);
    if(*c->json == ']') {
        c->json++;
        v->type = LEPT_ARRAY;
        v->u.a.size = 0;
        v->u.a.e = NULL;
        return LEPT_PARSE_OK;
    }

    for(;;) {
        lept_value e;
        lept_init(&e);
        /*lept_parse_value将c中的数据（字符串，数字等等）放入临时值e中，*/
        if((ret = lept_parse_value(c,&e)) != LEPT_PARSE_OK)
            return ret;
        /*lept_context_push先将一个lept_value大小的空间压栈，然后将e中的值赋值拷贝过去。
        * push函数返回的是指向新申请空间的头地址。
        * */
        memcpy(lept_context_push(c,sizeof(lept_value)),&e,sizeof(lept_value));
        /*数组元素的个数+1*/
        size++;
        if(*c->json == ',')
            c->json++;
        /*遇到了]就将当前的栈内的元素弹出。*/
        else if(*c->json == ']') {
            c->json++;
            v->type = LEPT_ARRAY;
            v->u.a.size = size;
            size *= sizeof(lept_value);
            memcpy(v->u.a.e = (lept_value *)malloc(size),lept_context_pop(c,size),size);
            return LEPT_PARSE_OK;
        }
        else{
            ret = LEPT_PARSE_MISS_COMMA_OR_SQUARE_BRACKET;
            break;
        }
    }
    for(int i = 0;i < size; i++) {
        lept_free((lept_value*)lept_context_pop(c,sizeof(lept_value)));
    }
    return ret;

}

static int lept_parse_value(lept_context* c, lept_value* v) {
    switch (*c->json) {
        case 'n':  return lept_parse_literal(c, v,"null",LEPT_NULL);
        case 't':  return lept_parse_literal(c, v,"true",LEPT_TRUE);
        case 'f':  return lept_parse_literal(c, v,"false",LEPT_FALSE);
        case '"':  return lept_parse_string(c, v);
        case '[':  return lept_parse_array(c, v);
        case '\0': return LEPT_PARSE_EXPECT_VALUE;
        default:   return lept_parse_number(c,v);
    }
}

void lept_free(lept_value *v)
{
    size_t i;
    assert(v != NULL);
    switch(v->type) {
        case LEPT_STRING:
            free(v->u.s.s);
            break;
        case LEPT_ARRAY:
            for(i = 0;i < v->u.a.size;i++)
                lept_free(&v->u.a.e[i]);
            free(v->u.a.e);
            break;
        default:break;
    }
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

    /*初始化stack*/
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

    /*确保所有的数据都被弹出*/
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

size_t lept_get_array_size(const lept_value *v)
{
    assert(v != NULL && v->type == LEPT_ARRAY);
    return v->u.a.size;
}

lept_value *lept_get_array_element(const lept_value *v,size_t index)
{
    assert(v != NULL && v->type == LEPT_ARRAY);
    assert(index < v->u.a.size);
    return &v->u.a.e[index];
}

lept_type lept_get_type(const lept_value* v) {
    assert(v != NULL);
    return v->type;
}
