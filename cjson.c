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
#include <stdio.h>

#define EXPECT(c, ch)       do { assert(*c->json == (ch)); c->json++; } while(0)
#define ISDIGIT(ch)         ((ch) >= '0' && (ch) <= '9')
#define ISDIGIT1T9(ch)      ((ch) >= '1' && (ch) <= '9')
#define PUTC(c,ch)          do { *(char*)lept_context_push(c,sizeof(char)) = (ch); } while(0)
#define PUTS(c,s,len)       memcpy(lept_context_push(c,len),s,len)

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


/*解析json字符串，把结果写入str和len */
static int lept_parse_string_raw(lept_context *c,char **str,size_t *len)
{
    size_t head = c->top;
    const char *p;
    unsigned u, u2;
    EXPECT(c,'\"');
    p = c->json;
    for(;;) {
        char ch = *p++;
        switch(ch) {
            case '\"' :
                *len = c->top - head;
                *str = lept_context_pop(c,*len);
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
    return 0;
}
/*处理字符串，将解析完成的字符串拷贝至v->u.s.s,返回处理的状态*/
static int lept_parse_string(lept_context *c,lept_value *v)
{
    int ret;
    char *s;
    size_t len;
    if((ret = lept_parse_string_raw(c,&s,&len)) == LEPT_PARSE_OK)
        lept_set_string(v,s,len);
    return ret;

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
        lept_parse_whitespace(c);
        size++;
        if(*c->json == ','){
            c->json++;
            lept_parse_whitespace(c);
        }/*遇到了]就将当前的栈内的元素弹出。*/
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

static int lept_parse_object(lept_context* c,lept_value *v)
{
    size_t size;
    lept_member m;
    int ret;
    EXPECT(c,'{');
    lept_parse_whitespace(c);
    
    if(*c->json == '}') {
        c->json++;
        v->type = LEPT_OBJECT;
        v->u.o.size = 0;
        v->u.o.m = NULL;
        return LEPT_PARSE_OK;
    }
    m.k = NULL;
    size = 0;
    for(;;) {
        char* str;
        lept_init(&m.v);
        if(*c->json != '"') {
            ret = LEPT_PARSE_MISS_KEY;
            break;
        }
        if((ret = lept_parse_string_raw(c,&str,&m.klen)) != LEPT_PARSE_OK)
            break;
        memcpy(m.k = (char *)malloc(m.klen + 1),str,m.klen);
        m.k[m.klen] = '\0';
        lept_parse_whitespace(c);
        if(*c->json != ':') {
            ret = LEPT_PARSE_MISS_COLON;
            break;
        }
        c->json++;
        lept_parse_whitespace(c);
        if((ret = lept_parse_value(c,&m.v)) != LEPT_PARSE_OK)
            break;
        memcpy(lept_context_push(c,sizeof(lept_member)),&m,sizeof(lept_member));
        size++;
        m.k = NULL;
        lept_parse_whitespace(c);
        if(*c->json == ','){
            c->json++;
            lept_parse_whitespace(c);
        } else if (*c->json == '}') {
            size_t s = sizeof(lept_member) * size;
            c->json++;
            v->type = LEPT_OBJECT;
            v->u.o.size = size;
            memcpy(v->u.o.m = (lept_member *)malloc(s),lept_context_pop(c,s),s);
            return LEPT_PARSE_OK;
        }
        else {
            ret = LEPT_PARSE_MISS_COMMA_OR_CURLY_BRACKET;
            break;
        }
    }
    
    /*遇到任何错误执行这里，free(null)是合法的。*/
    free(m.k);
    for(int i = 0; i < size;i++) {
        lept_member *m = (lept_member *)lept_context_pop(c,sizeof(lept_member));
        free(m->k);
        lept_free(&m->v);
    }
    v->type = LEPT_NULL;
    return ret;
}

static int lept_parse_value(lept_context* c, lept_value* v) {
    switch (*c->json) {
        case 'n':  return lept_parse_literal(c, v,"null",LEPT_NULL);
        case 't':  return lept_parse_literal(c, v,"true",LEPT_TRUE);
        case 'f':  return lept_parse_literal(c, v,"false",LEPT_FALSE);
        case '"':  return lept_parse_string(c, v);
        case '[':  return lept_parse_array(c, v);
        case '{':  return lept_parse_object(c, v);
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
        case LEPT_OBJECT:
            for(i = 0;i < v->u.o.size;i++) {
                free(v->u.o.m[i].k);
                lept_free(&v->u.o.m[i].v);
            }
            free(v->u.o.m);
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

size_t lept_get_obj_size(const lept_value* v) {
    assert(v != NULL && v->type == LEPT_OBJECT);
    return v->u.o.size;
}

const char* lept_get_obj_key(const lept_value* v,size_t index)
{
    assert(v != NULL && v->type == LEPT_OBJECT);
    assert(index < v->u.o.size);
    return v->u.o.m[index].k;
}

size_t lept_get_obj_key_length(const lept_value *v,size_t index)
{
    assert(v != NULL && v->type == LEPT_OBJECT);
    assert(index < v->u.o.size);
    return v->u.o.m[index].klen;
}

lept_value *lept_get_obj_value(const lept_value *v,size_t index)
{
    assert(v != NULL && v->type == LEPT_OBJECT);
    assert(index < v->u.o.size);
    return &v->u.o.m[index].v;
}

#ifndef LEPT_PARSE_STRINGIFY_INIT_SIZE
#define LEPT_PARSE_STRINGIFY_INIT_SIZE 256
#endif

#if 0
static void lept_stringify_string(lept_context *c, char *s,size_t len)
{
    size_t i;
    assert(s != NULL);
    PUTC(c,'"');
    for(i = 0;i < len;i++) {
        unsigned char ch = (unsigned char)s[i];
        switch(ch) {
            case '\"':PUTS(c,"\\\"",2);break;
            case '\\':PUTS(c,"\\\\",2);break;
            case '\b':PUTS(c,"\\b",2);break;
            case '\f':PUTS(c,"\\f",2);break;
            case '\t':PUTS(c,"\\t",2);break;
            case '\n':PUTS(c,"\\n",2);break;
            case '\r':PUTS(c,"\\r",2);break;
            default:
            if(ch < 0x20) {
                char buffer[7];
                /*%x:以十六进制形式输出无符号整数（不输出前缀0x）*/
                sprintf(buffer,"\\u%04X",ch);
                PUTS(c,buffer,6);
            }
            else
                PUTC(c,s[i]);
        }
    }
    PUTC(c,'"');
}
#else

/*优化点1：在PUTC中每次的调用都会使用lept_context_push函数，而该函数中是if语句的判断中每次都需要计算并且做分支检查就会消耗cpu
* 所以不要将预先分配足够的内存，每次加入字符就不需要做这个检查了；
* \u00xx加上引号一共len*6+2.
* 第一次调用push函数后，再使用*p++就可以了。
*
* 优化点2：自行编写16进位输出。避免使用printf内解析格式的开销。
* 用数组先写出16位，然后根据数据输出。
* 注意这里使用位运算使得计算很快。
* 空间换时间
* */
static void lept_stringify_string(lept_context* c, const char* s, size_t len) {
    static const char hex_digits[] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
    size_t i, size;
    char* head, *p;
    assert(s != NULL);
    p = head = lept_context_push(c, size = len * 6 + 2); /* "\u00xx..." */
    *p++ = '"';
    for (i = 0; i < len; i++) {
        unsigned char ch = (unsigned char)s[i];
        switch (ch) {
            case '\"': *p++ = '\\'; *p++ = '\"'; break;
            case '\\': *p++ = '\\'; *p++ = '\\'; break;
            case '\b': *p++ = '\\'; *p++ = 'b';  break;
            case '\f': *p++ = '\\'; *p++ = 'f';  break;
            case '\n': *p++ = '\\'; *p++ = 'n';  break;
            case '\r': *p++ = '\\'; *p++ = 'r';  break;
            case '\t': *p++ = '\\'; *p++ = 't';  break;
            default:
                if (ch < 0x20) {
                    *p++ = '\\'; *p++ = 'u'; *p++ = '0'; *p++ = '0';
                    *p++ = hex_digits[ch >> 4];
                    *p++ = hex_digits[ch & 15];
                }
                else
                    *p++ = s[i];
        }
    }
    *p++ = '"';
    c->top -= size - (p - head);
}

#endif
static void lept_stringify_value(lept_context *c,const lept_value *v)
{
    size_t i;
    switch(v->type) {
        case LEPT_NULL: PUTS(c,"null",4);break;
        case LEPT_TRUE: PUTS(c,"true",4);break;
        case LEPT_FALSE:PUTS(c,"false",5);break;
        case LEPT_NUMBER:
        {
            char *buffer = lept_context_push(c,32);
            int length = sprintf(buffer,"%.17g",v->u.n);
            c->top -= 32 - length;
        }
        /*压缩成一行：c->top -= 32 - sprintf(lept_context_push(c,32),"%.17g",v->u.n)*/
        break;
        case LEPT_STRING:lept_stringify_string(c,v->u.s.s,v->u.s.len);break;
        case LEPT_ARRAY:
            PUTC(c,'[');
            for(i = 0;i < v->u.a.size;i++) {
                if(i > 0)
                    PUTC(c,',');
                lept_stringify_value(c,&v->u.a.e[i]);
            }
            PUTC(c,']');
            break;
        case LEPT_OBJECT:
            PUTC(c,'{');
            for(i = 0; i < v->u.o.size;i++) {
                if(i > 0)
                    PUTC(c,',');
                lept_stringify_string(c,v->u.o.m[i].k,v->u.o.m[i].klen);
                PUTC(c,':');
                lept_stringify_value(c,&v->u.o.m[i].v);
            }
            PUTC(c,'}');
            break;
        default:break;
    }
}

char* lept_stringify(const lept_value* v,size_t *len)
{
    lept_context c;
    int ret;
    assert(v != NULL);
    c.stack = (char*)malloc(c.size = LEPT_PARSE_STRINGIFY_INIT_SIZE);
    c.top = 0;
    lept_stringify_value(&c,v);
    if(len)
        *len = c.top;
    PUTC(&c,'\0');
    return c.stack;
}


