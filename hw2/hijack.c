#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdarg.h>
#include <openssl/ssl.h>

typedef int (*real_open_type)(const char *pathname, int flags, ...);
typedef FILE* (*real_fopen_type)(const char *path, const char *mode);
typedef int (*real_connect_type)(int, const struct sockaddr* , socklen_t);
typedef int (*real_rename_type)(const char *oldpath, const char *newpath);
typedef int (*real_unlink_type)(const char *pathname);
typedef ssize_t (*real_read_type)(int fd, void *buf, size_t count);
typedef ssize_t (*real_write_type)(int fd, const void *buf, size_t count);
typedef int (*real_SSL_read_type)(SSL *ssl, void *buf, int num);
typedef int (*real_SSL_write_type)(SSL *ssl, const void *buf, int num);
typedef int (*real_SSL_connect_type)(SSL *ssl); 
real_open_type real_open = NULL;
real_fopen_type real_fopen = NULL;
real_connect_type real_connect = NULL;
real_rename_type real_rename = NULL;
real_unlink_type real_unlink = NULL;
real_read_type real_read = NULL;
real_write_type real_write = NULL;
real_SSL_read_type real_SSL_read = NULL;
real_SSL_write_type real_SSL_write = NULL;
real_SSL_connect_type real_SSL_connect = NULL;
FILE* hijack_log;
FILE* ssl_log;
void* handle;
void* tls_handle;
char* error;
char ip[20];


void msg(FILE * stream, const char * format, ...){
    va_list arglist;
    fprintf(stream, "*** ");
    va_start(arglist, format);
    vfprintf(stream, format, arglist);
    va_end(arglist);
    fprintf(stream, " ***\n");
}

void __attribute__ ((constructor (101))) initialize() {
    handle = dlopen("libc.so.6", RTLD_LAZY);
    if(!handle){
    	fputs (dlerror(), stderr);
        exit(1);
    }
    real_open = (real_open_type) dlsym(handle, "open"); 
    if ((error = dlerror()) != NULL)  {
    	fputs(error, stderr);
        exit(1);
    }
    real_fopen = (real_fopen_type) dlsym(handle, "fopen");
    if ((error = dlerror()) != NULL)  {
    	fputs(error, stderr);
        exit(1);
    }
    real_connect = (real_connect_type) dlsym(handle, "connect");
    if ((error = dlerror()) != NULL)  {
    	fputs(error, stderr);
        exit(1);
    }
    real_rename = (real_rename_type) dlsym(handle, "rename");
    if ((error = dlerror()) != NULL)  {
    	fputs(error, stderr);
        exit(1);
    }
    real_unlink = (real_unlink_type) dlsym(handle, "unlink");
    if ((error = dlerror()) != NULL)  {
    	fputs(error, stderr);
        exit(1);
    }
    real_read = (real_read_type) dlsym(handle, "read");
    if ((error = dlerror()) != NULL)  {
    	fputs(error, stderr);
        exit(1);
    }
    real_write = (real_write_type) dlsym(handle, "write");
    if ((error = dlerror()) != NULL)  {
    	fputs(error, stderr);
        exit(1);
    }
    
}
void __attribute__((constructor(102))) tls_initialize() {
    tls_handle = dlopen("libssl.so.1.0.0", RTLD_LAZY);
    if(!tls_handle){
    	fputs (dlerror(), stderr);
        exit(1);
    }

    real_SSL_read = (real_SSL_read_type) dlsym(tls_handle, "SSL_read");
    if ((error = dlerror()) != NULL)  {
    	fputs(error, stderr);
        exit(1);
    }
    real_SSL_write = (real_SSL_write_type) dlsym(tls_handle, "SSL_write");
    if ((error = dlerror()) != NULL)  {
    	fputs(error, stderr);
        exit(1);
    }
    real_SSL_connect = (real_SSL_connect_type) dlsym(tls_handle, "SSL_connect");
    if ((error = dlerror()) != NULL)  {
    	fputs(error, stderr);
        exit(1);
    }
}

void __attribute__((constructor(103))) init_log() {
    hijack_log = stderr;
    hijack_log = real_fopen( "log.txt","w" );
    if(hijack_log == NULL){
        fprintf(stderr, "Cannot open log.txt\n");
        exit(-1);
    }
    ssl_log = stderr;
    ssl_log = real_fopen( "ssl_log.txt","w" );
    if(ssl_log == NULL){
        fprintf(stderr, "Cannot open ssl_log.txt\n");
        exit(-1);
    }
}

void __attribute__((destructor(101))) destroy() {
    dlclose(handle);
}
void __attribute__((destructor(102))) destroy_tls() {
    dlclose(tls_handle);
}
void __attribute__((destructor(103))) destroy_log() {
    fclose(hijack_log);
    fclose(ssl_log);
}

int open(const char *pathname, int flags, ...){
    msg(hijack_log, "open[%s] flags=%d", pathname, flags);
    return real_open(pathname, flags);
}

FILE* fopen(const char *path, const char *mode){
    msg(hijack_log, "fopen[%s] mode=%s", path, mode);
    return real_fopen(path, mode);
}

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen){
    inet_ntop(AF_INET, &(((struct sockaddr_in *)addr)->sin_addr),ip, sizeof(ip));
    msg(hijack_log, "connect[] addr=%s", ip);
    return real_connect(sockfd, addr, addrlen);
}

int rename(const char *oldpath, const char *newpath){
    msg(hijack_log, "rename[] oldpath=%s newpath=%s", oldpath, newpath);
    return real_rename(oldpath, newpath);
}


int unlink(const char *pathname){
    msg(hijack_log, "unlink[%s]", pathname);
    return real_unlink(pathname);
}
ssize_t read(int fd, void *buf, size_t count) {
    ssize_t ret = real_read(fd, buf, count);
    msg(hijack_log, "read[fd=%d] buf='%s' count=%lu", fd, buf,  count);
    return ret;
}
ssize_t write(int fd, const void *buf, size_t count){
    msg(hijack_log, "write[fd=%d] buf='%p' count=%lu", fd, buf, count);
    return real_write(fd, buf, count);
}
int SSL_read(SSL *ssl, void *buf, int num){
    int ret =  real_SSL_read(ssl, buf, num);
    msg(ssl_log, "SSL_read[] buf='%s' num=%lu", buf, num);
    return ret;
}
int SSL_write(SSL *ssl, const void *buf, int num){
    msg(ssl_log, "SSL_write[] buf='%p' count=%lu",  buf, num);
    return real_SSL_write(ssl, buf, num);
}
int SSL_connect(SSL *ssl) {
    msg(ssl_log, "SSL_connect[] ");
    int ret = real_SSL_connect(ssl);
    SSL_SESSION_print_fp(ssl_log, SSL_get_session(ssl));
    return ret;
 }

