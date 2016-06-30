//
//  LPHRsa.m
//  LPHRsaDemo
//
//  Created by Mac on 16/6/7.
//  Copyright © 2016年 Lph. All rights reserved.
//

#import "LPHRsa.h"
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/md5.h>

#define  PADDING   RSA_PADDING_TYPE_PKCS1

typedef enum {
    RSA_PADDING_TYPE_NONE       = RSA_NO_PADDING,
    RSA_PADDING_TYPE_PKCS1      = RSA_PKCS1_PADDING,
    RSA_PADDING_TYPE_SSLV23     = RSA_SSLV23_PADDING
    
} RSA_PADDING_TYPE;

@interface LPHRsa ()

@end

@implementation LPHRsa {
    
    RSA *_rsaPub;
    RSA *_rsaPri;
}

- (NSString *)signString:(NSString *)string {

    if (!_rsaPri) {
        NSLog(@"请输入私钥！");
        return nil;
    }
    const char *message = [string cStringUsingEncoding:NSUTF8StringEncoding];
    int messageLength = (int)strlen(message);
    unsigned char *sig = (unsigned char *)malloc(256);
    unsigned int sig_len;
    
    unsigned char sha1[20];
    SHA1((unsigned char *)message, messageLength, sha1);
    
    int rsa_sign_valid = RSA_sign(NID_sha1
                                  , sha1, 20
                                  , sig, &sig_len
                                  , _rsaPri);
    if (rsa_sign_valid == 1) {
        NSData *data = [NSData dataWithBytes:sig length:sig_len];
        
        NSString *base64String = [data base64EncodedStringWithOptions:0];
        free(sig);
        return base64String;
    }
    
    free(sig);
    return nil;

}

- (NSString *)signMD5String:(NSString *)string {

    if (!_rsaPri) {
        NSLog(@"请输入私钥！");
        return nil;
    }
    const char *message = [string cStringUsingEncoding:NSUTF8StringEncoding];

    unsigned char *sig = (unsigned char *)malloc(256);
    unsigned int sig_len;
    
    unsigned char digest[MD5_DIGEST_LENGTH];
    MD5_CTX ctx;
    MD5_Init(&ctx);
    MD5_Update(&ctx, message, strlen(message));
    MD5_Final(digest, &ctx);
    
    int rsa_sign_valid = RSA_sign(NID_md5
                                  , digest, MD5_DIGEST_LENGTH
                                  , sig, &sig_len
                                  , _rsaPri);
    
    if (rsa_sign_valid == 1) {
        NSData* data = [NSData dataWithBytes:sig length:sig_len];
        
        NSString *base64String = [data base64EncodedStringWithOptions:0];
        free(sig);
        return base64String;
    }
    
    free(sig);
    return nil;
}

- (BOOL)verifyString:(NSString *)string withSign:(NSString *)signString {

    if (!_rsaPub) {
        NSLog(@"请输入公钥！");
        return NO;
    }
    
    const char *message = [string cStringUsingEncoding:NSUTF8StringEncoding];
    int messageLength = (int)[string lengthOfBytesUsingEncoding:NSUTF8StringEncoding];
    NSData *signatureData = [[NSData alloc]initWithBase64EncodedString:signString options:0];
    unsigned char *sig = (unsigned char *)[signatureData bytes];
    unsigned int sig_len = (int)[signatureData length];
    
    
    
    
    unsigned char sha1[20];
    SHA1((unsigned char *)message, messageLength, sha1);
    int verify_ok = RSA_verify(NID_sha1
                               , sha1, 20
                               , sig, sig_len
                               , _rsaPub);
    
    if (1 == verify_ok){
        return   YES;
    }
    return NO;
}

- (BOOL)verifyMD5String:(NSString *)string withSign:(NSString *)signString {

    if (!_rsaPub) {
        NSLog(@"请输入公钥！");
        return NO;
    }
    
    const char *message = [string cStringUsingEncoding:NSUTF8StringEncoding];

    NSData *signatureData = [[NSData alloc]initWithBase64EncodedString:signString options:0];
    unsigned char *sig = (unsigned char *)[signatureData bytes];
    unsigned int sig_len = (int)[signatureData length];
    
    unsigned char digest[MD5_DIGEST_LENGTH];
    MD5_CTX ctx;
    MD5_Init(&ctx);
    MD5_Update(&ctx, message, strlen(message));
    MD5_Final(digest, &ctx);
    int verify_ok = RSA_verify(NID_md5
                               , digest, MD5_DIGEST_LENGTH
                               , sig, sig_len
                               , _rsaPub);
    if (1 == verify_ok){
        return   YES;
    }
    return NO;
}

- (BOOL)importKeyWithType:(keyType)type andPath:(NSString *)path {

    BOOL status = NO;
    const char* cPath = [path cStringUsingEncoding:NSUTF8StringEncoding];
    FILE* file = fopen(cPath, "rb");
    if (!file) {
        return status;
    }
    if (type == keyTypePublic) {
        _rsaPub = NULL;
        if((_rsaPub = PEM_read_RSA_PUBKEY(file, NULL, NULL, NULL))){
            status = YES;
        }
        
        
    }else if(type == keyTypePrivate){
        _rsaPri = NULL;
        if ((_rsaPri = PEM_read_RSAPrivateKey(file, NULL, NULL, NULL))) {
            status = YES;
        }
        
    }
    fclose(file);
    return status;

}

- (BOOL)importKeyWithType:(keyType)type andkeyString:(NSString *)keyString {

    if (!keyString) {
        return NO;
    }
    BOOL status = NO;
    BIO *bio = NULL;
    RSA *rsa = NULL;
    bio = BIO_new(BIO_s_file());
    NSString* temPath = NSTemporaryDirectory();
    NSString* rsaFilePath = [temPath stringByAppendingPathComponent:@"RSAKEY"];
    NSString* formatRSAKeyString = [self formatRSAKeyWithKeyString:keyString andKeytype:type];
    BOOL writeSuccess = [formatRSAKeyString writeToFile:rsaFilePath atomically:YES encoding:NSUTF8StringEncoding error:nil];
    if (!writeSuccess) {
        return NO;
    }
    const char* cPath = [rsaFilePath cStringUsingEncoding:NSUTF8StringEncoding];
    BIO_read_filename(bio, cPath);
    if (type == keyTypePrivate) {
        rsa = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, "");
        _rsaPri = rsa;
        if (rsa != NULL && 1 == RSA_check_key(rsa)) {
            status = YES;
        } else {
            status = NO;
        }
        
        
    }
    else{
        rsa = PEM_read_bio_RSA_PUBKEY(bio, NULL, NULL, NULL);
        _rsaPub = rsa;
        if (rsa != NULL) {
            status = YES;
        } else {
            status = NO;
        }
    }
    
    BIO_free_all(bio);
    [[NSFileManager defaultManager] removeItemAtPath:rsaFilePath error:nil];
    return status;

}

-(NSString*)formatRSAKeyWithKeyString:(NSString*)keyString andKeytype:(keyType)type
{
    NSInteger lineNum = -1;
    NSMutableString *result = [NSMutableString string];
    
    if (type == keyTypePrivate) {
        [result appendString:@"-----BEGIN PRIVATE KEY-----\n"];
        lineNum = 79;
    }else if(type == keyTypePublic){
        [result appendString:@"-----BEGIN PUBLIC KEY-----\n"];
        lineNum = 76;
    }
    
    int count = 0;
    for (int i = 0; i < [keyString length]; ++i) {
        unichar c = [keyString characterAtIndex:i];
        if (c == '\n' || c == '\r') {
            continue;
        }
        [result appendFormat:@"%c", c];
        if (++count == lineNum) {
            [result appendString:@"\n"];
            count = 0;
        }
    }
    if (type == keyTypePrivate) {
        [result appendString:@"\n-----END PRIVATE KEY-----"];
        
    }else if(type == keyTypePublic){
        [result appendString:@"\n-----END PUBLIC KEY-----"];
    }
    return result;
    
}

- (NSString *)encryptWithPublicKey:(NSString *)content {

    if (!_rsaPub) {
        NSLog(@"请输入公钥！");
        return nil;
    }
    int status;
    int length  = (int)[content length];
    unsigned char input[length + 1];
    bzero(input, length + 1);
    int i = 0;
    for (; i < length; i++)
    {
        input[i] = [content characterAtIndex:i];
    }
    
    NSInteger  flen = [self getBlockSizeWithRSA_PADDING_TYPE:PADDING andRSA:_rsaPub];
    
    char *encData = (char*)malloc(flen);
    bzero(encData, flen);
    status = RSA_public_encrypt(length, (unsigned char*)input, (unsigned char*)encData, _rsaPub, PADDING);
    
    if (status){
        NSData *returnData = [NSData dataWithBytes:encData length:status];
        free(encData);
        encData = NULL;
        
        //NSString *ret = [returnData base64EncodedString];
        NSString *ret = [returnData base64EncodedStringWithOptions: NSDataBase64Encoding64CharacterLineLength];
        return ret;
    }
    
    free(encData);
    encData = NULL;
    
    return nil;

}

- (NSString *)decryptWithPrivatecKey:(NSString *)content {

    if (!_rsaPri) {
        NSLog(@"请输入私钥！");
        return nil;
    }    int status;
    
    //NSData *data = [content base64DecodedData];
    NSData *data = [[NSData alloc]initWithBase64EncodedString:content options:NSDataBase64DecodingIgnoreUnknownCharacters];
    int length = (int)[data length];
    
    NSInteger flen = [self getBlockSizeWithRSA_PADDING_TYPE:PADDING andRSA:_rsaPri];
    char *decData = (char*)malloc(flen);
    bzero(decData, flen);
    
    status = RSA_private_decrypt(length, (unsigned char*)[data bytes], (unsigned char*)decData, _rsaPri, PADDING);
    
    if (status)
    {
        NSMutableString *decryptString = [[NSMutableString alloc] initWithBytes:decData length:strlen(decData) encoding:NSASCIIStringEncoding];
        free(decData);
        decData = NULL;
        
        return decryptString;
    }
    
    free(decData);
    decData = NULL;
    
    return nil;
}

- (int)getBlockSizeWithRSA_PADDING_TYPE:(RSA_PADDING_TYPE)padding_type andRSA:(RSA *)rsa
{
    int len = RSA_size(rsa);
    
    if (padding_type == RSA_PADDING_TYPE_PKCS1 || padding_type == RSA_PADDING_TYPE_SSLV23) {
        len -= 11;
    }
    
    return len;
}

@end
