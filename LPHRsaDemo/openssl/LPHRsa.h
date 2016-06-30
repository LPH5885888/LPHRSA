//
//  LPHRsa.h
//  LPHRsaDemo
//
//  Created by Mac on 16/6/7.
//  Copyright © 2016年 Lph. All rights reserved.
//

#import <Foundation/Foundation.h>

typedef enum {
    
    keyTypePublic = 0,
    keyTypePrivate
    
} keyType;

@interface LPHRsa : NSObject

/// 签名
- (NSString *)signString:(NSString *)string;

- (NSString *)signMD5String:(NSString *)string;

/// 验证签名 sha1 + RSA
- (BOOL)verifyString:(NSString *)string withSign:(NSString *)signString;

/// 验证签名 md5 + RSA
- (BOOL)verifyMD5String:(NSString *)string withSign:(NSString *)signString;

/// 导入文件或字符串
- (BOOL)importKeyWithType:(keyType)type andPath:(NSString*)path;
- (BOOL)importKeyWithType:(keyType)type andkeyString:(NSString *)keyString;

/// 加密
- (NSString *)encryptWithPublicKey:(NSString*)content;
- (NSString *)decryptWithPrivatecKey:(NSString*)content;

@end
