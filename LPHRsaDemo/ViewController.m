//
//  ViewController.m
//  LPHRsaDemo
//
//  Created by Mac on 16/6/7.
//  Copyright © 2016年 Lph. All rights reserved.
//

#import "ViewController.h"
#import "LPHRsa.h"

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    
    NSString *privateKey = @"这里填写私钥！";
    
    NSString *publicKey = @"这里填写公钥!";
    
//    NSString *privatePath = [[NSBundle mainBundle] pathForResource:@"rsaPrivateKey.pem" ofType:nil];
//    NSString *publicPath = [[NSBundle mainBundle] pathForResource:@"rsaPublicKey.pem" ofType:nil];
    
    LPHRsa *rsaHandler = [[LPHRsa alloc] init];

//    //获取文件方式
//    [rsaHandler importKeyWithType:keyTypePrivate andPath:privatePath];
//    [rsaHandler importKeyWithType:keyTypePublic andPath:publicPath];

    //字符串方式
    [rsaHandler importKeyWithType:keyTypePrivate andkeyString:privateKey];
    [rsaHandler importKeyWithType:keyTypePublic andkeyString:publicKey];
    
    //签名
    NSString *sign = [rsaHandler signString:@"lph"];
    NSString *signMd5 = [rsaHandler signMD5String:@"lph"];
    
    NSLog(@"sign签名后== %@ \n\n signMd5签名后== %@", sign, signMd5);
    
    //验签
    BOOL isSign = [rsaHandler verifyString:@"lph" withSign:sign];
    BOOL isSignMd5 = [rsaHandler verifyMD5String:@"lph" withSign:signMd5];
    
    if (isSign) {
        NSLog(@"isSign 验签正确");
    } else {
        NSLog(@"isSign 验签失败");
    }
    
    if (isSignMd5) {
        NSLog(@"isSignMd5 验签正确");
    } else {
        NSLog(@"isSignMd5 验签失败");
    }
    
    //加密
    NSString *encStr = [rsaHandler encryptWithPublicKey:@"lph"];
    NSString *decStr = [rsaHandler decryptWithPrivatecKey:@"lph"];
    
    NSLog(@"encStr= %@ \n decStr= %@", encStr, decStr);
}


@end
