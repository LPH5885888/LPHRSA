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
    
    NSString *privateKey = @"MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBALgv/syFH337KzC29KvR0p6cP+glRqjDYAQno5ifafXZjgf1EhBjZblKv+HiLAzNBOlYU1PnLuOOkZj6pg1A5HUZLpsbYa5Mwr1bUHALjXLaB3THCpZX51/b5L14erGo52Jv/j/63YljEtMm8ALmkY8S+3fPxFeY7ya+2VXMEtplAgMBAAECgYAguvauZWGpQ37zUy+7cLfa061PlYAu8TkYw+qAbqOnupdQtq4VF3S2LqBWhZiKVcxvovB70nM0oNsisjfb1xJBpyfDBFug7d+y2f8yr6aTOezoY5DBYEF3Svg9Kp9ra+vvAYX/7fh+tHCU0HOvp0z8ikZiRSWZaQ+3A2GiCIJrwQJBAPKVji89hGAMEWLJJFZaPiLBqZUwR2W/rp7Ely5ddKfjcosHhggHfOb71BnrMOm0h4S85Gx6a87n9R2To0c51q0CQQDCX6yYdt/9JGORyNSXfzMfSZyVOrMpIo77R0YwKa3UOwwLA56l2Lc4AYO10/lyAyZCKse2/5D9ZZUB7xoYEmGZAkB8MEJVPuoY/bSc3RqENrjetERsAwZaObJcx4oaC3AgTxmhwV1FmQfBfKTODBDDZE+Ijedm/ZlZmHhtBtstKJgVAkBKma/DgHRtUscIT90QHBjB3F3FhJb4pbPcyzksCQMXXmY73/LG0ktXqnUjlyy4zm6jnIm0OZgrOQ6chGkubfeZAkBMCGF2tPfEJh8XODOvlw5ADnUiq+Qe/abcpKowkiT9zP+rYT9XJAx7QxChjdwTZb6ahnJY1+ny1emEHUOs2fm8";
    
    NSString *publicKey = @"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC4L/7MhR99+yswtvSr0dKenD/oJUaow2AEJ6OYn2n12Y4H9RIQY2W5Sr/h4iwMzQTpWFNT5y7jjpGY+qYNQOR1GS6bG2GuTMK9W1BwC41y2gd0xwqWV+df2+S9eHqxqOdib/4/+t2JYxLTJvAC5pGPEvt3z8RXmO8mvtlVzBLaZQIDAQAB";
    
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
