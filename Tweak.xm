// NetBlockTweak - 安全版（先关掉所有底层 %hookf，只保留 NSURLProtocol）
// 用途: 注入测试 App,按可配置规则拦截/放行 App 内的 HTTP/HTTPS 流量
// 修复目标: 解决注入后秒闪退问题
//
// 变更说明:
// 1. 暂时注释掉所有 %hookf (connect / sendto / getaddrinfo / CFStream* / CFHost*)
// 2. 只保留 NSURLProtocol + NSURLSessionConfiguration 的 protocolClasses hook
// 3. %ctor 更保守，延迟初始化
// 4. 日志路径支持 rootless，写文件全加保护
// 5. 规则引擎保持热加载

#import <Foundation/Foundation.h>
#import <CFNetwork/CFNetwork.h>
// 以下头文件在关掉底层 hook 后其实不需要，保留不影响
#import <sys/socket.h>
#import <sys/types.h>
#import <netinet/in.h>
#import <arpa/inet.h>
#import <netdb.h>
#import <errno.h>

#pragma mark - 类型定义

typedef NS_ENUM(NSInteger, NBProto) {
    NBProtoTCP = 1,
    NBProtoUDP = 2,
    NBProtoAny = 3
};

@interface NBRule : NSObject
@property (nonatomic, copy) NSString *host;
@property (nonatomic, assign) int port;
@property (nonatomic, assign) NBProto proto;
@property (nonatomic, assign) BOOL block;
@end

@implementation NBRule
@end

#pragma mark - 规则引擎

static NSString *RulesFilePath(void) {
    NSArray<NSString *> *candidates = @[
        @"/var/jb/var/mobile/Library/Preferences/com.yourteam.netblocktweak.rules.json",
        @"/var/mobile/Library/Preferences/com.yourteam.netblocktweak.rules.json",
    ];
    NSFileManager *fm = [NSFileManager defaultManager];
    for (NSString *p in candidates) {
        if ([fm fileExistsAtPath:p]) return p;
    }
    return candidates.lastObject;
}

static NSString *LogFilePath(void) {
    NSArray<NSString *> *candidates = @[
        @"/var/jb/var/mobile/Library/Logs/NetBlockTweak.log",
        @"/var/mobile/Library/Logs/NetBlockTweak.log",
    ];
    NSFileManager *fm = [NSFileManager defaultManager];
    for (NSString *p in candidates) {
        NSString *dir = [p stringByDeletingLastPathComponent];
        if ([fm fileExistsAtPath:dir]) return p;
    }
    return candidates.firstObject;
}

@interface NBRuleEngine : NSObject
+ (instancetype)shared;
- (void)reload;
- (BOOL)shouldBlockHost:(NSString *)host port:(int)port proto:(NBProto)proto;
- (void)logEvent:(NSString *)event;
@end

@implementation NBRuleEngine {
    NSArray<NBRule *> *_rules;
    BOOL _defaultBlock;
    BOOL _logEnabled;
    dispatch_queue_t _queue;
    dispatch_source_t _watchTimer;
}

+ (instancetype)shared {
    static NBRuleEngine *instance;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        instance = [NBRuleEngine new];
        instance->_queue = dispatch_queue_create("com.yourteam.netblocktweak.rules", DISPATCH_QUEUE_SERIAL);
        instance->_rules = @[];
        instance->_logEnabled = YES;
        @try {
            [instance reload];
            [instance startWatchingForChanges];
        } @catch (NSException *e) {
            NSLog(@"[NetBlockTweak] init exception: %@", e);
        }
    });
    return instance;
}

- (void)startWatchingForChanges {
    if (_watchTimer) return;
    _watchTimer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, _queue);
    if (!_watchTimer) return;
    dispatch_source_set_timer(_watchTimer,
                              dispatch_time(DISPATCH_TIME_NOW, 3 * NSEC_PER_SEC),
                              3 * NSEC_PER_SEC,
                              1 * NSEC_PER_SEC);
    __weak typeof(self) weakSelf = self;
    dispatch_source_set_event_handler(_watchTimer, ^{
        __strong typeof(weakSelf) strongSelf = weakSelf;
        if (strongSelf) [strongSelf reload];
    });
    dispatch_resume(_watchTimer);
}

- (void)reload {
    dispatch_sync(_queue, ^{
        @try {
            NSData *data = [NSData dataWithContentsOfFile:RulesFilePath()];
            NSMutableArray<NBRule *> *arr = [NSMutableArray array];
            BOOL defaultBlock = NO;
            BOOL logEnabled = YES;
            if (data) {
                NSError *err = nil;
                id json = [NSJSONSerialization JSONObjectWithData:data options:0 error:&err];
                if ([json isKindOfClass:[NSDictionary class]]) {
                    NSDictionary *dict = (NSDictionary *)json;
                    if (dict[@"log"]) logEnabled = [dict[@"log"] boolValue];
                    NSString *defAction = [[dict[@"default_action"] description] lowercaseString];
                    defaultBlock = [defAction isEqualToString:@"block"];
                    id rulesObj = dict[@"rules"];
                    if ([rulesObj isKindOfClass:[NSArray class]]) {
                        for (id item in (NSArray *)rulesObj) {
                            if (![item isKindOfClass:[NSDictionary class]]) continue;
                            NSDictionary *d = (NSDictionary *)item;
                            NBRule *r = [NBRule new];
                            r.host = d[@"host"] ?: @"*";
                            r.port = [d[@"port"] intValue];
                            NSString *p = [[d[@"proto"] description] lowercaseString];
                            if ([p isEqualToString:@"tcp"]) r.proto = NBProtoTCP;
                            else if ([p isEqualToString:@"udp"]) r.proto = NBProtoUDP;
                            else r.proto = NBProtoAny;
                            NSString *action = [[d[@"action"] description] lowercaseString];
                            r.block = action.length ? [action isEqualToString:@"block"] : YES;
                            [arr addObject:r];
                        }
                    }
                }
            }
            self->_rules = [arr copy];
            self->_defaultBlock = defaultBlock;
            self->_logEnabled = logEnabled;
        } @catch (NSException *e) {
            NSLog(@"[NetBlockTweak] reload exception: %@", e);
        }
    });
}

static BOOL HostMatchesPattern(NSString *host, NSString *pattern) {
    if (!host || !pattern) return NO;
    if ([pattern isEqualToString:@"*"]) return YES;
    if ([pattern hasPrefix:@"*."]) {
        NSString *suffix = [pattern substringFromIndex:1];
        if ([host hasSuffix:suffix]) return YES;
        NSString *exact = [pattern substringFromIndex:2];
        return [host caseInsensitiveCompare:exact] == NSOrderedSame;
    }
    return [host caseInsensitiveCompare:pattern] == NSOrderedSame;
}

- (BOOL)shouldBlockHost:(NSString *)host port:(int)port proto:(NBProto)proto {
    __block BOOL result = _defaultBlock;
    if (!host) host = @"";
    dispatch_sync(_queue, ^{
        for (NBRule *r in self->_rules) {
            BOOL hostMatch = HostMatchesPattern(host, r.host);
            BOOL portMatch = (r.port == 0) || (r.port == port);
            BOOL protoMatch = (r.proto == NBProtoAny) || (r.proto == proto);
            if (hostMatch && portMatch && protoMatch) {
                result = r.block;
                return;
            }
        }
    });
    return result;
}

- (void)logEvent:(NSString *)event {
    if (!_logEnabled || !event.length) return;
    NSString *line = [NSString stringWithFormat:@"[%@] %@\n", [NSDate date], event];
    NSLog(@"[NetBlockTweak] %@", event);
    dispatch_async(_queue, ^{
        @try {
            NSFileManager *fm = [NSFileManager defaultManager];
            NSString *path = LogFilePath();
            NSString *dir = [path stringByDeletingLastPathComponent];
            if (![fm fileExistsAtPath:dir]) {
                [fm createDirectoryAtPath:dir withIntermediateDirectories:YES attributes:nil error:nil];
            }
            if (![fm fileExistsAtPath:path]) {
                [fm createFileAtPath:path contents:nil attributes:nil];
            }
            NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:path];
            if (!fh) return;
            [fh seekToEndOfFile];
            NSData *data = [line dataUsingEncoding:NSUTF8StringEncoding];
            if (data) [fh writeData:data];
            [fh closeFile];
        } @catch (NSException *e) {
            NSLog(@"[NetBlockTweak] logEvent failed: %@", e);
        }
    });
}

@end

#pragma mark - 高层: NSURLProtocol 拦截 HTTP/HTTPS（目前唯一启用的拦截层）

static NSString *const kNBHandledKey = @"com.yourteam.netblocktweak.handled";

@interface NBURLProtocol : NSURLProtocol <NSURLSessionDataDelegate>
@property (nonatomic, strong) NSURLSession *session;
@property (nonatomic, strong) NSURLSessionDataTask *task;
@end

@implementation NBURLProtocol

+ (BOOL)canInitWithRequest:(NSURLRequest *)request {
    if ([NSURLProtocol propertyForKey:kNBHandledKey inRequest:request]) return NO;
    NSString *scheme = request.URL.scheme.lowercaseString;
    if (![scheme isEqualToString:@"http"] && ![scheme isEqualToString:@"https"]) return NO;
    return YES;
}

+ (NSURLRequest *)canonicalRequestForRequest:(NSURLRequest *)request {
    return request;
}

- (void)startLoading {
    NSURL *url = self.request.URL;
    NSString *host = url.host ?: @"";
    BOOL isHTTPS = [url.scheme.lowercaseString isEqualToString:@"https"];
    int port = url.port ? url.port.intValue : (isHTTPS ? 443 : 80);

    BOOL blocked = [[NBRuleEngine shared] shouldBlockHost:host port:port proto:NBProtoTCP];
    [[NBRuleEngine shared] logEvent:
        [NSString stringWithFormat:@"[HTTP%@] %@ %@ (port %d) -> %@",
            isHTTPS ? @"S" : @"", self.request.HTTPMethod ?: @"?", host, port,
            blocked ? @"BLOCKED" : @"ALLOWED"]];

    if (blocked) {
        NSError *error = [NSError errorWithDomain:@"com.yourteam.netblocktweak"
                                              code:-1009
                                          userInfo:@{NSLocalizedDescriptionKey: @"Blocked by NetBlockTweak test rule"}];
        [self.client URLProtocol:self didFailWithError:error];
        return;
    }

    NSMutableURLRequest *forwardedRequest = [self.request mutableCopy];
    [NSURLProtocol setProperty:@YES forKey:kNBHandledKey inRequest:forwardedRequest];

    NSURLSessionConfiguration *config = [NSURLSessionConfiguration ephemeralSessionConfiguration];
    self.session = [NSURLSession sessionWithConfiguration:config delegate:self delegateQueue:nil];
    self.task = [self.session dataTaskWithRequest:forwardedRequest];
    [self.task resume];
}

- (void)stopLoading {
    [self.task cancel];
    [self.session invalidateAndCancel];
}

- (void)URLSession:(NSURLSession *)session dataTask:(NSURLSessionDataTask *)task
    didReceiveResponse:(NSURLResponse *)response
     completionHandler:(void (^)(NSURLSessionResponseDisposition disposition))completionHandler {
    [self.client URLProtocol:self didReceiveResponse:response cacheStoragePolicy:NSURLCacheStorageNotAllowed];
    completionHandler(NSURLSessionResponseAllow);
}

- (void)URLSession:(NSURLSession *)session dataTask:(NSURLSessionDataTask *)task didReceiveData:(NSData *)data {
    [self.client URLProtocol:self didLoadData:data];
}

- (void)URLSession:(NSURLSession *)session task:(NSURLSessionTask *)task didCompleteWithError:(NSError *)error {
    if (error) {
        [self.client URLProtocol:self didFailWithError:error];
    } else {
        [self.client URLProtocolDidFinishLoading:self];
    }
}

- (void)URLSession:(NSURLSession *)session
              task:(NSURLSessionTask *)task
willPerformHTTPRedirection:(NSHTTPURLResponse *)response
        newRequest:(NSURLRequest *)request
 completionHandler:(void (^)(NSURLRequest *))completionHandler {
    completionHandler(request);
}

@end

%hook NSURLSessionConfiguration

- (NSArray *)protocolClasses {
    NSArray *orig = %orig;
    Class cls = [NBURLProtocol class];
    if (!orig) return @[cls];
    if ([orig containsObject:cls]) return orig;
    NSMutableArray *arr = [orig mutableCopy];
    [arr insertObject:cls atIndex:0];
    return arr;
}

%end

#pragma mark - 初始化（安全版）

%ctor {
    @autoreleasepool {
        %init;   // 只初始化上面的 NSURLSessionConfiguration hook

        // 延迟到主队列，尽量避开启动最早期
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            @try {
                [NBRuleEngine shared];
                [NSURLProtocol registerClass:[NBURLProtocol class]];
                [[NBRuleEngine shared] logEvent:@"NetBlockTweak (safe mode) loaded - only NSURLProtocol active"];
            } @catch (NSException *e) {
                NSLog(@"[NetBlockTweak] delayed init exception: %@", e);
            }
        });
    }
}

/*
 ============================================================
 以下是原来的底层 hook，全部暂时注释掉。
 等「安全版」能正常打开 App 后，再逐步取消注释测试。
 ============================================================

#pragma mark - 低层 socket（暂时禁用）

%hookf(int, connect, int socketFD, const struct sockaddr *address, socklen_t address_len) {
    // ... 原逻辑
    return %orig;
}

%hookf(ssize_t, sendto, int socketFD, const void *buffer, size_t length, int flags, const struct sockaddr *dest_addr, socklen_t dest_len) {
    // ...
    return %orig;
}

%hookf(int, getaddrinfo, const char *hostname, const char *servname, const struct addrinfo *hints, struct addrinfo **res) {
    // ...
    return %orig;
}

#pragma mark - CFNetwork（暂时禁用）

%hookf(void, CFStreamCreatePairWithSocketToHost, CFAllocatorRef alloc, CFStringRef host, UInt32 port, CFReadStreamRef *readStream, CFWriteStreamRef *writeStream) {
    // ...
    %orig;
}

%hookf(void, CFStreamCreatePairWithSocketToCFHost, CFAllocatorRef alloc, CFHostRef host, UInt32 port, CFReadStreamRef *readStream, CFWriteStreamRef *writeStream) {
    // ...
    %orig;
}

%hookf(Boolean, CFHostStartInfoResolution, CFHostRef theHost, CFHostInfoType info, CFStreamError *error) {
    // ...
    return %orig;
}
*/
