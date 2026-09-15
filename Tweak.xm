// NetBlockTweak
// 用途: 注入测试 App,按可配置规则拦截/放行 App 内的 HTTP/HTTPS/TCP/UDP 流量
// 仅供在你拥有权限的测试设备、测试 App 上做网络异常/弱网/防护逻辑测试使用
//
// 修复说明 (2026-09-14):
// 1. LogFilePath 支持 rootless / rootful 双路径，避免权限问题导致异常
// 2. 热加载 timer 用成员变量强引用，防止 ARC 释放后定时器失效
// 3. logEvent 对 fileHandle 做空判断，防止写日志崩溃
// 4. %ctor 更稳健：先 %init，再延迟初始化规则引擎，减少启动瞬间崩溃概率
// 5. 增加更多空指针与异常保护

#import <Foundation/Foundation.h>
#import <CFNetwork/CFNetwork.h>
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
@property (nonatomic, copy) NSString *host;   // 精确域名 / "*.example.com" 通配 / IP / "*" 全部
@property (nonatomic, assign) int port;       // 0 = 任意端口
@property (nonatomic, assign) NBProto proto;
@property (nonatomic, assign) BOOL block;     // YES = 拦截, NO = 放行
@end

@implementation NBRule
@end

#pragma mark - 规则引擎

static NSString *RulesFilePath(void) {
    NSArray<NSString *> *candidates = @[
        // rootless 越狱路径优先
        @"/var/jb/var/mobile/Library/Preferences/com.yourteam.netblocktweak.rules.json",
        // rootful 越狱路径
        @"/var/mobile/Library/Preferences/com.yourteam.netblocktweak.rules.json",
    ];
    NSFileManager *fm = [NSFileManager defaultManager];
    for (NSString *p in candidates) {
        if ([fm fileExistsAtPath:p]) return p;
    }
    return candidates.lastObject;
}

static NSString *LogFilePath(void) {
    // 与规则文件保持一致，优先 rootless
    NSArray<NSString *> *candidates = @[
        @"/var/jb/var/mobile/Library/Logs/NetBlockTweak.log",
        @"/var/mobile/Library/Logs/NetBlockTweak.log",
    ];
    NSFileManager *fm = [NSFileManager defaultManager];
    // 优先返回已存在的目录所在路径；若不存在则返回第一个（后续 create 时再处理）
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
- (void)noteResolvedIP:(NSString *)ip forHost:(NSString *)host;
- (NSString *)hostForIP:(NSString *)ip;
- (void)logEvent:(NSString *)event;
@end

@implementation NBRuleEngine {
    NSArray<NBRule *> *_rules;
    BOOL _defaultBlock;
    BOOL _logEnabled;
    NSMutableDictionary<NSString *, NSString *> *_ipToHost;
    dispatch_queue_t _queue;
    dispatch_source_t _watchTimer;   // 强引用，防止被 ARC 释放
}

+ (instancetype)shared {
    static NBRuleEngine *instance;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        instance = [NBRuleEngine new];
        instance->_queue = dispatch_queue_create("com.yourteam.netblocktweak.rules", DISPATCH_QUEUE_SERIAL);
        instance->_ipToHost = [NSMutableDictionary dictionary];
        instance->_rules = @[];
        instance->_logEnabled = YES; // 默认开日志，reload 后会覆盖
        // 延迟到第一次真正需要时再 reload + 启动 timer，减少 %ctor 瞬间崩溃概率
        // 这里仍立即初始化，但全部包在 try 逻辑里
        @try {
            [instance reload];
            [instance startWatchingForChanges];
        } @catch (NSException *e) {
            NSLog(@"[NetBlockTweak] NBRuleEngine init exception: %@", e);
        }
    });
    return instance;
}

- (void)startWatchingForChanges {
    if (_watchTimer) return; // 已启动

    _watchTimer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, _queue);
    if (!_watchTimer) return;

    dispatch_source_set_timer(_watchTimer,
                              dispatch_time(DISPATCH_TIME_NOW, 3 * NSEC_PER_SEC),
                              3 * NSEC_PER_SEC,
                              1 * NSEC_PER_SEC);
    __weak typeof(self) weakSelf = self;
    dispatch_source_set_event_handler(_watchTimer, ^{
        __strong typeof(weakSelf) strongSelf = weakSelf;
        if (strongSelf) {
            [strongSelf reload];
        }
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
                    if (dict[@"log"]) {
                        logEnabled = [dict[@"log"] boolValue];
                    }
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
        // "*.example.com" → 匹配 "sub.example.com" 或 "example.com"
        NSString *suffix = [pattern substringFromIndex:1]; // ".example.com"
        if ([host hasSuffix:suffix]) return YES;
        NSString *exact = [pattern substringFromIndex:2]; // "example.com"
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

- (void)noteResolvedIP:(NSString *)ip forHost:(NSString *)host {
    if (!ip.length || !host.length) return;
    dispatch_async(_queue, ^{
        self->_ipToHost[ip] = host;
    });
}

- (NSString *)hostForIP:(NSString *)ip {
    if (!ip.length) return nil;
    __block NSString *h = nil;
    dispatch_sync(_queue, ^{
        h = self->_ipToHost[ip];
    });
    return h;
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
            if (!fh) return; // 无写权限时静默失败，避免崩溃
            [fh seekToEndOfFile];
            NSData *data = [line dataUsingEncoding:NSUTF8StringEncoding];
            if (data) {
                [fh writeData:data];
            }
            [fh closeFile];
        } @catch (NSException *e) {
            // 写日志失败绝不让进程崩
            NSLog(@"[NetBlockTweak] logEvent failed: %@", e);
        }
    });
}

@end

#pragma mark - sockaddr 辅助函数

static NSString *IPStringFromSockaddr(const struct sockaddr *addr) {
    if (!addr) return nil;
    char buf[INET6_ADDRSTRLEN] = {0};
    if (addr->sa_family == AF_INET) {
        struct sockaddr_in *in4 = (struct sockaddr_in *)addr;
        if (!inet_ntop(AF_INET, &in4->sin_addr, buf, sizeof(buf))) return nil;
    } else if (addr->sa_family == AF_INET6) {
        struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)addr;
        if (!inet_ntop(AF_INET6, &in6->sin6_addr, buf, sizeof(buf))) return nil;
    } else {
        return nil;
    }
    return [NSString stringWithUTF8String:buf];
}

static int PortFromSockaddr(const struct sockaddr *addr) {
    if (!addr) return 0;
    if (addr->sa_family == AF_INET) {
        return ntohs(((struct sockaddr_in *)addr)->sin_port);
    } else if (addr->sa_family == AF_INET6) {
        return ntohs(((struct sockaddr_in6 *)addr)->sin6_port);
    }
    return 0;
}

static BOOL ShouldBlockSockaddr(const struct sockaddr *addr, NBProto proto) {
    NSString *ip = IPStringFromSockaddr(addr);
    if (!ip) return NO; // 非 IPv4/IPv6 (如 unix domain socket) 不处理
    int port = PortFromSockaddr(addr);
    NSString *host = [[NBRuleEngine shared] hostForIP:ip] ?: ip;
    BOOL blocked = [[NBRuleEngine shared] shouldBlockHost:host port:port proto:proto];
    if (blocked) {
        [[NBRuleEngine shared] logEvent:
            [NSString stringWithFormat:@"[SOCKET-BLOCKED] proto=%@ host=%@ ip=%@ port=%d",
                proto == NBProtoUDP ? @"UDP" : @"TCP", host, ip, port]];
    }
    return blocked;
}

#pragma mark - 低层: hook BSD socket API (覆盖 TCP / UDP,含未走 NSURLSession 的自定义协议栈)

%hookf(int, connect, int socketFD, const struct sockaddr *address, socklen_t address_len) {
    if (address) {
        int type = 0;
        socklen_t len = sizeof(type);
        if (getsockopt(socketFD, SOL_SOCKET, SO_TYPE, &type, &len) == 0) {
            NBProto proto = (type == SOCK_DGRAM) ? NBProtoUDP : NBProtoTCP;
            if (ShouldBlockSockaddr(address, proto)) {
                errno = ECONNREFUSED;
                return -1;
            }
        }
    }
    return %orig;
}

%hookf(ssize_t, sendto, int socketFD, const void *buffer, size_t length, int flags, const struct sockaddr *dest_addr, socklen_t dest_len) {
    if (dest_addr && ShouldBlockSockaddr(dest_addr, NBProtoUDP)) {
        errno = ECONNREFUSED;
        return -1;
    }
    return %orig;
}

%hookf(int, getaddrinfo, const char *hostname, const char *servname, const struct addrinfo *hints, struct addrinfo **res) {
    int ret = %orig;
    if (ret == 0 && hostname && res && *res) {
        NSString *host = [NSString stringWithUTF8String:hostname];
        if (host.length) {
            for (struct addrinfo *p = *res; p != NULL; p = p->ai_next) {
                NSString *ip = IPStringFromSockaddr(p->ai_addr);
                if (ip.length) {
                    [[NBRuleEngine shared] noteResolvedIP:ip forHost:host];
                }
            }
        }
    }
    return ret;
}

#pragma mark - CFNetwork 层: 覆盖直接使用 CFStream/CFSocket/CFHost 的代码路径

%hookf(void, CFStreamCreatePairWithSocketToHost, CFAllocatorRef alloc, CFStringRef host, UInt32 port, CFReadStreamRef *readStream, CFWriteStreamRef *writeStream) {
    NSString *hostStr = host ? (__bridge NSString *)host : @"";
    BOOL blocked = [[NBRuleEngine shared] shouldBlockHost:hostStr port:(int)port proto:NBProtoTCP];
    [[NBRuleEngine shared] logEvent:
        [NSString stringWithFormat:@"[CFNETWORK%@] CFStreamCreatePairWithSocketToHost host=%@ port=%u",
            blocked ? @"-BLOCKED" : @"", hostStr, (unsigned)port]];
    if (blocked) {
        if (readStream) *readStream = NULL;
        if (writeStream) *writeStream = NULL;
        return;
    }
    %orig;
}

%hookf(void, CFStreamCreatePairWithSocketToCFHost, CFAllocatorRef alloc, CFHostRef host, UInt32 port, CFReadStreamRef *readStream, CFWriteStreamRef *writeStream) {
    NSString *hostStr = nil;
    if (host) {
        Boolean resolved = false;
        CFArrayRef names = CFHostGetNames(host, &resolved);
        if (names && CFArrayGetCount(names) > 0) {
            hostStr = (__bridge NSString *)CFArrayGetValueAtIndex(names, 0);
        }
    }
    BOOL blocked = [[NBRuleEngine shared] shouldBlockHost:(hostStr ?: @"") port:(int)port proto:NBProtoTCP];
    [[NBRuleEngine shared] logEvent:
        [NSString stringWithFormat:@"[CFNETWORK%@] CFStreamCreatePairWithSocketToCFHost host=%@ port=%u",
            blocked ? @"-BLOCKED" : @"", hostStr ?: @"?", (unsigned)port]];
    if (blocked) {
        if (readStream) *readStream = NULL;
        if (writeStream) *writeStream = NULL;
        return;
    }
    %orig;
}

%hookf(Boolean, CFHostStartInfoResolution, CFHostRef theHost, CFHostInfoType info, CFStreamError *error) {
    Boolean ret = %orig;
    if (ret && info == kCFHostAddresses && theHost) {
        Boolean resolved = false;
        CFArrayRef names = CFHostGetNames(theHost, &resolved);
        NSString *hostStr = (names && CFArrayGetCount(names) > 0) ? (__bridge NSString *)CFArrayGetValueAtIndex(names, 0) : nil;
        Boolean addrResolved = false;
        CFArrayRef addrs = CFHostGetAddressing(theHost, &addrResolved);
        if (hostStr.length && addrs) {
            CFIndex count = CFArrayGetCount(addrs);
            for (CFIndex i = 0; i < count; i++) {
                CFDataRef addrData = (CFDataRef)CFArrayGetValueAtIndex(addrs, i);
                if (!addrData) continue;
                const struct sockaddr *sa = (const struct sockaddr *)CFDataGetBytePtr(addrData);
                NSString *ip = IPStringFromSockaddr(sa);
                if (ip.length) {
                    [[NBRuleEngine shared] noteResolvedIP:ip forHost:hostStr];
                }
            }
        }
    }
    return ret;
}

#pragma mark - 高层: NSURLProtocol 拦截 HTTP/HTTPS

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
            isHTTPS ? @"S" : @"", self.request.HTTPMethod ?: @"?", host, port, blocked ? @"BLOCKED" : @"ALLOWED"]];

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

// 部分 App 会给 NSURLSessionConfiguration 显式设置 protocolClasses,
// 此时全局 registerClass: 不生效,这里额外 hook 一下把自定义 Protocol 插进去
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

#pragma mark - 初始化

%ctor {
    @autoreleasepool {
        %init;  // 先完成所有 hook 注册

        // 延迟一点初始化规则引擎，避免在 dyld 加载最早期就做文件 IO / GCD
        // 用 dispatch_async 到主队列，确保进程基本就绪后再跑
        dispatch_async(dispatch_get_main_queue(), ^{
            @try {
                [NBRuleEngine shared];
                [NSURLProtocol registerClass:[NBURLProtocol class]];
                [[NBRuleEngine shared] logEvent:@"NetBlockTweak loaded"];
            } @catch (NSException *e) {
                NSLog(@"[NetBlockTweak] ctor delayed init exception: %@", e);
            }
        });
    }
}
