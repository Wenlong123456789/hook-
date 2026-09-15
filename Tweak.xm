// NetBlockTweak
// 用途: 注入测试 App,按可配置规则拦截/放行 App 内的 HTTP/HTTPS/TCP/UDP 流量
// 仅供在你拥有权限的测试设备、测试 App 上做网络异常/弱网/防护逻辑测试使用

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
    return @"/var/mobile/Library/Logs/NetBlockTweak.log";
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
}

+ (instancetype)shared {
    static NBRuleEngine *instance;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        instance = [NBRuleEngine new];
        instance->_queue = dispatch_queue_create("com.yourteam.netblocktweak.rules", DISPATCH_QUEUE_SERIAL);
        instance->_ipToHost = [NSMutableDictionary dictionary];
        instance->_rules = @[];
        [instance reload];
        [instance startWatchingForChanges];
    });
    return instance;
}

- (void)startWatchingForChanges {
    // 简单轮询热加载规则文件,便于测试时不重启 App 就能改规则
    dispatch_source_t timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, _queue);
    dispatch_source_set_timer(timer, dispatch_time(DISPATCH_TIME_NOW, 3 * NSEC_PER_SEC), 3 * NSEC_PER_SEC, 1 * NSEC_PER_SEC);
    dispatch_source_set_event_handler(timer, ^{
        [self reload];
    });
    dispatch_resume(timer);
}

- (void)reload {
    dispatch_sync(_queue, ^{
        NSData *data = [NSData dataWithContentsOfFile:RulesFilePath()];
        NSMutableArray<NBRule *> *arr = [NSMutableArray array];
        BOOL defaultBlock = NO;
        BOOL logEnabled = YES;
        if (data) {
            NSError *err = nil;
            id json = [NSJSONSerialization JSONObjectWithData:data options:0 error:&err];
            if ([json isKindOfClass:[NSDictionary class]]) {
                NSDictionary *dict = (NSDictionary *)json;
                logEnabled = dict[@"log"] ? [dict[@"log"] boolValue] : YES;
                NSString *defAction = [dict[@"default_action"] lowercaseString];
                defaultBlock = [defAction isEqualToString:@"block"];
                for (NSDictionary *d in dict[@"rules"]) {
                    if (![d isKindOfClass:[NSDictionary class]]) continue;
                    NBRule *r = [NBRule new];
                    r.host = d[@"host"] ?: @"*";
                    r.port = [d[@"port"] intValue];
                    NSString *p = [d[@"proto"] lowercaseString];
                    if ([p isEqualToString:@"tcp"]) r.proto = NBProtoTCP;
                    else if ([p isEqualToString:@"udp"]) r.proto = NBProtoUDP;
                    else r.proto = NBProtoAny;
                    NSString *action = [d[@"action"] lowercaseString];
                    r.block = action ? [action isEqualToString:@"block"] : YES;
                    [arr addObject:r];
                }
            }
        }
        self->_rules = arr;
        self->_defaultBlock = defaultBlock;
        self->_logEnabled = logEnabled;
    });
}

static BOOL HostMatchesPattern(NSString *host, NSString *pattern) {
    if (!host || !pattern) return NO;
    if ([pattern isEqualToString:@"*"]) return YES;
    if ([pattern hasPrefix:@"*."]) {
        NSString *suffix = [pattern substringFromIndex:1]; // 保留开头的 "."
        return [host hasSuffix:suffix] || [host isEqualToString:[pattern substringFromIndex:2]];
    }
    return [host caseInsensitiveCompare:pattern] == NSOrderedSame;
}

- (BOOL)shouldBlockHost:(NSString *)host port:(int)port proto:(NBProto)proto {
    __block BOOL result = _defaultBlock;
    if (!host) host = @"";
    dispatch_sync(_queue, ^{
        // 规则按数组顺序匹配,命中第一条即返回,方便"先精确后通配"这类优先级配置
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
    if (!ip || !host) return;
    dispatch_async(_queue, ^{
        self->_ipToHost[ip] = host;
    });
}

- (NSString *)hostForIP:(NSString *)ip {
    __block NSString *h = nil;
    if (!ip) return nil;
    dispatch_sync(_queue, ^{
        h = self->_ipToHost[ip];
    });
    return h;
}

- (void)logEvent:(NSString *)event {
    if (!_logEnabled) return;
    NSString *line = [NSString stringWithFormat:@"[%@] %@\n", [NSDate date], event];
    NSLog(@"[NetBlockTweak] %@", event);
    dispatch_async(_queue, ^{
        NSFileManager *fm = [NSFileManager defaultManager];
        NSString *path = LogFilePath();
        if (![fm fileExistsAtPath:path]) {
            [fm createFileAtPath:path contents:nil attributes:nil];
        }
        NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:path];
        [fh seekToEndOfFile];
        [fh writeData:[line dataUsingEncoding:NSUTF8StringEncoding]];
        [fh closeFile];
    });
}

@end

#pragma mark - sockaddr 辅助函数

static NSString *IPStringFromSockaddr(const struct sockaddr *addr) {
    if (!addr) return nil;
    char buf[INET6_ADDRSTRLEN] = {0};
    if (addr->sa_family == AF_INET) {
        struct sockaddr_in *in4 = (struct sockaddr_in *)addr;
        inet_ntop(AF_INET, &in4->sin_addr, buf, sizeof(buf));
    } else if (addr->sa_family == AF_INET6) {
        struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)addr;
        inet_ntop(AF_INET6, &in6->sin6_addr, buf, sizeof(buf));
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
    if (!ip) return NO; // 非 IPv4/IPv6(如 unix domain socket)不处理
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
        getsockopt(socketFD, SOL_SOCKET, SO_TYPE, &type, &len);
        NBProto proto = (type == SOCK_DGRAM) ? NBProtoUDP : NBProtoTCP;
        if (ShouldBlockSockaddr(address, proto)) {
            errno = ECONNREFUSED;
            return -1;
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
        for (struct addrinfo *p = *res; p != NULL; p = p->ai_next) {
            NSString *ip = IPStringFromSockaddr(p->ai_addr);
            if (ip) {
                [[NBRuleEngine shared] noteResolvedIP:ip forHost:host];
            }
        }
    }
    return ret;
}

#pragma mark - CFNetwork 层: 覆盖直接使用 CFStream/CFSocket/CFHost 的代码路径(域名信息在此处最完整,不必依赖 IP 反查)

// 老式/部分三方库会直接用域名建流,例如:
// CFStreamCreatePairWithSocketToHost(kCFAllocatorDefault, (CFStringRef)host, port, &readStream, &writeStream);
%hookf(void, CFStreamCreatePairWithSocketToHost, CFAllocatorRef alloc, CFStringRef host, UInt32 port, CFReadStreamRef *readStream, CFWriteStreamRef *writeStream) {
    NSString *hostStr = (__bridge NSString *)host;
    BOOL blocked = [[NBRuleEngine shared] shouldBlockHost:hostStr port:(int)port proto:NBProtoTCP];
    [[NBRuleEngine shared] logEvent:
        [NSString stringWithFormat:@"[CFNETWORK%@] CFStreamCreatePairWithSocketToHost host=%@ port=%u",
            blocked ? @"-BLOCKED" : @"", hostStr, (unsigned)port]];
    if (blocked) {
        // 直接给出两个 NULL 流,调用方按正常的"打开失败"逻辑处理即可
        if (readStream) *readStream = NULL;
        if (writeStream) *writeStream = NULL;
        return;
    }
    %orig;
}

// CFSocketStream 的另一常见入口: CFStreamCreatePairWithSocketToCFHost(alloc, CFHostRef, port, ...)
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

// CFHost 域名解析,用于把域名缓存起来,补充 socket 层只拿得到 IP 的情况
%hookf(Boolean, CFHostStartInfoResolution, CFHostRef theHost, CFHostInfoType info, CFStreamError *error) {
    Boolean ret = %orig;
    if (ret && info == kCFHostAddresses) {
        Boolean resolved = false;
        CFArrayRef names = CFHostGetNames(theHost, &resolved);
        NSString *hostStr = (names && CFArrayGetCount(names) > 0) ? (__bridge NSString *)CFArrayGetValueAtIndex(names, 0) : nil;
        Boolean addrResolved = false;
        CFArrayRef addrs = CFHostGetAddressing(theHost, &addrResolved);
        if (hostStr && addrs) {
            for (CFIndex i = 0; i < CFArrayGetCount(addrs); i++) {
                CFDataRef addrData = (CFDataRef)CFArrayGetValueAtIndex(addrs, i);
                const struct sockaddr *sa = (const struct sockaddr *)CFDataGetBytePtr(addrData);
                NSString *ip = IPStringFromSockaddr(sa);
                if (ip) {
                    [[NBRuleEngine shared] noteResolvedIP:ip forHost:hostStr];
                }
            }
        }
    }
    return ret;
}

#pragma mark - 高层: NSURLProtocol 拦截 HTTP/HTTPS(覆盖 NSURLSession / NSURLConnection / 大部分三方网络库)

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
            isHTTPS ? @"S" : @"", self.request.HTTPMethod, host, port, blocked ? @"BLOCKED" : @"ALLOWED"]];

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
// 此时全局 registerClass: 不生效,这里额外 hook 一下把自定义 Protocol 插进去,提高覆盖率
%hook NSURLSessionConfiguration

- (NSArray *)protocolClasses {
    NSArray *orig = %orig;
    if (!orig) return @[[NBURLProtocol class]];
    if ([orig containsObject:[NBURLProtocol class]]) return orig;
    NSMutableArray *arr = [orig mutableCopy];
    [arr insertObject:[NBURLProtocol class] atIndex:0];
    return arr;
}

%end

#pragma mark - 初始化

%ctor {
    @autoreleasepool {
        %init;
        [NBRuleEngine shared];
        [NSURLProtocol registerClass:[NBURLProtocol class]];
        [[NBRuleEngine shared] logEvent:@"NetBlockTweak loaded"];
    }
}
