// NetBlockTweak - 加强版（仅 NSURLProtocol，修复延迟崩溃 + 拦截失效）
// 1. 立即注册 Protocol，不再延迟 0.5s
// 2. 更安全的 NSURLProtocol 实现，减少几秒后崩溃
// 3. 详细日志，方便确认是否真正命中请求
// 4. 仍然不启用底层 %hookf（connect/getaddrinfo 等）

#import <Foundation/Foundation.h>
#import <CFNetwork/CFNetwork.h>

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
            NSLog(@"[NetBlockTweak] rules reloaded, count=%lu, defaultBlock=%d, log=%d",
                  (unsigned long)arr.count, defaultBlock, logEnabled);
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

#pragma mark - NSURLProtocol（加强稳定性）

static NSString *const kNBHandledKey = @"com.yourteam.netblocktweak.handled";

@interface NBURLProtocol : NSURLProtocol <NSURLSessionDataDelegate>
@property (nonatomic, strong) NSURLSession *session;
@property (nonatomic, strong) NSURLSessionDataTask *task;
@property (nonatomic, assign) BOOL stopped;
@end

@implementation NBURLProtocol

+ (BOOL)canInitWithRequest:(NSURLRequest *)request {
    if ([NSURLProtocol propertyForKey:kNBHandledKey inRequest:request]) {
        return NO;
    }
    NSString *scheme = request.URL.scheme.lowercaseString;
    if (![scheme isEqualToString:@"http"] && ![scheme isEqualToString:@"https"]) {
        return NO;
    }
    // 每次有请求进来都打日志，方便确认有没有真正走到 Protocol
    NSLog(@"[NetBlockTweak] canInitWithRequest: %@", request.URL.absoluteString);
    return YES;
}

+ (NSURLRequest *)canonicalRequestForRequest:(NSURLRequest *)request {
    return request;
}

+ (BOOL)requestIsCacheEquivalent:(NSURLRequest *)a toRequest:(NSURLRequest *)b {
    return [super requestIsCacheEquivalent:a toRequest:b];
}

- (void)startLoading {
    if (self.stopped) return;

    NSURL *url = self.request.URL;
    NSString *host = url.host ?: @"";
    BOOL isHTTPS = [url.scheme.lowercaseString isEqualToString:@"https"];
    int port = url.port ? url.port.intValue : (isHTTPS ? 443 : 80);

    BOOL blocked = [[NBRuleEngine shared] shouldBlockHost:host port:port proto:NBProtoTCP];
    [[NBRuleEngine shared] logEvent:
        [NSString stringWithFormat:@"[HTTP%@] %@ %@ (port %d) -> %@",
            isHTTPS ? @"S" : @"",
            self.request.HTTPMethod ?: @"?",
            host,
            port,
            blocked ? @"BLOCKED" : @"ALLOWED"]];

    if (blocked) {
        // 用网络错误码模拟断网，很多 App 能正常降级
        NSError *error = [NSError errorWithDomain:NSURLErrorDomain
                                              code:NSURLErrorNotConnectedToInternet
                                          userInfo:@{
                                              NSLocalizedDescriptionKey: @"Blocked by NetBlockTweak",
                                              NSURLErrorFailingURLErrorKey: url ?: [NSURL URLWithString:@""]
                                          }];
        // 回调尽量切回主线程，降低崩溃概率
        dispatch_async(dispatch_get_main_queue(), ^{
            if (!self.stopped) {
                [self.client URLProtocol:self didFailWithError:error];
            }
        });
        return;
    }

    // 放行：用独立 session 转发，并打上 handled 标记防止循环
    NSMutableURLRequest *forwarded = [self.request mutableCopy];
    if (!forwarded) {
        NSError *err = [NSError errorWithDomain:@"com.yourteam.netblocktweak" code:-1
                                       userInfo:@{NSLocalizedDescriptionKey: @"mutableCopy failed"}];
        [self.client URLProtocol:self didFailWithError:err];
        return;
    }
    [NSURLProtocol setProperty:@YES forKey:kNBHandledKey inRequest:forwarded];

    // 用 default 而不是 ephemeral，兼容性更好；禁止协议类再走我们自己，避免循环
    NSURLSessionConfiguration *config = [NSURLSessionConfiguration defaultSessionConfiguration];
    config.protocolClasses = @[];   // 关键，不再经过任何自定义 Protocol
    config.timeoutIntervalForRequest = 30;
    config.timeoutIntervalForResource = 60;

    self.session = [NSURLSession sessionWithConfiguration:config
                                                 delegate:self
                                            delegateQueue:nil];
    self.task = [self.session dataTaskWithRequest:forwarded];
    [self.task resume];
}

- (void)stopLoading {
    self.stopped = YES;
    [self.task cancel];
    self.task = nil;
    [self.session invalidateAndCancel];
    self.session = nil;
}

#pragma mark - NSURLSessionDataDelegate

- (void)URLSession:(NSURLSession *)session
          dataTask:(NSURLSessionDataTask *)task
didReceiveResponse:(NSURLResponse *)response
 completionHandler:(void (^)(NSURLSessionResponseDisposition))completionHandler {
    if (self.stopped) {
        completionHandler(NSURLSessionResponseCancel);
        return;
    }
    // 回调到主线程更安全
    dispatch_async(dispatch_get_main_queue(), ^{
        if (!self.stopped) {
            [self.client URLProtocol:self
                  didReceiveResponse:response
                  cacheStoragePolicy:NSURLCacheStorageNotAllowed];
        }
    });
    completionHandler(NSURLSessionResponseAllow);
}

- (void)URLSession:(NSURLSession *)session
          dataTask:(NSURLSessionDataTask *)task
    didReceiveData:(NSData *)data {
    if (self.stopped || !data) return;
    dispatch_async(dispatch_get_main_queue(), ^{
        if (!self.stopped) {
            [self.client URLProtocol:self didLoadData:data];
        }
    });
}

- (void)URLSession:(NSURLSession *)session
              task:(NSURLSessionTask *)task
didCompleteWithError:(NSError *)error {
    dispatch_async(dispatch_get_main_queue(), ^{
        if (self.stopped) return;
        if (error) {
            [self.client URLProtocol:self didFailWithError:error];
        } else {
            [self.client URLProtocolDidFinishLoading:self];
        }
    });
}

- (void)URLSession:(NSURLSession *)session
              task:(NSURLSessionTask *)task
willPerformHTTPRedirection:(NSHTTPURLResponse *)response
        newRequest:(NSURLRequest *)request
 completionHandler:(void (^)(NSURLRequest * _Nullable))completionHandler {
    // 重定向继续走原请求，由上层再决定是否拦截
    completionHandler(request);
}

@end

#pragma mark - 强制把 Protocol 插进所有 Configuration

%hook NSURLSessionConfiguration

- (NSArray *)protocolClasses {
    NSArray *orig = %orig;
    Class cls = [NBURLProtocol class];
    if (!cls) return orig;
    if (!orig) return @[cls];
    if ([orig containsObject:cls]) return orig;
    NSMutableArray *arr = [orig mutableCopy];
    [arr insertObject:cls atIndex:0];
    return [arr copy];
}

// 有些 App 会 setProtocolClasses:，这里也插进去
- (void)setProtocolClasses:(NSArray *)protocolClasses {
    Class cls = [NBURLProtocol class];
    if (cls && protocolClasses && ![protocolClasses containsObject:cls]) {
        NSMutableArray *arr = [protocolClasses mutableCopy];
        [arr insertObject:cls atIndex:0];
        %orig(arr);
        return;
    }
    %orig;
}

%end

#pragma mark - 初始化

%ctor {
    @autoreleasepool {
        %init;

        // 立刻初始化，不再延迟，避免启动早期请求漏拦
        @try {
            [NBRuleEngine shared];
            BOOL ok = [NSURLProtocol registerClass:[NBURLProtocol class]];
            NSLog(@"[NetBlockTweak] registerClass result = %d", ok);
            [[NBRuleEngine shared] logEvent:@"NetBlockTweak loaded (NSURLProtocol only)"];
        } @catch (NSException *e) {
            NSLog(@"[NetBlockTweak] ctor exception: %@", e);
        }
    }
}
