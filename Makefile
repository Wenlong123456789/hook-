ifndef THEOS
$(error THEOS 环境变量未设置,请先安装并配置 Theos: https://theos.dev)
endif

# 目标架构,rootless(iOS 15+ 无根越狱)一般只需 arm64e,可按需调整
ARCHS = arm64 arm64e
TARGET = iphone:clang:latest:14.0

# 需要注入的目标进程可执行文件名(不是 bundle id,是 Info.plist 里的 CFBundleExecutable)
# 也可以留空,完全依赖 NetBlockTweak.plist 的 Filter 来限定注入范围
INSTALL_TARGET_PROCESSES = TargetAppExecutable

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = NetBlockTweak

NetBlockTweak_FILES = Tweak.xm
NetBlockTweak_CFLAGS = -fobjc-arc -Wall
NetBlockTweak_FRAMEWORKS = Foundation
NetBlockTweak_EXTRA_FRAMEWORKS = CFNetwork

include $(THEOS_MAKE_PATH)/tweak.mk

after-install::
	install.exec "killall -9 TargetAppExecutable || true"
