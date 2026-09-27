# RevolutGuard — Datei-Existenz-Checks für JB-Pfade in Revolut verstecken
#
# Hookt NSFileManager/defaultManager fileExistsAtPath: + access/stat/lstat/open
# und liefert für bekannte JB-Pfade "existiert nicht".

ARCHS := arm64 arm64e
TARGET := iphone:clang:14.0:14.0
INSTALL_TARGET_PROCESSES = Revolut

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = RevolutGuard

RevolutGuard_FILES = Tweak.x
RevolutGuard_CFLAGS = -fobjc-arc
RevolutGuard_LIBRARIES = 

include $(THEOS_MAKE_PATH)/tweak.mk

after-install::
	install.exec "killall -9 Revolut || true"
