#include <substrate.h>
#include <Foundation/Foundation.h>
#include <dlfcn.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

// JB-Pfade, die SEON/Revolut prüft und die roothide nicht versteckt
static NSArray<NSString *> *hiddenPaths(void) {
    static NSArray *p = nil;
    if (!p) {
        p = @[
            @"/usr/sbin/sshd",
            @"/bin/bash",
            @"/bin/sh",
            @"/etc/apt",
            @"/private/etc/apt",
            @"/private/var/lib/apt",
            @"/private/var/lib/apt/",
            @"/usr/bin/ssh",
            @"/var/jb",
            @"/private/jailbreak.txt",
            @"/Library/MobileSubstrate/MobileSubstrate.dylib",
            @"/usr/lib/TweakInject",
            @"/usr/libexec/cydia/firmware.sh",
            @"/Applications/Cydia.app",
        ];
    }
    return p;
}

static BOOL isHiddenPath(NSString *path) {
    if (!path) return NO;
    NSString *clean = [path stringByStandardizingPath];
    if (!clean) return NO;
    // Exakte + Präfix-Matches mit Pfadgrenze
    for (NSString *h in hiddenPaths()) {
        if ([clean isEqualToString:h]) return YES;
        if ([clean hasPrefix:[h stringByAppendingString:@"/"]]) return YES;
    }
    return NO;
}

static BOOL (*orig_fileExistsAtPath)(id, SEL, NSString *);
static BOOL hook_fileExistsAtPath(id self, SEL _cmd, NSString *path) {
    if (isHiddenPath(path)) return NO;
    return orig_fileExistsAtPath(self, _cmd, path);
}

static BOOL (*orig_fileExistsAtPath_isDir)(id, SEL, NSString *, BOOL *);
static BOOL hook_fileExistsAtPath_isDir(id self, SEL _cmd, NSString *path, BOOL *isDir) {
    if (isHiddenPath(path)) {
        if (isDir) *isDir = NO;
        return NO;
    }
    return orig_fileExistsAtPath_isDir(self, _cmd, path, isDir);
}

static int (*orig_access)(const char *, int);
static int hook_access(const char *path, int mode) {
    if (path && isHiddenPath([NSString stringWithUTF8String:path])) {
        errno = ENOENT;
        return -1;
    }
    return orig_access(path, mode);
}

static int (*orig_stat)(const char *, struct stat *);
static int hook_stat(const char *path, struct stat *sb) {
    if (path && isHiddenPath([NSString stringWithUTF8String:path])) {
        errno = ENOENT;
        return -1;
    }
    return orig_stat(path, sb);
}

static int (*orig_lstat)(const char *, struct stat *);
static int hook_lstat(const char *path, struct stat *sb) {
    if (path && isHiddenPath([NSString stringWithUTF8String:path])) {
        errno = ENOENT;
        return -1;
    }
    return orig_lstat(path, sb);
}

// fopen-Familie: SEON nutzt teilweise fopen zum Pfad-Check
static FILE *(*orig_fopen)(const char *, const char *);
static FILE *hook_fopen(const char *path, const char *mode) {
    if (path && isHiddenPath([NSString stringWithUTF8String:path])) {
        errno = ENOENT;
        return NULL;
    }
    return orig_fopen(path, mode);
}

__attribute__((constructor))
static void init(void) {
    // Nur in Revolut (Filter-Plists greifen, aber doppelt absichern)
    NSString *bundleId = [[NSBundle mainBundle] bundleIdentifier];
    if (![bundleId isEqualToString:@"com.revolut.revolut"]) return;

    MSHookMessageEx(
        [NSFileManager class],
        @selector(fileExistsAtPath:),
        (IMP)&hook_fileExistsAtPath,
        (IMP *)&orig_fileExistsAtPath);

    MSHookMessageEx(
        [NSFileManager class],
        @selector(fileExistsAtPath:isDirectory:),
        (IMP)&hook_fileExistsAtPath_isDir,
        (IMP *)&orig_fileExistsAtPath_isDir);

    MSHookFunction((void *)access, (void *)hook_access, (void **)&orig_access);
    MSHookFunction((void *)stat, (void *)hook_stat, (void **)&orig_stat);
    MSHookFunction((void *)lstat, (void *)hook_lstat, (void **)&orig_lstat);
    MSHookFunction((void *)fopen, (void *)hook_fopen, (void **)&orig_fopen);
}
