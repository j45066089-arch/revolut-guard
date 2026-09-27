#include <substrate.h>
#include <Foundation/Foundation.h>
#include <UIKit/UIKit.h>
#include <dlfcn.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/sysctl.h>
#include <stdlib.h>
#include <string.h>

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

// --- canOpenURL: JB-URL-Schemata (cydia://, sileo://, filza://, zbra://) blocken ---
static BOOL (*orig_canOpenURL)(id, SEL, NSURL *);
static BOOL hook_canOpenURL(id self, SEL _cmd, NSURL *url) {
    if (url) {
        NSString *scheme = [[url scheme] lowercaseString];
        if ([scheme isEqualToString:@"cydia"] ||
            [scheme isEqualToString:@"sileo"] ||
            [scheme isEqualToString:@"filza"] ||
            [scheme isEqualToString:@"zbra"] ||
            [scheme isEqualToString:@"installer"] ||
            [scheme isEqualToString:@"undecimus"] ||
            [scheme isEqualToString:@"taurine"]) {
            return NO;
        }
    }
    return orig_canOpenURL(self, _cmd, url);
}

// --- getenv: JB-bezogene Umgebungsvariablen verstecken ---
static char *(*orig_getenv)(const char *);
static char *hook_getenv(const char *name) {
    if (name) {
        NSString *n = [NSString stringWithUTF8String:name];
        if ([n isEqualToString:@"DYLD_INSERT_LIBRARIES"] ||
            [n hasPrefix:@"DYLD_"] ||
            [n isEqualToString:@"SUBSTRATE_ROOT"] ||
            [n hasSuffix:@"_JBROOT"] ||
            [n containsString:@"JBROOT"]) {
            return NULL;
        }
    }
    return orig_getenv(name);
}

// --- sysctl: kern.bootargs / security.mac.proc_* / cs_enforcement abfangen ---
// (SEON liest z.B. kern.bootargs auf "jailbreak"-Marker)
static int (*orig_sysctlbyname)(const char *, void *, size_t *, void *, size_t);
static int hook_sysctlbyname(const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    if (name) {
        NSString *n = [NSString stringWithUTF8String:name];
        if ([n isEqualToString:@"kern.bootargs"] ||
            [n hasPrefix:@"security.mac.proc_"] ||
            [n isEqualToString:@"kern.csr_active_config"] ||
            [n hasPrefix:@"machdep.cpu.features"]) {
            // sauberen "nicht-jailbroken"-Wert liefern: leerer String
            if (oldp && oldlenp && *oldlenp > 0) {
                memset(oldp, 0, *oldlenp);
                ((char *)oldp)[0] = '\0';
                return 0;
            }
            return 0; // stillen Erfolg ohne Daten
        }
    }
    return orig_sysctlbyname(name, oldp, oldlenp, newp, newlen);
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

    MSHookMessageEx(
        [UIApplication class],
        @selector(canOpenURL:),
        (IMP)&hook_canOpenURL,
        (IMP *)&orig_canOpenURL);

    MSHookFunction((void *)access, (void *)hook_access, (void **)&orig_access);
    MSHookFunction((void *)stat, (void *)hook_stat, (void **)&orig_stat);
    MSHookFunction((void *)lstat, (void *)hook_lstat, (void **)&orig_lstat);
    MSHookFunction((void *)fopen, (void *)hook_fopen, (void **)&orig_fopen);
    MSHookFunction((void *)getenv, (void *)hook_getenv, (void **)&orig_getenv);
    MSHookFunction((void *)sysctlbyname, (void *)hook_sysctlbyname, (void **)&orig_sysctlbyname);
}
