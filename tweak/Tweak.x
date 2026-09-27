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
#include <dirent.h>
#include <stdint.h>
#include <mach-o/dyld.h>

// JB-Pfade, die SEON/Incognia/Revolut prüfen und die roothide nicht versteckt.
// Liste aus der Revolut-Hauptbinary extrahiert (Incognia jailbreak_suspect_urls) + SEON-Liste.
static NSArray<NSString *> *hiddenPaths(void) {
    static NSArray *p = nil;
    if (!p) {
        p = @[
            // --- roothide-Marker (aus Revolut/Incognia-Binary) ---
            @"/jb/jailbreakd.plist",
            @"/jb/amfid_payload.dylib",
            @"/var/jb/.installed_dopamine",
            @"/var/jb/.installed_fugu15",
            @"/var/jb/.installed_taurine",
            @"/var/jb/.installed_xina",
            @"/var/jb/.procursus_strapped",
            @"/var/jb/Applications/Cydia.app",
            @"/var/jb/Applications/Sileo.app",
            @"/var/jb/Library/PreferenceBundles/XinaPrefs.bundle",
            @"/var/jb/Library/dpkg",
            @"/var/jb/etc/apt",
            @"/var/jb/prep_bootstrap.sh",
            @"/var/jb/usr/bin/jailbreakd",
            @"/var/jb/usr/bin/xina",
            @"/var/jb/usr/lib/TweakInject",
            @"/var/jb/usr/lib/ellekit.dylib",
            @"/var/jb/usr/lib/libhooker.dylib",
            @"/var/jb/usr/lib/libjailbreak.dylib",
            @"/var/jb/usr/lib/libsubstitute.dylib",
            @"/var/jb/usr/lib/pspawn_payload.dylib",
            @"/var/jb/usr/lib/substrate",
            @"/var/jb/usr/lib/xina",
            @"/var/jb/usr/libexec/substrated",
            @"/var/jb/var/lib/dpkg",
            @"/var/jb",
            // --- alte/rootless-lose Marker ---
            @"/usr/lib/libjailbreak.dylib",
            @"/usr/lib/ABDYLD.dylib",
            @"/usr/lib/substrate",
            @"/usr/lib/TweakInject",
            @"/libsubstitute.dylib",
            @"/usr/libexec/substrated",
            @"/Library/MobileSubstrate",
            @"/Library/MobileSubstrate/MobileSubstrate.dylib",
            @"/Library/MobileSubstrate/CydiaSubstrate.dylib",
            @"/Library/MobileSubstrate/DynamicLibraries",
            @"/Library/PreferenceBundles/FlyJBPrefs.bundle",
            @"/Library/PreferenceBundles/ShadowPreferences.bundle",
            @"/Library/PreferenceBundles/Cephei.bundle",
            @"/Library/BawAppie/ABypass",
            @"/Library/Frameworks/AltList.framework",
            @"/var/tmp/jailbreak.txt",
            @"/private/jailbreak.txt",
            @"/var/tmp/frida",
            @"/private/var/cache/apt",
            @"/private/var/lib/apt",
            @"/private/var/lib/cydia",
            @"/private/var/log/syslog",
            @"/private/var/Users",
            @"/System/Library/LaunchDaemons/com.ikey.bbot.plist",
            @"/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist",
            @"/var/mobile/Library/Preferences/jp.akusio.kernbypass.plist",
            // --- SEON-Klassiker ---
            @"/usr/sbin/sshd",
            @"/bin/bash",
            @"/bin/sh",
            @"/etc/apt",
            @"/private/etc/apt",
            @"/usr/bin/ssh",
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

// --- opendir: JB-Verzeichnisse "leer" erscheinen lassen ---
static DIR *(*orig_opendir)(const char *);
static DIR *hook_opendir(const char *path) {
    if (path && isHiddenPath([NSString stringWithUTF8String:path])) {
        errno = ENOENT;
        return NULL;
    }
    return orig_opendir(path);
}

// --- dlsym: Substrate/Hook-Symbol-Lookups verstecken ---
// Incognia/SEON suchen z.B. nach MSHookFunction/SubstrateLoader um Hooking zu erkennen.
static void *(*orig_dlsym)(void *, const char *);
static void *hook_dlsym(void *handle, const char *symbol) {
    if (symbol) {
        NSString *s = [NSString stringWithUTF8String:symbol];
        if ([s containsString:@"MSHook"] ||
            [s isEqualToString:@"SubstrateLoader"] ||
            [s isEqualToString:@"_substrate_init"] ||
            [s containsString:@"fishhook"] ||
            [s containsString:@"hook_function"]) {
            return NULL;
        }
    }
    return orig_dlsym(handle, symbol);
}

// --- _dyld_image_count / _dyld_get_image_name: JB-Dylibs aus der Liste nehmen ---
// Incognia enumeriert geladene Images; unsere injizierten Pfade verstecken.
static const char *(*orig_dyld_get_image_name)(uint32_t);
static const char *hook_dyld_get_image_name(uint32_t index) {
    const char *n = orig_dyld_get_image_name(index);
    if (!n) return n;
    NSString *s = [NSString stringWithUTF8String:n];
    // JB-Bibliotheksnamen, die eine Erkennung triggern
    if ([s hasPrefix:@"/var/jb/"] ||
        [s containsString:@"TweakInject"] ||
        [s containsString:@"MobileSubstrate"] ||
        [s containsString:@"libhooker"] ||
        [s containsString:@"ellekit"] ||
        [s containsString:@"libsubstitute"] ||
        [s containsString:@"jailbreak"] ||
        [s containsString:@"substrate"]) {
        // "unsichtbares" System-Image vorspielen
        return "/System/Library/Frameworks/UIKit.framework/UIKit";
    }
    return n;
}

static uint32_t (*orig_dyld_image_count)(void);
static uint32_t hook_dyld_image_count(void) {
    uint32_t n = orig_dyld_image_count();
    // Count unverändert lassen (Index-Mapping bleibt konsistent über hook_dyld_get_image_name)
    return n;
}

__attribute__((constructor))
static void init(void) {
    // Marker: Läuft dieser Konstruktor im Revolut-Prozess?
    FILE *m = fopen("/var/tmp/rg_ctor.txt", "a");
    if (m) {
        fprintf(m, "%ld ctor lief\n", (long)time(NULL));
        fclose(m);
    }
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
    MSHookFunction((void *)opendir, (void *)hook_opendir, (void **)&orig_opendir);
    MSHookFunction((void *)dlsym, (void *)hook_dlsym, (void **)&orig_dlsym);
    MSHookFunction((void *)_dyld_get_image_name, (void *)hook_dyld_get_image_name, (void **)&orig_dyld_get_image_name);
    MSHookFunction((void *)_dyld_image_count, (void *)hook_dyld_image_count, (void **)&orig_dyld_image_count);
}
