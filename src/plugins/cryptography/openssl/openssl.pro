include(../../../../defaults.pri)

QT += core

TARGET = openssl

TEMPLATE = lib

CONFIG += plugin static c++14

# Qt Creator Debug/Release Differentiation
# Ensure one "debug_and_release" in CONFIG, for clarity.
debug_and_release {
  CONFIG -= debug_and_release
  CONFIG += debug_and_release
}
# Ensure one "debug" or "release" in CONFIG so they can be used as conditionals
# instead of writing "CONFIG(debug, debug|release)"
CONFIG(debug, debug|release) {
  CONFIG -= debug release
  CONFIG += debug
}
CONFIG(release, debug|release) {
  CONFIG -= debug release
  CONFIG += release
}

SOURCES += OpenSslProvider.cpp

HEADERS += \
  OpenSslProvider.hpp \
  $$PWD/../../../core/Constants.hpp \
  $$PWD/../../../core/DispatcherState.hpp

OTHER_FILES += openssl.json

# Platform-specific configuration
linux {
  message(Linux)

  android {
    message(Android)

    contains(ANDROID_TARGET_ARCH, armeabi-v7a) {
      message(armeabi-v7a)

      INCLUDEPATH += openssl/android/armv7/include

      LIBS += -Lopenssl/android/armv7/lib -lcrypto

      debug {
        message(Debug)
        DESTDIR = $$PWD/../../../../build/android/armv7/debug/plugins/cryptography/openssl
      }
      release {
        message(Release)
        DESTDIR = $$PWD/../../../../build/android/armv7/release/plugins/cryptography/openssl
      }
    }

    contains(ANDROID_TARGET_ARCH, arm64-v8a) {
      message(arm64-v8a)

      INCLUDEPATH += openssl/android/arm64_v8a/include

      LIBS += -Lopenssl/android/arm64_v8a/lib -lcrypto

      debug {
        message(Debug)
        DESTDIR = $$PWD/../../../../build/android/arm64_v8a/debug/plugins/cryptography/openssl
      }
      release {
        message(Release)
        DESTDIR = $$PWD/../../../../build/android/arm64_v8a/release/plugins/cryptography/openssl
      }
    }
  } # End android

  linux-clang {
    message(clang)

    INCLUDEPATH += openssl/linux/clang/x86_64/include

    LIBS += -Lopenssl/linux/clang/x86_64/lib -lcrypto

    QMAKE_CXXFLAGS += -fstack-protector -maes -mpclmul -mssse3 -mavx2
    QMAKE_LFLAGS += -fstack-protector
    QMAKE_LFLAGS += -Wl,-rpath,"'\$$ORIGIN'"

    debug {
      message(Debug)
      DESTDIR = $$PWD/../../../../build/linux/clang/x86_64/debug/plugins/cryptography/openssl
    }
    release {
      message(Release)
      DESTDIR = $$PWD/../../../../build/linux/clang/x86_64/release/plugins/cryptography/openssl
    }
  } # End linux-clang

  linux-g++-64 {
    message(g++ x86_64)

    INCLUDEPATH += openssl/linux/gcc/x86_64/include

    LIBS += -Lopenssl/linux/gcc/x86_64/lib -lcrypto

    QMAKE_CXXFLAGS += -fstack-protector -maes -mpclmul -mssse3 -mavx2
    QMAKE_LFLAGS += -fstack-protector
    QMAKE_LFLAGS += -Wl,-rpath,"'\$$ORIGIN'"

    debug {
      message(Debug)
      DESTDIR = $$PWD/../../../../build/linux/gcc/x86_64/debug/plugins/cryptography/openssl
    }
    release {
      message(Release)
      DESTDIR = $$PWD/../../../../build/linux/gcc/x86_64/release/plugins/cryptography/openssl
    }
  } # End linux-g++-64
} # End linux

darwin {
#  LIBS += -framework Security

  ios {
    message(iOS)
    message(clang)

    CONFIG -= simulator

    INCLUDEPATH += openssl/ios/include

    LIBS += -Lopenssl/ios/lib -lcrypto

    debug {
      message(Debug)
      DESTDIR = $$PWD/../../../../build/iOS/debug/plugins/cryptography/openssl
    }
    release {
      message(Release)
      DESTDIR = $$PWD/../../../../build/iOS/release/plugins/cryptography/openssl
    }
  } # End ios

  macos {
    message(macOS)
    message(clang)

    INCLUDEPATH += openssl/macOS/include

    LIBS += -Lopenssl/macOS/lib -lcrypto

    QMAKE_CXXFLAGS += -fstack-protector -maes -mpclmul -mssse3 -mavx2
    QMAKE_LFLAGS += -fstack-protector

    debug {
      message(Debug)
      DESTDIR = $$PWD/../../../../build/macOS/clang/x86_64/debug/plugins/cryptography/openssl
    }
    release {
      message(Release)
      DESTDIR = $$PWD/../../../../build/macOS/clang/x86_64/release/plugins/cryptography/openssl
    }
  } # End macos
} # End darwin

win32 {
  message(Windows)

  win32-g++ {
    message(g++)

    INCLUDEPATH += openssl/windows/mingw/x86_32/include

    LIBS += -Lopenssl/windows/mingw/x86_32/lib -lcrypto

    debug {
      message(Debug)
      DESTDIR = $$PWD/../../build/windows/mingw/x86_32/debug/plugins/cryptography/openssl
    }
    release {
      message(Release)
      DESTDIR = $$PWD/../../build/windows/mingw/x86_32/release/plugins/cryptography/openssl
    }
  }

  win32-msvc {
    message(MSVC)

    LIBS += advapi32.lib user32.lib ws2_32.lib

    QMAKE_CXXFLAGS += -bigobj -arch:AVX2

    contains(QT_ARCH, x86_64) {
      message(x86_64)

      INCLUDEPATH += openssl/windows/msvc/x86_64/include

      LIBS += -Lopenssl/windows/msvc/x86_64/lib -lcrypto

      debug {
        message(Debug)
        DESTDIR = $$PWD/../../../../build/windows/msvc/x86_64/debug/plugins/cryptography/openssl
      }
      release {
        message(Release)
        DESTDIR = $$PWD/../../../../build/windows/msvc/x86_64/release/plugins/cryptography/openssl
      }
    }
  }
} # End win32

OBJECTS_DIR = $${DESTDIR}/obj
MOC_DIR = $${DESTDIR}/moc
