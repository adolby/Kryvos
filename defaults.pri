DEFINES += QT_DEPRECATED_WARNINGS

INCLUDEPATH += $$PWD/src/core
INCLUDEPATH += $$PWD/3rdparty/zlib
INCLUDEPATH += $$PWD/3rdparty/catch
SRC_DIR = $$PWD

macos {
  QMAKE_MAC_SDK = macosx10.15
  QMAKE_MACOSX_DEPLOYMENT_TARGET = 10.15
}
