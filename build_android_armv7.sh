#!/bin/bash

set -o errexit -o nounset

project_dir=$(pwd)
qt_install_dir=~

# Get Qt
echo "Installing Qt..."
cd "${qt_install_dir}"
echo "Downloading Qt files..."
wget -N https://github.com/adolby/qt-more-builds/releases/download/5.12.4/qt-opensource-5.12.4-android-armv7.7z
echo "Extracting Qt files..."
7z x qt-opensource-5.12.4-android-armv7.7z -aos &> /dev/null

# Add Qt binaries to path
echo "Adding Qt binaries to path..."
PATH="${qt_install_dir}/Qt/5.12.4/android_armv7/bin/:${PATH}"

wget -N https://dl.google.com/android/repository/android-ndk-r19c-linux-x86_64.zip
unzip android-ndk-r19c-linux-x86_64.zip > /dev/null

ANDROID_NDK_ROOT=`pwd`/android-ndk-r19c
ANDROID_SDK_ROOT=/usr/local/android-sdk
PATH=`pwd`/android-ndk-r19c:${PATH}

# Get Botan
# echo "Installing Botan..."
# wget https://github.com/randombit/botan/archive/1.11.32.zip
# 7z x 1.11.32.zip &>/dev/null
# chmod -R +x /usr/local/botan-1.11.32/
# cd /usr/local/botan-1.11.32/
# ./configure.py --cc=clang --amalgamation --disable-shared --with-zlib
# cp botan_all_aesni.cpp ${project_dir}/src/cryptography/botan/android/armv7/botan_all_aesni.cpp
# cp botan_all_avx2.cpp ${project_dir}/src/cryptography/botan/android/armv7/botan_all_avx2.cpp
# cp botan_all_internal.h ${project_dir}/src/cryptography/botan/android/armv7/botan_all_internal.h
# cp botan_all_rdrand.cpp ${project_dir}/src/cryptography/botan/android/armv7/botan_all_rdrand.cpp
# cp botan_all_rdseed.cpp ${project_dir}/src/cryptography/botan/android/armv7/botan_all_rdseed.cpp
# cp botan_all_ssse3.cpp ${project_dir}/src/cryptography/botan/android/armv7/botan_all_ssse3.cpp
# cp botan_all.cpp ${project_dir}/src/cryptography/botan/android/armv7/botan_all.cpp
# cp botan_all.h ${project_dir}/src/cryptography/botan/android/armv7/botan_all.h

cd "${project_dir}"

# Clean build directory
rm -rf "${project_dir}/build/android/armv7/"

mkdir -p "${project_dir}/build/android/armv7/release/widgets/"
mkdir -p "${project_dir}/build/android/armv7/release/widgets/moc"
mkdir -p "${project_dir}/build/android/armv7/release/widgets/qrc"
mkdir -p "${project_dir}/build/android/armv7/release/widgets/obj"
mkdir -p "${project_dir}/build/android/armv7/release/quick/"
mkdir -p "${project_dir}/build/android/armv7/release/quick/moc"
mkdir -p "${project_dir}/build/android/armv7/release/quick/qrc"
mkdir -p "${project_dir}/build/android/armv7/release/quick/obj"
mkdir -p "${project_dir}/build/android/armv7/release/lib/"
mkdir -p "${project_dir}/build/android/armv7/release/lib/zlib/"
mkdir -p "${project_dir}/build/android/armv7/release/test/"
mkdir -p "${project_dir}/build/android/armv7/release/Kryvo/"

# Build Kryvo
echo "Building Kryvo..."

if [ -f "${project_dir}/Makefile" ]; then
  make distclean
fi

qmake CONFIG+=release -spec android-armv7
make

# Copy plugins for test app
# echo "Copying plugins for test app..."
# mkdir -p "${project_dir}/build/android/armv7/release/test/plugins/cryptography/botan/"
# cd "${project_dir}/build/android/armv7/release/test/plugins/cryptography/botan/"
# cp "${project_dir}/build/android/armv7/release/plugins/cryptography/botan/libbotan.so" libbotan.so

# Copy test data
# echo "Copying test data archive..."
# cd "${project_dir}/build/android/armv7/release/test/"
# cp "${project_dir}/src/tests/data/test-data.zip" test-data.zip

# echo "Extracting test data..."
# 7z e test-data.zip -aos &> /dev/null

# Run tests
# echo "Running tests..."
# chmod +x tests
# ./tests

# Copy plugins for app
# echo "Copy plugins to app..."
# mkdir -p "${project_dir}/build/android/armv7/release/widgets/plugins/cryptography/botan/"
# cd "${project_dir}/build/android/armv7/release/widgets/plugins/cryptography/botan/"
# cp "${project_dir}/build/android/armv7/release/plugins/cryptography/botan/libbotan.so" libbotan.so

# Package Kryvo
echo "Packaging..."

echo "Copying app dependencies..."
androiddeployqt --output "${project_dir}/build/android/armv7/release/Kryvo/"

TAG_NAME="${TAG_NAME:-dev}"

echo "Done!"

exit 0