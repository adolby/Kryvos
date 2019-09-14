#include "OpenSslProvider.hpp"
#include "DispatcherState.hpp"
#include "FileUtility.h"
#include "Constants.hpp"
#include <QSaveFile>
#include <QFile>
#include <QFileInfo>
#include <QDir>
#include <QStringBuilder>
#include <string>

class Kryvo::OpenSslProviderPrivate {
  Q_DISABLE_COPY(OpenSslProviderPrivate)
  Q_DECLARE_PUBLIC(OpenSslProvider)

 public:
  OpenSslProviderPrivate(OpenSslProvider* pro);

  void init(DispatcherState* ds);

  bool encrypt(std::size_t id,
               const QString& compressionFormat,
               const QString& passphrase,
               const QFileInfo& inputFileInfo,
               const QFileInfo& outputFileInfo,
               const QString& cipher,
               std::size_t keySize,
               const QString& modeOfOperation);

  bool decrypt(std::size_t id,
               const QString& passphrase,
               const QFileInfo& inputFileInfo,
               const QFileInfo& outputFileInfo,
               const QByteArray& algorithmNameByteArray,
               const QByteArray& keySizeByteArray,
               const QByteArray& pbkdfSaltByteArray,
               const QByteArray& keySaltByteArray,
               const QByteArray& ivSaltByteArray);

  bool encryptFile(std::size_t id,
                   const QString& compressionFormat,
                   const QString& passphrase,
                   const QFileInfo& inputFileInfo,
                   const QFileInfo& outputFileInfo,
                   const QString& algorithmName,
                   std::size_t keySize);

  bool decryptFile(std::size_t id,
                   const QString& passphrase,
                   const QFileInfo& inputFilePath,
                   const QFileInfo& outputFilePath,
                   const QByteArray& algorithmNameByteArray,
                   const QByteArray& keySizeByteArray,
                   const QByteArray& pbkdfSaltByteArray,
                   const QByteArray& keySaltByteArray,
                   const QByteArray& ivSaltByteArray);

  bool executeCipher(std::size_t id, Kryvo::CryptDirection direction,
                     QFile* inFile, QSaveFile* outFile);

  OpenSslProvider* const q_ptr{nullptr};

  DispatcherState* state{nullptr};

  const std::size_t kPbkdfIterations{15000};
};

Kryvo::OpenSslProviderPrivate::OpenSslProviderPrivate(OpenSslProvider* pro)
  : q_ptr(pro) {
}

void Kryvo::OpenSslProviderPrivate::init(DispatcherState* ds) {
  state = ds;
}

bool Kryvo::OpenSslProviderPrivate::encrypt(const std::size_t id,
                                            const QString& compressionFormat,
                                            const QString& passphrase,
                                            const QFileInfo& inputFileInfo,
                                            const QFileInfo& outputFileInfo,
                                            const QString& cipher,
                                            const std::size_t keySize,
                                            const QString& modeOfOperation) {
  Q_Q(OpenSslProvider);
  Q_ASSERT(state);

  if (!state) {
    emit q->errorMessage(Constants::kMessages[0], QFileInfo());
    emit q->fileFailed(id);
    return false;
  }

  if (state->isAborted() || state->isStopped(id)) {
    emit q->errorMessage(Kryvo::Constants::kMessages[3], inputFileInfo);
    emit q->fileFailed(id);

    return false;
  }

  const QString& algorithm = [&cipher, &keySize, &modeOfOperation]() {
    QString algo = QString(cipher % QStringLiteral("/") % modeOfOperation);

    if (QStringLiteral("AES") == cipher) {
      algo = QString(cipher % QStringLiteral("-") % QString::number(keySize) %
                     QStringLiteral("/") % modeOfOperation);
    }

    return algo;
  }();

  const bool success = encryptFile(id, compressionFormat, passphrase,
                                   inputFileInfo, outputFileInfo, algorithm,
                                   keySize);

  if (state->isAborted() || state->isStopped(id)) {
    emit q->errorMessage(Kryvo::Constants::kMessages[3], inputFileInfo);
    emit q->fileFailed(id);

    return false;
  }

  return success;
}

bool Kryvo::OpenSslProviderPrivate::decrypt(const std::size_t id,
                                            const QString& passphrase,
                                            const QFileInfo& inputFileInfo,
                                            const QFileInfo& outputFileInfo,
                                            const QByteArray& algorithmNameString,
                                            const QByteArray& keySizeString,
                                            const QByteArray& pbkdfSaltString,
                                            const QByteArray& keySaltString,
                                            const QByteArray& ivSaltString) {
  Q_Q(OpenSslProvider);
  Q_ASSERT(state);

  if (!state) {
    emit q->errorMessage(Constants::kMessages[0], QFileInfo());
    emit q->fileFailed(id);
    return false;
  }

  if (state->isAborted() || state->isStopped(id)) {
    emit q->errorMessage(Kryvo::Constants::kMessages[4], inputFileInfo);
    emit q->fileFailed(id);

    return false;
  }

  const bool success = decryptFile(id, passphrase, inputFileInfo,
                                   outputFileInfo, algorithmNameString,
                                   keySizeString, pbkdfSaltString,
                                   keySaltString, ivSaltString);

  if (state->isAborted() || state->isStopped(id)) {
    emit q->errorMessage(Kryvo::Constants::kMessages[4], inputFileInfo);
    emit q->fileFailed(id);

    return false;
  }

  return success;
}

bool Kryvo::OpenSslProviderPrivate::encryptFile(
  const std::size_t id, const QString& compressionFormat,
  const QString& passphrase, const QFileInfo& inputFileInfo,
  const QFileInfo& outputFileInfo, const QString& algorithmName,
  const std::size_t keySize) {
  Q_Q(OpenSslProvider);
  Q_ASSERT(state);

  if (!state) {
    emit q->errorMessage(Constants::kMessages[0], QFileInfo());
    emit q->fileFailed(id);
    return false;
  }

  if (state->isAborted() || state->isStopped(id)) {
    emit q->fileFailed(id);
    return false;
  }

  if (!inputFileInfo.exists() || !inputFileInfo.isFile() ||
      !inputFileInfo.isReadable()) {
    emit q->errorMessage(Constants::kMessages[5], inputFileInfo);
    emit q->fileFailed(id);
    return false;
  }

  // Setup

  QFile inFile(inputFileInfo.absoluteFilePath());
  const bool inFileOpen = inFile.open(QIODevice::ReadOnly);

  if (!inFileOpen) {
    emit q->errorMessage(Constants::kMessages[5], inputFileInfo);
    emit q->fileFailed(id);
    return false;
  }

  QSaveFile outFile(outputFileInfo.absoluteFilePath());
  const bool outFileOpen = outFile.open(QIODevice::WriteOnly);

  if (!outFileOpen) {
    outFile.cancelWriting();
    emit q->errorMessage(Constants::kMessages[8], inputFileInfo);
    emit q->fileFailed(id);
    return false;
  }

  QHash<QByteArray, QByteArray> headerData;

  headerData.insert(QByteArrayLiteral("Version"),
                    QByteArray::number(Constants::kFileVersion));
  headerData.insert(QByteArrayLiteral("Cryptography provider"),
                    QByteArrayLiteral("Botan"));

  if (!compressionFormat.isEmpty() &&
      compressionFormat != QStringLiteral("None")) {
    headerData.insert(QByteArrayLiteral("Compression format"),
                      compressionFormat.toUtf8());
  }

  headerData.insert(QByteArrayLiteral("Algorithm name"),
                    algorithmName.toUtf8());

  headerData.insert(QByteArrayLiteral("Key size"),
                    QByteArray::number(static_cast<uint>(keySize)));

  const std::string& pbkdfSaltString =
    Botan::base64_encode(&pbkdfSalt[0], pbkdfSalt.size());

  headerData.insert(QByteArrayLiteral("PBKDF salt"),
                    QString::fromStdString(pbkdfSaltString).toUtf8());

  const std::string& keySaltString =
    Botan::base64_encode(&keySalt[0], keySalt.size());

  headerData.insert(QByteArrayLiteral("Key salt"),
                    QString::fromStdString(keySaltString).toUtf8());

  const std::string& ivSaltString =
    Botan::base64_encode(&ivSalt[0], ivSalt.size());

  headerData.insert(QByteArrayLiteral("IV salt"),
                    QString::fromStdString(ivSaltString).toUtf8());

  writeHeader(&outFile, headerData);

//  const bool success = executeCipher(id, Kryvo::CryptDirection::Encrypt,
//                                     &inFile, &outFile);

  if (!success) {
    outFile.cancelWriting();
    emit q->errorMessage(Constants::kMessages[8], inputFileInfo);
    emit q->fileFailed(id);
    return false;
  }

  if (state->isAborted() || state->isStopped(id)) {
    outFile.cancelWriting();
    emit q->fileFailed(id);
    return false;
  }

  outFile.commit();

  // Progress: finished
  emit q->fileProgress(id, QObject::tr("Encrypted"), 100);

  // Encryption success message
  emit q->statusMessage(
    Constants::kMessages[1].arg(inputFileInfo.absoluteFilePath()));

  emit q->fileCompleted(id);

  return success;
}

bool Kryvo::OpenSslProviderPrivate::decryptFile(const std::size_t id,
                                                const QString& passphrase,
                                                const QFileInfo& inputFilePath,
                                                const QFileInfo& outputFilePath,
                                                const QByteArray& algorithmNameByteArray,
                                                const QByteArray& keySizeByteArray,
                                                const QByteArray& pbkdfSaltByteArray,
                                                const QByteArray& keySaltByteArray,
                                                const QByteArray& ivSaltByteArray) {
  Q_Q(OpenSslProvider);
  Q_ASSERT(state);

  if (!state) {
    emit q->errorMessage(Constants::kMessages[0], QFileInfo());
    emit q->fileFailed(id);
    return false;
  }

  if (state->isAborted()) {
    emit q->fileFailed(id);
    return false;
  }

  const QFileInfo inputFileInfo(inputFilePath);

  if (!inputFileInfo.exists() || !inputFileInfo.isFile() ||
      !inputFileInfo.isReadable()) {
    emit q->errorMessage(Constants::kMessages[5], inputFilePath);
    emit q->fileFailed(id);
    return false;
  }

  QFile inFile(inputFilePath.absoluteFilePath());

  const bool inFileOpen = inFile.open(QIODevice::ReadOnly);

  if (!inFileOpen) {
    emit q->errorMessage(Constants::kMessages[5], inputFilePath);
    emit q->fileFailed(id);
    return false;
  }

  for (int i = 0; i < 8; ++i) { // Skip header as it was already read
    inFile.readLine();
  }

  QSaveFile outFile(outputFilePath.absoluteFilePath());

  const bool outFileOpen = outFile.open(QIODevice::WriteOnly);

  if (!outFileOpen) {
    outFile.cancelWriting();
    emit q->errorMessage(Constants::kMessages[7], inputFilePath);
    emit q->fileFailed(id);
    return false;
  }

  // Set up the key derive functions
  const std::size_t macSize = 512;

  // PKCS5_PBKDF2 takes ownership of the new HMAC and the HMAC takes ownership
  // of the Keccak_1600 hash function object (via unique_ptr)
//  Botan::PKCS5_PBKDF2 pbkdf(new Botan::HMAC(new Botan::Keccak_1600(macSize)));

  // Create the PBKDF key

  const std::size_t pbkdfKeySize = 256;

  const std::string& passphraseString = passphrase.toStdString();

  // PBKDF

  // Create the key and IV

  // Key salt

  bool keySizeIntOk = false;

  const int keySizeInt = keySizeString.toInt(&keySizeIntOk);

  if (!keySizeIntOk) {
    outFile.cancelWriting();
    emit q->errorMessage(Constants::kMessages[7], inputFilePath);
    emit q->fileFailed(id);
    return false;
  }

  const std::size_t keySize = static_cast<std::size_t>(keySizeInt);

  const std::size_t keySizeInBytes = keySize / 8;

  const bool success = executeCipher(id, Kryvo::CryptDirection::Decrypt,
                                     &inFile, &outFile);

  if (!success) {
    outFile.cancelWriting();
    emit q->errorMessage(Constants::kMessages[7], inputFilePath);
    emit q->fileFailed(id);
    return false;
  }

  if (state->isAborted() || state->isStopped(id)) {
    outFile.cancelWriting();
    emit q->fileFailed(id);
    return false;
  }

  outFile.commit();

  // Progress: finished
  emit q->fileProgress(id, QObject::tr("Decrypted"), 100);

  // Decryption success message
  emit q->statusMessage(
    Constants::kMessages[2].arg(inputFileInfo.absoluteFilePath()));

  emit q->fileCompleted(id);

  return true;
}

bool Kryvo::OpenSslProviderPrivate::executeCipher(
  const std::size_t id, const Kryvo::CryptDirection direction, QFile* inFile,
  QSaveFile* outFile) {
  Q_Q(OpenSslProvider);
  Q_ASSERT(state);
  Q_ASSERT(inFile);
  Q_ASSERT(outFile);

  // Define a size for the buffer vector
//  const std::size_t bufferSize = 4096;
//  Botan::secure_vector<Botan::byte> buffer;
//  buffer.resize(bufferSize);

  // Get file size for percent progress calculation
  const qint64 size = inFile->size();

  qint64 fileIndex = 0;
  qint64 percent = -1;

//  pipe->start_msg();

  while (!inFile->atEnd() && !state->isAborted() && !state->isStopped(id)) {
    while (state->isPaused()) {
      // Wait while paused
    }

//    const qint64 readSize =
//      inFile->read(reinterpret_cast<char*>(&buffer[0]), buffer.size());

//    if (readSize < 0) {
//      outFile->cancelWriting();
//      emit q->errorMessage(Constants::kMessages[5], inFile->fileName());
//      emit q->fileFailed(id);
//      return false;
//    }

//    pipe->write(&buffer[0], static_cast<std::size_t>(readSize));

    // Calculate progress in percent
//    fileIndex += readSize;

    const double fractionalProgress = static_cast<double>(fileIndex) /
                                      static_cast<double>(size);

    const double percentProgress = fractionalProgress * 100.0;

    const int percentProgressInteger = static_cast<int>(percentProgress);

    if (percentProgressInteger > percent && percentProgressInteger < 100) {
      percent = percentProgressInteger;

      const QString& task = Kryvo::CryptDirection::Encrypt == direction ?
                            QObject::tr("Encrypting") :
                            QObject::tr("Decrypting");

      emit q->fileProgress(id, task, percent);
    }

    if (inFile->atEnd()) {
//      pipe->end_msg();
    }

//    while (pipe->remaining() > 0) {
//      const std::size_t buffered = pipe->read(&buffer[0], buffer.size());

//      if (buffered < 0) {
//        if (Botan::ENCRYPTION == direction) {
//          outFile->cancelWriting();
//          emit q->errorMessage(Constants::kMessages[8], inFile->fileName());
//          emit q->fileFailed(id);
//          return false;
//        } else {
//          outFile->cancelWriting();
//          emit q->errorMessage(Constants::kMessages[7], inFile->fileName());
//          emit q->fileFailed(id);
//          return false;
//        }
//      }

//      const qint64 writeSize =
//        outFile->write(reinterpret_cast<const char*>(&buffer[0]), buffered);

//      if (writeSize < 0) {
//        if (Botan::ENCRYPTION == direction) {
//          outFile->cancelWriting();
//          emit q->errorMessage(Constants::kMessages[8], inFile->fileName());
//          emit q->fileFailed(id);
//          return false;
//        } else {
//          outFile->cancelWriting();
//          emit q->errorMessage(Constants::kMessages[7], inFile->fileName());
//          emit q->fileFailed(id);
//          return false;
//        }
//      }
//    }
  }

  return true;
}

Kryvo::OpenSslProvider::OpenSslProvider(QObject* parent)
  : QObject(parent),
    d_ptr(std::make_unique<OpenSslProviderPrivate>(this)) {
}

Kryvo::OpenSslProvider::~OpenSslProvider() = default;

void Kryvo::OpenSslProvider::init(DispatcherState* state) {
  Q_D(OpenSslProvider);

  d->init(state);
}

bool Kryvo::OpenSslProvider::encrypt(const std::size_t id,
                                     const QString& compressionFormat,
                                     const QString& passphrase,
                                     const QFileInfo& inputFileInfo,
                                     const QFileInfo& outputFileInfo,
                                     const QString& cipher,
                                     const std::size_t keySize,
                                     const QString& modeOfOperation) {
  Q_D(OpenSslProvider);

  return d->encrypt(id, compressionFormat, passphrase, inputFileInfo,
                    outputFileInfo, cipher, keySize, modeOfOperation);
}

bool Kryvo::OpenSslProvider::decrypt(const std::size_t id,
                                     const QString& passphrase,
                                     const QFileInfo& inputFileInfo,
                                     const QFileInfo& outputFileInfo,
                                     const QByteArray& algorithmNameByteArray,
                                     const QByteArray& keySizeByteArray,
                                     const QByteArray& pbkdfSaltByteArray,
                                     const QByteArray& keySaltByteArray,
                                     const QByteArray& ivSaltByteArray) {
  Q_D(OpenSslProvider);

  return d->decrypt(id, passphrase, inputFileInfo, outputFileInfo,
                    algorithmNameByteArray, keySizeByteArray,
                    pbkdfSaltByteArray, keySaltByteArray, ivSaltByteArray);
}

QObject* Kryvo::OpenSslProvider::qObject() {
  return this;
}
