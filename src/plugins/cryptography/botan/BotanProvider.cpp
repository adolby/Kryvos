#include "BotanProvider.hpp"
#include "DispatcherState.hpp"
#include "Constants.hpp"
#include "FileUtility.h"
#include <QSaveFile>
#include <QFile>
#include <QFileInfo>
#include <QDir>
#include <QStringBuilder>
#include <string>
#include <QHash>
#include <stdexcept>

class Kryvo::BotanProviderPrivate {
  Q_DISABLE_COPY(BotanProviderPrivate)
  Q_DECLARE_PUBLIC(BotanProvider)

 public:
  BotanProviderPrivate(BotanProvider* pro);

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
               const QByteArray& pbkdfByteArray,
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
                   const QFileInfo& inputFileInfo,
                   const QFileInfo& outputFileInfo,
                   const QByteArray& algorithmNameByteArray,
                   const QByteArray& keySizeByteArray,
                   const QByteArray& pbkdfSaltByteArray,
                   const QByteArray& keySaltByteArray,
                   const QByteArray& ivSaltByteArray);

  bool executeCipher(std::size_t id, Kryvo::CryptDirection direction,
                     QFile* inFile, QSaveFile* outFile, Botan::Pipe* pipe);

  BotanProvider* const q_ptr{nullptr};

  DispatcherState* state{nullptr};

  const std::string kKDFHash{"KDF2(Keccak-1600)"};
  const std::string kKeyLabel{"user secret"};
  const std::string kIVLabel{"initialization vector"};
  const std::size_t kPbkdfIterations{15000};
};

Kryvo::BotanProviderPrivate::BotanProviderPrivate(BotanProvider* pro)
  : q_ptr(pro) {
}

void Kryvo::BotanProviderPrivate::init(DispatcherState* ds) {
  state = ds;
}

bool Kryvo::BotanProviderPrivate::encrypt(const std::size_t id,
                                          const QString& compressionFormat,
                                          const QString& passphrase,
                                          const QFileInfo& inputFileInfo,
                                          const QFileInfo& outputFileInfo,
                                          const QString& cipher,
                                          const std::size_t keySize,
                                          const QString& modeOfOperation) {
  Q_Q(BotanProvider);
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

  bool success = false;

  try {
    success = encryptFile(id, compressionFormat, passphrase, inputFileInfo,
                          outputFileInfo, algorithm, keySize);
  }
  catch (const Botan::Stream_IO_Error&) {
    emit q->errorMessage(Kryvo::Constants::kMessages[8], inputFileInfo);
    emit q->fileFailed(id);
    return false;
  }
  catch (const Botan::Invalid_Argument&) {
    emit q->errorMessage(Kryvo::Constants::kMessages[8], inputFileInfo);
    emit q->fileFailed(id);
    return false;
  }
  catch (const Botan::Exception& e) {
    emit q->errorMessage(QStringLiteral("Error: ") % QString(e.what()),
                         inputFileInfo);
    emit q->fileFailed(id);
    return false;
  }
  catch (const std::invalid_argument&) {
    emit q->errorMessage(Kryvo::Constants::kMessages[8], inputFileInfo);
    emit q->fileFailed(id);
    return false;
  }
  catch (const std::exception& e) {
    emit q->errorMessage(QStringLiteral("Error: ") % QString(e.what()),
                         inputFileInfo);
    emit q->fileFailed(id);
    return false;
  }

  if (state->isAborted() || state->isStopped(id)) {
    emit q->errorMessage(Kryvo::Constants::kMessages[3], inputFileInfo);
    emit q->fileFailed(id);

    return false;
  }

  return success;
}

bool Kryvo::BotanProviderPrivate::decrypt(
  const std::size_t id, const QString& passphrase,
  const QFileInfo& inputFileInfo, const QFileInfo& outputFileInfo,
  const QByteArray& algorithmNameByteArray, const QByteArray& keySizeByteArray,
  const QByteArray& pbkdfSaltByteArray, const QByteArray& keySaltByteArray,
  const QByteArray& ivSaltByteArray) {
  Q_Q(BotanProvider);
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

  bool success = false;

  try {
    success = decryptFile(id, passphrase, inputFileInfo, outputFileInfo,
                          algorithmNameByteArray, keySizeByteArray,
                          pbkdfSaltByteArray, keySaltByteArray,
                          ivSaltByteArray);
  }
  catch (const Botan::Stream_IO_Error&) {
    emit q->errorMessage(Constants::kMessages[7], inputFileInfo);
    emit q->fileFailed(id);
    return false;
  }
  catch (const Botan::Invalid_Argument&) {
    emit q->errorMessage(Constants::kMessages[7], inputFileInfo);
    emit q->fileFailed(id);
    return false;
  }
  catch (const Botan::Lookup_Error&) {
    emit q->errorMessage(Constants::kMessages[7], inputFileInfo);
    emit q->fileFailed(id);
    return false;
  }
  catch (const Botan::Exception& e) {
    emit q->errorMessage(QStringLiteral("Error: ") % QString(e.what()),
                         inputFileInfo);
    emit q->fileFailed(id);
    return false;
  }
  catch (const std::invalid_argument&) {
    emit q->errorMessage(Constants::kMessages[7], inputFileInfo);
    emit q->fileFailed(id);
    return false;
  }
  catch (const std::exception& e) {
    emit q->errorMessage(QStringLiteral("Error: ") % QString(e.what()),
                         inputFileInfo);
    emit q->fileFailed(id);
    return false;
  }

  if (state->isAborted() || state->isStopped(id)) {
    emit q->errorMessage(Kryvo::Constants::kMessages[4], inputFileInfo);
    emit q->fileFailed(id);

    return false;
  }

  return success;
}

bool Kryvo::BotanProviderPrivate::encryptFile(
  const std::size_t id, const QString& compressionFormat,
  const QString& passphrase, const QFileInfo& inputFileInfo,
  const QFileInfo& outputFileInfo, const QString& algorithmName,
  const std::size_t keySize) {
  Q_Q(BotanProvider);
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

  Botan::AutoSeeded_RNG rng;

  // Define a size for the PBKDF salt vector
  const std::size_t pbkdfSaltSize = 256;
  Botan::secure_vector<Botan::byte> pbkdfSalt;
  pbkdfSalt.resize(pbkdfSaltSize);

  // Create random PBKDF salt
  rng.randomize(&pbkdfSalt[0], pbkdfSalt.size());

  // Set up the key derive functions
  const std::size_t macSize = 512;

  // PKCS5_PBKDF2 takes ownership of the new HMAC and the HMAC takes ownership
  // of the Keccak_1600 hash function object (both via unique_ptr)
  Botan::PKCS5_PBKDF2 pbkdf(new Botan::HMAC(new Botan::Keccak_1600(macSize)));

  // Create the PBKDF key
  const std::size_t pbkdfKeySize = 256;

  const std::string& passphraseString = passphrase.toStdString();

  Botan::secure_vector<Botan::byte> pbkdfKey =
    pbkdf.derive_key(pbkdfKeySize, passphraseString, &pbkdfSalt[0],
                     pbkdfSalt.size(), kPbkdfIterations).bits_of();

  // Create the key and IV
  std::unique_ptr<Botan::KDF> kdf(Botan::KDF::create(kKDFHash));

  // Set up key salt size
  const std::size_t keySaltSize = 64;
  Botan::secure_vector<Botan::byte> keySalt;
  keySalt.resize(keySaltSize);
  rng.randomize(&keySalt[0], keySalt.size());

  // Key is constrained to sizes allowed by algorithm
  const std::size_t keySizeInBytes = keySize / 8;
  const auto* keyLabelVector =
    reinterpret_cast<const Botan::byte*>(kKeyLabel.data());
  Botan::SymmetricKey key(kdf->derive_key(keySizeInBytes,
                                          pbkdfKey.data(),
                                          pbkdfKey.size(),
                                          keySalt.data(),
                                          keySalt.size(),
                                          keyLabelVector,
                                          kKeyLabel.size()));

  // Set up IV salt size
  const std::size_t ivSaltSize = 64;
  Botan::secure_vector<Botan::byte> ivSalt;
  ivSalt.resize(ivSaltSize);
  rng.randomize(&ivSalt[0], ivSalt.size());

  const std::size_t ivSize = 256;
  const auto* ivLabelVector =
    reinterpret_cast<const Botan::byte*>(kIVLabel.data());
  Botan::InitializationVector iv(kdf->derive_key(ivSize,
                                                 pbkdfKey.data(),
                                                 pbkdfKey.size(),
                                                 ivSalt.data(),
                                                 ivSalt.size(),
                                                 ivLabelVector,
                                                 kIVLabel.size()));

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

  Botan::Pipe pipe;

  pipe.append_filter(Botan::get_cipher(algorithmName.toStdString(), key, iv,
                                       Botan::ENCRYPTION));

  const bool success = executeCipher(id, Kryvo::CryptDirection::Encrypt,
                                     &inFile, &outFile, &pipe);

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

bool Kryvo::BotanProviderPrivate::decryptFile(
  const std::size_t id, const QString& passphrase,
  const QFileInfo& inputFileInfo, const QFileInfo& outputFileInfo,
  const QByteArray& algorithmNameByteArray, const QByteArray& keySizeByteArray,
  const QByteArray& pbkdfSaltByteArray, const QByteArray& keySaltByteArray,
  const QByteArray& ivSaltByteArray) {
  Q_Q(BotanProvider);
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

  if (!inputFileInfo.exists() || !inputFileInfo.isFile() ||
      !inputFileInfo.isReadable()) {
    emit q->errorMessage(Constants::kMessages[5], inputFileInfo);
    emit q->fileFailed(id);
    return false;
  }

  QFile inFile(inputFileInfo.absoluteFilePath());

  const bool inFileOpen = inFile.open(QIODevice::ReadOnly);

  if (!inFileOpen) {
    emit q->errorMessage(Constants::kMessages[5], inputFileInfo);
    emit q->fileFailed(id);
    return false;
  }

  readHeader(&inFile);

  QSaveFile outFile(outputFileInfo.absoluteFilePath());

  const bool outFileOpen = outFile.open(QIODevice::WriteOnly);

  if (!outFileOpen) {
    outFile.cancelWriting();
    emit q->errorMessage(Constants::kMessages[7], inputFileInfo);
    emit q->fileFailed(id);
    return false;
  }

  // Set up the key derive functions
  const std::size_t macSize = 512;

  // PKCS5_PBKDF2 takes ownership of the new HMAC and the HMAC takes ownership
  // of the Keccak_1600 hash function object (via unique_ptr)
  Botan::PKCS5_PBKDF2 pbkdf(new Botan::HMAC(new Botan::Keccak_1600(macSize)));

  // Create the PBKDF key
  const Botan::secure_vector<Botan::byte>& pbkdfSalt =
    Botan::base64_decode(pbkdfSaltByteArray.toStdString());

  const std::size_t pbkdfKeySize = 256;

  const std::string& passphraseString = passphrase.toStdString();

  const Botan::secure_vector<Botan::byte>& pbkdfKey =
    pbkdf.derive_key(pbkdfKeySize, passphraseString, &pbkdfSalt[0],
                     pbkdfSalt.size(), kPbkdfIterations).bits_of();

  // Create the key and IV
  std::unique_ptr<Botan::KDF> kdf(Botan::KDF::create(kKDFHash));

  // Key salt
  const Botan::secure_vector<Botan::byte>& keySalt =
    Botan::base64_decode(keySaltByteArray.toStdString());

  bool keySizeIntOk = false;

  const int keySizeInt = keySizeByteArray.toInt(&keySizeIntOk);

  if (!keySizeIntOk) {
    outFile.cancelWriting();
    emit q->errorMessage(Constants::kMessages[7], inputFileInfo);
    emit q->fileFailed(id);
    return false;
  }

  const std::size_t keySize = static_cast<std::size_t>(keySizeInt);

  const std::size_t keySizeInBytes = keySize / 8;

  const auto* keyLabelVector =
    reinterpret_cast<const Botan::byte*>(kKeyLabel.data());

  Botan::SymmetricKey key(kdf->derive_key(keySizeInBytes,
                                          pbkdfKey.data(),
                                          pbkdfKey.size(),
                                          keySalt.data(),
                                          keySalt.size(),
                                          keyLabelVector,
                                          kKeyLabel.size()));

  const Botan::secure_vector<Botan::byte>& ivSalt =
    Botan::base64_decode(ivSaltByteArray.toStdString());
  const std::size_t ivSize = 256;
  const auto* ivLabelVector =
    reinterpret_cast<const Botan::byte*>(kIVLabel.data());
  Botan::InitializationVector iv(kdf->derive_key(ivSize,
                                                 pbkdfKey.data(),
                                                 pbkdfKey.size(),
                                                 ivSalt.data(),
                                                 ivSalt.size(),
                                                 ivLabelVector,
                                                 kIVLabel.size()));

  Botan::Pipe pipe;

  pipe.append_filter(Botan::get_cipher(algorithmNameByteArray.toStdString(),
                                       key, iv, Botan::DECRYPTION));

  const bool success = executeCipher(id, Kryvo::CryptDirection::Decrypt,
                                     &inFile, &outFile, &pipe);

  if (!success) {
    outFile.cancelWriting();
    emit q->errorMessage(Constants::kMessages[7], inputFileInfo);
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

bool Kryvo::BotanProviderPrivate::executeCipher(
  const std::size_t id, const Kryvo::CryptDirection direction,
  QFile* inFile, QSaveFile* outFile, Botan::Pipe* pipe) {
  Q_Q(BotanProvider);
  Q_ASSERT(state);
  Q_ASSERT(inFile);
  Q_ASSERT(outFile);
  Q_ASSERT(pipe);

  // Define a size for the buffer vector
  const std::size_t bufferSize = 4096;
  Botan::secure_vector<Botan::byte> buffer;
  buffer.resize(bufferSize);

  // Get file size for percent progress calculation
  const qint64 size = inFile->size();

  qint64 fileIndex = 0;
  qint64 percent = -1;

  pipe->start_msg();

  while (!inFile->atEnd() && !state->isAborted() && !state->isStopped(id)) {
    while (state->isPaused()) {
      // Wait while paused
    }

    const qint64 readSize =
      inFile->read(reinterpret_cast<char*>(&buffer[0]), buffer.size());

    if (readSize < 0) {
      outFile->cancelWriting();
      emit q->errorMessage(Constants::kMessages[5],
                           QFileInfo(inFile->fileName()));
      emit q->fileFailed(id);
      return false;
    }

    pipe->write(&buffer[0], static_cast<std::size_t>(readSize));

    // Calculate progress in percent
    fileIndex += readSize;

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
      pipe->end_msg();
    }

    while (pipe->remaining() > 0) {
      const std::size_t buffered = pipe->read(&buffer[0], buffer.size());

      if (buffered < 0) {
        outFile->cancelWriting();

        if (Kryvo::CryptDirection::Encrypt == direction) {
          emit q->errorMessage(Constants::kMessages[8], inFile->fileName());
        } else {
          emit q->errorMessage(Constants::kMessages[7], inFile->fileName());
        }

        emit q->fileFailed(id);
        return false;
      }

      const qint64 writeSize =
        outFile->write(reinterpret_cast<const char*>(&buffer[0]), buffered);

      if (writeSize < 0) {
        outFile->cancelWriting();

        if (Kryvo::CryptDirection::Encrypt == direction) {
          emit q->errorMessage(Constants::kMessages[8], inFile->fileName());
        } else {
          emit q->errorMessage(Constants::kMessages[7], inFile->fileName());
        }

        emit q->fileFailed(id);
        return false;
      }
    }
  }

  return true;
}

Kryvo::BotanProvider::BotanProvider(QObject* parent)
  : QObject(parent),
    d_ptr(std::make_unique<BotanProviderPrivate>(this)) {
}

Kryvo::BotanProvider::~BotanProvider() = default;

void Kryvo::BotanProvider::init(DispatcherState* state) {
  Q_D(BotanProvider);

  d->init(state);
}

bool Kryvo::BotanProvider::encrypt(const std::size_t id,
                                   const QString& compressionFormat,
                                   const QString& passphrase,
                                   const QFileInfo& inputFileInfo,
                                   const QFileInfo& outputFileInfo,
                                   const QString& cipher,
                                   const std::size_t keySize,
                                   const QString& modeOfOperation) {
  Q_D(BotanProvider);

  return d->encrypt(id, compressionFormat, passphrase, inputFileInfo,
                    outputFileInfo, cipher, keySize, modeOfOperation);
}

bool Kryvo::BotanProvider::decrypt(const std::size_t id,
                                   const QString& passphrase,
                                   const QFileInfo& inputFileInfo,
                                   const QFileInfo& outputFileInfo,
                                   const QByteArray& algorithmNameByteArray,
                                   const QByteArray& keySizeByteArray,
                                   const QByteArray& pbkdfSaltByteArray,
                                   const QByteArray& keySaltByteArray,
                                   const QByteArray& ivSaltByteArray) {
  Q_D(BotanProvider);

  return d->decrypt(id, passphrase, inputFileInfo, outputFileInfo,
                    algorithmNameByteArray, keySizeByteArray,
                    pbkdfSaltByteArray, keySaltByteArray, ivSaltByteArray);
}

QObject* Kryvo::BotanProvider::qObject() {
  return this;
}
