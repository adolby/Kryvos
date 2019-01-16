#include "Dispatcher.hpp"
#include "DispatcherState.hpp"
#include "archive/Archiver.hpp"
#include "cryptography/Crypto.hpp"
#include "Constants.hpp"
#include "utility/Thread.hpp"
#include <QCoreApplication>

#include <QDebug>

class Kryvo::DispatcherPrivate {
  Q_DISABLE_COPY(DispatcherPrivate)
  Q_DECLARE_PUBLIC(Dispatcher)

 public:
  DispatcherPrivate(Dispatcher* q);

  void dispatch();

  void processPipeline(int pipelineId);

  void encrypt(const QString& passphrase,
               const QStringList& inputFilePaths,
               const QString& outputPath,
               const QString& cipher,
               std::size_t inputKeySize,
               const QString& modeOfOperation,
               bool compress);

  void decrypt(const QString& passphrase,
               const QStringList& inputFilePaths,
               const QString& outputPath);

  Dispatcher* const q_ptr{nullptr};

  DispatcherState state;

  Archiver archiver;
  Thread archiverThread;
  Crypto cryptographer;
  Thread cryptographerThread;

  std::vector<Pipeline> pipelines;
};

Kryvo::DispatcherPrivate::DispatcherPrivate(Dispatcher* dispatcher)
  : q_ptr(dispatcher), archiver(&state), cryptographer(&state) {
  archiver.moveToThread(&archiverThread);
  cryptographer.moveToThread(&cryptographerThread);

  QObject::connect(&archiver, &Archiver::fileProgress,
                   q_ptr, &Dispatcher::updateFileProgress);

  QObject::connect(&archiver, &Archiver::statusMessage,
                   q_ptr, &Dispatcher::statusMessage);

  QObject::connect(&archiver, &Archiver::errorMessage,
                   q_ptr, &Dispatcher::errorMessage);

  QObject::connect(q_ptr, &Dispatcher::compressFile,
                   &archiver, &Archiver::compress);

  QObject::connect(q_ptr, &Dispatcher::decompressFile,
                   &archiver, &Archiver::decompress);

  QObject::connect(&archiver, &Archiver::fileCompressed,
                   q_ptr, &Dispatcher::processPipeline);

  QObject::connect(&archiver, &Archiver::fileDecompressed,
                   q_ptr, &Dispatcher::processPipeline);

  QObject::connect(&cryptographer, &Crypto::fileProgress,
                   q_ptr, &Dispatcher::updateFileProgress);

  QObject::connect(&cryptographer, &Crypto::statusMessage,
                   q_ptr, &Dispatcher::statusMessage);

  QObject::connect(&cryptographer, &Crypto::errorMessage,
                   q_ptr, &Dispatcher::errorMessage);

  QObject::connect(q_ptr, &Dispatcher::encryptFile,
                   &cryptographer, &Crypto::encrypt);

  QObject::connect(q_ptr, &Dispatcher::decryptFile,
                   &cryptographer, &Crypto::decrypt);

  QObject::connect(&cryptographer, &Crypto::fileEncrypted,
                   q_ptr, &Dispatcher::processPipeline);

  QObject::connect(&cryptographer, &Crypto::fileDecrypted,
                   q_ptr, &Dispatcher::processPipeline);

  archiverThread.start();
  cryptographerThread.start();
}

void Kryvo::DispatcherPrivate::dispatch() {
  Q_Q(Dispatcher);

  bool finished = true;

  for (int i = 0; i < pipelines.size(); ++i) {
    const Pipeline& pipeline = pipelines.at(i);

    if (pipeline.stage < pipeline.stages.size()) {
      finished = false;
      processPipeline(i);
      break;
    }
  }

  if (finished) {
    state.reset();

    state.busy(false);
    emit q->busyStatus(state.isBusy());
  }
}

void Kryvo::DispatcherPrivate::processPipeline(int id) {
  Q_Q(Dispatcher);

  if (id >= pipelines.size()) {
    return;
  }

  Pipeline pipeline = pipelines.at(id);

  if (pipeline.stage >= pipeline.stages.size()) {
    dispatch();

    return;
  }

  const std::function<void(int)>& func = pipeline.stages.at(pipeline.stage);

  pipeline.stage = pipeline.stage + 1;

  pipelines[id] = pipeline;

  func(id);
}

void Kryvo::DispatcherPrivate::encrypt(const QString& passphrase,
                                       const QStringList& inputFilePaths,
                                       const QString& outputPath,
                                       const QString& cipher,
                                       std::size_t inputKeySize,
                                       const QString& modeOfOperation,
                                       bool compress) {
  Q_Q(Dispatcher);

  state.busy(true);
  emit q->busyStatus(state.isBusy());

  pipelines.clear();

  int id = 0;

  for (const QString& inputFilePath : inputFilePaths) {
    const std::size_t keySize = [&inputKeySize]() {
      std::size_t size = 128;

      if (inputKeySize > 0) {
        size = inputKeySize;
      }

      return size;
    }();

    const QDir outputDir(outputPath);

    // Create output path if it doesn't exist
    if (!outputDir.exists()) {
      outputDir.mkpath(outputPath);
    }

    const QFileInfo inputFileInfo(inputFilePath);
    const QString& inFilePath = inputFileInfo.absoluteFilePath();

    const QString& outPath = outputDir.exists() ?
                             outputDir.absolutePath() :
                             inputFileInfo.absolutePath();

    Pipeline pipeline;

    pipeline.inputFilePath = inputFilePath;

    id = id + 1;

    if (compress) {
      const QString& compressedFilePath =
        QString(outPath % QStringLiteral("/") % inputFileInfo.fileName() %
                Kryvo::Constants::kDot %
                Kryvo::Constants::kCompressedFileExtension);

      auto compressFunction =
        [this, q, inputFilePath, compressedFilePath](int id) {
          emit q->compressFile(id, inputFilePath, compressedFilePath);
        };

      pipeline.stages.push_back(compressFunction);

      const QString& encryptedFilePath =
        QString(compressedFilePath % Kryvo::Constants::kDot %
                Kryvo::Constants::kEncryptedFileExtension);

      auto encryptFunction =
        [this, q, passphrase, compressedFilePath, encryptedFilePath, cipher,
         keySize, modeOfOperation, compress](int id) {
          emit q->encryptFile(id, passphrase, compressedFilePath,
                              encryptedFilePath, cipher, keySize,
                              modeOfOperation, compress);
        };

      pipeline.stages.push_back(encryptFunction);
    } else {
      const QString& encryptedFilePath =
        QString(outPath % QStringLiteral("/") % inputFileInfo.fileName() %
                Kryvo::Constants::kDot %
                Kryvo::Constants::kEncryptedFileExtension);

      auto encryptFunction =
        [this, q, passphrase, inputFilePath, encryptedFilePath, cipher, keySize,
         modeOfOperation, compress](int id) {
          emit q->encryptFile(id, passphrase, inputFilePath,
                              encryptedFilePath, cipher, keySize,
                              modeOfOperation, compress);
        };

      pipeline.stages.push_back(encryptFunction);
    }

    pipelines.push_back(pipeline);
  }

  dispatch();
}

void Kryvo::DispatcherPrivate::decrypt(const QString& passphrase,
                                       const QStringList& inputFilePaths,
                                       const QString& outputPath) {
  Q_Q(Dispatcher);

  state.busy(true);
  emit q->busyStatus(state.isBusy());

  pipelines.clear();

  int id = 0;

  for (const QString& inputFilePath : inputFilePaths) {
    QFile inFile(inputFilePath);

    const bool inFileOpen = inFile.open(QIODevice::ReadOnly);

    if (!inFileOpen) {
      emit q->errorMessage(Constants::messages[5], inputFilePath);
    }

    // Read metadata from file

    // Read line but skip \n
    auto readLine = [](QFile* file) {
      if (file) {
        QByteArray line = file->readLine();
        return line.replace(QByteArrayLiteral("\n"), QByteArrayLiteral(""));
      }

      return QByteArray();
    };

    const QByteArray& headerString = readLine(&inFile);

    if (headerString != QByteArrayLiteral("-------- ENCRYPTED FILE --------")) {
      emit q->errorMessage(Constants::messages[7], inputFilePath);
    }

    const QString& algorithmNameString = readLine(&inFile);
    const QString& keySizeString = readLine(&inFile);
    const QString& compressString = readLine(&inFile);

    const QString& pbkdfSaltString = readLine(&inFile);
    const QString& keySaltString = readLine(&inFile);
    const QString& ivSaltString = readLine(&inFile);

    const QByteArray& footerString = readLine(&inFile);

    if (footerString !=
        QByteArrayLiteral("---------------------------------")) {
      emit q->errorMessage(Constants::messages[7], inputFilePath);
    }

    const QDir outputDir(outputPath);

    // Create output path if it doesn't exist
    if (!outputDir.exists()) {
      outputDir.mkpath(outputPath);
    }

    const QFileInfo inputFileInfo(inputFilePath);
    const QString& outPath = outputDir.exists() ?
                             outputDir.absolutePath() :
                             inputFileInfo.absolutePath();

    const QString& inFilePath = inputFileInfo.absoluteFilePath();

    const QString& outputFilePath = QString(outPath % QStringLiteral("/") %
                                            inputFileInfo.fileName());

    // Remove the .enc extensions if at the end of the file path
    const QString& decryptedFilePath =
      Constants::removeExtension(outputFilePath,
                                 Constants::kEncryptedFileExtension);

    // Create a unique file name for the file in this directory
    const QString& uniqueDecryptedFilePath =
      Constants::uniqueFilePath(decryptedFilePath);

    Pipeline pipeline;

    pipeline.inputFilePath = inputFilePath;

    id = id + 1;

    if (QByteArrayLiteral("Gzip Compressed") == compressString) {
      // Remove the gz extension if at the end of the file path
      const QString& decompressedFilePath =
        Constants::removeExtension(outputFilePath,
                                   Constants::kCompressedFileExtension);

      // Create a unique file name for the file in this directory
      const QString& uniqueDecompressedFilePath =
        Constants::uniqueFilePath(decompressedFilePath);

      auto decompress =
        [this, q, inputFilePath, uniqueDecompressedFilePath](int id) {
          emit q->decompressFile(id, inputFilePath, uniqueDecompressedFilePath);
        };

      pipeline.stages.push_back(decompress);

      auto decrypt =
        [this, q, passphrase, uniqueDecompressedFilePath,
         uniqueDecryptedFilePath, algorithmNameString, keySizeString,
         pbkdfSaltString, keySaltString, ivSaltString](int id) {
          emit q->decryptFile(id, passphrase, uniqueDecompressedFilePath,
                              uniqueDecryptedFilePath, algorithmNameString,
                              keySizeString, pbkdfSaltString, keySaltString,
                              ivSaltString);
        };

      pipeline.stages.push_back(decrypt);
    } else {
        auto decrypt =
          [this, q, passphrase, inputFilePath, uniqueDecryptedFilePath,
           algorithmNameString, keySizeString, pbkdfSaltString, keySaltString,
           ivSaltString](int id) {
            emit q->decryptFile(id, passphrase, inputFilePath,
                                uniqueDecryptedFilePath, algorithmNameString,
                                keySizeString, pbkdfSaltString, keySaltString,
                                ivSaltString);
          };

        pipeline.stages.push_back(decrypt);
    }

    pipelines[id] = pipeline;
  }

  dispatch();
}

Kryvo::Dispatcher::Dispatcher(QObject* parent)
  : QObject(parent), d_ptr(std::make_unique<DispatcherPrivate>(this)) {
}

Kryvo::Dispatcher::~Dispatcher() = default;

void Kryvo::Dispatcher::encrypt(const QString& passphrase,
                                const QStringList& inputFilePaths,
                                const QString& outputPath,
                                const QString& cipher,
                                std::size_t inputKeySize,
                                const QString& modeOfOperation,
                                bool compress) {
  Q_D(Dispatcher);

  d->encrypt(passphrase, inputFilePaths, outputPath, cipher, inputKeySize,
             modeOfOperation, compress);
}

void Kryvo::Dispatcher::decrypt(const QString& passphrase,
                                const QStringList& inputFilePaths,
                                const QString& outputPath) {
  Q_D(Dispatcher);

  d->decrypt(passphrase, inputFilePaths, outputPath);
}

void Kryvo::Dispatcher::abort() {
  Q_D(Dispatcher);

  if (d->state.isBusy()) {
    d->state.abort(true);
  }
}

void Kryvo::Dispatcher::pause(const bool pause) {
  Q_D(Dispatcher);

  d->state.pause(pause);
}

void Kryvo::Dispatcher::stop(const QString& filePath) {
  Q_D(Dispatcher);

  if (d->state.isBusy()) {
    int id = -1;

    for (int i = 0; i < d->pipelines.size(); ++i) {
      const Pipeline& pipeline = d->pipelines.at(i);

      if (pipeline.inputFilePath == filePath) {
        id = i;
        break;
      }
    }

    if (id > -1) {
      d->state.stop(id, true);
    }
  }
}

void Kryvo::Dispatcher::processPipeline(int id) {
  Q_D(Dispatcher);

  d->processPipeline(id);
}

void Kryvo::Dispatcher::updateFileProgress(const int id, const QString& task,
                                           const qint64 percentProgress) {
  Q_D(Dispatcher);

  if (id >= d->pipelines.size()) {
    return;
  }

  const Pipeline& pipeline = d->pipelines.at(id);

  emit fileProgress(pipeline.inputFilePath, task, percentProgress);
}
