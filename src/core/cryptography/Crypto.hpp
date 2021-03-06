#ifndef KRYVO_CRYPTOGRAPHY_CRYPTO_HPP_
#define KRYVO_CRYPTOGRAPHY_CRYPTO_HPP_

#include "SchedulerState.hpp"
#include "cryptography/CryptoProviderInterface.hpp"
#include "Plugin.hpp"
#include "utility/pimpl.h"
#include <QFileInfo>
#include <QObject>
#include <QString>
#include <memory>

namespace Kryvo {

class CryptoPrivate;

class Crypto : public QObject {
  Q_OBJECT
  Q_DISABLE_COPY(Crypto)
  DECLARE_PRIVATE(Crypto)
  std::unique_ptr<CryptoPrivate> const d_ptr;

 public:
  /*!
   * \brief Crypto Constructs the Crypto class
   * \param parent
   */
  explicit Crypto(SchedulerState* state, QObject* parent = nullptr);

  ~Crypto() override;

  /*!
   * \brief encryptFile Executed when a signal is received for encryption with a
   * passphrase, a list of input file paths, and the algorithm name
   * \param id Pipeline ID
   * \param cryptoProvider Cryptography provider name
   * \param compressionFormat Compression format name
   * \param passphrase String representing the user-entered passphrase
   * \param inputFileInfo File to encrypt
   * \param outputFileInfo Encrypted file
   * \param cipher String representing name of the cipher
   * \param keySize Key size (in bits)
   * \param modeOfOperation String representing mode of operation
   */
  bool encryptFile(std::size_t id,
                   const QString& cryptoProvider,
                   const QString& compressionFormat,
                   const QString& passphrase,
                   const QFileInfo& inputFileInfo,
                   const QFileInfo& outputFileInfo,
                   const QString& cipher,
                   std::size_t keySize,
                   const QString& modeOfOperation);

  /*!
   * \brief decryptFile Executed when a signal is received for decryption with a
   * passphrase and an input file path
   * \param id Pipeline ID
   * \param cryptoProvider Cryptography provider name
   * \param passphrase String representing the user-entered passphrase
   * \param inputFileInfo File to decrypt
   * \param outputFileInfo Decrypted file
   */
  bool decryptFile(std::size_t id,
                   const QString& cryptoProvider,
                   const QString& passphrase,
                   const QFileInfo& inputFileInfo,
                   const QFileInfo& outputFileInfo);

 signals:
  void fileCompleted(std::size_t id);
  void fileFailed(std::size_t id);

  /*!
   * \brief fileProgress Emitted when the cipher operation file progress changes
   * \param id ID representing the file to update progress on
   * \param task Path name string
   * \param percentProgress Integer representing the current progress as a
   * percent
   */
  void fileProgress(std::size_t id, const QString& task,
                    qint64 percentProgress);

  /*!
   * \brief statusMessage Emitted when a message about the current cipher
   * operation is produced
   * \param message Information message string
   */
  void statusMessage(const QString& message);

  /*!
   * \brief errorMessage Emitted when an error occurs
   * \param message Error message string
   * \param fileInfo File that encountered an error
   */
  void errorMessage(const QString& message, const QFileInfo& fileInfo);

 public slots:
  void updateProviders(const QHash<QString, Plugin>& loadedProviders);

  /*!
   * \brief encrypt Executed when a signal is received for encryption with a
   * passphrase, a list of input file paths, and the algorithm name
   * \param id Pipeline ID
   * \param cryptoProvider Cryptography provider name
   * \param compressionFormat Compression format name
   * \param passphrase String representing the user-entered passphrase
   * \param inputFileInfo File to encrypt
   * \param outputFileInfo Encrypted file
   * \param cipher String representing name of the cipher
   * \param keySize Key size (in bits)
   * \param modeOfOperation String representing mode of operation
   */
  void encrypt(std::size_t id,
               const QString& cryptoProvider,
               const QString& compressionFormat,
               const QString& passphrase,
               const QFileInfo& inputFileInfo,
               const QFileInfo& outputFileInfo,
               const QString& cipher,
               std::size_t keySize,
               const QString& modeOfOperation);

  /*!
   * \brief decrypt Executed when a signal is received for decryption with a
   * passphrase and an input file path
   * \param id Pipeline ID
   * \param cryptoProvider Cryptography provider name
   * \param passphrase String representing the user-entered passphrase
   * \param inputFileInfo File to decrypt
   * \param outputFileInfo Decrypted file
   */
  void decrypt(std::size_t id,
               const QString& cryptoProvider,
               const QString& passphrase,
               const QFileInfo& inputFileInfo,
               const QFileInfo& outputFileInfo);
};

} // namespace Kryvo

#endif // KRYVO_CRYPTOGRAPHY_CRYPTO_HPP_
