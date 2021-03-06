#ifndef KRYVO_WIDGETS_SETTINGSFRAME_HPP_
#define KRYVO_WIDGETS_SETTINGSFRAME_HPP_

#include "utility/pimpl.h"
#include <QFrame>
#include <QString>
#include <memory>

namespace Kryvo {

class SettingsFramePrivate;

/*!
 * \brief The SettingsFrame class contains controls for customizing encryption
 * settings.
 */
class SettingsFrame : public QFrame {
  Q_OBJECT
  Q_DISABLE_COPY(SettingsFrame)
  DECLARE_PRIVATE(SettingsFrame)
  std::unique_ptr<SettingsFramePrivate> const d_ptr;

 public:
  /*!
   * \brief SettingsFrame Constructs a settings frame
   * \param cipher String representing the cipher name
   * \param keySize String representing the key size
   * \param mode String representing the mode of operation
   * \param removeIntermediateFiles Remove intermediate files enable/disable
   * \param containerMode Container mode archives multiple input files together
   * \param parent QWidget parent
   */
  explicit SettingsFrame(const QString& cryptoProvider,
                         const QString& compressionFormat,
                         const QString& cipher,
                         std::size_t keySize,
                         const QString& mode,
                         bool removeIntermediateFiles,
                         bool containerMode,
                         QWidget* parent = nullptr);

  ~SettingsFrame() override;

 signals:
  /*!
   * \brief switchFrame Emitted when the user requests that the main frame
   * should be displayed
   */
  void switchFrame();

  /*!
   * \brief updateCipher Emitted when the user has changed the cipher algorithm
   * via the combobox representing it
   * \param cipher String containing the cipher name
   */
  void updateCipher(const QString& cipher);

  /*!
   * \brief updateKeySize Emitted when the user has changed the key size via the
   * combobox representing it
   * \param keySize Key size in bits
   */
  void updateKeySize(std::size_t keySize);

  /*!
   * \brief updateModeOfOperation Emitted when the user has changed the cipher
   * mode of operation via the combobox representing it
   * \param modeOfOperation String containing the mode of operation
   */
  void updateModeOfOperation(const QString& modeOfOperation);

  /*!
   * \brief updateCompressionMode Emitted when the user has changed the
   * compression mode via the checkbox representing it
   * \param format String representing compression format
   */
  void updateCompressionFormat(const QString& format);

  /*!
   * \brief updateRemoveIntermediateFiles Emitted when the user has changed the
   * remove intermediate files preference via the checkbox representing it
   * \param compress Boolean representing remove intermediate files preference
   */
  void updateRemoveIntermediateFiles(bool removeIntermediate);

  /*!
   * \brief updateContainerMode Emitted when the user has changed the container
   * mode via the checkbox representing it
   * \param container Boolean representing container
   */
  void updateContainerMode(bool container);

 public slots:
  /*!
   * \brief changeCipher Executed when the cipher changes
   */
  void changeCipher();

  /*!
   * \brief changeKeySize Executed when the key size changes
   */
  void changeKeySize();

  /*!
   * \brief changeModeOfOperation Executed when the mode of operation changes
   */
  void changeModeOfOperation();

  /*!
   * \brief changeCompressionFormat Executed when the compression format changes
   */
  void changeCompressionFormat();

  /*!
   * \brief changeRemoveIntermediateFiles Executed when the remove intermediate
   * files preference changes
   */
  void changeRemoveIntermediateFiles();

  /*!
   * \brief changeContainerMode Executed when the container mode changes
   */
  void changeContainerMode();
};

} // namespace Kryvo

#endif // KRYVO_WIDGETS_SETTINGSFRAME_HPP_
