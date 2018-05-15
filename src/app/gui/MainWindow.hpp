#ifndef KRYVO_GUI_MAINWINDOW_HPP_
#define KRYVO_GUI_MAINWINDOW_HPP_

#include "settings/Settings.hpp"
#include "gui/SettingsFrame.hpp"
#include "gui/HeaderFrame.hpp"
#include "gui/FileListFrame.hpp"
#include "gui/ProgressFrame.hpp"
#include "gui/MessageFrame.hpp"
#include "gui/OutputFrame.hpp"
#include "gui/PasswordFrame.hpp"
#include "gui/ControlButtonFrame.hpp"
#include "utility/pimpl.h"
#include <QMainWindow>
#include <QVBoxLayout>
#include <memory>

namespace Kryvo {

class MainWindowPrivate;

/*!
 * \brief The MainWindow class is the main window for the application.
 */
class MainWindow : public QMainWindow {
  Q_OBJECT
  DECLARE_PRIVATE(MainWindow)
  std::unique_ptr<MainWindowPrivate> const d_ptr;

 public:
  /*!
   * \brief MainWindow Constructs the application's main window
   * \param settings Application settings
   * \param parent Widget parent of this main window
   */
  explicit MainWindow(Settings* s = nullptr,
                      QWidget* parent = nullptr);

  /*!
   * \brief ~MainWindow Destroys the application's main window
   */
  virtual ~MainWindow();

 signals:
  /*!
   * \brief encrypt Emitted when the user provides all required data for
   * encryption and clicks the Encrypt push button
   * \param passphrase String representing the user supplied passphrase
   * \param inputFileNames List of input file strings
   * \param outputPath String containing output file path
   * \param cipher String representing the current cipher
   * \param keySize Key size
   * \param modeOfOperation String representing mode of operation
   * \param compress Boolean representing compression mode
   * \param container Boolean representing container mode
   */
  void encrypt(const QString& passphrase,
               const QStringList& inputFileNames,
               const QString& outputPath,
               const QString& cipher,
               const std::size_t keySize,
               const QString& modeOfOperation,
               const bool compress,
               const bool container);

  /*!
   * \brief decrypt Emitted when the user provides all required data for
   * decryption and clicks the Decrypt push button
   * \param passphrase String representing the user supplied passphrase
   * \param inputFileNames List of input file strings
   * \param outputFileName String containing output file path in container mode
   */
  void decrypt(const QString& passphrase,
               const QStringList& inputFileNames,
               const QString& outputFileName);

  /*!
   * \brief pauseCipher Emitted when the user toggles the Pause push button
   * \param pause Boolean representing the pause status
   */
  void pauseCipher(const bool pause);

  /*!
   * \brief abortCipher Emitted when the user clicks the Clear Files push
   * button
   */
  void abortCipher();

  /*!
   * \brief stopFile Emitted when the user clicks a remove file button
   */
  void stopFile(const QString& fileName);

 public slots:
  /*!
   * \brief addFiles Executed when the Add Files toolbar push button is clicked
   */
  void addFiles();

  /*!
   * \brief removeFiles Executed when the Remove All Files toolbar push
   * button is clicked
   */
  void removeFiles();

  /*!
   * \brief processFiles Executed when the encrypt or decrypt push button is
   * clicked. Starts the encryption or decryption operation using the passphrase
   * from the password line edit, the file list from the file list model, and
   * the algorithm name from the settings panel.
   * \param cryptDirection Boolean representing encrypt or decrypt
   */
  void processFiles(const bool cryptDirection);

  /*!
   * \brief updateFileProgress Executed when the cipher operation progress is
   * updated. Updates the progress bar for the item at the specified index.
   * \param path File path serving as the index to update the progress
   * \param task Task operating on file
   * \param progressValue Integer representing the current progress in percent
   */
  void updateFileProgress(const QString& path, const QString& task,
                          const qint64 progressValue);

  /*!
   * \brief updateStatusMessage Executed when a message should be displayed to
   * the user. Updates the message text edit text to the message.
   * \param message String containing the message
   */
  void updateStatusMessage(const QString& message);

  /*!
   * \brief updateError Executed when a cipher operation fails
   * \param message String containing the error message
   * \param path String containing the error file name path
   */
  void updateError(const QString& message, const QString& fileName = QString{});

  /*!
   * \brief updateBusyStatus Executed when the cipher operation updates its busy
   * status. Stores the status to allow the GUI to decide when the user can
   * request new encryption.
   * \param busy Boolean representing the busy status
   */
  void updateBusyStatus(const bool busy);

  /*!
   * \brief updateCipher Executed when the cipher is updated by the user in the
   * settings frame
   * \param cipher String representing the new cipher
   */
  void updateCipher(const QString& cipher);

  /*!
   * \brief updateKeySize Executed when the key size is updated by the user in
   * the settings frame
   * \param keySize Key size in bits
   */
  void updateKeySize(const std::size_t keySize);

  /*!
   * \brief updateModeOfOperation Executed when the mode of operation is updated
   * by the user in the settings frame
   * \param mode String representing the new mode of operation
   */
  void updateModeOfOperation(const QString& mode);

  /*!
   * \brief updateCompressionMode Executed when the compression mode is updated
   * by the user in the settings frame
   * \param compress Boolean representing the new compression mode
   */
  void updateCompressionMode(const bool compress);

  /*!
   * \brief updateContainerMode Executed when the container mode is updated
   * by the user in the settings frame
   * \param compress Boolean representing the new container mode
   */
  void updateContainerMode(const bool container);

 protected:
  /*!
   * \brief loadStyleSheet Attempts to load a Qt stylesheet from the local
   * themes folder with the name specified in the local settings file. If the
   * load fails, the method will load the default stylesheet from the
   * application resources.
   * \param styleFile String representing the name of the stylesheet without
   * a file extension
   * \param defaultFile String containing the name of the default stylesheet,
   * which will be used if the selected stylesheet file doesn't exist
   * \return String containing the stylesheet file contents
   */
  QString loadStyleSheet(const QString& styleFile,
                         const QString& defaultFile) const;

 protected:
  Settings* settings;
  SettingsFrame* settingsFrame;
  HeaderFrame* headerFrame;
  FileListFrame* fileListFrame;
  MessageFrame* messageFrame;
  OutputFrame* outputFrame;
  PasswordFrame* passwordFrame;
  ControlButtonFrame* controlButtonFrame;
  QVBoxLayout* contentLayout;
};

}

#endif // KRYVO_GUI_MAINWINDOW_HPP_