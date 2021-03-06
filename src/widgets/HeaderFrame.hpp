#ifndef KRYVO_WIDGETS_HEADERFRAME_HPP_
#define KRYVO_WIDGETS_HEADERFRAME_HPP_

#include "utility/pimpl.h"
#include <QFrame>
#include <memory>

namespace Kryvo {

class HeaderFramePrivate;

/*!
 * \brief The HeaderFrame class contains the header frame which contains the
 * header text, pause button, add files button, and remove all files button.
 */
class HeaderFrame : public QFrame {
  Q_OBJECT
  Q_DISABLE_COPY(HeaderFrame)
  DECLARE_PRIVATE(HeaderFrame)
  std::unique_ptr<HeaderFramePrivate> const d_ptr;

 public:
  /*!
   * \brief HeaderFrame Constructs a header frame
   * \param parent Widget parent
   */
  explicit HeaderFrame(QWidget* parent = nullptr);

  ~HeaderFrame() override;

  /*!
   * \brief setIconSize Sets the icon size for buttons
   * \param iconSize Icon size
   */
  void setIconSize(const QSize& iconSize);

 signals:
  /*!
   * \brief addFiles Emitted when the add files button is clicked
   */
  void addFiles();

  /*!
   * \brief removeFiles Emitted when the remove files button is clicked
   */
  void removeFiles();

  /*!
   * \brief pause Emitted when the pause/resume button is checked/unchecked
   * \param pause Boolean representing the pause/resume state of the
   * pause/resume button
   */
  void pause(bool pause);

  /*!
   * \brief switchFrame Emitted when the settings button is clicked
   */
  void switchFrame();

 private slots:
  void removeAllFiles();
  void pauseIconChecked(bool checked);
};

} // namespace Kryvo

#endif // KRYVO_WIDGETS_HEADERFRAME_HPP_
