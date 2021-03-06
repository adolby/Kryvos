#include "DesktopMainWindow.hpp"
#include <QAction>
#include <QDropEvent>
#include <QMimeData>
#include <QUrl>

Kryvo::DesktopMainWindow::DesktopMainWindow(Settings* s, QWidget* parent)
  : MainWindow(s, parent) {
  messageFrame->appendMessage(tr("To begin, click the Add Files button or drag "
                                 "and drop files. Next, enter a file path for "
                                 "the output files. Enter a password. Finally, "
                                 "click the Encrypt or Decrypt button."));

  // Adjust stretch of file list view
  contentLayout->setStretch(1, 200);

  // Adjust stretch of message box
  contentLayout->setStretch(2, 0);

  // Add files action
  auto addFilesAction = new QAction(this);
  addFilesAction->setShortcut(Qt::Key_O | Qt::CTRL);
  connect(addFilesAction, &QAction::triggered,
          this, &MainWindow::addFiles);
  this->addAction(addFilesAction);

  // Quit action
  auto quitAction = new QAction(this);
  quitAction->setShortcut(Qt::Key_Q | Qt::CTRL);
  connect(quitAction, &QAction::triggered,
          this, &QMainWindow::close);
  this->addAction(quitAction);

  this->move(settings->position());

  if (settings->maximized()) {
    // Move window, then maximize to ensure maximize occurs on correct screen
    this->setWindowState(this->windowState() | Qt::WindowMaximized);
  } else {
    this->resize(settings->size());
  }

  // Enable drag and drop
  this->setAcceptDrops(true);

  // Load stylesheet
  const QString styleSheet = loadStyleSheet(settings->styleSheetPath(),
                                            QStringLiteral("kryvo.qss"));

  if (!styleSheet.isEmpty()) {
    this->setStyleSheet(styleSheet);
  }
}

void Kryvo::DesktopMainWindow::closeEvent(QCloseEvent* event) {
  settings->position(this->pos());

  if (this->isMaximized()) {
    settings->maximized(true);
  } else {
    settings->maximized(false);
    settings->size(this->size());
  }

  QMainWindow::closeEvent(event);
}

void Kryvo::DesktopMainWindow::dragEnterEvent(QDragEnterEvent* event) {
  // Show drag and drop as a move action
  event->setDropAction(Qt::MoveAction);

  if (event->mimeData()->hasUrls()) { // Accept drag and drops with files only
    event->accept();
  }
}

void Kryvo::DesktopMainWindow::dropEvent(QDropEvent* event) {
  // Check for the URL MIME type, which is a list of files
  if (event->mimeData()->hasUrls()) { // Extract the local path from the file(s)
    for (const QUrl& url : event->mimeData()->urls()) {
      fileListFrame->addFileToModel(QFileInfo(url.toLocalFile()));
    }
  }
}

QSize Kryvo::DesktopMainWindow::sizeHint() const {
  return QSize(800, 600);
}

QSize Kryvo::DesktopMainWindow::minimumSizeHint() const {
  return QSize(600, 420);
}
