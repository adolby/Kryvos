#include "gui/FileListFrame.hpp"
#include "gui/FileListDelegate.hpp"
#include <QHeaderView>
#include <QTableView>
#include <QVBoxLayout>
#include <QStandardItemModel>
#include <QFileInfo>
#include <QDir>
#include <QStringRef>
#include <QStringBuilder>
#include <QString>

#include <QDebug>

class Kryvo::FileListFramePrivate {
  Q_DISABLE_COPY(FileListFramePrivate)

 public:
  /*!
   * \brief FileListFramePrivate Constructs the FileListFrame private
   * implementation.
   */
  FileListFramePrivate();

  /*!
   * \brief addFileToModel Adds a file to the file list model.
   * \param filePath String containing the file path.
   */
  void addFileToModel(const QString& filePath);

  std::unique_ptr<QStandardItemModel> fileListModel;
  QTableView* fileListView;
};

Kryvo::FileListFrame::FileListFrame(QWidget* parent)
  : QFrame{parent}, d_ptr{std::make_unique<FileListFramePrivate>()} {
  Q_D(FileListFrame);

  // File list header
  const QStringList headerList = {tr("File"), tr("Task"), tr("Progress"),
                                  tr("Remove")};
  d->fileListModel->setHorizontalHeaderLabels(headerList);

  d->fileListView = new QTableView{this};
  d->fileListView->setModel(d->fileListModel.get());
  d->fileListView->setShowGrid(false);
  d->fileListView->verticalHeader()->hide();
  d->fileListView->horizontalHeader()->hide();
  d->fileListView->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
  d->fileListView->setFrameShape(QFrame::NoFrame);

  QHeaderView* header = d->fileListView->horizontalHeader();
  header->setStretchLastSection(false);
  header->setDefaultSectionSize(130);
  header->setSectionResizeMode(QHeaderView::Fixed);

  // Custom delegate paints progress bar and file close button for each file
  auto delegate = new FileListDelegate{this};
  d->fileListView->setItemDelegate(delegate);
  d->fileListView->setHorizontalScrollMode(QAbstractItemView::ScrollPerPixel);

  auto fileListLayout = new QVBoxLayout{this};
  fileListLayout->addWidget(d->fileListView);
  fileListLayout->setContentsMargins(0, 0, 0, 0);

  connect(delegate, &FileListDelegate::removeRow,
          this, &FileListFrame::removeFileFromModel);
}

Kryvo::FileListFrame::~FileListFrame() {
}

QStandardItem* Kryvo::FileListFrame::item(const int row) {
  Q_D(FileListFrame);
  Q_ASSERT(d->fileListModel);

  return d->fileListModel->item(row, 0);
}

int Kryvo::FileListFrame::rowCount() const {
  Q_D(const FileListFrame);
  Q_ASSERT(d->fileListModel);

  return d->fileListModel->rowCount();
}

void Kryvo::FileListFrame::clear() {
  Q_D(FileListFrame);
  Q_ASSERT(d->fileListModel);

  d->fileListModel->clear();

  // File list header
  const QStringList headerList = {tr("File"), tr("Task"), tr("Progress"),
                                  tr("Remove")};
  d->fileListModel->setHorizontalHeaderLabels(headerList);

  QHeaderView* header = d->fileListView->horizontalHeader();
  header->setStretchLastSection(false);
  header->setDefaultSectionSize(130);
  d->fileListView->setColumnWidth(0, this->width() * 0.6);
  d->fileListView->setColumnWidth(1, this->width() * 0.15);
  d->fileListView->setColumnWidth(2, this->width() * 0.2);
  d->fileListView->setColumnWidth(3, this->width() * 0.04);
}

void Kryvo::FileListFrame::updateProgress(const QString& path,
                                          const QString& task,
                                          const qint64 percent) {
  Q_D(FileListFrame);
  Q_ASSERT(d->fileListModel);

  qDebug() << path << " " << task << " " << percent;

  if (!path.isEmpty()) {
    const QList<QStandardItem*> items = d->fileListModel->findItems(path);

    if (items.size() > 0) {
      QStandardItem* item = items[0];

      if (item) {
        const int index = item->row();

        QStandardItem* taskItem = d->fileListModel->item(index, 1);
        if (taskItem) {
          taskItem->setData(task, Qt::DisplayRole);
        }

        QStandardItem* progressItem = d->fileListModel->item(index, 2);
        if (progressItem) {
          progressItem->setData(percent, Qt::DisplayRole);
        }
      }
    }
  }
}

void Kryvo::FileListFrame::addFileToModel(const QString& path) {
  Q_D(FileListFrame);

  const QFileInfo fileInfo{path};

  if (fileInfo.exists() && fileInfo.isFile()) {
    // If the file exists, add it to the model
    auto pathItem = new QStandardItem{path};
    pathItem->setDragEnabled(false);
    pathItem->setDropEnabled(false);
    pathItem->setEditable(false);
    pathItem->setSelectable(false);
    pathItem->setToolTip(path);

    const QVariant pathVariant = QVariant::fromValue(path);
    pathItem->setData(pathVariant);

    auto taskItem = new QStandardItem{};
    pathItem->setDragEnabled(false);
    pathItem->setDropEnabled(false);
    pathItem->setEditable(false);
    pathItem->setSelectable(false);

    auto progressItem = new QStandardItem{};
    progressItem->setDragEnabled(false);
    progressItem->setDropEnabled(false);
    progressItem->setEditable(false);
    progressItem->setSelectable(false);

    auto closeFileItem = new QStandardItem{};
    closeFileItem->setDragEnabled(false);
    closeFileItem->setDropEnabled(false);
    closeFileItem->setEditable(false);
    closeFileItem->setSelectable(false);

    const QList<QStandardItem*> items = {pathItem, taskItem, progressItem,
                                         closeFileItem};

    // Search to see if this item is already in the model
    bool addNewItem = true;

    const int rowCount = d->fileListModel->rowCount();
    for (int row = 0; row < rowCount; ++row) {
      const auto testItem = d->fileListModel->item(row, 0);

      const QVariant testItemData = testItem->data();
      const QVariant pathItemData = pathItem->data();

      if (testItemData.toString() == pathItemData.toString()) {
        addNewItem = false;
      }
    }

    if (addNewItem) { // Add the item to the model if it's new
      d->fileListModel->appendRow(items);
    }
  } // End if file exists and is a file
}

void Kryvo::FileListFrame::removeFileFromModel(const QModelIndex& index) {
  Q_D(FileListFrame);
  Q_ASSERT(d->fileListModel);

  QStandardItem* testItem = d->fileListModel->item(index.row(), 0);

  // Signal that this file shouldn't be encrypted or decrypted
  emit stopFile(testItem->data().toString());

  // Remove row from model
  d->fileListModel->removeRow(index.row());
}

void Kryvo::FileListFrame::resizeEvent(QResizeEvent* event) {
  Q_D(FileListFrame);
  Q_UNUSED(event);
  Q_ASSERT(d->fileListView);

  const int width = this->width();

  d->fileListView->setColumnWidth(0, width * 0.6);
  d->fileListView->setColumnWidth(1, width * 0.15);
  d->fileListView->setColumnWidth(2, width * 0.2);
  d->fileListView->setColumnWidth(3, width * 0.04);
}

Kryvo::FileListFramePrivate::FileListFramePrivate()
  : fileListModel{std::make_unique<QStandardItemModel>()},
    fileListView{nullptr} {
}