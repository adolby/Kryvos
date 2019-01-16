#include "DispatcherState.hpp"
#include "archive/Archiver.hpp"
#include "FileOperations.hpp"
#include "catch.hpp"
#include <QFileInfo>
#include <QFile>
#include <QStringList>
#include <QString>


/*!
 * testCompressDecompress Tests the compression/decompression process with a
 * text file as input.
 */
SCENARIO("Test compression and decompression on a text file",
         "[testCompressDecompressText]") {
  GIVEN("A text file") {
    Kryvo::DispatcherState state;
    Kryvo::Archiver archiver(&state);

    const QString& inputFilePath = QStringLiteral("test1.txt");
    const QString& compressedFilePath = QStringLiteral("test1.txt.gz");
    const QString& decompressedFilePath = QStringLiteral("test1 (2).txt");

    const QFileInfo inputFileInfo(inputFilePath);

    const QString& msgTemplate = QStringLiteral("Test file %1 is missing.");

    if (!inputFileInfo.exists()) {
      FAIL(msgTemplate.arg(inputFilePath).toStdString());
    }

    WHEN("Compressing and decompressing file") {
      const int id = 0;

      archiver.compress(id, inputFilePath, compressedFilePath);
      archiver.decompress(id, compressedFilePath, decompressedFilePath);

      // Compare initial file with decompressed file
      const bool equivalentTest =
        FileOperations::filesEqual(inputFilePath, decompressedFilePath);

      // Clean up test files
      QFile compressedFile(compressedFilePath);

      if (compressedFile.exists()) {
        compressedFile.remove();
      }

      QFile decompressedFile(decompressedFilePath);

      if (decompressedFile.exists()) {
        decompressedFile.remove();
      }

      THEN("Decompressed file matches original file: " +
           inputFilePath.toStdString()) {
        REQUIRE(equivalentTest);
      }
    }
  }
}
