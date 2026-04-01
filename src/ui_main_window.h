/*
 * PacketSanitizer - Wireshark Native C Plugin
 *
 * Copyright (C) 2026 Walter Hofstetter
 *
 * ui_main_window.h — Qt start / status / result window.
 */

#ifndef UI_MAIN_WINDOW_H
#define UI_MAIN_WINDOW_H

#include <QDialog>
#include <QLabel>
#include <QRadioButton>
#include <QPushButton>
#include <QProgressBar>
#include <QTextEdit>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGroupBox>
#include <QButtonGroup>
#include <QThread>
#include <QPixmap>
#include <QString>
#include <QStackedWidget>
#include <QFrame>

#include "sanitizer_engine.h"

/* ------------------------------------------------------------------ */
/* Worker thread that runs the sanitizer off the GUI thread            */
/* ------------------------------------------------------------------ */
class SanitizerWorker : public QThread
{
    Q_OBJECT

public:
    explicit SanitizerWorker(QObject *parent = nullptr);

    void setParameters(const QString &inputPath,
                       const QString &outputPath,
                       sanitize_mode_t mode);

    void requestCancel();

signals:
    void progressUpdate(int current, int total, const QString &status);
    void finished(bool success,
                  const QString &outputPath,
                  int packetsWritten,
                  int ipsAnon,
                  int macsAnon,
                  const QString &errorMessage);

protected:
    void run() override;

private:
    QString          m_inputPath;
    QString          m_outputPath;
    sanitize_mode_t  m_mode;
    volatile gboolean m_cancel;

    static void progressCallback(int current, int total,
                                 const char *status, void *userData);
};

/* ------------------------------------------------------------------ */
/* Main window                                                         */
/* ------------------------------------------------------------------ */
class PacketSanitizerWindow : public QDialog
{
    Q_OBJECT

public:
    explicit PacketSanitizerWindow(const QString &captureFilePath,
                                   QWidget *parent = nullptr);
    ~PacketSanitizerWindow();

private slots:
    void onStartClicked();
    void onCancelClicked();
    void onLoadFileClicked();
    void onModeChanged(int id);
    void onProgressUpdate(int current, int total, const QString &status);
    void onSanitizationFinished(bool success,
                                const QString &outputPath,
                                int packetsWritten,
                                int ipsAnon,
                                int macsAnon,
                                const QString &errorMessage);

private:
    /* UI setup */
    void setupUi();
    void buildSelectPage();
    void buildProgressPage();
    void buildResultPage();

    void showSelectPage();
    void showProgressPage();
    void showResultPage(bool success,
                        const QString &outputPath,
                        int packetsWritten,
                        int ipsAnon,
                        int macsAnon,
                        const QString &error);

    QString generateOutputPath(const QString &inputPath,
                               sanitize_mode_t mode) const;
    QString modeDescription(sanitize_mode_t mode) const;
    bool    isDarkTheme() const;

    /* Data */
    QString          m_captureFilePath;
    QString          m_outputFilePath;
    SanitizerWorker *m_worker;

    /* Pages */
    QStackedWidget  *m_stack;

    /* ── Page 0: Mode selection ── */
    QWidget        *m_selectPage;
    QLabel         *m_logoLabel;
    QLabel         *m_titleLabel;
    QLabel         *m_descLabel;
    QRadioButton   *m_radioAll;
    QRadioButton   *m_radioCleartext;
    QRadioButton   *m_radioFull;
    QButtonGroup   *m_modeGroup;
    QLabel         *m_modeHintLabel;
    QPushButton    *m_startBtn;

    /* ── Page 1: Progress ── */
    QWidget        *m_progressPage;
    QLabel         *m_progressTitleLabel;
    QProgressBar   *m_progressBar;
    QTextEdit      *m_statusLog;
    QPushButton    *m_cancelBtn;

    /* ── Page 2: Result ── */
    QWidget        *m_resultPage;
    QLabel         *m_resultIconLabel;
    QLabel         *m_resultTitleLabel;
    QTextEdit      *m_resultDetail;
    QPushButton    *m_loadFileBtn;
    QPushButton    *m_closeBtn;
};

#endif /* UI_MAIN_WINDOW_H */
