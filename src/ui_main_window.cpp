/*
 * PacketSanitizer - Wireshark Native C Plugin
 *
 * Copyright (C) 2026 Walter Hofstetter
 *
 * ui_main_window.cpp — Qt start / status / result window implementation.
 *
 * Flow:
 *   Page 0 (select)   — Logo, mode radio buttons, Start button.
 *   Page 1 (progress) — Progress bar, scrolling log, Cancel button.
 *   Page 2 (result)   — Success/error summary, Load File button.
 */

#include "ui_main_window.h"

#include <QApplication>
#include <QScreen>
#include <QFileInfo>
#include <QDir>
#include <QProcess>
#include <QDesktopServices>
#include <QUrl>
#include <QDateTime>
#include <QScrollBar>
#include <QFont>
#include <QSizePolicy>
#include <QFrame>
#include <QSpacerItem>
#include <QMessageBox>
#include <QPalette>
#include <QDebug>

/* ================================================================== */
/* SanitizerWorker                                                     */
/* ================================================================== */

SanitizerWorker::SanitizerWorker(QObject *parent)
    : QThread(parent)
    , m_mode(SANITIZE_ALL_PAYLOAD)
    , m_cancel(FALSE)
{}

void SanitizerWorker::setParameters(const QString &inputPath,
                                    const QString &outputPath,
                                    sanitize_mode_t mode)
{
    m_inputPath  = inputPath;
    m_outputPath = outputPath;
    m_mode       = mode;
    m_cancel     = FALSE;
}

void SanitizerWorker::requestCancel()
{
    m_cancel = TRUE;
}

void SanitizerWorker::progressCallback(int current, int total,
                                       const char *status, void *userData)
{
    SanitizerWorker *self = static_cast<SanitizerWorker *>(userData);
    emit self->progressUpdate(current, total,
                              QString::fromUtf8(status ? status : ""));
}

void SanitizerWorker::run()
{
    sanitizer_result_t *result = sanitizer_run(
        m_inputPath.toUtf8().constData(),
        m_outputPath.toUtf8().constData(),
        m_mode,
        &SanitizerWorker::progressCallback,
        this,
        &m_cancel
    );

    bool    success    = result ? (bool)result->success : false;
    QString outPath    = result ? QString::fromUtf8(result->output_path  ? result->output_path  : "") : QString();
    QString errMsg     = result ? QString::fromUtf8(result->error_message? result->error_message: "") : QString("Unknown error");
    int     written    = result ? result->packets_written   : 0;
    int     ipsAnon    = result ? result->ips_anonymized    : 0;
    int     macsAnon   = result ? result->macs_anonymized   : 0;

    sanitizer_result_free(result);

    emit finished(success, outPath, written, ipsAnon, macsAnon, errMsg);
}

/* ================================================================== */
/* PacketSanitizerWindow                                               */
/* ================================================================== */

PacketSanitizerWindow::PacketSanitizerWindow(const QString &captureFilePath,
                                             QWidget *parent)
    : QDialog(parent, Qt::Window)
    , m_captureFilePath(captureFilePath)
    , m_worker(nullptr)
    , m_stack(nullptr)
    , m_selectPage(nullptr)
    , m_progressPage(nullptr)
    , m_resultPage(nullptr)
{
    setWindowTitle("PacketSanitizer");
    setMinimumSize(520, 480);
    setModal(false);

    setupUi();
    showSelectPage();

    /* Centre on screen */
    if (QScreen *scr = QApplication::primaryScreen()) {
        QRect sg = scr->availableGeometry();
        move(sg.center() - rect().center());
    }
}

PacketSanitizerWindow::~PacketSanitizerWindow()
{
    if (m_worker) {
        m_worker->requestCancel();
        m_worker->wait(3000);
    }
}

/* ------------------------------------------------------------------ */
/* UI construction                                                     */
/* ------------------------------------------------------------------ */

bool PacketSanitizerWindow::isDarkTheme() const
{
    return qApp->palette().windowText().color().lightness() >
           qApp->palette().window().color().lightness();
}

void PacketSanitizerWindow::setupUi()
{
    m_stack = new QStackedWidget(this);

    auto *root = new QVBoxLayout(this);
    root->setContentsMargins(0, 0, 0, 0);
    root->addWidget(m_stack);
    setLayout(root);

    buildSelectPage();
    buildProgressPage();
    buildResultPage();

    m_stack->addWidget(m_selectPage);   /* index 0 */
    m_stack->addWidget(m_progressPage); /* index 1 */
    m_stack->addWidget(m_resultPage);   /* index 2 */
}

void PacketSanitizerWindow::buildSelectPage()
{
    m_selectPage = new QWidget;
    auto *vbox = new QVBoxLayout(m_selectPage);
    vbox->setContentsMargins(24, 24, 24, 24);
    vbox->setSpacing(12);

    /* ── Logo ── */
    m_logoLabel = new QLabel;
    m_logoLabel->setAlignment(Qt::AlignHCenter);
    {
        QPixmap logo(":/packetsanitizer/PacketSanitizer-Logo.png");
        if (logo.isNull()) {
            /* Fallback: plain text logo */
            m_logoLabel->setText("<b style='font-size:28px;color:#2ea44f;'>PS</b>");
        } else {
            m_logoLabel->setPixmap(
                logo.scaledToWidth(160, Qt::SmoothTransformation));
        }
    }
    vbox->addWidget(m_logoLabel);

    /* ── Title ── */
    m_titleLabel = new QLabel("PacketSanitizer");
    {
        QFont f = m_titleLabel->font();
        f.setPointSize(f.pointSize() + 6);
        f.setBold(true);
        m_titleLabel->setFont(f);
    }
    m_titleLabel->setAlignment(Qt::AlignHCenter);
    vbox->addWidget(m_titleLabel);

    /* ── Subtitle ── */
    m_descLabel = new QLabel(
        "Sanitize the current Wireshark capture buffer for safe sharing.");
    m_descLabel->setAlignment(Qt::AlignHCenter);
    m_descLabel->setWordWrap(true);
    {
        QPalette pal = m_descLabel->palette();
        QColor   fg  = pal.color(QPalette::WindowText);
        fg.setAlphaF(0.65f);
        pal.setColor(QPalette::WindowText, fg);
        m_descLabel->setPalette(pal);
    }
    vbox->addWidget(m_descLabel);

    /* ── Separator ── */
    auto *sep = new QFrame;
    sep->setFrameShape(QFrame::HLine);
    sep->setFrameShadow(QFrame::Sunken);
    vbox->addWidget(sep);

    /* ── Mode group box ── */
    auto *modeBox = new QGroupBox("Select sanitization mode:");
    auto *modeVBox = new QVBoxLayout(modeBox);
    modeVBox->setSpacing(10);

    m_modeGroup = new QButtonGroup(this);

    m_radioAll = new QRadioButton(
        "Sanitize All Payloads\n"
        "  Zeros all TCP/UDP payload data — keeps IP/MAC addresses intact.");
    m_radioAll->setChecked(true);
    modeVBox->addWidget(m_radioAll);
    m_modeGroup->addButton(m_radioAll, SANITIZE_ALL_PAYLOAD);

    m_radioCleartext = new QRadioButton(
        "Sanitize Cleartext Payloads Only\n"
        "  Zeros payloads of HTTP, FTP, Telnet, SMTP, POP3, IMAP, DNS only.");
    modeVBox->addWidget(m_radioCleartext);
    m_modeGroup->addButton(m_radioCleartext, SANITIZE_CLEARTEXT_PAYLOAD);

    m_radioFull = new QRadioButton(
        "Sanitize Payloads + Anonymize IP & MAC Addresses\n"
        "  Zeros all payloads AND replaces IPs/MACs with consistent aliases.");
    modeVBox->addWidget(m_radioFull);
    m_modeGroup->addButton(m_radioFull, SANITIZE_PAYLOAD_AND_ADDRESSES);

    vbox->addWidget(modeBox);

    /* ── Mode hint ── */
    m_modeHintLabel = new QLabel;
    m_modeHintLabel->setWordWrap(true);
    m_modeHintLabel->setAlignment(Qt::AlignHCenter);
    {
        QPalette pal = m_modeHintLabel->palette();
        pal.setColor(QPalette::WindowText,
                     isDarkTheme() ? QColor("#7ee787") : QColor("#1a7f37"));
        m_modeHintLabel->setPalette(pal);
    }
    vbox->addWidget(m_modeHintLabel);

    vbox->addStretch();

    /* ── Start button ── */
    m_startBtn = new QPushButton("Start Sanitizing");
    m_startBtn->setMinimumHeight(36);
    {
        QFont f = m_startBtn->font();
        f.setBold(true);
        m_startBtn->setFont(f);
    }
    vbox->addWidget(m_startBtn);

    /* Connections */
    connect(m_startBtn, &QPushButton::clicked,
            this, &PacketSanitizerWindow::onStartClicked);
    connect(m_modeGroup,
            QOverload<int>::of(&QButtonGroup::idClicked),
            this, &PacketSanitizerWindow::onModeChanged);

    /* Trigger initial hint */
    onModeChanged(SANITIZE_ALL_PAYLOAD);
}

void PacketSanitizerWindow::buildProgressPage()
{
    m_progressPage = new QWidget;
    auto *vbox = new QVBoxLayout(m_progressPage);
    vbox->setContentsMargins(24, 24, 24, 24);
    vbox->setSpacing(12);

    /* Title row with small logo */
    auto *titleRow = new QHBoxLayout;
    {
        auto *logoSmall = new QLabel;
        QPixmap logo(":/packetsanitizer/PacketSanitizer-Logo.png");
        if (!logo.isNull())
            logoSmall->setPixmap(logo.scaledToWidth(48, Qt::SmoothTransformation));
        titleRow->addWidget(logoSmall);
    }
    m_progressTitleLabel = new QLabel("Sanitizing capture…");
    {
        QFont f = m_progressTitleLabel->font();
        f.setPointSize(f.pointSize() + 2);
        f.setBold(true);
        m_progressTitleLabel->setFont(f);
    }
    titleRow->addWidget(m_progressTitleLabel);
    titleRow->addStretch();
    vbox->addLayout(titleRow);

    /* Progress bar */
    m_progressBar = new QProgressBar;
    m_progressBar->setRange(0, 0);   /* indeterminate until we have total */
    m_progressBar->setTextVisible(true);
    m_progressBar->setFormat("Processing…");
    vbox->addWidget(m_progressBar);

    /* Status log */
    m_statusLog = new QTextEdit;
    m_statusLog->setReadOnly(true);
    m_statusLog->setMinimumHeight(220);
    {
        QFont mono("Monospace");
        mono.setStyleHint(QFont::TypeWriter);
        mono.setPointSize(mono.pointSize() - 1);
        m_statusLog->setFont(mono);
    }
    vbox->addWidget(m_statusLog);

    /* Cancel button */
    m_cancelBtn = new QPushButton("Cancel");
    vbox->addWidget(m_cancelBtn, 0, Qt::AlignRight);

    connect(m_cancelBtn, &QPushButton::clicked,
            this, &PacketSanitizerWindow::onCancelClicked);
}

void PacketSanitizerWindow::buildResultPage()
{
    m_resultPage = new QWidget;
    auto *vbox = new QVBoxLayout(m_resultPage);
    vbox->setContentsMargins(24, 24, 24, 24);
    vbox->setSpacing(14);

    /* Icon + title row */
    auto *titleRow = new QHBoxLayout;
    m_resultIconLabel = new QLabel;
    m_resultIconLabel->setAlignment(Qt::AlignVCenter);
    m_resultIconLabel->setFixedSize(64, 64);
    titleRow->addWidget(m_resultIconLabel);

    m_resultTitleLabel = new QLabel;
    {
        QFont f = m_resultTitleLabel->font();
        f.setPointSize(f.pointSize() + 4);
        f.setBold(true);
        m_resultTitleLabel->setFont(f);
    }
    titleRow->addWidget(m_resultTitleLabel);
    titleRow->addStretch();
    vbox->addLayout(titleRow);

    /* Detail text */
    m_resultDetail = new QTextEdit;
    m_resultDetail->setReadOnly(true);
    m_resultDetail->setMinimumHeight(160);
    vbox->addWidget(m_resultDetail);

    vbox->addStretch();

    /* Buttons */
    auto *btnRow = new QHBoxLayout;
    m_loadFileBtn = new QPushButton("Load Sanitized File in Wireshark");
    {
        QFont f = m_loadFileBtn->font();
        f.setBold(true);
        m_loadFileBtn->setFont(f);
    }
    m_loadFileBtn->setMinimumHeight(36);
    btnRow->addWidget(m_loadFileBtn);

    m_closeBtn = new QPushButton("Close");
    m_closeBtn->setMinimumHeight(36);
    btnRow->addWidget(m_closeBtn);

    vbox->addLayout(btnRow);

    connect(m_loadFileBtn, &QPushButton::clicked,
            this, &PacketSanitizerWindow::onLoadFileClicked);
    connect(m_closeBtn, &QPushButton::clicked,
            this, &QDialog::accept);
}

/* ------------------------------------------------------------------ */
/* Page transitions                                                    */
/* ------------------------------------------------------------------ */

void PacketSanitizerWindow::showSelectPage()
{
    m_stack->setCurrentIndex(0);
    adjustSize();
}

void PacketSanitizerWindow::showProgressPage()
{
    m_statusLog->clear();
    m_progressBar->setRange(0, 0);
    m_progressBar->setFormat("Processing…");
    m_stack->setCurrentIndex(1);
}

void PacketSanitizerWindow::showResultPage(bool success,
                                           const QString &outputPath,
                                           int packetsWritten,
                                           int ipsAnon,
                                           int macsAnon,
                                           const QString &error)
{
    if (success) {
        m_resultTitleLabel->setText("Sanitization Complete");
        {
            QPalette pal = m_resultTitleLabel->palette();
            pal.setColor(QPalette::WindowText,
                         isDarkTheme() ? QColor("#7ee787") : QColor("#1a7f37"));
            m_resultTitleLabel->setPalette(pal);
        }

        /* Use the logo as icon */
        QPixmap logo(":/packetsanitizer/PacketSanitizer-Logo.png");
        if (!logo.isNull())
            m_resultIconLabel->setPixmap(
                logo.scaled(64, 64, Qt::KeepAspectRatio, Qt::SmoothTransformation));

        QString detail =
            QString("<b>Output file:</b><br>%1<br><br>"
                    "<b>Packets sanitized:</b> %2<br>")
                .arg(outputPath.toHtmlEscaped())
                .arg(packetsWritten);

        if (ipsAnon > 0)
            detail += QString("<b>IP addresses anonymized:</b> %1<br>").arg(ipsAnon);
        if (macsAnon > 0)
            detail += QString("<b>MAC addresses anonymized:</b> %1<br>").arg(macsAnon);

        detail += "<br>The sanitized capture is ready for safe sharing.";
        m_resultDetail->setHtml(detail);

        m_loadFileBtn->setVisible(true);
        m_outputFilePath = outputPath;
    } else {
        m_resultTitleLabel->setText("Sanitization Failed");
        {
            QPalette pal = m_resultTitleLabel->palette();
            pal.setColor(QPalette::WindowText, QColor("#d1242f"));
            m_resultTitleLabel->setPalette(pal);
        }

        m_resultIconLabel->setText("<span style='font-size:32px;'>&#9888;</span>");

        m_resultDetail->setHtml(
            QString("<b>Error:</b><br>%1").arg(error.toHtmlEscaped()));

        m_loadFileBtn->setVisible(false);
    }

    m_stack->setCurrentIndex(2);
    adjustSize();
}

/* ------------------------------------------------------------------ */
/* Slots                                                               */
/* ------------------------------------------------------------------ */

void PacketSanitizerWindow::onModeChanged(int id)
{
    switch (id) {
    case SANITIZE_ALL_PAYLOAD:
        m_modeHintLabel->setText(
            "All TCP/UDP payload bytes will be replaced with 0x53 ('S').\n"
            "IP and MAC addresses are preserved.");
        break;
    case SANITIZE_CLEARTEXT_PAYLOAD:
        m_modeHintLabel->setText(
            "Only payloads on cleartext ports (HTTP 80, FTP 20/21, "
            "Telnet 23, SMTP 25/587, POP3 110, IMAP 143, DNS 53) are zeroed.\n"
            "Encrypted traffic and IP/MAC addresses are preserved.");
        break;
    case SANITIZE_PAYLOAD_AND_ADDRESSES:
        m_modeHintLabel->setText(
            "All payloads are zeroed AND IP/MAC addresses are replaced\n"
            "with consistent anonymous aliases (conversation flows intact).");
        break;
    default:
        m_modeHintLabel->clear();
    }
}

void PacketSanitizerWindow::onStartClicked()
{
    if (m_captureFilePath.isEmpty()) {
        QMessageBox::warning(this, "PacketSanitizer",
                             "No capture file is currently open.\n"
                             "Please open a PCAP/PCAPNG file in Wireshark first.");
        return;
    }

    sanitize_mode_t mode = static_cast<sanitize_mode_t>(
        m_modeGroup->checkedId());

    m_outputFilePath = generateOutputPath(m_captureFilePath, mode);

    showProgressPage();

    /* Append initial status */
    m_statusLog->append(QString("[%1]  Input:  %2")
        .arg(QDateTime::currentDateTime().toString("hh:mm:ss"))
        .arg(m_captureFilePath));
    m_statusLog->append(QString("[%1]  Output: %2")
        .arg(QDateTime::currentDateTime().toString("hh:mm:ss"))
        .arg(m_outputFilePath));
    m_statusLog->append(QString("[%1]  Mode:   %2")
        .arg(QDateTime::currentDateTime().toString("hh:mm:ss"))
        .arg(modeDescription(mode)));
    m_statusLog->append("─────────────────────────────────────────");

    /* Start worker thread */
    m_worker = new SanitizerWorker(this);
    m_worker->setParameters(m_captureFilePath, m_outputFilePath, mode);

    connect(m_worker, &SanitizerWorker::progressUpdate,
            this, &PacketSanitizerWindow::onProgressUpdate);
    connect(m_worker, &SanitizerWorker::finished,
            this, &PacketSanitizerWindow::onSanitizationFinished);
    connect(m_worker, &QThread::finished,
            m_worker, &QObject::deleteLater);

    m_worker->start();
}

void PacketSanitizerWindow::onCancelClicked()
{
    if (m_worker) {
        m_statusLog->append(
            QString("\n[%1]  Cancelling…")
                .arg(QDateTime::currentDateTime().toString("hh:mm:ss")));
        m_cancelBtn->setEnabled(false);
        m_worker->requestCancel();
    }
}

void PacketSanitizerWindow::onProgressUpdate(int current, int total,
                                             const QString &status)
{
    /* Update progress bar */
    if (total > 0) {
        m_progressBar->setRange(0, total);
        m_progressBar->setValue(current);
        m_progressBar->setFormat(
            QString("%1 / %2 packets").arg(current).arg(total));
    } else {
        m_progressBar->setFormat(
            QString("%1 packets…").arg(current));
    }

    /* Append to log */
    m_statusLog->append(
        QString("[%1]  %2")
            .arg(QDateTime::currentDateTime().toString("hh:mm:ss"))
            .arg(status));

    /* Auto-scroll */
    QScrollBar *sb = m_statusLog->verticalScrollBar();
    sb->setValue(sb->maximum());

    /* Keep the GUI responsive */
    QApplication::processEvents(QEventLoop::AllEvents, 20);
}

void PacketSanitizerWindow::onSanitizationFinished(bool success,
                                                   const QString &outputPath,
                                                   int packetsWritten,
                                                   int ipsAnon,
                                                   int macsAnon,
                                                   const QString &errorMessage)
{
    m_worker = nullptr;   /* deleteLater is connected; don't double-free */

    if (success) {
        m_statusLog->append(
            QString("[%1]  ✓  Finished — %2 packets written.")
                .arg(QDateTime::currentDateTime().toString("hh:mm:ss"))
                .arg(packetsWritten));
    } else {
        m_statusLog->append(
            QString("[%1]  ✗  Error: %2")
                .arg(QDateTime::currentDateTime().toString("hh:mm:ss"))
                .arg(errorMessage));
    }

    showResultPage(success, outputPath, packetsWritten, ipsAnon, macsAnon,
                   errorMessage);
}

void PacketSanitizerWindow::onLoadFileClicked()
{
    if (m_outputFilePath.isEmpty() || !QFileInfo::exists(m_outputFilePath)) {
        QMessageBox::warning(this, "PacketSanitizer",
                             "Output file not found:\n" + m_outputFilePath);
        return;
    }

#if defined(Q_OS_MACOS)
    QProcess::startDetached("/usr/bin/open",
                            {"-a", "Wireshark", m_outputFilePath});
#elif defined(Q_OS_WIN)
    /* Use the Windows shell to open — Wireshark should be registered for
     * .pcap / .pcapng by its installer.                                    */
    QDesktopServices::openUrl(QUrl::fromLocalFile(m_outputFilePath));
#else
    /* Linux: try wireshark directly, then fall back to xdg-open */
    if (!QProcess::startDetached("wireshark", {m_outputFilePath}))
        QDesktopServices::openUrl(QUrl::fromLocalFile(m_outputFilePath));
#endif
}

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

QString PacketSanitizerWindow::generateOutputPath(const QString &inputPath,
                                                  sanitize_mode_t mode) const
{
    QFileInfo fi(inputPath);
    QString base    = fi.dir().filePath(fi.completeBaseName());
    QString suffix;

    switch (mode) {
    case SANITIZE_ALL_PAYLOAD:           suffix = "_sanitized_payload";    break;
    case SANITIZE_CLEARTEXT_PAYLOAD:     suffix = "_sanitized_cleartext";  break;
    case SANITIZE_PAYLOAD_AND_ADDRESSES: suffix = "_sanitized_full";       break;
    default:                             suffix = "_sanitized";            break;
    }

    return base + suffix + ".pcap";
}

QString PacketSanitizerWindow::modeDescription(sanitize_mode_t mode) const
{
    switch (mode) {
    case SANITIZE_ALL_PAYLOAD:           return "Sanitize All Payloads";
    case SANITIZE_CLEARTEXT_PAYLOAD:     return "Sanitize Cleartext Payloads Only";
    case SANITIZE_PAYLOAD_AND_ADDRESSES: return "Sanitize Payloads + Anonymize IP & MAC";
    default:                             return "Unknown";
    }
}
