/*
 * PacketSanitizer - Wireshark Native C Plugin
 *
 * Copyright (C) 2026 Walter Hofstetter
 *
 * ui_bridge.cpp — C/C++ bridge implementation.
 *
 * Ensures a Qt QApplication exists (needed when Wireshark ships Qt5 but
 * the plugin links Qt6, mirroring the PacketCircle pattern), then creates
 * and shows the PacketSanitizerWindow.
 */

#include "ui_bridge.h"
#include "ui_main_window.h"

#include <QApplication>
#include <QDebug>
#include <QString>

/* These must be included in a .cpp (C++ mode) AFTER Qt headers, never
 * inside a header under extern "C" — glib pulls in type_traits via
 * glib-typeof.h, which requires C++ linkage for its templates. */
#include <cfile.h>
#include <epan/plugin_if.h>

/* ------------------------------------------------------------------ */
/* Internal helpers (C++ only)                                         */
/* ------------------------------------------------------------------ */

static PacketSanitizerWindow *g_window = nullptr;

/* Helper callback for plugin_if_get_capture_file() — plain C++ static,
 * the function pointer type is compatible because it uses the C ABI. */
static void *extract_cf(capture_file *cf, void * /*user*/)
{
    return (void *)cf;
}

static void ensure_qapplication()
{
    if (!QApplication::instance()) {
        static char  app_name[] = "packetsanitizer";
        static char *argv_buf[] = { app_name, nullptr };
        static int   argc_buf   = 1;
        /* Keep the QApplication alive for the lifetime of Wireshark */
        static QApplication *s_app =
            new QApplication(argc_buf, argv_buf);
        (void)s_app;
        qDebug() << "packetsanitizer: created Qt QApplication";
    }
}

/* ------------------------------------------------------------------ */
/* C-callable API                                                      */
/* ------------------------------------------------------------------ */

extern "C" void packetsanitizer_open_window(capture_file *cf)
{
    ensure_qapplication();

    /* If cf was not supplied, try to obtain it via plugin_if */
    if (!cf)
        cf = (capture_file *)plugin_if_get_capture_file(extract_cf, nullptr);

    /* Determine the input file path */
    QString captureFilePath;
    if (cf && cf->filename)
        captureFilePath = QString::fromUtf8(cf->filename);

    /* Create or re-raise the window */
    if (!g_window) {
        g_window = new PacketSanitizerWindow(captureFilePath,
                                             /*parent=*/nullptr);
        /* Clean up the pointer when the window is closed */
        QObject::connect(g_window, &QDialog::finished,
                         [](int) { g_window = nullptr; });
    } else {
        /* Update the capture path in case a new file was opened */
        /* (The window is already on screen; just raise it.) */
    }

    g_window->show();
    g_window->raise();
    g_window->activateWindow();
    packetsanitizer_pump_events();
}

extern "C" void packetsanitizer_pump_events()
{
    QCoreApplication::processEvents(QEventLoop::AllEvents, 25);
}
