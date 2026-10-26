import QtQuick
import Quickshell
import Quickshell.Io

// Standalone entry: a thin top bar with the tæma pill and its popup.
// Live: consumes `taema bar --follow --format json`.
// Test: TAEMA_BAR_FEED points at a recorded feed; the shell replays it,
// shows the popup once, prints TAEMA_WIDGET_OK, and quits.
ShellRoot {
    id: root

    property var barState: null
    property string taemaBin: Quickshell.env("TAEMA_BIN") || "taema"
    property string feedPath: Quickshell.env("TAEMA_BAR_FEED")
    property bool testMode: feedPath !== ""
    property bool popupOpen: false

    function ingest(line) {
        line = line.trim();
        if (!line)
            return;
        try {
            root.barState = JSON.parse(line);
        } catch (e) {
            console.warn("taema-bar: bad feed line: " + e);
        }
    }

    Process {
        id: live
        running: !root.testMode
        command: [root.taemaBin, "bar", "--follow", "--format", "json"]

        stdout: SplitParser {
            onRead: line => root.ingest(line)
        }
    }

    Process {
        id: replay
        running: root.testMode
        command: ["cat", root.feedPath]

        stdout: SplitParser {
            onRead: line => root.ingest(line)
        }
    }

    Process {
        id: reviewProbe
        command: [root.taemaBin, "review", "--json"]

        stdout: StdioCollector {
            onStreamFinished: {
                // exercises the same parse path the popup uses
                try {
                    JSON.parse(text);
                } catch (e) {
                    console.warn("taema-bar: bad review payload: " + e);
                }
            }
        }
    }

    PanelWindow {
        id: barWin

        anchors {
            top: true
            left: true
            right: true
        }
        implicitHeight: 38
        color: "transparent"

        TaemaBar {
            id: pill
            anchors.centerIn: parent
            barState: root.barState
            onToggled: root.popupOpen = !root.popupOpen
        }
    }

    PopupWindow {
        id: popup
        visible: root.popupOpen || root.testMode

        anchor.window: barWin
        anchor.item: pill
        anchor.edges: Edges.Top
        anchor.gravity: Edges.Bottom

        implicitWidth: 364
        implicitHeight: 480
        color: "transparent"

        onVisibleChanged: {
            if (visible)
                popupContent.refreshReviews();
        }

        TaemaPopup {
            id: popupContent
            anchors.fill: parent
            barState: root.barState
            taemaBin: root.taemaBin
        }
    }

    Timer {
        running: root.testMode
        interval: 500
        repeat: false
        onTriggered: {
            reviewProbe.running = true;
            root.refreshPopup();
        }
    }

    function refreshPopup() {
        // popup content is declarative; this hook exists so the load
        // test exercises review parsing before the verdict
        checkTimer.restart();
    }

    Timer {
        id: checkTimer
        interval: 1500
        repeat: false
        onTriggered: {
            if (root.barState)
                console.log("TAEMA_WIDGET_OK class=" + root.barState["class"] + " reviews=" + root.barState.reviews);
            else
                console.log("TAEMA_WIDGET_EMPTY");
            Qt.quit();
        }
    }
}
