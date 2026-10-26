import QtQuick
import Quickshell
import Quickshell.Io

// The popup behind the pill: state, reviews with answers, hold/snooze,
// profile switcher, agent starter, dashboard opener. Every action runs
// the existing taema CLI.
Rectangle {
    id: root

    property var barState: null
    property string taemaBin: "taema"
    property var reviews: []
    property var profiles: ["auto", "default", "focus", "battery", "game", "quiet", "server"]

    implicitWidth: 340
    implicitHeight: column.implicitHeight + 24
    radius: 12
    color: "#1e1e2e"
    border.width: 1
    border.color: "#45475a"

    function formatBytes(value) {
        let amount = Number(value) || 0;
        const units = ["B", "K", "M", "G", "T"];
        for (let i = 0; i < units.length; i++) {
            if (amount < 1024 || i === units.length - 1) {
                return units[i] === "B" ? String(Math.floor(amount)) : amount.toFixed(1) + units[i];
            }
            amount /= 1024;
        }
        return String(value);
    }

    function refreshReviews() {
        reviewProc.running = false;
        root.reviews = [];
        reviewProc.running = true;
    }

    function act(args) {
        Quickshell.execDetached([root.taemaBin].concat(args));
    }

    Process {
        id: reviewProc
        command: [root.taemaBin, "review", "--json"]

        stdout: StdioCollector {
            onStreamFinished: {
                try {
                    const parsed = JSON.parse(text);
                    root.reviews = parsed.reviews || [];
                } catch (e) {
                    root.reviews = [];
                }
            }
        }
    }

    Timer {
        id: refreshTimer
        interval: 800
        repeat: false
        onTriggered: root.refreshReviews()
    }

    Column {
        id: column
        anchors.fill: parent
        anchors.margins: 12
        spacing: 10

        Text {
            text: "tæma"
            color: "#ffffff"
            font.pixelSize: 15
            font.bold: true
        }

        Text {
            text: {
                if (!root.barState)
                    return "waiting for state …";
                return "mode " + root.barState.mode + " · profile " + root.barState.profile;
            }
            color: "#cdd6f4"
            font.pixelSize: 12
        }

        Text {
            text: {
                if (!root.barState)
                    return "";
                return root.barState.reviews + " reviews · " + root.barState.frozen + " frozen · "
                    + root.formatBytes(root.barState.freed_today_bytes) + " freed today"
                    + (root.barState.pressure ? " · PRESSURE" : "")
                    + (root.barState.hold ? " · held: " + root.barState.hold : "");
            }
            color: "#cdd6f4"
            font.pixelSize: 12
            wrapMode: Text.WordWrap
            width: parent.width
        }

        // reviews
        Repeater {
            model: root.reviews

            delegate: Rectangle {
                id: reviewCard
                required property var modelData
                width: column.width
                implicitHeight: reviewRow.implicitHeight + 12
                radius: 8
                color: "#313244"

                Row {
                    id: reviewRow
                    anchors.fill: parent
                    anchors.margins: 6
                    spacing: 6

                    Text {
                        width: parent.width - stopButton.width - keepButton.width - neverButton.width - 18
                        anchors.verticalCenter: parent.verticalCenter
                        text: {
                            const r = reviewCard.modelData;
                            return (r.owner || r.signature || "review") + " → " + (r.leftover || r.kind || "?");
                        }
                        color: "#ffffff"
                        font.pixelSize: 11
                        elide: Text.ElideRight
                    }

                    Rectangle {
                        id: stopButton
                        anchors.verticalCenter: parent.verticalCenter
                        implicitWidth: 52
                        implicitHeight: 24
                        radius: 6
                        color: "#e06c75"

                        Text {
                            anchors.centerIn: parent
                            text: "Stop"
                            color: "#11111b"
                            font.pixelSize: 11
                        }

                        MouseArea {
                            anchors.fill: parent
                            onClicked: {
                                root.act(["answer", String(reviewCard.modelData.id), "stop"]);
                                refreshTimer.restart();
                            }
                        }
                    }

                    Rectangle {
                        id: keepButton
                        anchors.verticalCenter: parent.verticalCenter
                        implicitWidth: 52
                        implicitHeight: 24
                        radius: 6
                        color: "#a6e3a1"

                        Text {
                            anchors.centerIn: parent
                            text: "Keep"
                            color: "#11111b"
                            font.pixelSize: 11
                        }

                        MouseArea {
                            anchors.fill: parent
                            onClicked: {
                                root.act(["answer", String(reviewCard.modelData.id), "keep"]);
                                refreshTimer.restart();
                            }
                        }
                    }

                    Rectangle {
                        id: neverButton
                        anchors.verticalCenter: parent.verticalCenter
                        implicitWidth: 56
                        implicitHeight: 24
                        radius: 6
                        color: "#6c7086"

                        Text {
                            anchors.centerIn: parent
                            text: "Never"
                            color: "#11111b"
                            font.pixelSize: 11
                        }

                        MouseArea {
                            anchors.fill: parent
                            onClicked: {
                                root.act(["answer", String(reviewCard.modelData.id), "never"]);
                                refreshTimer.restart();
                            }
                        }
                    }
                }
            }
        }

        // hold / snooze / resume
        Row {
            spacing: 6

            Rectangle {
                implicitWidth: 76
                implicitHeight: 26
                radius: 6
                color: "#61afef"

                Text {
                    anchors.centerIn: parent
                    text: (root.barState && root.barState.hold) ? "Resume" : "Hold"
                    color: "#11111b"
                    font.pixelSize: 11
                }

                MouseArea {
                    anchors.fill: parent
                    onClicked: {
                        if (root.barState && root.barState.hold)
                            root.act(["resume"]);
                        else
                            root.act(["hold", "--reason", "widget"]);
                    }
                }
            }

            Rectangle {
                implicitWidth: 88
                implicitHeight: 26
                radius: 6
                color: "#45475a"

                Text {
                    anchors.centerIn: parent
                    text: "Snooze 1h"
                    color: "#ffffff"
                    font.pixelSize: 11
                }

                MouseArea {
                    anchors.fill: parent
                    onClicked: root.act(["snooze", "1h"])
                }
            }

            Rectangle {
                implicitWidth: 96
                implicitHeight: 26
                radius: 6
                color: "#45475a"
                visible: root.barState && !root.barState.agent_running

                Text {
                    anchors.centerIn: parent
                    text: "Start agent"
                    color: "#ffffff"
                    font.pixelSize: 11
                }

                MouseArea {
                    anchors.fill: parent
                    onClicked: root.act(["agent"])
                }
            }
        }

        // profiles
        Flow {
            width: parent.width
            spacing: 6

            Repeater {
                model: root.profiles

                delegate: Rectangle {
                    required property string modelData
                    implicitWidth: 64
                    implicitHeight: 24
                    radius: 6
                    color: (root.barState && root.barState.profile === modelData) ? "#cba6f7" : "#45475a"

                    Text {
                        anchors.centerIn: parent
                        text: parent.modelData
                        color: (root.barState && root.barState.profile === parent.modelData) ? "#11111b" : "#ffffff"
                        font.pixelSize: 11
                    }

                    MouseArea {
                        anchors.fill: parent
                        onClicked: root.act(["profile", parent.modelData])
                    }
                }
            }
        }

        // dashboard
        Rectangle {
            implicitWidth: 140
            implicitHeight: 26
            radius: 6
            color: "#89b4fa"

            Text {
                anchors.centerIn: parent
                text: "Open dashboard"
                color: "#11111b"
                font.pixelSize: 11
            }

            MouseArea {
                anchors.fill: parent
                onClicked: Quickshell.execDetached(["xdg-terminal-exec", root.taemaBin, "dash"])
            }
        }
    }
}
