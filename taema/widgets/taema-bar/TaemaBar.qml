import QtQuick

// The clickable bar pill. Feed it the parsed `taema bar --format json` model.
Rectangle {
    id: root

    property var barState: null
    signal toggled

    implicitWidth: row.implicitWidth + 28
    implicitHeight: 30
    radius: 15
    color: "#1e1e2e"
    border.width: 2
    border.color: {
        const cls = (root.barState && root.barState["class"]) || "error";
        const colors = {
            "ok": "#8a8a8a",
            "review": "#e5c07c",
            "pressure": "#e06c75",
            "hold": "#61afef",
            "error": "#ff5555"
        };
        return colors[cls] || "#ff5555";
    }

    Row {
        id: row
        anchors.centerIn: parent
        spacing: 8

        Text {
            text: (root.barState && root.barState.text) || "tæma …"
            color: "#ffffff"
            font.pixelSize: 13
            font.family: "monospace"
        }
    }

    MouseArea {
        anchors.fill: parent
        acceptedButtons: Qt.LeftButton
        onClicked: root.toggled()
    }
}
