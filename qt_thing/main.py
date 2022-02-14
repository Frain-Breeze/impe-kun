"""PySide6 port of the widgets/layouts/basiclayout example from Qt v5.x"""

import sys
import json
import os

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QApplication, QComboBox, QDialog,
                               QDialogButtonBox, QGridLayout, QGroupBox,
                               QFormLayout, QHBoxLayout, QLabel, QLineEdit,
                               QMenu, QMenuBar, QPushButton, QSpinBox,
                               QTextEdit, QVBoxLayout, QWidget, QListWidget, QListWidgetItem)

class MainDialog(QDialog):

    items = {}
    current_path = []

    def load_json_path(self):
        print("loading json from path {}".format(self.json_path.text()))
        with open(self.json_path.text(), "r") as jsonin:
            self.items = json.loads(jsonin.read())
        self.update_item_list()
    
    def on_item_list_enter(self, item: QListWidgetItem):

        if(item.text() == ".."):
            self.current_path.pop()
        else:
            itref = self.items
            for p in self.current_path:
                itref = itref[p]
            self.current_path.append(item.text().split(':')[-1])
        
        cool_working_text = ""
        working_text = ""
        itref = self.items
        for p in self.current_path:
            if "humanName" in itref[p]:
                cool_working_text += itref[p]["humanName"] + "/"
            else:
                cool_working_text += p + "/"
            working_text += p + "/"
            itref = itref[p]
        self.gui_working_path.setText(working_text)
        self.gui_rich_working_path.setText(cool_working_text)

        self.update_item_list()

    def update_item_list(self):
        itref = self.items
        for p in self.current_path:
            itref = itref[p]
        
        self.item_list.clear()
        if len(self.current_path) != 0:
            self.item_list.addItem("..")
        
        if "keys" in itref:
            #print(itref)
            for k in itref["keys"]:
                curr_keyname = ""
                curr_key = ""
                for i in k:
                    if(i == "key"):
                        curr_key = k["key"]
                    elif(i == "keyName"):
                        curr_keyname = k["keyName"]
                new_name = "{} :{}".format(curr_key, curr_keyname)
                self.item_list.addItem(new_name)
        else:
            for key1, value1 in itref.items():
                if isinstance(value1, dict):
                    curr_key = ""
                    curr_name = ""
                    for key2, value2 in value1.items():
                        if isinstance(value2, str):
                            #print(key2, value2)
                            if(key2 == "encryptKey"):
                                curr_key = value2
                            elif(key2 == "humanName"):
                                curr_name = value2
                    new_name = "{} - {} :{}".format(curr_name, curr_key, key1)
                    self.item_list.addItem(new_name)

    

    def __init__(self):
        QDialog.__init__(self)

        self.json_path = QLineEdit("E:/temp_ggr_match/assemble.json")
        self.json_path.returnPressed.connect(self.load_json_path)
        self.exec_path = QLineEdit("./x64/Release/ggr-crypt.exe")

        self.gui_working_path = QLabel("")
        self.gui_working_path.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.gui_rich_working_path = QLabel("")
        self.gui_rich_working_path.setTextInteractionFlags(Qt.TextSelectableByMouse)

        self.layout = QVBoxLayout(self)
        self.layout.addWidget(self.json_path)
        self.layout.addWidget(self.exec_path)
        self.layout.addWidget(self.gui_working_path)
        self.layout.addWidget(self.gui_rich_working_path)

        self.item_list = QListWidget(self)
        self.item_list.itemPressed.connect(self.on_item_list_enter)
        self.layout.addWidget(self.item_list)

        self.load_json_path()


if __name__ == '__main__':
    app = QApplication(sys.argv)
    dialog = MainDialog()
    sys.exit(dialog.exec())

"""class Dialog(QDialog):
    num_grid_rows = 3
    num_buttons = 4

    def __init__(self):
        super().__init__()

        self.create_menu()
        self.create_horizontal_group_box()
        self.create_grid_group_box()
        self.create_form_group_box()

        big_editor = QTextEdit()
        big_editor.setPlainText("This widget takes up all the remaining space "
                "in the top-level layout.")

        button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)

        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)

        main_layout = QVBoxLayout()
        main_layout.setMenuBar(self._menu_bar)
        main_layout.addWidget(self._horizontal_group_box)
        main_layout.addWidget(self._grid_group_box)
        main_layout.addWidget(self._form_group_box)
        main_layout.addWidget(big_editor)
        main_layout.addWidget(button_box)
        self.setLayout(main_layout)

        self.setWindowTitle("Basic Layouts")

    def create_menu(self):
        self._menu_bar = QMenuBar()

        self._file_menu = QMenu("&File", self)
        self._exit_action = self._file_menu.addAction("E&xit")
        self._menu_bar.addMenu(self._file_menu)

        self._exit_action.triggered.connect(self.accept)

    def create_horizontal_group_box(self):
        self._horizontal_group_box = QGroupBox("Horizontal layout")
        layout = QHBoxLayout()

        for i in range(Dialog.num_buttons):
            button = QPushButton(f"Button {i + 1}")
            layout.addWidget(button)

        self._horizontal_group_box.setLayout(layout)

    def on_loli_changed(self):
        print(hello)

    def create_grid_group_box(self):
        self._grid_group_box = QGroupBox("Grid layout")
        layout = QGridLayout()

        for i in range(Dialog.num_grid_rows):
            label = QLabel(f"Line {i + 1}:")
            line_edit = QLineEdit()
            layout.addWidget(label, i + 1, 0)
            layout.addWidget(line_edit, i + 1, 1)

        self.thing = QListWidget()
        self.item1 = QListWidgetItem("haha", self.thing)
        self.thing.currentItemChanged.connect(self.on_loli_changed)
        self.thing.addItem("loli")
        self.thing.addItem("loli2")
        self.thing.addItem("loli3")
        layout.addWidget(self.thing)

        self._small_editor = QTextEdit()
        self._small_editor.setPlainText("This widget takes up about two thirds "
                "of the grid layout.")

        layout.addWidget(self._small_editor, 0, 2, 4, 1)

        layout.setColumnStretch(1, 10)
        layout.setColumnStretch(2, 20)
        self._grid_group_box.setLayout(layout)

    def create_form_group_box(self):
        self._form_group_box = QGroupBox("Form layout")
        layout = QFormLayout()
        layout.addRow(QLabel("Line 1:"), QLineEdit())
        layout.addRow(QLabel("Line 2, long text:"), QComboBox())
        layout.addRow(QLabel("Line 3:"), QSpinBox())
        self._form_group_box.setLayout(layout)


if __name__ == '__main__':
    app = QApplication(sys.argv)
    dialog = Dialog()
    sys.exit(dialog.exec())"""