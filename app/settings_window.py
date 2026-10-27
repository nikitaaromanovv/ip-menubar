"""Native settings window: grouped options, each with a short explanation. Main thread only."""
import objc
from Foundation import NSObject
from AppKit import (NSApplication, NSButton, NSColor, NSFont, NSPopUpButton, NSScrollView,
                    NSTextField, NSView, NSWindow, NSBox)

from ping_monitor import validate_host

WIDTH, HEIGHT, VISIBLE = 520, 1010, 640
INNER = WIDTH - 48
RADIO, CHECKBOX = 4, 3          # NSButtonTypeRadio, NSButtonTypeSwitch
STYLE_MASK = 1 | 2 | 4          # titled, closable, miniaturizable
STYLES = (('full', 'Значок, флаг и IP'), ('ip', 'Значок и IP'),
          ('flag', 'Значок и флаг'), ('icon', 'Только значок'))
RETENTION = (30, 90, 365)


def ensure_edit_menu():
    """An agent app has no main menu, so Cmd+C/V/X/A/Z would not reach text fields.
    An invisible Edit menu supplies the standard key equivalents."""
    from AppKit import NSMenu, NSMenuItem
    app = NSApplication.sharedApplication()
    menu = app.mainMenu()
    if menu is not None and menu.itemWithTitle_('Edit') is not None:
        return
    if menu is None:
        menu = NSMenu.alloc().initWithTitle_('Main')
        menu.addItem_(NSMenuItem.alloc().initWithTitle_action_keyEquivalent_('IP Menubar', None, ''))
        app.setMainMenu_(menu)
    edit = NSMenu.alloc().initWithTitle_('Edit')
    for title, action, key in (('Undo', 'undo:', 'z'), ('Cut', 'cut:', 'x'), ('Copy', 'copy:', 'c'),
                               ('Paste', 'paste:', 'v'), ('Select All', 'selectAll:', 'a')):
        edit.addItem_(NSMenuItem.alloc().initWithTitle_action_keyEquivalent_(title, action, key))
    holder = NSMenuItem.alloc().initWithTitle_action_keyEquivalent_('Edit', None, '')
    holder.setSubmenu_(edit)
    menu.addItem_(holder)


class Flipped(NSView):
    def isFlipped(self):
        return True


class SettingsActions(NSObject):
    @objc.python_method
    def connect(self, controller):
        self.controller = controller

    def style_(self, sender): self.controller.choose_style(sender.tag())
    def openMode_(self, sender): self.controller.app.apply_settings(hover_open=sender.tag() == 0); self.controller.refresh()
    def frequency_(self, sender): self.controller.app.apply_settings(economical=sender.tag() == 1); self.controller.refresh()
    def pingApply_(self, sender): self.controller.apply_ping()
    def pingDefault_(self, sender): self.controller.apply_ping('google.com')
    def notify_(self, sender): self.controller.toggle_notifications(sender.state() == 1)
    def testNotify_(self, sender): self.controller.app.test_notification()
    def history_(self, sender): self.controller.toggle_history(sender.state() == 1)
    def retention_(self, sender): self.controller.choose_retention(sender.indexOfSelectedItem())
    def clearHistory_(self, sender): self.controller.app.clear_history(); self.controller.refresh()
    def export_(self, sender): self.controller.app.export_history()
    def exportIP_(self, sender): self.controller.app.apply_settings(exclude_export_ip=sender.state() == 1); self.controller.refresh()
    def resetTraffic_(self, sender): self.controller.app.reset_traffic(); self.controller.refresh()
    def login_(self, sender): self.controller.toggle_login(sender.state() == 1)
    def warnVPN_(self, sender): self.controller.app.apply_settings(warn_no_vpn=sender.state() == 1); self.controller.refresh()


def text(parent, string, frame, size=11, secondary=True, bold=False):
    field = NSTextField.wrappingLabelWithString_(string)
    field.setFrame_(frame)
    field.setFont_(NSFont.boldSystemFontOfSize_(size) if bold else NSFont.systemFontOfSize_(size))
    field.setTextColor_(NSColor.secondaryLabelColor() if secondary else NSColor.labelColor())
    parent.addSubview_(field)
    return field


def control(parent, kind, title, frame, target, action, tag=0):
    item = NSButton.alloc().initWithFrame_(frame)
    if kind is not None:
        item.setButtonType_(kind)
    else:
        item.setBezelStyle_(1)  # rounded push button
    item.setTitle_(title)
    item.setFont_(NSFont.systemFontOfSize_(13 if kind is not None else 12))
    item.setTarget_(target)
    item.setAction_(action)
    item.setTag_(tag)
    parent.addSubview_(item)
    return item


class SettingsController:
    def __init__(self, app):
        self.app = app
        self.window = None
        self.target = SettingsActions.alloc().init()
        self.target.connect(self)

    # ----- layout -----------------------------------------------------------------------

    def header(self, view, y, title, explanation, lines=2):
        if y > 16:
            line = NSBox.alloc().initWithFrame_(((24, y - 10), (INNER, 1)))
            line.setBoxType_(2)  # separator
            view.addSubview_(line)
        text(view, title, ((24, y), (INNER, 18)), 13, secondary=False, bold=True)
        text(view, explanation, ((24, y + 20), (INNER, 15 * lines)), 11)
        return y + 24 + 15 * lines

    def radios(self, view, y, titles, action):
        # Each group gets its own container: AppKit makes sibling radio buttons exclusive.
        group = Flipped.alloc().initWithFrame_(((24, y), (INNER, 22 * len(titles))))
        view.addSubview_(group)
        buttons = [control(group, RADIO, title, ((0, 22 * i), (INNER, 20)), self.target, action, i)
                   for i, title in enumerate(titles)]
        return y + 22 * len(titles) + 18, buttons

    def build(self):
        view = Flipped.alloc().initWithFrame_(((0, 0), (WIDTH, HEIGHT)))
        t = self.target
        y = 16
        y = self.header(view, y, 'Строка меню',
                        'IPv6-адрес показывается только в панели.', lines=1)
        y, self.style_buttons = self.radios(view, y, [title for _, title in STYLES], 'style:')

        y = self.header(view, y, 'Открытие панели',
                        'Открытие через 1 с, закрытие через 1,5 с после ухода указателя.', lines=1)
        y, self.open_buttons = self.radios(view, y, ['При наведении на значок', 'Только по клику'], 'openMode:')

        y = self.header(view, y, 'Частота проверок',
                        'Обычная: пинг 2 с, HTTPS 30 с (стабильно 2 мин), IP 2 мин.\n'
                        'Экономная: пинг 5 с, HTTPS 60 с (стабильно 5 мин), IP 5 мин.')
        y, self.frequency_buttons = self.radios(view, y, ['Обычная', 'Экономная'], 'frequency:')

        y = self.header(view, y, 'Адрес пинга',
                        'Домен или IP без https:// и порта.', lines=1)
        self.ping_field = NSTextField.alloc().initWithFrame_(((24, y), (230, 24)))
        view.addSubview_(self.ping_field)
        control(view, None, 'Применить', ((262, y - 2), (100, 28)), t, 'pingApply:')
        control(view, None, 'По умолчанию', ((366, y - 2), (130, 28)), t, 'pingDefault:')
        y += 50

        y = self.header(view, y, 'Уведомления',
                        'Обрыв и восстановление связи.', lines=1)
        self.notify_box = control(view, CHECKBOX, 'Уведомлять об обрыве и восстановлении',
                                  ((24, y), (INNER, 20)), t, 'notify:')
        control(view, None, 'Проверить уведомление', ((24, y + 26), (190, 28)), t, 'testNotify:')
        y += 74

        y = self.header(view, y, 'История событий',
                        'Обрывы, ухудшения, смена IP и сети. Выключение удаляет записи.', lines=1)
        self.history_box = control(view, CHECKBOX, 'Сохранять историю событий', ((24, y), (INNER, 20)), t, 'history:')
        text(view, 'Хранить:', ((24, y + 30), (70, 18)), 13, secondary=False)
        self.retention = NSPopUpButton.alloc().initWithFrame_pullsDown_(((96, y + 26), (130, 26)), False)
        self.retention.addItemsWithTitles_([f'{days} дней' for days in RETENTION])
        self.retention.setTarget_(t)
        self.retention.setAction_('retention:')
        view.addSubview_(self.retention)
        self.history_info = text(view, '', ((236, y + 30), (INNER - 212, 18)), 11)
        control(view, None, 'Очистить историю…', ((24, y + 60), (170, 28)), t, 'clearHistory:')
        control(view, None, 'Экспорт в CSV…', ((198, y + 60), (150, 28)), t, 'export:')
        self.export_box = control(view, CHECKBOX, 'При экспорте заменять IP-адреса на [IP]',
                                  ((24, y + 94), (INNER, 20)), t, 'exportIP:')
        y += 138

        y = self.header(view, y, 'Трафик',
                        'Байты основного интерфейса, пока приложение запущено.', lines=1)
        self.traffic_info = text(view, '', ((24, y), (INNER, 18)), 11)
        control(view, None, 'Сбросить трафик…', ((24, y + 22), (170, 28)), t, 'resetTraffic:')
        y += 70

        y = self.header(view, y, 'VPN',
                        'Зеленый: VPN на Mac или выход через хостинг. Желтый: VPN частично или IPv6 мимо.\n'
                        'Серый: без VPN. С предупреждением: красный и уведомление.')
        self.warn_box = control(view, CHECKBOX, 'Предупреждать, если трафик идет без VPN',
                                ((24, y), (INNER, 20)), t, 'warnVPN:')
        y += 46

        y = self.header(view, y, 'Запуск', 'Только для приложения .app.', lines=1)
        self.login_box = control(view, CHECKBOX, 'Запускать при входе в macOS', ((24, y), (INNER, 20)), t, 'login:')
        self.login_info = text(view, '', ((24, y + 24), (INNER, 30)), 11)
        y += 68

        text(view, 'Проверочные сервисы', ((24, y), (INNER, 18)), 13, secondary=False, bold=True)
        self.services_info = text(view, '', ((24, y + 20), (INNER, 15 * 7)), 11)
        y += 24 + 15 * 7
        view.setFrameSize_((WIDTH, y + 16))

        scroll = NSScrollView.alloc().initWithFrame_(((0, 0), (WIDTH, VISIBLE)))
        scroll.setHasVerticalScroller_(True)
        scroll.setAutohidesScrollers_(True)
        scroll.setDrawsBackground_(False)
        scroll.setDocumentView_(view)
        self.window = NSWindow.alloc().initWithContentRect_styleMask_backing_defer_(
            ((0, 0), (WIDTH, VISIBLE)), STYLE_MASK, 2, False)
        self.window.setTitle_('Настройки IP Menubar')
        self.window.setReleasedWhenClosed_(False)
        self.window.setContentView_(scroll)
        self.window.center()

    # ----- state ------------------------------------------------------------------------

    def refresh(self):
        if self.window is None:
            return
        s = self.app.settings
        keys = [key for key, _ in STYLES]
        for i, button in enumerate(self.style_buttons):
            button.setState_(1 if keys[i] == s.menubar_style else 0)
        for i, button in enumerate(self.open_buttons):
            button.setState_(1 if (i == 0) == s.hover_open else 0)
        for i, button in enumerate(self.frequency_buttons):
            button.setState_(1 if (i == 1) == s.economical else 0)
        self.ping_field.setStringValue_(s.ping_host)
        self.notify_box.setState_(1 if s.notifications else 0)
        self.history_box.setState_(1 if s.history_enabled else 0)
        self.retention.selectItemAtIndex_(RETENTION.index(s.history_days) if s.history_days in RETENTION else 2)
        self.retention.setEnabled_(s.history_enabled)
        size = self.app.store.size() / 1_000_000
        self.history_info.setStringValue_(f'Событий: {self.app.store.count()} · '
                                          f'{size:.1f} МБ'.replace('.', ','))
        self.export_box.setState_(1 if s.exclude_export_ip else 0)
        self.warn_box.setState_(1 if s.warn_no_vpn else 0)
        self.traffic_info.setStringValue_(f'Учет с {self.app.traffic_store.started}')
        self.services_info.setStringValue_(self.app.services_text())
        import autostart
        status = autostart.status()
        self.login_box.setState_(1 if status in (1, 2) else 0)
        self.login_box.setEnabled_(status != 3)
        self.login_info.setStringValue_(autostart.STATUS_TEXT.get(status, ''))

    def show(self):
        ensure_edit_menu()
        if self.window is None:
            self.build()
        self.refresh()
        self.window.makeKeyAndOrderFront_(None)
        NSApplication.sharedApplication().activateIgnoringOtherApps_(True)

    # ----- actions ----------------------------------------------------------------------

    def choose_style(self, index):
        self.app.apply_settings(menubar_style=STYLES[index][0])
        self.refresh()

    def apply_ping(self, value=None):
        value = self.ping_field.stringValue() if value is None else value
        try:
            host = validate_host(str(value))
        except ValueError as error:
            self.app.alert('Адрес пинга', str(error))
            self.refresh()
            return
        self.app.apply_settings(ping_host=host)
        self.refresh()

    def toggle_notifications(self, enabled):
        if self.app.apply_settings(notifications=enabled) and enabled:
            # The first notification is also what makes macOS ask for permission.
            self.app.test_notification()
        self.refresh()

    def toggle_history(self, enabled):
        if not enabled and self.app.settings.history_enabled and not self.app.confirm_history_off():
            self.refresh()
            return
        self.app.apply_settings(history_enabled=enabled)
        self.refresh()

    def choose_retention(self, index):
        days = RETENTION[index]
        if days < self.app.settings.history_days:
            answer = self.app.alert('Сократить срок хранения?',
                                    f'События старше {days} дней будут удалены', ok='Удалить', cancel='Отмена')
            if answer != 1:
                self.refresh()
                return
        self.app.apply_settings(history_days=days)
        self.refresh()

    def toggle_login(self, enabled):
        self.app.set_login(enabled)
        self.refresh()
