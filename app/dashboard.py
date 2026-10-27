"""Compact native interface. Drawing, tracking and all AppKit access stay on main thread."""
import math
import time
import objc
from Foundation import NSObject, NSTimer, NSRunLoop, NSRunLoopCommonModes
from AppKit import (
    NSApplication, NSView, NSViewController, NSScrollView, NSTextField, NSFont, NSColor,
    NSBox, NSButton, NSPanel, NSPopover, NSScreen, NSImage, NSImageView, NSBezierPath,
    NSEvent, NSPointInRect, NSWorkspace, NSInsetRect, NSUnionRect,
    NSBoxCustom, NSNoBorder, NSBezelStyleRounded, NSPopoverBehaviorTransient,
    NSWindowStyleMaskTitled, NSWindowStyleMaskClosable, NSWindowStyleMaskMiniaturizable,
    NSFloatingWindowLevel, NSNormalWindowLevel, NSMinYEdge,
    NSLeftMouseUpMask, NSRightMouseUpMask, NSRightMouseUp,
    NSViewWidthSizable, NSViewHeightSizable, NSRectFill, NSTrackingArea,
)

# NSTrackingAreaOptions: MouseEnteredAndExited | ActiveAlways | InVisibleRect
TRACKING_OPTIONS = 0x01 | 0x80 | 0x200
FAST_TICK = .15   # while the pointer is near, the panel is open or the icon animates
IDLE_TICK = .5    # fallback poll; with a tracking area the timer stops when idle

WIDTH, HEIGHT = 340, 400
HOVER_OPEN_DELAY = 1.0
HOVER_CLOSE_DELAY = 1.5
HOVER_MARGIN = 30   # points of tolerance around the icon and the panel


def status_image(state, phase=0):
    image = NSImage.alloc().initWithSize_((19, 19))
    image.lockFocus()
    color = (NSColor.systemOrangeColor() if state in ('degraded', 'recovering') else
             NSColor.systemRedColor() if state == 'offline' else NSColor.labelColor())
    color.set()
    if state == 'pending':
        reduce_motion = NSWorkspace.sharedWorkspace().accessibilityDisplayShouldReduceMotion()
        for index in range(3):
            offset = 0 if reduce_motion else math.sin(phase - index * .8) * 1.5
            NSBezierPath.bezierPathWithOvalInRect_(((2 + index * 6, 8 + offset), (3, 3))).fill()
    else:
        for index, height in enumerate((5, 10, 15)):
            path = NSBezierPath.bezierPath()
            path.setLineWidth_(2)
            path.moveToPoint_((3 + index * 6, 2))
            path.lineToPoint_((3 + index * 6, 2 + height))
            path.stroke()
        if state == 'offline':
            path = NSBezierPath.bezierPath()
            path.setLineWidth_(2)
            path.moveToPoint_((1, 18))
            path.lineToPoint_((18, 1))
            path.stroke()
    image.unlockFocus()
    image.setTemplate_(state in ('online', 'pending'))
    return image


def route_image(proxy=False):
    image = NSImage.alloc().initWithSize_((19, 19))
    image.lockFocus()
    NSColor.labelColor().set()
    path = NSBezierPath.bezierPath()
    path.setLineWidth_(1.4)
    if proxy:
        path.appendBezierPathWithRect_(((1, 6), (5, 7)))
        path.appendBezierPathWithRect_(((13, 6), (5, 7)))
        path.moveToPoint_((6, 9)); path.lineToPoint_((13, 9))
        path.moveToPoint_((10, 12)); path.lineToPoint_((13, 9)); path.lineToPoint_((10, 6))
    else:
        path.moveToPoint_((3, 2)); path.lineToPoint_((3, 10))
        path.curveToPoint_controlPoint1_controlPoint2_((16, 10), (3, 19), (16, 19))
        path.lineToPoint_((16, 2))
        path.moveToPoint_((9.5, 2)); path.lineToPoint_((9.5, 7))
        path.moveToPoint_((9.5, 10)); path.lineToPoint_((9.5, 12))
    path.stroke()
    image.unlockFocus()
    image.setTemplate_(True)
    return image


BADGE_COLORS = {'green': 'systemGreenColor', 'amber': 'systemOrangeColor',
                'red': 'systemRedColor', 'gray': 'systemGrayColor'}
_badge_cache = {}


def badge_image(name):
    """Small status dot: green (VPN/proxy seen and working), amber (partial), red (warning
    enabled and no VPN, or proxy failing), gray (nothing detected)."""
    if name not in _badge_cache:
        image = NSImage.alloc().initWithSize_((10, 10))
        image.lockFocus()
        getattr(NSColor, BADGE_COLORS.get(name, 'systemGrayColor'))().setFill()
        NSBezierPath.bezierPathWithOvalInRect_(((1, 1), (8, 8))).fill()
        image.unlockFocus()
        _badge_cache[name] = image
    return _badge_cache[name]


def pointer_position():
    return NSEvent.mouseLocation()


class FlippedView(NSView):
    def isFlipped(self): return True
    def drawRect_(self, rect):
        NSColor.windowBackgroundColor().setFill()
        NSRectFill(rect)


class Actions(NSObject):
    @objc.python_method
    def connect(self, dashboard): self.dashboard = dashboard
    def toggle_(self, sender):
        event = NSApplication.sharedApplication().currentEvent()
        if event is not None and event.type() == NSRightMouseUp:
            self.dashboard.show_menu(self.dashboard.app._menu._menu, sender)
        else:
            self.dashboard.toggle()
    def refresh_(self, sender): self.dashboard.app.manual_refresh(None)
    def detach_(self, sender): self.dashboard.open_window()
    def pin_(self, sender): self.dashboard.toggle_pin()
    def history_(self, sender): self.dashboard.app.show_history(None)
    def settings_(self, sender): self.dashboard.app.open_settings(None)
    def period_(self, sender): self.dashboard.app.cycle_traffic_period()
    def dates_(self, sender): self.dashboard.app.ask_traffic_range(None)
    def vpnCheck_(self, sender): self.dashboard.app.run_vpn_check(None)
    def mouseEntered_(self, event): self.dashboard.wake()
    def mouseExited_(self, event): self.dashboard.wake()
    def explain_(self, sender): self.dashboard.show_details()
    def back_(self, sender): self.dashboard.show_details(False)
    def site_(self, sender): self.dashboard.app.test_site(None)
    def segments_(self, sender): self.dashboard.app.test_segments(None)
    def compact_(self, sender): self.dashboard.app.toggle_compact(None)
    def quit_(self, sender): self.dashboard.app.quit(None)
    def uiTick_(self, timer): self.dashboard.ui_tick()
    def popoverShouldClose_(self, popover):
        # Let our status-button action handle its own click. Otherwise AppKit
        # may dismiss first and the same click immediately opens it again.
        if self.dashboard.closing:
            return True
        event = NSApplication.sharedApplication().currentEvent()
        if event is None or event.type() not in (1, 2, 3, 4):
            return True
        button = self.dashboard.status_item.button()
        if button.window() is None:
            return True
        rect = button.window().convertRectToScreen_(button.convertRect_toView_(button.bounds(), None))
        return not NSPointInRect(pointer_position(), rect)
    def popoverDidClose_(self, notification):
        self.dashboard.closing = False
        self.dashboard.suppress_hover = True
        self.dashboard.hover_since = self.dashboard.outside_since = None


def label(parent, text, rect, size=12):
    field = NSTextField.wrappingLabelWithString_(text)
    field.setFrame_(rect)
    field.setFont_(NSFont.systemFontOfSize_(size))
    field.setTextColor_(NSColor.labelColor())
    field.setSelectable_(True)
    parent.addSubview_(field)
    return field


def button(parent, title, rect, target, action):
    item = NSButton.alloc().initWithFrame_(rect)
    item.setTitle_(title)
    item.setBezelStyle_(NSBezelStyleRounded)
    item.setFont_(NSFont.systemFontOfSize_(11))
    item.setTarget_(target)
    item.setAction_(action)
    parent.addSubview_(item)
    return item


def card(parent, rect):
    box = NSBox.alloc().initWithFrame_(rect)
    box.setBoxType_(NSBoxCustom)
    box.setBorderType_(NSNoBorder)
    box.setCornerRadius_(8)
    box.setFillColor_(NSColor.controlBackgroundColor())
    parent.addSubview_(box)


class DashboardView:
    def __init__(self, target, height, detached=False):
        self.fields = {}
        self.scroll = NSScrollView.alloc().initWithFrame_(((0, 0), (WIDTH, height)))
        self.scroll.setHasVerticalScroller_(True)
        self.scroll.setAutohidesScrollers_(True)
        self.scroll.setDrawsBackground_(False)
        self.scroll.setAutoresizingMask_(NSViewWidthSizable | NSViewHeightSizable)
        self.view = FlippedView.alloc().initWithFrame_(((0, 0), (WIDTH, HEIGHT)))
        self.scroll.setDocumentView_(self.view)
        v = self.view
        self.top_button = button(v, 'Поверх окон' if detached else 'Окно ↗', ((230, 8), (100, 26)),
                                 target, 'pin:' if detached else 'detach:')
        self.fields['ip'] = label(v, 'IP не определен', ((14, 10), (212, 30)), 18)
        self.fields['country'] = label(v, '', ((14, 44), (312, 32)), 10)
        self.state_icon = NSImageView.alloc().initWithFrame_(((14, 80), (19, 19)))
        v.addSubview_(self.state_icon)
        self.fields['connection'] = label(v, 'Проверка…', ((42, 78), (282, 34)), 11)
        for x, key, title in ((12, 'ping_value', 'ПИНГ'), (176, 'loss_value', 'ПОТЕРИ')):
            card(v, ((x, 116), (152, 60)))
            label(v, title, ((x + 12, 123), (130, 14)), 9)
            self.fields[key] = label(v, '—', ((x + 12, 142), (130, 28)), 19)
        for x, key, title in ((12, 'down', 'ПОЛУЧЕНИЕ ↓'), (176, 'up', 'ОТПРАВКА ↑')):
            card(v, ((x, 182), (152, 60)))
            label(v, title, ((x + 12, 189), (130, 14)), 9)
            self.fields[key] = label(v, '—', ((x + 12, 208), (130, 28)), 18)
        self.fields['vpn'] = label(v, '', ((40, 253), (286, 28)), 11)
        self.fields['proxy'] = label(v, '', ((40, 285), (286, 28)), 11)
        self.badges = {}
        for y, is_proxy in ((253, False), (285, True)):
            icon = NSImageView.alloc().initWithFrame_(((14, y), (19, 19)))
            icon.setImage_(route_image(is_proxy))
            v.addSubview_(icon)
            dot = NSImageView.alloc().initWithFrame_(((26, y + 10), (10, 10)))
            dot.setImage_(badge_image('gray'))
            v.addSubview_(dot)
            self.badges['proxy' if is_proxy else 'vpn'] = dot
        # The traffic line is a button: each click shows the next period.
        self.period_button = NSButton.alloc().initWithFrame_(((10, 316), (316, 24)))
        self.period_button.setBordered_(False)
        self.period_button.setAlignment_(0)
        self.period_button.setFont_(NSFont.systemFontOfSize_(11))
        self.period_button.setTitle_('Сегодня')
        self.period_button.setToolTip_('Период: сегодня, 7 дней, 30 дней, месяц, год, все время')
        self.period_button.setTarget_(target)
        self.period_button.setAction_('period:')
        v.addSubview_(self.period_button)
        self.fields['storage'] = label(v, '', ((14, 342), (312, 16)), 9)
        button(v, 'Подробнее', ((6, 366), (86, 28)), target, 'explain:')
        button(v, 'История', ((92, 366), (72, 28)), target, 'history:')
        button(v, 'Настройки', ((164, 366), (88, 28)), target, 'settings:')
        self.quit_button = button(v, 'Выход', ((252, 366), (82, 28)), target, 'quit:')
        self.quit_button.setToolTip_('Завершить IP Menubar')
        self.details_view = FlippedView.alloc().initWithFrame_(((0, 0), (WIDTH, 1200)))
        self.details_field = label(self.details_view, '', ((14, 76), (312, 1100)), 11)
        button(self.details_view, 'Назад', ((8, 8), (70, 28)), target, 'back:')
        button(self.details_view, 'Проверить сайт', ((82, 8), (126, 28)), target, 'site:')
        button(self.details_view, 'Маршрут', ((212, 8), (116, 28)), target, 'segments:')
        button(self.details_view, 'Трафик за даты…', ((8, 40), (150, 28)), target, 'dates:')
        button(self.details_view, 'Проверить VPN', ((162, 40), (166, 28)), target, 'vpnCheck:')

    def details(self, value):
        self.scroll.setDocumentView_(self.details_view if value else self.view)
        self.scroll.contentView().scrollToPoint_((0, 0))

    def update(self, data):
        for key, field in self.fields.items():
            field.setStringValue_(str(data.get(key, '—')))
            field.setToolTip_(str(data.get(key, '—')))
        self.period_button.setTitle_(str(data.get('today', '')))
        text = data.get('details', '')
        self.details_field.setStringValue_(text)
        # Conservative line estimate keeps detailed reports scrollable without clipping.
        lines = sum(max(1, math.ceil(len(line) / 40)) for line in text.splitlines())
        height = max(600, lines * 17 + 120)
        self.details_view.setFrameSize_((WIDTH, height))
        self.details_field.setFrame_(((14, 76), (312, height - 82)))
        self.state_icon.setImage_(status_image(data.get('status', 'pending')))
        for key, dot in self.badges.items():
            dot.setImage_(badge_image(data.get(key + '_badge', 'gray')))


class DashboardController:
    def __init__(self, app, status_item):
        self.app, self.status_item = app, status_item
        self.data = {}
        self.pinned = False
        self.window = self.window_view = None
        self.in_menu = False
        self.closing = False
        self.suppress_hover = False
        self.hover_since = self.outside_since = None
        self.last_icon_state = None
        self.details_open = False
        screen = NSScreen.mainScreen()
        available = screen.visibleFrame().size.height if screen else 800
        self.height = min(HEIGHT, max(280, available - 100))
        self.target = Actions.alloc().init()
        self.target.connect(self)
        self.popup_view = DashboardView(self.target, self.height)
        controller = NSViewController.alloc().init()
        controller.setView_(self.popup_view.scroll)
        self.popover = NSPopover.alloc().init()
        self.popover.setDelegate_(self.target)
        self.popover.setBehavior_(NSPopoverBehaviorTransient)
        self.popover.setContentViewController_(controller)
        self.popover.setContentSize_((WIDTH, self.height))
        status_item.setMenu_(None)
        status_button = status_item.button()
        status_button.setTarget_(self.target)
        status_button.setAction_('toggle:')
        status_button.sendActionOn_(NSLeftMouseUpMask | NSRightMouseUpMask)
        self.timer = None
        self.timer_interval = None
        # A tracking area wakes the controller when the pointer reaches the icon, so no
        # timer has to run while nothing is happening. Without it, a slow poll remains.
        self.tracking = False
        try:
            area = NSTrackingArea.alloc().initWithRect_options_owner_userInfo_(
                status_button.bounds(), TRACKING_OPTIONS, self.target, None)
            status_button.addTrackingArea_(area)
            self.tracking = True
        except Exception:
            self.tracking = False
        self.set_timer(IDLE_TICK)

    def set_timer(self, interval):
        if interval == self.timer_interval and self.timer is not None:
            return
        if self.timer is not None:
            self.timer.invalidate()
            self.timer = None
        self.timer_interval = interval
        if interval is None:
            return
        self.timer = NSTimer.timerWithTimeInterval_target_selector_userInfo_repeats_(
            interval, self.target, 'uiTick:', None, True)
        NSRunLoop.mainRunLoop().addTimer_forMode_(self.timer, NSRunLoopCommonModes)

    def wake(self):
        self.set_timer(FAST_TICK)
        self.ui_tick()

    def is_visible(self):
        return bool(self.popover.isShown() or (self.window is not None and self.window.isVisible()))

    def idle(self):
        state = self.data.get('status', 'pending')
        return (not self.popover.isShown() and state != 'pending' and self.hover_since is None
                and self.outside_since is None and not self.closing)

    def pace(self, active):
        if active:
            self.set_timer(FAST_TICK)
        elif self.idle():
            self.set_timer(None if self.tracking else IDLE_TICK)

    def update(self, data):
        self.data = data
        if data.get('status') == 'pending':
            self.set_timer(FAST_TICK)  # the waiting dots animate
        if self.popover.isShown(): self.popup_view.update(data)
        if self.window is not None and self.window.isVisible(): self.window_view.update(data)
        self.status_item.button().setToolTip_(data.get('connection', '') + '\n' + data.get('country', ''))
        self.status_item.button().setAccessibilityLabel_('IP Menubar: ' + data.get('connection', ''))
        self.ui_tick()

    def ui_tick(self):
        now = time.monotonic()
        state = self.data.get('status', 'pending')
        if state != self.last_icon_state or state == 'pending':
            self.status_item.button().setImage_(status_image(state, now * 5))
            self.last_icon_state = state
        if self.closing:
            return
        if not self.app.settings.hover_open or self.app.dialog_open or self.in_menu:
            self.outside_since = self.hover_since = None
            self.pace(state == 'pending' or self.popover.isShown())
            return
        point = pointer_position()
        button = self.status_item.button()
        if button.window() is None: return
        rect = button.window().convertRectToScreen_(button.convertRect_toView_(button.bounds(), None))
        in_button = NSPointInRect(point, rect)
        self.pace(in_button or state == 'pending' or self.popover.isShown())
        if self.suppress_hover:
            if not in_button:
                self.suppress_hover = False
            self.hover_since = self.outside_since = None
            return
        in_panel = False
        if self.popover.isShown():
            window = self.popup_view.scroll.window()
            if window is not None:
                # The icon, the panel and the gap between them form one forgiving zone,
                # so a slightly misplaced pointer does not close the panel.
                zone = NSInsetRect(NSUnionRect(rect, window.frame()), -HOVER_MARGIN, -HOVER_MARGIN)
                in_panel = NSPointInRect(point, zone)
        if in_button or in_panel:
            self.outside_since = None
            if not self.popover.isShown() and in_button:
                if self.hover_since is None: self.hover_since = now
                if now - self.hover_since >= HOVER_OPEN_DELAY:
                    self.show()
        else:
            self.hover_since = None
            if self.popover.isShown():
                if self.outside_since is None: self.outside_since = now
                if now - self.outside_since >= HOVER_CLOSE_DELAY: self.close_popover()

    def show(self):
        self.app.last_data = None  # next tick sends full data, including details
        self.popup_view.update(self.data)
        self.set_timer(FAST_TICK)
        button = self.status_item.button()
        self.popover.showRelativeToRect_ofView_preferredEdge_(button.bounds(), button, NSMinYEdge)

    def toggle(self):
        if self.closing:
            return
        if self.popover.isShown():
            self.close_popover()
        else:
            self.suppress_hover = False
            self.hover_since = self.outside_since = None
            if not self.popover.isShown(): self.show()

    def close_popover(self):
        self.suppress_hover = True
        self.hover_since = self.outside_since = None
        if self.popover.isShown() and not self.closing:
            self.closing = True
            self.popover.close()

    def show_details(self, value=True):
        self.details_open = value
        self.popup_view.details(value)
        self.popup_view.update(self.data)
        if self.window_view:
            self.window_view.details(value)
            self.window_view.update(self.data)
        if not self.popover.isShown() and not (self.window and self.window.isVisible()):
            self.show()
        self.refresh_now()

    def refresh_now(self):
        # Details are only assembled while visible; ask for a full update right away.
        self.app.last_data = None
        self.app.render()

    def open_window(self):
        self.close_popover()
        if self.window is None:
            self.window_view = DashboardView(self.target, self.height, detached=True)
            self.window = NSPanel.alloc().initWithContentRect_styleMask_backing_defer_(
                ((0, 0), (WIDTH, self.height)),
                NSWindowStyleMaskTitled | NSWindowStyleMaskClosable | NSWindowStyleMaskMiniaturizable, 2, False)
            self.window.setTitle_('IP Menubar')
            self.window.setReleasedWhenClosed_(False)
            self.window.setHidesOnDeactivate_(False)
            self.window.setContentView_(self.window_view.scroll)
            self.window.center()
        self.window_view.update(self.data)
        self.window.setLevel_(NSFloatingWindowLevel if self.pinned else NSNormalWindowLevel)
        self.window.makeKeyAndOrderFront_(None)
        NSApplication.sharedApplication().activateIgnoringOtherApps_(True)
        self.refresh_now()

    def toggle_pin(self):
        self.pinned = not self.pinned
        self.window.setLevel_(NSFloatingWindowLevel if self.pinned else NSNormalWindowLevel)
        self.window_view.top_button.setTitle_('Открепить' if self.pinned else 'Поверх окон')

    def show_menu(self, menu, sender):
        self.in_menu = True
        try:
            menu.popUpMenuPositioningItem_atLocation_inView_(None, (0, sender.bounds().size.height), sender)
        finally:
            self.in_menu = False
            self.outside_since = None
