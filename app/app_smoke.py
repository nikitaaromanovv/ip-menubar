"""Opt-in packaged launch check with temporary data, no user preferences changes."""
import os
from Foundation import NSObject, NSTimer, NSRunLoop, NSRunLoopCommonModes


class SmokeFinish(NSObject):
    def finish_(self, timer):
        app = self.app
        try:
            assert app.dashboard is not None, 'Native panel missing'
            assert app.health.last_cycle is not None, 'No bounded HTTPS cycle completed'
            assert app.snapshot is not None, 'System inspection missing'
            assert app.traffic_store.totals() is not None
            print('PACKAGED PASS: native panel, system inspection, HTTPS cycle, local storage; state=' + app.health.status, flush=True)
            app.close()
            self.folder.cleanup()
            import rumps
            rumps.quit_application()
        except Exception:
            import traceback
            traceback.print_exc()
            os._exit(1)


def install(app, folder):
    target = SmokeFinish.alloc().init()
    target.app, target.folder = app, folder
    timer = NSTimer.timerWithTimeInterval_target_selector_userInfo_repeats_(
        20, target, 'finish:', None, False)
    NSRunLoop.mainRunLoop().addTimer_forMode_(timer, NSRunLoopCommonModes)
    app.smoke_target, app.smoke_timer = target, timer
