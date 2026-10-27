"""SMAppService registration, loaded only on an explicit user action."""
# SMAppServiceStatus: 0 not registered, 1 enabled, 2 requires approval, 3 not found.
STATUS_TEXT = {0: 'Выключен', 1: 'Включен',
               2: 'Нужно подтверждение: Системные настройки → Основные → Объекты входа',
               3: 'Недоступен для этой сборки'}


def service():
    import objc
    from Foundation import NSBundle
    if not NSBundle.mainBundle().bundlePath().endswith('.app'):
        raise RuntimeError('Автозапуск работает только в .app')
    objc.loadBundle('ServiceManagement', globals(),
                    bundle_path='/System/Library/Frameworks/ServiceManagement.framework')
    return objc.lookUpClass('SMAppService').mainAppService()


def status():
    try:
        return int(service().status())
    except Exception:
        return 3


def enabled():
    return status() == 1


def set_enabled(value):
    current = service()
    result = (current.registerAndReturnError_(None) if value
              else current.unregisterAndReturnError_(None))
    ok = result[0] if isinstance(result, tuple) else result
    if not ok:
        raise RuntimeError('macOS отклонила изменение · см. Объекты входа')
    return int(current.status())
