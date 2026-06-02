import re
import warnings
from collections.abc import Sequence
from dataclasses import dataclass
from dataclasses import fields
from dataclasses import is_dataclass
from typing import Any
from typing import ClassVar
from typing import TYPE_CHECKING

import mitmproxy.flow

if TYPE_CHECKING:
    import mitmproxy.addonmanager
    import mitmproxy.log


class Hook:
    """
    所有 mitmproxy hook 事件的基类。

    Hook 对象本质上是一个 dataclass 事件载体，字段就是传给 addon 方法的
    参数。例如 `UpdateHook(flows)` 最终会调用 addon 的 `update(flows)`。

    这里用到了几个元编程技巧：

    - `__new__` 在实例创建前校验：禁止直接实例化 `Hook` 基类，并要求所有
      子类必须是 dataclass，这样后续可以通过 dataclasses.fields 自动读取
      参数。
    - `__init_subclass__` 在每个子类定义完成时自动执行，用类名推导 hook
      名称，例如 `HttpRequestHook` -> `http_request`，并注册到 `all_hooks`。
    - `__init_subclass__` 还会动态改写子类的 `__hash__` 和 `__eq__`，让 hook
      实例按对象身份比较并保持可哈希，而不是使用 dataclass 默认的字段比较。
    """

    name: ClassVar[str]

    def args(self) -> list[Any]:
        """
        按 dataclass 字段顺序返回 hook 参数列表。

        AddonManager 分发 hook 时会调用这个方法，然后把结果展开传给 addon
        上同名方法。这样 hook 类只需要声明字段，就能自动决定 handler 的
        调用参数。
        """
        args = []
        for field in fields(self):  # type: ignore[arg-type]
            args.append(getattr(self, field.name))
        return args

    def __new__(cls, *args, **kwargs):
        """
        创建 hook 实例前进行类型约束。

        这是一个元编程入口：`__new__` 比 `__init__` 更早执行，因此可以在
        对象真正创建前阻止非法用法。这里禁止直接实例化抽象的 `Hook`，并
        要求子类必须使用 `@dataclass`，否则 `args()` 无法可靠读取字段。
        """
        if cls is Hook:
            raise TypeError("Hook may not be instantiated directly.")
        if not is_dataclass(cls):
            raise TypeError("Subclass is not a dataclass.")
        return super().__new__(cls)

    def __init_subclass__(cls, **kwargs):
        """
        在 hook 子类定义时自动生成名称并注册。

        这是本文件最关键的元编程用法。Python 在创建每个 `Hook` 子类后都会
        调用该方法，因此 mitmproxy 不需要手写注册表：

        1. 如果子类没有显式定义 `name`，就把类名去掉 `Hook` 后转成 snake_case。
           例如 `RunningHook` -> `running`，`UpdateHook` -> `update`。
        2. 把生成的名称写入 `all_hooks`，后续命令行展示、文档生成或校验都
           可以从这个全局表查到所有 hook 类型。
        3. 动态设置 `__hash__` 和 `__eq__`，避免 dataclass 的值相等语义影响
           hook 事件对象。hook 是事件实例，通常应该按对象身份区分。
        """
        # initialize .name attribute. HttpRequestHook -> http_request
        # 初始化 .name 属性。HttpRequestHook -> http_request。
        if cls.__dict__.get("name", None) is None:
            name = cls.__name__.replace("Hook", "")
            cls.name = re.sub("(?!^)([A-Z]+)", r"_\1", name).lower()
        if cls.name in all_hooks:
            other = all_hooks[cls.name]
            warnings.warn(
                f"Two conflicting event classes for {cls.name}: {cls} and {other}",
                RuntimeWarning,
            )
        if cls.name == "":
            return  # don't register Hook class.
        all_hooks[cls.name] = cls

        # define a custom hash and __eq__ function so that events are hashable and not comparable.
        # dataclass 默认会生成基于字段的比较逻辑；hook 事件更适合按对象身份
        # 比较，所以这里在类创建阶段直接改写为 object 的实现。
        cls.__hash__ = object.__hash__  # type: ignore
        cls.__eq__ = object.__eq__  # type: ignore


all_hooks: dict[str, type[Hook]] = {}
"""
所有已定义 hook 的全局注册表。

键是 hook 名称，例如 `running`、`update`；值是对应的 Hook 子类。该表由
`Hook.__init_subclass__` 自动填充。
"""


@dataclass
class ConfigureHook(Hook):
    """
    Called when configuration changes. The updated argument is a
    set-like object containing the keys of all changed options. This
    event is called during startup with all options in the updated set.

    配置变化时触发。

    `updated` 是发生变化的 option 名称集合。启动阶段会用“所有 option 都已
    更新”的形式触发一次，方便 addon 根据完整配置初始化自身状态。
    """

    updated: set[str]


@dataclass
class DoneHook(Hook):
    """
    Called when the addon shuts down, either by being removed from
    the mitmproxy instance, or when mitmproxy itself shuts down. On
    shutdown, this event is called after the event loop is
    terminated, guaranteeing that it will be the final event an addon
    sees. Note that log handlers are shut down at this point, so
    calls to log functions will produce no output.

    addon 关闭时触发。

    这可能发生在 addon 被移除时，也可能发生在 mitmproxy 退出时。关闭流程
    中它是 addon 能看到的最后一个事件，因此适合释放资源，但此时日志处理器
    可能已经不可用。
    """


@dataclass
class RunningHook(Hook):
    """
    Called when the proxy is completely up and running. At this point,
    you can expect all addons to be loaded and all options to be set.

    代理完全启动后触发。

    收到这个事件时，addon 已经加载完成，配置也已经应用完成，可以安全执行
    依赖运行环境的初始化逻辑。
    """


@dataclass
class UpdateHook(Hook):
    """
    Update is called when one or more flow objects have been modified,
    usually from a different addon.

    一个或多个 flow 被修改后触发。

    这个事件常用于通知 UI 或其他 addon 刷新状态。通常由别的 addon 修改
    flow 后间接触发。
    """

    flows: Sequence[mitmproxy.flow.Flow]
