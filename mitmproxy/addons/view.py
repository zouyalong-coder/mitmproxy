"""
The View:

- Keeps track of a store of flows
- Maintains a filtered, ordered view onto that list of flows
- Exposes a number of signals so the view can be monitored
- Tracks focus within the view
- Exposes a settings store for flows that automatically expires if the flow is
  removed from the store.

中文说明：本模块属于 mitmproxy 的 addon 系统，负责上方英文说明所描述的功能。

触发点：
- `load/configure`：注册并应用 view_filter、排序、倒序和焦点跟随选项。
- HTTP：`requestheaders` 添加新 flow，`response/error` 更新 flow。
- TCP/UDP：`*_start` 添加 flow，`*_message/*_error/*_end` 更新 flow。
- DNS：`dns_request` 添加 flow，`dns_response/dns_error` 更新 flow。
- flow 生命周期：`intercept/resume/kill` 更新对应 flow。
- `view.*` 命令：由 UI/控制台调用，用于焦点、排序、过滤、增删和设置。
"""

import collections
import logging
import re
from collections.abc import Iterator
from collections.abc import MutableMapping
from collections.abc import Sequence
from typing import Any
from typing import Optional

import sortedcontainers

import mitmproxy.flow
from mitmproxy import command
from mitmproxy import connection
from mitmproxy import ctx
from mitmproxy import dns
from mitmproxy import exceptions
from mitmproxy import flowfilter
from mitmproxy import hooks
from mitmproxy import http
from mitmproxy import io
from mitmproxy import tcp
from mitmproxy import udp
from mitmproxy.log import ALERT
from mitmproxy.utils import human
from mitmproxy.utils import signals

# The underlying sorted list implementation expects the sort key to be stable
# for the lifetime of the object. However, if we sort by size, for instance,
# the sort order changes as the flow progresses through its lifecycle. We
# address this through two means:
#
# - Let order keys cache the sort value by flow ID.
#
# - Add a facility to refresh items in the list by removing and re-adding them
# when they are updated.


class _OrderKey:
    """
    View 排序键的基类。

    排序键会按 flow ID 缓存生成值；当 flow 内容变化可能影响排序时，`refresh`
    会移除并重新插入该 flow，保持 sorted list 的排序不变量。
    """
    def __init__(self, view):
        """
        初始化对象状态。
        """
        self.view = view

    def generate(self, f: mitmproxy.flow.Flow) -> Any:  # pragma: no cover
        """
        `view` addon 中的方法，用于处理 `generate` 相关逻辑。
        """
        pass

    def refresh(self, f):
        """
        `view` addon 中的方法，用于处理 `refresh` 相关逻辑。
        """
        k = self._key()
        old = self.view.settings[f][k]
        new = self.generate(f)
        if old != new:
            self.view._view.remove(f)
            self.view.settings[f][k] = new
            self.view._view.add(f)
            self.view.sig_view_refresh.send()

    def _key(self):
        """
        `view` addon 的内部辅助方法。
        """
        return "_order_%s" % id(self)

    def __call__(self, f):
        """
        让对象可以像函数一样被调用。
        """
        if f.id in self.view._store:
            k = self._key()
            s = self.view.settings[f]
            if k in s:
                return s[k]
            val = self.generate(f)
            s[k] = val
            return val
        else:
            return self.generate(f)


class OrderRequestStart(_OrderKey):
    """
    按 flow 创建时间排序。
    """
    def generate(self, f: mitmproxy.flow.Flow) -> float:
        """
        `view` addon 中的方法，用于处理 `generate` 相关逻辑。
        """
        return f.timestamp_created


class OrderRequestMethod(_OrderKey):
    """
    按请求方法或协议操作类型排序。
    """
    def generate(self, f: mitmproxy.flow.Flow) -> str:
        """
        `view` addon 中的方法，用于处理 `generate` 相关逻辑。
        """
        if isinstance(f, http.HTTPFlow):
            return f.request.method
        elif isinstance(f, (tcp.TCPFlow, udp.UDPFlow)):
            return f.type.upper()
        elif isinstance(f, dns.DNSFlow):
            return dns.op_codes.to_str(f.request.op_code)
        else:
            raise NotImplementedError()


class OrderRequestURL(_OrderKey):
    """
    按 URL、目标地址或 DNS 查询名排序。
    """
    def generate(self, f: mitmproxy.flow.Flow) -> str:
        """
        `view` addon 中的方法，用于处理 `generate` 相关逻辑。
        """
        if isinstance(f, http.HTTPFlow):
            return f.request.url
        elif isinstance(f, (tcp.TCPFlow, udp.UDPFlow)):
            return human.format_address(f.server_conn.address)
        elif isinstance(f, dns.DNSFlow):
            return f.request.questions[0].name if f.request.questions else ""
        else:
            raise NotImplementedError()


class OrderKeySize(_OrderKey):
    """
    按 flow 已知内容大小排序。
    """
    def generate(self, f: mitmproxy.flow.Flow) -> int:
        """
        `view` addon 中的方法，用于处理 `generate` 相关逻辑。
        """
        if isinstance(f, http.HTTPFlow):
            size = 0
            if f.request.raw_content:
                size += len(f.request.raw_content)
            if f.response and f.response.raw_content:
                size += len(f.response.raw_content)
            return size
        elif isinstance(f, (tcp.TCPFlow, udp.UDPFlow)):
            size = 0
            for message in f.messages:
                size += len(message.content)
            return size
        elif isinstance(f, dns.DNSFlow):
            return f.response.size if f.response else 0
        else:
            raise NotImplementedError()


orders = [
    ("t", "time"),
    ("m", "method"),
    ("u", "url"),
    ("z", "size"),
]

# view 信号回调签名：通知监听者某个 flow 已经变化。
def _signal_with_flow(flow: mitmproxy.flow.Flow) -> None: ...


# view 删除信号回调签名：通知监听者被删除的 flow 及其原索引。
def _sig_view_remove(flow: mitmproxy.flow.Flow, index: int) -> None: ...


class View(collections.abc.Sequence):
    """
    管理所有 flow 的底层 store，以及经过过滤/排序后的可见 view。

    `_store` 保存所有已知 flow，`_view` 只保存当前过滤条件下可见的 flow；
    Focus 和 Settings 都依赖这里的增删信号保持一致。
    """

    def __init__(self) -> None:
        """
        初始化对象状态。
        """
        super().__init__()
        self._store: collections.OrderedDict[str, mitmproxy.flow.Flow] = (
            collections.OrderedDict()
        )
        self.filter = flowfilter.match_all
        # Should we show only marked flows?
        self.show_marked = False

        self.default_order = OrderRequestStart(self)
        self.orders = dict(
            time=OrderRequestStart(self),
            method=OrderRequestMethod(self),
            url=OrderRequestURL(self),
            size=OrderKeySize(self),
        )
        self.order_key: _OrderKey = self.default_order
        self.order_reversed = False
        self.focus_follow = False

        self._view = sortedcontainers.SortedListWithKey(key=self.order_key)

        # The sig_view* signals broadcast events that affect the view. That is,
        # an update to a flow in the store but not in the view does not trigger
        # a signal. All signals are called after the view has been updated.
        self.sig_view_update = signals.SyncSignal(_signal_with_flow)
        self.sig_view_add = signals.SyncSignal(_signal_with_flow)
        self.sig_view_remove = signals.SyncSignal(_sig_view_remove)
        # Signals that the view should be refreshed completely
        self.sig_view_refresh = signals.SyncSignal(lambda: None)

        # The sig_store* signals broadcast events that affect the underlying
        # store. If a flow is removed from just the view, sig_view_remove is
        # triggered. If it is removed from the store while it is also in the
        # view, both sig_store_remove and sig_view_remove are triggered.
        self.sig_store_remove = signals.SyncSignal(_signal_with_flow)
        # Signals that the store should be refreshed completely
        self.sig_store_refresh = signals.SyncSignal(lambda: None)

        self.focus = Focus(self)
        self.settings = Settings(self)

    def load(self, loader):
        """
        addon 加载事件：注册 view 过滤、排序和焦点跟随选项。
        """
        loader.add_option(
            "view_filter", Optional[str], None, "Limit the view to matching flows."
        )
        loader.add_option(
            "view_order",
            str,
            "time",
            "Flow sort order.",
            choices=list(map(lambda c: c[1], orders)),
        )
        loader.add_option(
            "view_order_reversed", bool, False, "Reverse the sorting order."
        )
        loader.add_option(
            "console_focus_follow", bool, False, "Focus follows new flows."
        )

    def store_count(self):
        """
        返回底层 store 中的 flow 数量，不受当前过滤条件影响。
        """
        return len(self._store)

    def _rev(self, idx: int) -> int:
        """
        Reverses an index, if needed
        
        中文说明：把面向用户的索引转换为底层 `_view` 索引，支持倒序视图。
        """
        if self.order_reversed:
            if idx < 0:
                idx = -idx - 1
            else:
                idx = len(self._view) - idx - 1
                if idx < 0:
                    raise IndexError
        return idx

    def __len__(self):
        """
        返回当前集合或视图中的元素数量。
        """
        return len(self._view)

    def __getitem__(self, offset) -> Any:
        """
        按索引或键读取当前集合中的元素。
        """
        return self._view[self._rev(offset)]

    # Reflect some methods to the efficient underlying implementation

    def _bisect(self, f: mitmproxy.flow.Flow) -> int:
        """
        `view` addon 的内部辅助方法。
        """
        v = self._view.bisect_right(f)
        return self._rev(v - 1) + 1

    def index(
        self, f: mitmproxy.flow.Flow, start: int = 0, stop: int | None = None
    ) -> int:
        """
        `view` addon 中的方法，用于处理 `index` 相关逻辑。
        """
        return self._rev(self._view.index(f, start, stop))

    def __contains__(self, f: Any) -> bool:
        """
        判断指定对象是否存在于当前集合中。
        """
        return self._view.__contains__(f)

    def _order_key_name(self):
        """
        `view` addon 的内部辅助方法。
        """
        return "_order_%s" % id(self.order_key)

    def _base_add(self, f):
        """
        `view` addon 的内部辅助方法。
        """
        self.settings[f][self._order_key_name()] = self.order_key(f)
        self._view.add(f)

    def _refilter(self):
        """
        `view` addon 的内部辅助方法。
        """
        self._view.clear()
        for i in self._store.values():
            if self.show_marked and not i.marked:
                continue
            if self.filter(i):
                self._base_add(i)
        self.sig_view_refresh.send()

    """ View API """

    # Focus
    @command.command("view.focus.go")
    def go(self, offset: int) -> None:
        """
        Go to a specified offset. Positive offests are from the beginning of
        the view, negative from the end of the view, so that 0 is the first
        flow, -1 is the last flow.
        
        中文说明：命令触发点是 `view.focus.go`，把焦点移动到指定偏移。
        """
        if len(self) == 0:
            return
        if offset < 0:
            offset = len(self) + offset
        if offset < 0:
            offset = 0
        if offset > len(self) - 1:
            offset = len(self) - 1
        self.focus.flow = self[offset]

    @command.command("view.focus.next")
    def focus_next(self) -> None:
        """
        Set focus to the next flow.
        
        中文说明：命令触发点是 `view.focus.next`，把焦点移动到下一条可见 flow。
        """
        if self.focus.index is not None:
            idx = self.focus.index + 1
            if self.inbounds(idx):
                self.focus.flow = self[idx]
        else:
            pass

    @command.command("view.focus.prev")
    def focus_prev(self) -> None:
        """
        Set focus to the previous flow.
        
        中文说明：命令触发点是 `view.focus.prev`，把焦点移动到上一条可见 flow。
        """
        if self.focus.index is not None:
            idx = self.focus.index - 1
            if self.inbounds(idx):
                self.focus.flow = self[idx]
        else:
            pass

    # Order
    @command.command("view.order.options")
    def order_options(self) -> Sequence[str]:
        """
        Choices supported by the view_order option.
        
        中文说明：命令触发点是 `view.order.options`，返回可用排序键用于补全。
        """
        return list(sorted(self.orders.keys()))

    @command.command("view.order.reverse")
    def set_reversed(self, boolean: bool) -> None:
        """
        `view.order.reverse` 命令：设置是否倒序展示当前 view。
        """
        self.order_reversed = boolean
        self.sig_view_refresh.send()

    @command.command("view.order.set")
    def set_order(self, order_key: str) -> None:
        """
        Sets the current view order.
        
        中文说明：命令触发点是 `view.order.set`，重建 sorted list 使用新的排序键。
        """
        if order_key not in self.orders:
            raise exceptions.CommandError("Unknown flow order: %s" % order_key)
        key = self.orders[order_key]
        self.order_key = key
        newview = sortedcontainers.SortedListWithKey(key=key)
        newview.update(self._view)
        self._view = newview

    @command.command("view.order")
    def get_order(self) -> str:
        """
        Returns the current view order.
        
        中文说明：命令触发点是 `view.order`，返回当前排序键名称。
        """
        order = ""
        for k in self.orders.keys():
            if self.order_key == self.orders[k]:
                order = k
        return order

    # Filter
    @command.command("view.filter.set")
    def set_filter_cmd(self, filter_expr: str) -> None:
        """
        Sets the current view filter.
        
        中文说明：命令触发点是 `view.filter.set`，解析 flow filter 并刷新 view。
        """
        filt = None
        if filter_expr:
            try:
                filt = flowfilter.parse(filter_expr)
            except ValueError as e:
                raise exceptions.CommandError(str(e)) from e
        self.set_filter(filt)

    def set_filter(self, flt: flowfilter.TFilter | None):
        """
        设置当前过滤器并重新计算可见 view。
        """
        self.filter = flt or flowfilter.match_all
        self._refilter()

    # View Updates
    @command.command("view.clear")
    def clear(self) -> None:
        """
        Clears both the store and view.
        
        中文说明：命令触发点是 `view.clear`，同时清空底层 store 和可见 view。
        """
        self._store.clear()
        self._view.clear()
        self.sig_view_refresh.send()
        self.sig_store_refresh.send()

    @command.command("view.clear_unmarked")
    def clear_not_marked(self) -> None:
        """
        Clears only the unmarked flows.
        
        中文说明：命令触发点是 `view.clear_unmarked`，只移除未标记 flow。
        """
        for flow in self._store.copy().values():
            if not flow.marked:
                self._store.pop(flow.id)

        self._refilter()
        self.sig_store_refresh.send()

    # View Settings
    @command.command("view.settings.getval")
    def getvalue(self, flow: mitmproxy.flow.Flow, key: str, default: str) -> str:
        """
        Get a value from the settings store for the specified flow.
        
        中文说明：命令触发点是 `view.settings.getval`，读取单个 flow 的 UI 设置值。
        """
        return self.settings[flow].get(key, default)

    @command.command("view.settings.setval.toggle")
    def setvalue_toggle(self, flows: Sequence[mitmproxy.flow.Flow], key: str) -> None:
        """
        Toggle a boolean value in the settings store, setting the value to
        the string "true" or "false".
        
        中文说明：命令触发点是 `view.settings.setval.toggle`，切换 flow 的布尔型 UI 设置。
        """
        updated = []
        for f in flows:
            current = self.settings[f].get(key, "false")
            self.settings[f][key] = "false" if current == "true" else "true"
            updated.append(f)
        ctx.master.addons.trigger(hooks.UpdateHook(updated))

    @command.command("view.settings.setval")
    def setvalue(
        self, flows: Sequence[mitmproxy.flow.Flow], key: str, value: str
    ) -> None:
        """
        Set a value in the settings store for the specified flows.
        
        中文说明：命令触发点是 `view.settings.setval`，为一组 flow 写入 UI 设置值。
        """
        updated = []
        for f in flows:
            self.settings[f][key] = value
            updated.append(f)
        ctx.master.addons.trigger(hooks.UpdateHook(updated))

    # Flows
    @command.command("view.flows.duplicate")
    def duplicate(self, flows: Sequence[mitmproxy.flow.Flow]) -> None:
        """
        Duplicates the specified flows, and sets the focus to the first
        duplicate.
        
        中文说明：命令触发点是 `view.flows.duplicate`，复制 flow 并聚焦第一个副本。
        """
        dups = [f.copy() for f in flows]
        if dups:
            self.add(dups)
            self.focus.flow = dups[0]
            logging.log(ALERT, "Duplicated %s flows" % len(dups))

    @command.command("view.flows.remove")
    def remove(self, flows: Sequence[mitmproxy.flow.Flow]) -> None:
        """
        Removes the flow from the underlying store and the view.
        
        中文说明：命令触发点是 `view.flows.remove`，从 store/view 移除 flow，必要时先 kill live flow。
        """
        for f in flows:
            if f.id in self._store:
                if f.killable:
                    f.kill()
                if f in self._view:
                    # We manually pass the index here because multiple flows may have the same
                    # sorting key, and we cannot reconstruct the index from that.
                    idx = self._view.index(f)
                    self._view.remove(f)
                    self.sig_view_remove.send(flow=f, index=idx)
                del self._store[f.id]
                self.sig_store_remove.send(flow=f)
        if len(flows) > 1:
            logging.log(ALERT, "Removed %s flows" % len(flows))

    @command.command("view.flows.resolve")
    def resolve(self, flow_spec: str) -> Sequence[mitmproxy.flow.Flow]:
        """
        Resolve a flow list specification to an actual list of flows.
        
        中文说明：命令触发点是 `view.flows.resolve`，把 `@all`、`@focus`、filter 等规格解析成 flow 列表。
        """
        if flow_spec == "@all":
            return [i for i in self._store.values()]
        if flow_spec == "@focus":
            return [self.focus.flow] if self.focus.flow else []
        elif flow_spec == "@shown":
            return [i for i in self]
        elif flow_spec == "@hidden":
            return [i for i in self._store.values() if i not in self._view]
        elif flow_spec == "@marked":
            return [i for i in self._store.values() if i.marked]
        elif flow_spec == "@unmarked":
            return [i for i in self._store.values() if not i.marked]
        elif re.match(r"@[0-9a-f\-,]{36,}", flow_spec):
            ids = flow_spec[1:].split(",")
            return [i for i in self._store.values() if i.id in ids]
        else:
            try:
                filt = flowfilter.parse(flow_spec)
            except ValueError as e:
                raise exceptions.CommandError(str(e)) from e
            return [i for i in self._store.values() if filt(i)]

    @command.command("view.flows.create")
    def create(self, method: str, url: str) -> None:
        """
        `view.flows.create` 命令：手动创建一个新的 HTTPFlow 并加入 view。
        """
        try:
            req = http.Request.make(method.upper(), url)
        except ValueError as e:
            raise exceptions.CommandError("Invalid URL: %s" % e)

        c = connection.Client(
            peername=("", 0),
            sockname=("", 0),
            timestamp_start=req.timestamp_start - 0.0001,
        )
        s = connection.Server(address=(req.host, req.port))

        f = http.HTTPFlow(c, s)
        f.request = req
        f.request.headers["Host"] = req.host
        self.add([f])

    @command.command("view.flows.load")
    def load_file(self, path: mitmproxy.types.Path) -> None:
        """
        Load flows into the view, without processing them with addons.
        
        中文说明：命令触发点是 `view.flows.load`，从 dump 文件加载 flow 到 view，但不触发其他 addon 生命周期。
        """
        try:
            with open(path, "rb") as f:
                for i in io.FlowReader(f).stream():
                    # Do this to get a new ID, so we can load the same file N times and
                    # get new flows each time. It would be more efficient to just have a
                    # .newid() method or something.
                    self.add([i.copy()])
        except OSError as e:
            logging.error(e.strerror)
        except exceptions.FlowReadException as e:
            logging.error(str(e))

    def add(self, flows: Sequence[mitmproxy.flow.Flow]) -> None:
        """
        Adds a flow to the state. If the flow already exists, it is
        ignored.
        
        中文说明：事件 hook 和命令都会调用这里新增 flow；重复 ID 会被忽略。
        """
        for f in flows:
            if f.id not in self._store:
                self._store[f.id] = f
                if self.filter(f):
                    self._base_add(f)
                    if self.focus_follow:
                        self.focus.flow = f
                    self.sig_view_add.send(flow=f)

    def get_by_id(self, flow_id: str) -> mitmproxy.flow.Flow | None:
        """
        Get flow with the given id from the store.
        Returns None if the flow is not found.
        
        中文说明：按 flow ID 从底层 store 查找，不受当前过滤 view 影响。
        """
        return self._store.get(flow_id)

    # View Properties
    @command.command("view.properties.length")
    def get_length(self) -> int:
        """
        Returns view length.
        
        中文说明：命令触发点是 `view.properties.length`，返回当前可见 view 长度。
        """
        return len(self)

    @command.command("view.properties.marked")
    def get_marked(self) -> bool:
        """
        Returns true if view is in marked mode.
        
        中文说明：命令触发点是 `view.properties.marked`，返回是否处于仅显示标记 flow 模式。
        """
        return self.show_marked

    @command.command("view.properties.marked.toggle")
    def toggle_marked(self) -> None:
        """
        Toggle whether to show marked views only.
        
        中文说明：命令触发点是 `view.properties.marked.toggle`，切换仅显示标记 flow 模式。
        """
        self.show_marked = not self.show_marked
        self._refilter()

    @command.command("view.properties.inbounds")
    def inbounds(self, index: int) -> bool:
        """
        Is this 0 <= index < len(self)?
        
        中文说明：命令触发点是 `view.properties.inbounds`，判断索引是否在当前 view 范围内。
        """
        return 0 <= index < len(self)

    # Event handlers
    def configure(self, updated):
        """
        `configure` 事件：view 相关选项变化后触发。

        过滤器变化会重建可见 view；排序或倒序变化会刷新展示顺序；焦点跟随选项
        控制新 flow 到来时是否自动聚焦。
        """
        if "view_filter" in updated:
            filt = None
            if ctx.options.view_filter:
                try:
                    filt = flowfilter.parse(ctx.options.view_filter)
                except ValueError as e:
                    raise exceptions.OptionsError(str(e)) from e
            self.set_filter(filt)
        if "view_order" in updated:
            if ctx.options.view_order not in self.orders:
                raise exceptions.OptionsError(
                    "Unknown flow order: %s" % ctx.options.view_order
                )
            self.set_order(ctx.options.view_order)
        if "view_order_reversed" in updated:
            self.set_reversed(ctx.options.view_order_reversed)
        if "console_focus_follow" in updated:
            self.focus_follow = ctx.options.console_focus_follow

    def requestheaders(self, f):
        """
        HTTP `requestheaders` 事件：请求头解析完成时触发，把 HTTP flow 加入 view。
        """
        self.add([f])

    def error(self, f):
        """
        HTTP `error` 事件：HTTP flow 出错时触发，刷新已有 flow 状态。
        """
        self.update([f])

    def response(self, f):
        """
        HTTP `response` 事件：响应返回客户端前触发，刷新已有 flow 状态。
        """
        self.update([f])

    def intercept(self, f):
        """
        `intercept` 事件：flow 被暂停时触发，刷新 view 中状态。
        """
        self.update([f])

    def resume(self, f):
        """
        `resume` 事件：flow 从拦截状态恢复时触发。
        """
        self.update([f])

    def kill(self, f):
        """
        `kill` 事件：flow 被终止时触发。
        """
        self.update([f])

    def tcp_start(self, f):
        """
        TCP `tcp_start` 事件：TCP flow 创建时触发，加入 view。
        """
        self.add([f])

    def tcp_message(self, f):
        """
        TCP `tcp_message` 事件：TCP 消息到达时触发，刷新 view。
        """
        self.update([f])

    def tcp_error(self, f):
        """
        TCP `tcp_error` 事件：TCP flow 出错时触发，刷新 view。
        """
        self.update([f])

    def tcp_end(self, f):
        """
        TCP `tcp_end` 事件：TCP flow 正常结束时触发，刷新 view。
        """
        self.update([f])

    def udp_start(self, f):
        """
        UDP `udp_start` 事件：UDP flow 创建时触发，加入 view。
        """
        self.add([f])

    def udp_message(self, f):
        """
        UDP `udp_message` 事件：UDP 数据报到达时触发，刷新 view。
        """
        self.update([f])

    def udp_error(self, f):
        """
        UDP `udp_error` 事件：UDP flow 出错时触发，刷新 view。
        """
        self.update([f])

    def udp_end(self, f):
        """
        UDP `udp_end` 事件：UDP flow 正常结束时触发，刷新 view。
        """
        self.update([f])

    def dns_request(self, f):
        """
        DNS `dns_request` 事件：DNS 请求进入代理时触发，加入 view。
        """
        self.add([f])

    def dns_response(self, f):
        """
        DNS `dns_response` 事件：DNS 响应返回客户端前触发，刷新 view。
        """
        self.update([f])

    def dns_error(self, f):
        """
        DNS `dns_error` 事件：DNS flow 出错时触发，刷新 view。
        """
        self.update([f])

    def update(self, flows: Sequence[mitmproxy.flow.Flow]) -> None:
        """
        Updates a list of flows. If flow is not in the state, it's ignored.
        
        中文说明：所有更新类 hook 最终走到这里。它会根据当前过滤器决定 flow
        是否应出现在 view 中，并在排序键变化时刷新 sorted list 位置。
        """
        for f in flows:
            if f.id in self._store:
                if self.filter(f):
                    if f not in self._view:
                        self._base_add(f)
                        if self.focus_follow:
                            self.focus.flow = f
                        self.sig_view_add.send(flow=f)
                    else:
                        # This is a tad complicated. The sortedcontainers
                        # implementation assumes that the order key is stable. If
                        # it changes mid-way Very Bad Things happen. We detect when
                        # this happens, and re-fresh the item.
                        self.order_key.refresh(f)
                        self.sig_view_update.send(flow=f)
                else:
                    try:
                        idx = self._view.index(f)
                    except ValueError:
                        pass  # The value was not in the view
                    else:
                        self._view.remove(f)
                        self.sig_view_remove.send(flow=f, index=idx)


class Focus:
    """
    Tracks a focus element within a View.
    
    中文说明：跟踪当前 UI 焦点 flow，并监听 view 增删刷新事件来保持焦点有效。
    """

    def __init__(self, v: View) -> None:
        """
        初始化对象状态。
        """
        self.view = v
        self._flow: mitmproxy.flow.Flow | None = None
        self.sig_change = signals.SyncSignal(lambda: None)
        if len(self.view):
            self.flow = self.view[0]
        v.sig_view_add.connect(self._sig_view_add)
        v.sig_view_remove.connect(self._sig_view_remove)
        v.sig_view_refresh.connect(self._sig_view_refresh)

    @property
    def flow(self) -> mitmproxy.flow.Flow | None:
        """
        `view` addon 中的方法，用于处理 `flow` 相关逻辑。
        """
        return self._flow

    @flow.setter
    def flow(self, f: mitmproxy.flow.Flow | None):
        """
        `view` addon 中的方法，用于处理 `flow` 相关逻辑。
        """
        if f is not None and f not in self.view:
            raise ValueError("Attempt to set focus to flow not in view")
        self._flow = f
        self.sig_change.send()

    @property
    def index(self) -> int | None:
        """
        `view` addon 中的方法，用于处理 `index` 相关逻辑。
        """
        if self.flow:
            return self.view.index(self.flow)
        return None

    @index.setter
    def index(self, idx):
        """
        `view` addon 中的方法，用于处理 `index` 相关逻辑。
        """
        if idx < 0 or idx > len(self.view) - 1:
            raise ValueError("Index out of view bounds")
        self.flow = self.view[idx]

    def _nearest(self, f, v):
        """
        `view` addon 的内部辅助方法。
        """
        return min(v._bisect(f), len(v) - 1)

    def _sig_view_remove(self, flow, index):
        """
        `view` addon 的内部辅助方法。
        """
        if len(self.view) == 0:
            self.flow = None
        elif flow is self.flow:
            self.index = min(index, len(self.view) - 1)

    def _sig_view_refresh(self):
        """
        `view` addon 的内部辅助方法。
        """
        if len(self.view) == 0:
            self.flow = None
        elif self.flow is None:
            self.flow = self.view[0]
        elif self.flow not in self.view:
            self.flow = self.view[self._nearest(self.flow, self.view)]

    def _sig_view_add(self, flow):
        # We only have to act if we don't have a focus element
        """
        `view` addon 的内部辅助方法。
        """
        if not self.flow:
            self.flow = flow


class Settings(collections.abc.Mapping):
    """
    保存 view addon 的过滤、排序和展示设置。
    """
    def __init__(self, view: View) -> None:
        """
        初始化对象状态。
        """
        self.view = view
        self._values: MutableMapping[str, dict] = {}
        view.sig_store_remove.connect(self._sig_store_remove)
        view.sig_store_refresh.connect(self._sig_store_refresh)

    def __iter__(self) -> Iterator:
        """
        迭代当前集合或视图中的元素。
        """
        return iter(self._values)

    def __len__(self) -> int:
        """
        返回当前集合或视图中的元素数量。
        """
        return len(self._values)

    def __getitem__(self, f: mitmproxy.flow.Flow) -> dict:
        """
        按索引或键读取当前集合中的元素。
        """
        if f.id not in self.view._store:
            raise KeyError
        return self._values.setdefault(f.id, {})

    def _sig_store_remove(self, flow):
        """
        `view` addon 的内部辅助方法。
        """
        if flow.id in self._values:
            del self._values[flow.id]

    def _sig_store_refresh(self):
        """
        `view` addon 的内部辅助方法。
        """
        for fid in list(self._values.keys()):
            if fid not in self.view._store:
                del self._values[fid]
