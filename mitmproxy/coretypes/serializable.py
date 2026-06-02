import abc
import collections.abc
import dataclasses
import enum
import typing
import uuid
from functools import cache
from typing import TypeVar

try:
    from types import NoneType
    from types import UnionType
except ImportError:  # pragma: no cover

    class UnionType:  # type: ignore
        """
        Python 3.10 以下没有 `types.UnionType`，这里提供一个占位类型。
        """

        pass

    NoneType = type(None)  # type: ignore

T = TypeVar("T", bound="Serializable")

State = typing.Any


class Serializable(metaclass=abc.ABCMeta):
    """
    Abstract Base Class that defines an API to save an object's state and restore it later on.

    可序列化对象的抽象基类。

    子类需要定义如何导出自身状态，以及如何从状态恢复。mitmproxy 的 Flow、
    连接对象、HTTP 消息等都通过这套接口保存到 dump 文件或从 dump 文件中
    恢复。
    """

    @classmethod
    @abc.abstractmethod
    def from_state(cls: type[T], state) -> T:
        """
        Create a new object from the given state.
        Consumes the passed state.

        根据给定状态创建新对象。

        该方法会消费传入的 state。调用方不应假设调用后 state 还能保持原样。
        """
        raise NotImplementedError()

    @abc.abstractmethod
    def get_state(self) -> State:
        """
        Retrieve object state.

        导出对象状态。

        返回值必须只包含可进一步写入 dump 格式的基础结构，或其他已转换过的
        state。
        """
        raise NotImplementedError()

    @abc.abstractmethod
    def set_state(self, state):
        """
        Set object state to the given state. Consumes the passed state.
        May return a `dataclasses.FrozenInstanceError` if the object is immutable.

        用给定状态覆盖当前对象。

        该方法会消费传入的 state。如果对象是不可变 dataclass，可能抛出
        `dataclasses.FrozenInstanceError`。
        """
        raise NotImplementedError()

    def copy(self: T) -> T:
        """
        基于序列化状态创建当前对象的副本。

        如果状态中包含 `id` 字段，则复制时生成新的 UUID，避免副本和原对象
        共享同一个逻辑标识。
        """
        state = self.get_state()
        if isinstance(state, dict) and "id" in state:
            state["id"] = str(uuid.uuid4())
        return self.from_state(state)


U = TypeVar("U", bound="SerializableDataclass")


class SerializableDataclass(Serializable):
    """
    基于 dataclass 字段自动实现 `Serializable`。

    子类通常只需要声明 dataclass 字段和类型标注，本类会根据字段类型递归地
    将对象转换为 state，或从 state 恢复对象。字段 metadata 中
    `serialize=False` 的字段会被跳过。
    """

    @classmethod
    @cache
    def __fields(cls) -> tuple[dataclasses.Field, ...]:
        """
        返回需要参与序列化的 dataclass 字段。

        结果会缓存，避免每次序列化都重新解析类型。对于启用了
        `from __future__ import annotations` 的类，dataclass 字段类型可能是
        字符串，这里会用 `typing.get_type_hints()` 解析成真实类型。
        """
        # with from __future__ import annotations, `field.type` is a string,
        # see https://github.com/python/cpython/issues/83623.
        hints = typing.get_type_hints(cls)
        fields = []
        # noinspection PyDataclass
        for field in dataclasses.fields(cls):  # type: ignore[arg-type]
            if field.metadata.get("serialize", True) is False:
                continue
            if isinstance(field.type, str):
                field.type = hints[field.name]
            fields.append(field)
        return tuple(fields)

    def get_state(self) -> State:
        """
        将 dataclass 实例导出为字典状态。

        每个字段都会根据类型标注交给 `_to_state()` 递归转换，确保嵌套的
        Serializable、list、tuple、dict、Enum 等都变成可保存的 state。
        """
        state: dict[str, State] = {}
        for field in self.__fields():
            val = getattr(self, field.name)
            state[field.name] = _to_state(val, field.type, field.name)
        return state

    @classmethod
    def from_state(cls: type[U], state) -> U:
        """
        从字典状态创建 dataclass 实例。

        传入的 state 会被原地转换：每个字段先按类型标注通过 `_to_val()`
        还原为运行时对象，然后再传入 dataclass 构造函数。
        """
        # state = state.copy()
        for field in cls.__fields():
            state[field.name] = _to_val(state[field.name], field.type, field.name)
        try:
            return cls(**state)  # type: ignore
        except TypeError as e:
            raise ValueError(f"Invalid state for {cls}: {e} ({state=})") from e

    def set_state(self, state: State) -> None:
        """
        用字典状态更新当前 dataclass 实例。

        如果当前字段值本身是可变的 `Serializable`，优先调用它的
        `set_state()` 原地更新，以保留对象身份；如果字段不可变或无法原地
        更新，再把 state 转换为新值并赋给字段。最后如果 state 中还有未消费
        字段，则说明输入状态和当前类型不匹配。
        """
        for field in self.__fields():
            current = getattr(self, field.name)
            f_state = state.pop(field.name)
            if isinstance(current, Serializable) and f_state is not None:
                try:
                    current.set_state(f_state)
                    continue
                except dataclasses.FrozenInstanceError:
                    pass
            val: typing.Any = _to_val(f_state, field.type, field.name)
            try:
                setattr(self, field.name, val)
            except dataclasses.FrozenInstanceError:
                state[field.name] = f_state  # restore state dict.
                raise

        if state:
            raise ValueError(
                f"Unexpected fields in {type(self).__name__}.set_state: {state}"
            )


def _process(
    attr_val: typing.Any, attr_type: typing.Any, attr_name: str, make: bool
) -> typing.Any:
    """
    在运行时值和可序列化 state 之间递归转换。

    `make=True` 表示从 state 还原运行时对象，`make=False` 表示从运行时对象
    导出 state。算法按类型标注递归分派：

    - `Literal` 校验值是否在允许集合中。
    - `T | None` 支持空值，否则继续按 `T` 处理。
    - `Serializable` 子类调用 `from_state()` 或 `get_state()`。
    - list/Sequence、tuple、dict 逐项递归转换。
    - int/float/str/bytes/bool 做类型校验和轻量转换。
    - Enum 在 state 中保存 `.value`，恢复时用值构造枚举成员。

    这个函数是状态格式的类型边界：不符合标注的数据会在这里抛出
    ValueError 或 TypeError。
    """
    origin = typing.get_origin(attr_type)
    if origin is typing.Literal:
        if attr_val not in typing.get_args(attr_type):
            raise ValueError(
                f"Invalid value for {attr_name}: {attr_val!r} does not match any literal value."
            )
        return attr_val
    if origin in (UnionType, typing.Union):
        attr_type, nt = typing.get_args(attr_type)
        assert nt is NoneType, (
            f"{attr_name}: only `x | None` union types are supported`"
        )
        if attr_val is None:
            return None  # type: ignore
        else:
            return _process(attr_val, attr_type, attr_name, make)
    else:
        if attr_val is None:
            raise ValueError(f"Attribute {attr_name} must not be None.")

    if make and hasattr(attr_type, "from_state"):
        return attr_type.from_state(attr_val)  # type: ignore
    elif not make and hasattr(attr_type, "get_state"):
        return attr_val.get_state()

    if origin in (list, collections.abc.Sequence):
        (T,) = typing.get_args(attr_type)
        return [_process(x, T, attr_name, make) for x in attr_val]  # type: ignore
    elif origin is tuple:
        # We don't have a good way to represent tuple[str,int] | tuple[str,int,int,int], so we do a dirty hack here.
        if attr_name in ("peername", "sockname"):
            # peername/sockname 在不同平台上可能是 2 元组或 4 元组。这里用
            # 固定类型序列逐项转换已有值，兼容 IPv4/IPv6 socket 地址形态。
            return tuple(
                _process(x, T, attr_name, make)
                for x, T in zip(attr_val, [str, int, int, int])
            )  # type: ignore
        Ts = typing.get_args(attr_type)
        if len(Ts) != len(attr_val):
            raise ValueError(
                f"Invalid data for {attr_name}. Expected {Ts}, got {attr_val}."
            )
        return tuple(_process(x, T, attr_name, make) for T, x in zip(Ts, attr_val))  # type: ignore
    elif origin is dict:
        k_cls, v_cls = typing.get_args(attr_type)
        return {
            _process(k, k_cls, attr_name, make): _process(v, v_cls, attr_name, make)
            for k, v in attr_val.items()
        }  # type: ignore
    elif attr_type in (int, float):
        if not isinstance(attr_val, (int, float)):
            raise ValueError(
                f"Invalid value for {attr_name}. Expected {attr_type}, got {attr_val} ({type(attr_val)})."
            )
        return attr_type(attr_val)  # type: ignore
    elif attr_type in (str, bytes, bool):
        if not isinstance(attr_val, attr_type):
            raise ValueError(
                f"Invalid value for {attr_name}. Expected {attr_type}, got {attr_val} ({type(attr_val)})."
            )
        return attr_type(attr_val)  # type: ignore
    elif isinstance(attr_type, type) and issubclass(attr_type, enum.Enum):
        if make:
            return attr_type(attr_val)  # type: ignore
        else:
            return attr_val.value
    else:
        raise TypeError(f"Unexpected type for {attr_name}: {attr_type!r}")


def _to_val(state: typing.Any, attr_type: typing.Any, attr_name: str) -> typing.Any:
    """
    Create an object based on the state given in val.

    按字段类型把 state 还原为运行时值。
    """
    return _process(state, attr_type, attr_name, True)


def _to_state(value: typing.Any, attr_type: typing.Any, attr_name: str) -> typing.Any:
    """
    Get the state of the object given as val.

    按字段类型把运行时值转换为可序列化 state。
    """
    return _process(value, attr_type, attr_name, False)
