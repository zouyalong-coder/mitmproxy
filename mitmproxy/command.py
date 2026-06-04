"""
This module manages and invokes typed commands.

中文说明：mitmproxy 的控制台、Web UI 和 addon 可以通过统一的命令系统调用
功能。命令函数用类型标注声明参数和返回值，本模块负责注册、解析字符串参数、
类型转换、调用函数并校验返回值。
"""

import functools
import inspect
import logging
import sys
import textwrap
import types
from collections.abc import Callable
from collections.abc import Iterable
from collections.abc import Sequence
from typing import Any
from typing import NamedTuple

import pyparsing

import mitmproxy.types
from mitmproxy import command_lexer
from mitmproxy import exceptions
from mitmproxy.command_lexer import unquote


def verify_arg_signature(f: Callable, args: Iterable[Any], kwargs: dict) -> None:
    """
    校验给定参数是否能绑定到函数签名。

    这里还不做 mitmproxy 命令类型转换，只利用 Python 的 inspect 签名机制检查
    参数数量、关键字等调用形状是否正确。
    """
    sig = inspect.signature(f, eval_str=True)
    try:
        sig.bind(*args, **kwargs)
    except TypeError as v:
        raise exceptions.CommandError("command argument mismatch: %s" % v.args[0])


def typename(t: type) -> str:
    """
    Translates a type to an explanatory string.
    """
    if t == inspect._empty:  # type: ignore
        raise exceptions.CommandError("missing type annotation")
    to = mitmproxy.types.CommandTypes.get(t, None)
    if not to:
        raise exceptions.CommandError(
            "unsupported type: %s" % getattr(t, "__name__", t)
        )
    return to.display


def _empty_as_none(x: Any) -> Any:
    if x == inspect.Signature.empty:
        return None
    return x


class CommandParameter(NamedTuple):
    """
    命令参数的轻量描述。

    `kind` 保留 Python 参数种类，尤其用于识别 `*args` 这种可变位置参数，
    以便帮助信息和参数解析展示正确形态。
    """

    name: str
    type: type
    kind: inspect._ParameterKind = inspect.Parameter.POSITIONAL_OR_KEYWORD

    def __str__(self):
        if self.kind is inspect.Parameter.VAR_POSITIONAL:
            return f"*{self.name}"
        else:
            return self.name


class Command:
    """
    已注册命令的运行时包装器。

    它把原始函数、命令名、函数签名、帮助文本和类型校验放在一起。调用命令时
    先把字符串参数按类型标注解析为 Python 对象，再执行函数并校验返回类型。
    """

    name: str
    manager: "CommandManager"
    signature: inspect.Signature
    help: str | None

    def __init__(self, manager: "CommandManager", name: str, func: Callable) -> None:
        self.name = name
        self.manager = manager
        self.func = func
        self.signature = inspect.signature(self.func, eval_str=True)

        if func.__doc__:
            txt = func.__doc__.strip()
            self.help = "\n".join(textwrap.wrap(txt))
        else:
            self.help = None

        # This fails with a CommandException if types are invalid
        for name, parameter in self.signature.parameters.items():
            t = parameter.annotation
            if not mitmproxy.types.CommandTypes.get(parameter.annotation, None):
                raise exceptions.CommandError(
                    f"Argument {name} has an unknown type {t} in {func}."
                )
        if self.return_type and not mitmproxy.types.CommandTypes.get(
            self.return_type, None
        ):
            raise exceptions.CommandError(
                f"Return type has an unknown type ({self.return_type}) in {func}."
            )

    @property
    def return_type(self) -> type | None:
        return _empty_as_none(self.signature.return_annotation)

    @property
    def parameters(self) -> list[CommandParameter]:
        """Returns a list of CommandParameters."""
        ret = []
        for name, param in self.signature.parameters.items():
            ret.append(CommandParameter(name, param.annotation, param.kind))
        return ret

    def signature_help(self) -> str:
        params = " ".join(str(param) for param in self.parameters)
        if self.return_type:
            ret = f" -> {typename(self.return_type)}"
        else:
            ret = ""
        return f"{self.name} {params}{ret}"

    def prepare_args(self, args: Sequence[str]) -> inspect.BoundArguments:
        """
        将命令行/控制台传入的字符串参数转换为函数实参。

        参数先绑定到函数签名，再根据每个参数的类型标注调用 `parsearg()`；
        可变位置参数会逐个转换，最后应用默认值。
        """
        try:
            bound_arguments = self.signature.bind(*args)
        except TypeError:
            expected = f"Expected: {self.signature.parameters}"
            received = f"Received: {args}"
            raise exceptions.CommandError(
                f"Command argument mismatch: \n    {expected}\n    {received}"
            )

        for name, value in bound_arguments.arguments.items():
            param = self.signature.parameters[name]
            convert_to = param.annotation
            if param.kind == param.VAR_POSITIONAL:
                bound_arguments.arguments[name] = tuple(
                    parsearg(self.manager, x, convert_to) for x in value
                )
            else:
                bound_arguments.arguments[name] = parsearg(
                    self.manager, value, convert_to
                )

        bound_arguments.apply_defaults()

        return bound_arguments

    def call(self, args: Sequence[str]) -> Any:
        """
        Call the command with a list of arguments. At this point, all
        arguments are strings.
        """
        bound_args = self.prepare_args(args)
        ret = self.func(*bound_args.args, **bound_args.kwargs)
        if ret is None and self.return_type is None:
            return
        typ = mitmproxy.types.CommandTypes.get(self.return_type)
        assert typ
        if not typ.is_valid(self.manager, typ, ret):
            raise exceptions.CommandError(
                f"{self.name} returned unexpected data - expected {typ.display}"
            )
        return ret


class ParseResult(NamedTuple):
    """
    部分命令解析结果。

    用于命令补全和输入提示：`value` 是已解析文本，`type` 是推断出的命令类型，
    `valid` 表示当前片段是否已经满足类型要求。
    """

    value: str
    type: type
    valid: bool


class CommandManager:
    """
    命令注册表和解析入口。

    `collect_commands()` 从 addon 中收集带 `command_name` 的方法，`add()` 注册
    单个命令，`parse_partial()` 支持控制台补全，`call()` 负责按名字执行命令。
    """

    commands: dict[str, Command]

    def __init__(self, master):
        self.master = master
        self.commands = {}

    def collect_commands(self, addon):
        for i in dir(addon):
            if not i.startswith("__"):
                o = getattr(addon, i)
                try:
                    # hasattr is not enough, see https://github.com/mitmproxy/mitmproxy/issues/3794
                    is_command = isinstance(getattr(o, "command_name", None), str)
                except Exception:
                    pass  # getattr may raise if o implements __getattr__.
                else:
                    if is_command:
                        try:
                            self.add(o.command_name, o)
                        except exceptions.CommandError as e:
                            logging.warning(
                                f"Could not load command {o.command_name}: {e}"
                            )

    def add(self, path: str, func: Callable):
        self.commands[path] = Command(self, path, func)

    @functools.lru_cache(maxsize=128)
    def parse_partial(
        self, cmdstr: str
    ) -> tuple[Sequence[ParseResult], Sequence[CommandParameter]]:
        """
        Parse a possibly partial command. Return a sequence of ParseResults and a sequence of remainder type help items.
        """

        parts: pyparsing.ParseResults = command_lexer.expr.parseString(
            cmdstr, parseAll=True
        )

        parsed: list[ParseResult] = []
        next_params: list[CommandParameter] = [
            CommandParameter("", mitmproxy.types.Cmd),
            CommandParameter("", mitmproxy.types.CmdArgs),
        ]
        expected: CommandParameter | None = None
        for part in parts:
            if part.isspace():
                parsed.append(
                    ParseResult(
                        value=part,
                        type=mitmproxy.types.Space,
                        valid=True,
                    )
                )
                continue

            if expected and expected.kind is inspect.Parameter.VAR_POSITIONAL:
                assert not next_params
            elif next_params:
                expected = next_params.pop(0)
            else:
                expected = CommandParameter("", mitmproxy.types.Unknown)

            arg_is_known_command = (
                expected.type == mitmproxy.types.Cmd and part in self.commands
            )
            arg_is_unknown_command = (
                expected.type == mitmproxy.types.Cmd and part not in self.commands
            )
            command_args_following = (
                next_params and next_params[0].type == mitmproxy.types.CmdArgs
            )
            if arg_is_known_command and command_args_following:
                next_params = self.commands[part].parameters + next_params[1:]
            if arg_is_unknown_command and command_args_following:
                next_params.pop(0)

            to = mitmproxy.types.CommandTypes.get(expected.type, None)
            valid = False
            if to:
                try:
                    to.parse(self, expected.type, part)
                except ValueError:
                    valid = False
                else:
                    valid = True

            parsed.append(
                ParseResult(
                    value=part,
                    type=expected.type,
                    valid=valid,
                )
            )

        return parsed, next_params

    def call(self, command_name: str, *args: Any) -> Any:
        """
        Call a command with native arguments. May raise CommandError.
        """
        if command_name not in self.commands:
            raise exceptions.CommandError("Unknown command: %s" % command_name)
        return self.commands[command_name].func(*args)

    def call_strings(self, command_name: str, args: Sequence[str]) -> Any:
        """
        Call a command using a list of string arguments. May raise CommandError.
        """
        if command_name not in self.commands:
            raise exceptions.CommandError("Unknown command: %s" % command_name)

        return self.commands[command_name].call(args)

    def execute(self, cmdstr: str) -> Any:
        """
        Execute a command string. May raise CommandError.
        """
        parts, _ = self.parse_partial(cmdstr)
        if not parts:
            raise exceptions.CommandError(f"Invalid command: {cmdstr!r}")
        command_name, *args = (
            unquote(part.value) for part in parts if part.type != mitmproxy.types.Space
        )
        return self.call_strings(command_name, args)

    def dump(self, out=sys.stdout) -> None:
        cmds = list(self.commands.values())
        cmds.sort(key=lambda x: x.signature_help())
        for c in cmds:
            for hl in (c.help or "").splitlines():
                print("# " + hl, file=out)
            print(c.signature_help(), file=out)
            print(file=out)


def parsearg(manager: CommandManager, spec: str, argtype: type) -> Any:
    """
    Convert a string to a argument to the appropriate type.
    """
    t = mitmproxy.types.CommandTypes.get(argtype, None)
    if not t:
        raise exceptions.CommandError(f"Unsupported argument type: {argtype}")
    try:
        return t.parse(manager, argtype, spec)
    except ValueError as e:
        raise exceptions.CommandError(str(e)) from e


def command(name: str | None = None):
    def decorator(function):
        @functools.wraps(function)
        def wrapper(*args, **kwargs):
            verify_arg_signature(function, args, kwargs)
            return function(*args, **kwargs)

        wrapper.__dict__["command_name"] = name or function.__name__.replace("_", ".")
        return wrapper

    return decorator


def argument(name, type):
    """
    Set the type of a command argument at runtime. This is useful for more
    specific types such as mitmproxy.types.Choice, which we cannot annotate
    directly as mypy does not like that.
    """

    def decorator(f: types.FunctionType) -> types.FunctionType:
        assert name in f.__annotations__
        f.__annotations__[name] = type
        return f

    return decorator
