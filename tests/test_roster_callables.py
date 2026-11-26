"""WorkerRoster's Python process target is a synchronous callable."""
import asyncio
from functools import partial, partialmethod, wraps
import inspect
from multiprocessing import get_context
from pathlib import Path
from tempfile import TemporaryDirectory
from time import monotonic_ns
from types import coroutine
import unittest

from worker_handoff import WorkerRoster


async def _async_function(value=7):
    return value


async def _async_generator(*args):
    yield 7


class _AsyncCallable:
    async def __call__(self, value=7):
        return value


class _AsyncGeneratorCallable:
    __call__ = partialmethod(_async_generator)


class _AsyncStaticCallable:
    __call__ = staticmethod(_async_function)


class _SyncPartial(partial):
    def __call__(self):
        return 7


class _PartialWithHiddenFunc(partial):
    @property
    def func(self):
        raise AssertionError("launch validation should not call this property")


class _Awaitable:
    def __await__(self):
        yield 7


class _OpaqueMeta(type):
    def __getattribute__(self, name):
        if name in ("__mro__", "__dict__"):
            raise AssertionError("return validation should not call metaclass hooks")
        return super().__getattribute__(name)


class _OpaqueResult(metaclass=_OpaqueMeta):
    @property
    def __class__(self):
        raise AssertionError("normal return values should be discarded")


def _coroutine_factory():
    return _async_function()


if hasattr(inspect, "markcoroutinefunction"):
    inspect.markcoroutinefunction(_coroutine_factory)


@wraps(_coroutine_factory, assigned=())
def _bridge():
    return asyncio.run(_coroutine_factory())


@wraps(_async_function, assigned=(), updated=())
def _returns_coroutine():
    return _async_function()


def _returns_async_generator():
    return _async_generator()


def _returns_awaitable():
    return _Awaitable()


@coroutine
def _generator_coroutine():
    yield 7


def _returns_generator_coroutine():
    return _generator_coroutine()


def _returns_opaque(args):
    return _OpaqueResult()


def _sync_generator(marker):
    marker.write_text("generator body ran", encoding="utf-8")
    yield 7


def _returns_generator(marker):
    marker.write_text("handler ran", encoding="utf-8")
    return _sync_generator(marker)


def _exit(status):
    raise SystemExit(status)


class RosterCallableTest(unittest.TestCase):
    def start(self, roster, target, args=(), *, context=None):
        worker = roster.start("job", "test", target, args=args, context=context)
        self.addCleanup(self.reap, worker.process)
        return worker

    @staticmethod
    def reap(process):
        if process.is_alive():
            process.kill()
        process.join(3)

    def assert_outcome(self, target, expected, args=(), *, context=None):
        roster = WorkerRoster()
        worker = self.start(roster, target, args, context=context)
        self.assertEqual(roster.join("job", due_ns=monotonic_ns() + 5_000_000_000), expected)
        self.assertFalse(worker.process.is_alive())

    def test_recognizable_async_targets_refuse_and_leave_name_available(self):
        targets = (
            _async_function, _async_generator, _generator_coroutine,
            partial(_async_function, 7),
            _PartialWithHiddenFunc(_async_function),
            _AsyncCallable(), _AsyncCallable().__call__, partial(_AsyncCallable(), 7),
            _AsyncGeneratorCallable(), _AsyncStaticCallable(),
        )
        for target in targets:
            roster = WorkerRoster()
            with self.subTest(target=target):
                with self.assertRaises(TypeError):
                    self.start(roster, target)
                with self.assertRaises(KeyError):
                    roster.owned("job")
                self.start(roster, _exit, (0,))
                self.assertEqual(roster.join("job", due_ns=monotonic_ns() + 5_000_000_000), 0)

    def test_async_return_from_sync_target_fails_in_child(self):
        targets = (
            _returns_coroutine, _returns_async_generator, _returns_awaitable,
            _returns_generator_coroutine,
        )
        for target in targets:
            for context in (None, get_context("fork")):
                with self.subTest(target=target, context=context):
                    self.assert_outcome(target, 1, context=context)

    def test_generator_target_refusal_leaves_name_available(self):
        for context in (None, get_context("fork")):
            with self.subTest(context=context), TemporaryDirectory() as directory:
                marker = Path(directory) / "marker"
                roster = WorkerRoster()
                for target, args in (
                    (_sync_generator, (marker,)),
                    (partial(_sync_generator, marker), ()),
                ):
                    with self.assertRaises(TypeError):
                        self.start(roster, target, args, context=context)
                    with self.assertRaises(KeyError):
                        roster.owned("job")
                worker = self.start(roster, _returns_generator, (marker,), context=context)
                self.assertEqual(roster.join("job", due_ns=monotonic_ns() + 5_000_000_000), 0)
                self.assertFalse(worker.process.is_alive())
                self.assertEqual(marker.read_text(encoding="utf-8"), "handler ran")

    def test_sync_returns_remain_ignored_and_explicit_exit_is_preserved(self):
        cases = (
            (_bridge, (), 0),
            (_returns_opaque, ("example argument",), 0),
            (_SyncPartial(_async_function), (), 0),
            (_PartialWithHiddenFunc(_exit, 7), (), 7),
            (_exit, (7,), 7),
        )
        for target, args, status in cases:
            for context in (None, get_context("fork")):
                with self.subTest(target=target, context=context):
                    self.assert_outcome(target, status, args, context=context)
