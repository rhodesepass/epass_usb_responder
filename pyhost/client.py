from __future__ import annotations

import argparse
import os
import struct
import sys
from typing import Dict, List, Optional, Tuple

import usb.core
import usb.util

import protocol as P

MAX_PAYLOAD = 8 * 1024 * 1024
USB_REQUEST_CHUNK = 16 * 1024
DEFAULT_CHUNK = USB_REQUEST_CHUNK - 4


def _write_exact(ep, data: bytes, timeout: int) -> None:
    sent = 0
    while sent < len(data):
        n = ep.write(data[sent: sent + USB_REQUEST_CHUNK], timeout=timeout)
        if n <= 0:
            raise IOError("USB write failed")
        sent += n


def struct_pack_u32(v: int) -> bytes:
    return v.to_bytes(4, "little")


def struct_unpack_header(hdr: bytes) -> Tuple[int, int, int, int, int, int, int]:
    return struct.unpack("<IHHIIII", hdr)


class UsbResponderClient:
    def __init__(
        self,
        vid: int,
        pid: int,
        *,
        serial: Optional[str] = None,
        interface: int = 0,
        timeout_ms: int = 300_000,
    ) -> None:
        self._dev = usb.core.find(
            idVendor=vid,
            idProduct=pid,
            custom_match=lambda d: serial is None or d.serial_number == serial,
        )
        if self._dev is None:
            raise RuntimeError(
                f"未找到设备 vid=0x{vid:04x} pid=0x{pid:04x}" +
                (f" serial={serial!r}" if serial else "")
            )
        self._timeout = timeout_ms
        self._iface = interface
        try:
            if self._dev.is_kernel_driver_active(interface):
                self._dev.detach_kernel_driver(interface)
        except (NotImplementedError, ValueError, usb.core.USBError):
            pass
        self._dev.set_configuration()
        cfg = self._dev.get_active_configuration()
        intf = usb.util.find_descriptor(cfg, bInterfaceNumber=interface)
        if intf is None:
            raise RuntimeError(f"无接口 {interface}")
        self._ep_in = usb.util.find_descriptor(
            intf,
            custom_match=lambda e: usb.util.endpoint_direction(
                e.bEndpointAddress) == usb.util.ENDPOINT_IN,
        )
        self._ep_out = usb.util.find_descriptor(
            intf,
            custom_match=lambda e: usb.util.endpoint_direction(
                e.bEndpointAddress) == usb.util.ENDPOINT_OUT,
        )
        if self._ep_in is None or self._ep_out is None:
            raise RuntimeError("未找到 bulk IN/OUT 端点（期望 0x81 / 0x02）")
        self._req = 0
        self._rxbuf = bytearray()
        self._rx_read_size = USB_REQUEST_CHUNK

    def close(self) -> None:
        usb.util.dispose_resources(self._dev)

    def _next_id(self) -> int:
        self._req = (self._req + 1) & 0xFFFFFFFF
        if self._req == 0:
            self._req = 1
        return self._req

    def _send_frame(self, typ: int, payload: bytes = b"", req_id: Optional[int] = None) -> int:
        rid = self._next_id() if req_id is None else req_id
        raw = P.Frame(type=typ, request_id=rid, payload=payload).encode()
        _write_exact(self._ep_out, raw, self._timeout)
        # 当帧总长为端点最大包大小的整数倍时，需补发零长包(ZLP)通知设备传输结束
        if len(raw) % self._ep_out.wMaxPacketSize == 0:
            try:
                self._ep_out.write(b"", timeout=self._timeout)
            except Exception:
                pass
        return rid

    def _recv_frame(self) -> P.Frame:
        # _read_some 内部已用 wMaxPacketSize 对齐，每次读自然以 short packet
        # 或收满请求量终止，不依赖设备端 ZLP。此处只需按需补足缓冲区。
        while len(self._rxbuf) < P.HEADER_SIZE:
            self._read_some(P.HEADER_SIZE - len(self._rxbuf))
        hdr = bytes(self._rxbuf[: P.HEADER_SIZE])
        _magic, _ver, _typ, _fl, _rid, plen, _crc = struct_unpack_header(hdr)
        if plen > MAX_PAYLOAD:
            raise ValueError("payload too large")
        frame_size = P.HEADER_SIZE + plen
        while len(self._rxbuf) < frame_size:
            self._read_some(frame_size - len(self._rxbuf))
        raw = bytes(self._rxbuf[:frame_size])
        del self._rxbuf[:frame_size]
        return P.decode_frame(raw)

    def _read_some(self, size: int) -> None:
        # 用端点 wMaxPacketSize 作为最小读取单元：
        # - 避免 read(size) 过小导致 libUSB OVERFLOW（UDC 驱动不支持拆分
        #   FunctionFS 事件到多个 URB）
        # - 每次 read 要么收到 short packet 自然终止，要么收满请求量按 USB
        #   规范终止，全程不依赖设备端 ZLP
        # - FunctionFS 残留的 ZLP 事件（0 字节）被循环吞掉
        mps = self._ep_in.wMaxPacketSize
        while True:
            chunk = self._ep_in.read(max(size, mps), timeout=self._timeout)
            if chunk is None or len(chunk) == 0:
                # ZLP 残留：忽略，继续尝试读下一笔数据
                continue
            self._rxbuf.extend(bytes(chunk))
            return


    def _expect_kv(self, req_id: int) -> Dict[str, str]:
        fr = self._recv_frame()
        if fr.request_id != req_id:
            raise RuntimeError(
                f"request_id 不匹配: 期望 {req_id} 收到 {fr.request_id}")
        if fr.type == P.MSG_ERROR:
            kv = P.decode_kv(fr.payload)
            raise RuntimeError(kv.get("message", "ERROR"))
        if fr.type != P.MSG_STATUS:
            raise RuntimeError(f"意外消息类型 {fr.type}，期望 STATUS")
        return P.decode_kv(fr.payload)

    def hello(self) -> Dict[str, str]:
        rid = self._send_frame(P.MSG_HELLO)
        return self._expect_kv(rid)

    def file_put(
        self,
        local_path: str,
        remote_path: str,
        chunk_size: int = DEFAULT_CHUNK,
        desire_storage: Optional[str] = None,
        perm: Optional[str] = None,
    ) -> None:
        rid = self._next_id()
        items: List[Tuple[str, str]] = [("path", remote_path)]
        if desire_storage:
            items.append(("desire_storage", desire_storage))
        if perm:
            items.append(("perm", perm))
        begin = P.encode_kv(items)
        self._send_frame(P.MSG_FILE_PUT_BEGIN, begin, req_id=rid)
        self._expect_kv(rid)

        with open(local_path, "rb") as f:
            while True:
                piece = f.read(chunk_size)
                if not piece:
                    break
                chunk_payload = struct_pack_u32(rid) + piece
                self._send_frame(P.MSG_FILE_PUT_CHUNK,
                                 chunk_payload, req_id=rid)
                self._expect_kv(rid)

        self._send_frame(P.MSG_FILE_PUT_END, struct_pack_u32(rid), req_id=rid)
        self._expect_kv(rid)

    def file_get(self, remote_path: str, local_path: str) -> None:
        rid = self._send_frame(
            P.MSG_FILE_GET, P.encode_kv([("path", remote_path)]))
        fr = self._recv_frame()
        if fr.request_id != rid:
            raise RuntimeError(f"request_id 不匹配: 期望 {rid} 收到 {fr.request_id}")
        if fr.type == P.MSG_ERROR:
            kv = P.decode_kv(fr.payload)
            raise RuntimeError(kv.get("message", "ERROR"))
        if fr.type != P.MSG_FILE_GET:
            raise RuntimeError(f"意外类型 {fr.type}，期望 FILE_GET")
        with open(local_path, "wb") as out:
            out.write(fr.payload)

    def file_list(self, path: str = ".") -> Tuple[List[str], List[str]]:
        rid = self._send_frame(P.MSG_FILE_LIST, P.encode_kv([("path", path)]))
        kv = self._expect_kv(rid)
        files_raw = kv.get("files", "")
        dirs_raw = kv.get("dirs", "")
        files = [line for line in files_raw.splitlines() if line]
        dirs = [line for line in dirs_raw.splitlines() if line]
        return files, dirs

    def file_stat(self, path: str) -> Dict[str, str]:
        rid = self._send_frame(P.MSG_FILE_STAT, P.encode_kv([("path", path)]))
        return self._expect_kv(rid)

    def file_delete(self, remote_path: str, desire_storage: Optional[str] = None) -> None:
        items: List[Tuple[str, str]] = [("path", remote_path)]
        if desire_storage:
            items.append(("desire_storage", desire_storage))
        rid = self._send_frame(P.MSG_FILE_DELETE, P.encode_kv(items))
        self._expect_kv(rid)

    def file_rename(self, src: str, dst: str, desire_storage: Optional[str] = None) -> None:
        items: List[Tuple[str, str]] = [("from", src), ("to", dst)]
        if desire_storage:
            items.append(("desire_storage", desire_storage))
        rid = self._send_frame(P.MSG_FILE_RENAME, P.encode_kv(items))
        self._expect_kv(rid)

    def dir_mkdir(self, path: str, parents: bool = False, desire_storage: Optional[str] = None) -> None:
        items: List[Tuple[str, str]] = [("path", path)]
        if parents:
            items.append(("parents", "1"))
        if desire_storage:
            items.append(("desire_storage", desire_storage))
        rid = self._send_frame(P.MSG_FILE_MKDIR, P.encode_kv(items))
        self._expect_kv(rid)

    def devinfo(self) -> Dict[str, str]:
        rid = self._send_frame(P.MSG_DEVINFO)
        fr = self._recv_frame()
        if fr.request_id != rid:
            raise RuntimeError(f"request_id 不匹配: 期望 {rid} 收到 {fr.request_id}")
        if fr.type == P.MSG_ERROR:
            kv = P.decode_kv(fr.payload)
            raise RuntimeError(kv.get("message", "ERROR"))
        if fr.type != P.MSG_DEVINFO:
            raise RuntimeError(f"意外类型 {fr.type}，期望 DEVINFO")
        return P.decode_kv(fr.payload)

    def command_exec(
        self,
        command: str,
        *,
        timeout_ms: int = 0,
        max_stdout: int = 0,
        max_stderr: int = 0,
    ) -> P.CommandResult:
        pl = P.encode_command_exec(
            command, timeout_ms=timeout_ms, max_stdout=max_stdout, max_stderr=max_stderr
        )
        rid = self._send_frame(P.MSG_COMMAND_EXEC, pl)
        fr = self._recv_frame()
        if fr.request_id != rid:
            raise RuntimeError(f"request_id 不匹配: 期望 {rid} 收到 {fr.request_id}")
        if fr.type == P.MSG_ERROR:
            kv = P.decode_kv(fr.payload)
            raise RuntimeError(kv.get("message", "ERROR"))
        if fr.type != P.MSG_COMMAND_RESULT:
            raise RuntimeError(f"意外类型 {fr.type}，期望 COMMAND_RESULT")
        return P.decode_command_result(fr.payload)


def _remote_is_dir(cl: "UsbResponderClient", dest: str) -> bool:
    # 尾斜杠按目录意图处理，即便设备上还不存在；否则查 stat。
    if dest.endswith("/"):
        return True
    try:
        return cl.file_stat(dest).get("type") == "dir"
    except Exception:
        return False


def _remote_join(dest: str, local: str) -> str:
    return dest.rstrip("/") + "/" + os.path.basename(local.rstrip("/"))


def _local_perm(path: str) -> str:
    # 只取权限位（低 12 bit，含 setuid/sticky），不涉及 owner —— 协议无法设 owner。
    return f"{os.stat(path).st_mode & 0o7777:04o}"


def _cp_one(cl: "UsbResponderClient", src: str, remote: str, args) -> None:
    perm = None if args.no_perm else (args.perm or _local_perm(src))
    cl.file_put(src, remote, chunk_size=args.chunk,
                desire_storage=args.desire_storage, perm=perm)
    print(f"{src} -> {remote}")


def _cp_dir(cl: "UsbResponderClient", src: str, remote_root: str, args) -> None:
    for root, _dirs, files in os.walk(src):
        rel = os.path.relpath(root, src)
        remote_dir = remote_root if rel == "." else remote_root + \
            "/" + rel.replace(os.sep, "/")
        cl.dir_mkdir(remote_dir, parents=True,
                     desire_storage=args.desire_storage)
        for name in files:
            _cp_one(cl, os.path.join(root, name),
                    remote_dir + "/" + name, args)


def _parse_hex(s: str) -> int:
    s = s.strip().lower()
    if s.startswith("0x"):
        s = s[2:]
    return int(s, 16)


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="usb_responder 上位机（pyusb），协议见 PROTOCOL.md")
    p.add_argument("--vid", type=_parse_hex, default=0x1d6b,
                   help="USB Vendor ID（十六进制，如 0x1234）")
    p.add_argument("--pid", type=_parse_hex,
                   default=0x0203, help="USB Product ID")
    p.add_argument("--serial", default=None, help="按序列号筛选（可选）")
    p.add_argument("--interface", type=int, default=0, help="接口号，默认 0")
    p.add_argument(
        "--timeout",
        type=int,
        default=300_000,
        help="单次 USB 传输超时（毫秒）。大文件写慢速 NAND 时内核脏页回写会阻塞 write，"
        "单次操作可能卡几十秒，故默认放宽到 300s",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("hello", help="握手，打印 STATUS KV")

    sub.add_parser("devinfo", help="读取设备信息（model/kernel/rootfs/app/存储状态）")

    sp = sub.add_parser("put", help="上传文件")
    sp.add_argument("local")
    sp.add_argument("remote")
    sp.add_argument("--chunk", type=int, default=DEFAULT_CHUNK,
                    help="每片字节数（默认约 16KiB）")
    sp.add_argument("--desire-storage", choices=("nand", "sd"),
                    default=None, help="期望写入存储")
    sp.add_argument("--perm", default=None, help="上传完成后 chmod 权限（八进制，如 0644）")

    scp = sub.add_parser(
        "cp",
        help="上传一个或多个文件，类似 cp：目标为目录时复制为 目标/源文件名",
    )
    scp.add_argument("paths", nargs="+", metavar="SRC... DEST",
                     help="一个或多个本地源，最后一个为设备目标")
    scp.add_argument("-r", "--recursive", action="store_true", help="递归上传目录")
    scp.add_argument("--chunk", type=int,
                     default=DEFAULT_CHUNK, help="每片字节数（默认约 16KiB）")
    scp.add_argument("--desire-storage", choices=("nand",
                     "sd"), default=None, help="期望写入存储")
    scp.add_argument("--perm", default=None,
                     help="覆盖权限（八进制，如 0644）；默认保留本地文件原权限")
    scp.add_argument("--no-perm", action="store_true",
                     help="不设置权限，使用设备默认 umask")

    sg = sub.add_parser("get", help="下载文件")
    sg.add_argument("remote")
    sg.add_argument("local")

    sl = sub.add_parser("ls", help="列目录")
    sl.add_argument("path", nargs="?", default=".")

    sd = sub.add_parser("rm", help="删除文件或目录（目录为递归删除）")
    sd.add_argument("path")
    sd.add_argument("--desire-storage", choices=("nand", "sd"),
                    default=None, help="期望删除目标所在存储")

    sm = sub.add_parser("mv", help="重命名")
    sm.add_argument("src")
    sm.add_argument("dst")
    sm.add_argument("--desire-storage", choices=("nand", "sd"),
                    default=None, help="期望源和目标所在存储")

    sk = sub.add_parser("mkdir", help="创建目录")
    sk.add_argument("path")
    sk.add_argument("-p", "--parents", action="store_true",
                    help="递归创建父目录（类似 mkdir -p）")
    sk.add_argument("--desire-storage", choices=("nand", "sd"),
                    default=None, help="期望创建目标所在存储")

    ss = sub.add_parser("stat", help="路径元数据（owner/perm/size/type）")
    ss.add_argument("path")

    se = sub.add_parser("exec", help="在设备上执行 shell 命令（/bin/sh -c）")
    se.add_argument("--shell-timeout", type=int,
                    default=0, help="设备侧超时 ms（0=设备默认）")
    se.add_argument("--max-stdout", type=int,
                    default=0, help="stdout 上限（0=设备默认）")
    se.add_argument("--max-stderr", type=int,
                    default=0, help="stderr 上限（0=设备默认）")
    se.add_argument("args", nargs=argparse.REMAINDER, help="命令（若含 - 开头请加 --）")

    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        cl = UsbResponderClient(
            args.vid, args.pid, serial=args.serial, interface=args.interface, timeout_ms=args.timeout
        )
    except Exception as e:
        print(e, file=sys.stderr)
        return 1
    try:
        if args.cmd == "hello":
            kv = cl.hello()
            for k in sorted(kv.keys()):
                print(f"{k}={kv[k]}")
        elif args.cmd == "devinfo":
            kv = cl.devinfo()
            for k in (
                "model",
                "kernel",
                "rootfs",
                "app",
                "sd_mounted",
                "nand_total_bytes",
                "nand_free_bytes",
                "sd_total_bytes",
                "sd_free_bytes",
            ):
                v = kv.get(k, "")
                if "\n" in v:
                    print(f"--- {k} ---")
                    print(v)
                else:
                    print(f"{k}={v}")
        elif args.cmd == "put":
            cl.file_put(
                args.local,
                args.remote,
                chunk_size=args.chunk,
                desire_storage=args.desire_storage,
                perm=args.perm,
            )
        elif args.cmd == "cp":
            if len(args.paths) < 2:
                print("cp: 需要至少一个源和一个目标", file=sys.stderr)
                return 2
            *srcs, dest = args.paths
            dest_is_dir = _remote_is_dir(cl, dest)
            if len(srcs) > 1 and not dest_is_dir:
                print(f"cp: 目标 {dest!r} 不是目录", file=sys.stderr)
                return 2
            for src in srcs:
                if os.path.isdir(src):
                    if not args.recursive:
                        print(f"cp: 略过目录 {src!r}（需要 -r）", file=sys.stderr)
                        return 2
                    root = _remote_join(dest, src) if dest_is_dir else dest
                    _cp_dir(cl, src, root, args)
                else:
                    remote = _remote_join(dest, src) if dest_is_dir else dest
                    _cp_one(cl, src, remote, args)
        elif args.cmd == "get":
            cl.file_get(args.remote, args.local)
        elif args.cmd == "ls":
            files, dirs = cl.file_list(args.path)
            for name in dirs:
                print(f"{name}/")
            for name in files:
                print(name)
        elif args.cmd == "stat":
            kv = cl.file_stat(args.path)
            for k in ("owner", "perm", "size", "type"):
                print(f"{k}={kv.get(k, '')}")
        elif args.cmd == "rm":
            cl.file_delete(args.path, desire_storage=args.desire_storage)
        elif args.cmd == "mv":
            cl.file_rename(args.src, args.dst,
                           desire_storage=args.desire_storage)
        elif args.cmd == "mkdir":
            cl.dir_mkdir(args.path, parents=args.parents,
                         desire_storage=args.desire_storage)
        elif args.cmd == "exec":
            cmd = " ".join(args.args).strip()
            if not cmd:
                print("exec: 需要命令", file=sys.stderr)
                return 2
            r = cl.command_exec(
                cmd,
                timeout_ms=args.shell_timeout,
                max_stdout=args.max_stdout,
                max_stderr=args.max_stderr,
            )
            sys.stdout.buffer.write(r.stdout)
            sys.stderr.buffer.write(r.stderr)
            if r.timed_out:
                print(
                    f"\n[timed_out duration_ms={r.duration_ms}]", file=sys.stderr)
            ec = r.exit_code
            if ec < 0 or ec > 255:
                return 1
            return ec
        return 0
    except Exception as e:
        print(e, file=sys.stderr)
        return 1
    finally:
        cl.close()


if __name__ == "__main__":
    raise SystemExit(main())
