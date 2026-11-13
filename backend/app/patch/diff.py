"""unified diff 的生成与回放。

行只按 \\n 切分，\\r 留在行内容里，与 git 的行模型一致，CRLF 文件生成的补丁同样能被 `git apply` 应用。
"""

from __future__ import annotations

import difflib
import re

NO_NEWLINE = "\\ No newline at end of file\n"
_LINE = re.compile(r"[^\n]*\n|[^\n]+$")
_HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


class PatchApplyError(ValueError):
    pass


def split_lines(text: str) -> list[str]:
    """按 \\n 切分并保留行尾；最后一行没有换行符时原样保留。"""
    return _LINE.findall(text)


def unified_diff(path: str, old: str, new: str, *, context: int = 3) -> str:
    """生成带 `diff --git` 头的补丁，路径前缀为 a/ 与 b/，在工程根目录执行 `git apply` 即可应用。"""
    lines = list(
        difflib.unified_diff(split_lines(old), split_lines(new), fromfile=f"a/{path}", tofile=f"b/{path}", n=context)
    )
    if not lines:
        return ""
    out = [f"diff --git a/{path} b/{path}\n"]
    for line in lines:
        out.append(line if line.endswith("\n") else f"{line}\n{NO_NEWLINE}")
    return "".join(out)


def diff_stats(diff: str) -> tuple[int, int]:
    """新增与删除的行数，不含文件头。"""
    added = removed = 0
    in_hunk = False
    for line in diff.splitlines():
        if line.startswith("@@"):
            in_hunk = True
        elif in_hunk and line.startswith("+"):
            added += 1
        elif in_hunk and line.startswith("-"):
            removed += 1
    return added, removed


def apply_diff(original: str, diff: str) -> str:
    """把单文件补丁应用到原文，上下文或删除行对不上时抛出 PatchApplyError。"""
    src = split_lines(original)
    lines = split_lines(diff)
    out: list[str] = []
    pos = 0  # 原文中下一行的下标
    i = 0
    while i < len(lines) and not lines[i].startswith("@@"):
        i += 1
    if i == len(lines):
        raise PatchApplyError("补丁里没有修改块")
    while i < len(lines):
        match = _HUNK.match(lines[i])
        if not match:
            raise PatchApplyError(f"无法识别的补丁行：{lines[i].rstrip()}")
        start = int(match.group(1))
        old_count = int(match.group(2) or 1)
        # 原文行数为 0 时，起始行号表示插在该行之后
        target = start - 1 if old_count else start
        if target < pos or target > len(src):
            raise PatchApplyError("修改块的位置超出原文范围")
        out.extend(src[pos:target])
        pos = target
        i += 1
        while i < len(lines) and not lines[i].startswith("@@"):
            line = lines[i]
            tag, body = line[:1], line[1:]
            if i + 1 < len(lines) and lines[i + 1] == NO_NEWLINE:
                body = body[:-1] if body.endswith("\n") else body
                i += 1
            if tag in (" ", "-"):
                if pos >= len(src) or src[pos] != body:
                    raise PatchApplyError(f"原文第 {pos + 1} 行与补丁不一致")
                pos += 1
                if tag == " ":
                    out.append(body)
            elif tag == "+":
                out.append(body)
            else:
                raise PatchApplyError(f"无法识别的补丁行：{line.rstrip()}")
            i += 1
    out.extend(src[pos:])
    return "".join(out)
