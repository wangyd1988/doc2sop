"""页面上的两种回答模式：知识库模式（kb）和智能模式（smart）。

知识库模式就是原来的行为：回答只依据知识库、工具查到的实际数据和（开了联网时的）网络结果，资料不足就说没有。
智能模式：查不查知识库、查几次由模型决定；知识库和网络都不够时，可以用模型自身的通用知识补充，
补充的句子末尾标 [💡]，页面显示成「💡 通用知识」（未经核实）。

两种模式只差两件事：知识库怎么查（代码先查 vs 模型决定查），资料不足时能不能用模型自身的知识。
数据工具、SOP、计算、联网和对外 MCP 都一样。提示词只有一套，智能模式换掉其中「回答依据」那几句（loop.py）。

这里放两边共用的：认出、去掉回答里标了通用知识的内容。
"""
import re

MODES = ("kb", "smart")
LABELS = {"kb": "知识库模式", "smart": "智能模式"}
# 模型自身的通用知识在句末标这个。也认模型偶尔写出来的变体：[💡通用知识]、【💡】
GENERAL_TAG = "[💡]"
GENERAL_MARK = re.compile(r"[\[【]\s*💡[^\]】\n]{0,20}[\]】]")
# 存进知识库的文档里换成这句：标记还在，但不再是回答里的那个标记
GENERAL_NOTE = "（💡 通用知识，未经核实）"


def uses_general(text) -> bool:
    """回答里有没有标了通用知识的内容。"""
    return bool(GENERAL_MARK.search(str(text or "")))


def strip_general(text) -> str:
    """去掉标了通用知识的内容：标记所在的整行（段落、列表项、表格行）都去掉。

    模型按句标注，同一行里别的句子也跟着去掉：宁可少留，也不让通用知识混进 SOP 的结论和检查点。
    """
    kept = [line for line in str(text or "").split("\n") if not GENERAL_MARK.search(line)]
    return re.sub(r"\n{3,}", "\n\n", "\n".join(kept)).strip()


def history_uses_general(history) -> bool:
    """对话历史 [(role, content)] 里，有没有助手的回答标了通用知识。"""
    return any(role != "user" and uses_general(content) for role, content in history or ())
