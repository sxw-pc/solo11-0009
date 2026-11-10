"""Heuristic Chinese person-name and address detectors."""

from __future__ import annotations

import re
from typing import Sequence

from .base import Candidate, score_candidate

# Common Chinese surnames only. This is a heuristic, not an authoritative list.
SURNAMES = set(
    "赵钱孙李周吴郑王冯陈褚卫蒋沈韩杨朱秦尤许何吕施张孔曹严华金魏陶姜"
    "戚谢邹喻柏水窦章云苏潘葛奚范彭郎鲁韦昌马苗凤花方俞任袁柳鲍史唐"
    "费廉岑薛雷贺倪汤滕殷罗毕郝邬安常乐于时傅皮卞齐康伍余元卜顾孟平"
    "黄和穆萧尹姚邵湛汪祁毛禹狄米贝明臧计伏成戴谈宋茅庞熊纪舒屈项祝"
    "董梁杜阮蓝闵席季麻强贾路娄危江童颜郭梅盛林刁钟徐邱骆高夏蔡田樊"
    "胡凌霍虞万支柯管卢莫经房裘缪干解应宗丁宣贲邓郁单杭洪包诸左石崔"
    "吉钮龚程嵇邢滑裴陆荣翁荀羊惠甄曲封芮羿储靳汲邴糜松井段富巫乌焦"
    "巴弓牧隗山谷车侯宓蓬全郗班仰秋仲伊宫宁仇栾暴甘钭厉戎祖武符刘景"
    "詹束龙叶幸司韶郜黎蓟薄印宿白怀蒲邰从鄂索咸籍赖卓蔺屠蒙池乔阴胥"
    "能苍双闻莘党翟谭贡劳逄姬申扶堵冉宰郦雍卻璩桑桂濮牛寿通边扈燕冀"
    "郏浦尚农温别庄晏柴瞿阎充慕连茹习宦艾鱼容向古易慎戈廖庾终暨居衡"
    "步都耿满弘匡国文寇广禄阙东欧殳沃利蔚越夔隆师巩厍聂晁勾敖融冷訾"
    "辛阚那简饶空曾毋沙乜养鞠须丰巢关蒯相查后荆红游竺权逯盖益桓公"
)
NAME_RE = re.compile(r"[一-龥]{2,4}")
ADDRESS_RE = re.compile(
    r"[一-龥]{2,}(?:省|市|区|县|旗|镇|乡|村|街道|路|街|巷|弄|号|"
    r"小区|大厦|广场|苑|园)"
)


class PersonNameDetector:
    sensitive_type = "person_name"

    def evaluate(self, values: Sequence[str]) -> Candidate | None:
        matches = [
            value
            for value in values
            if NAME_RE.fullmatch(value) and value[0] in SURNAMES
        ]
        return score_candidate(self.sensitive_type, len(values), matches)


class AddressDetector:
    sensitive_type = "address"

    def evaluate(self, values: Sequence[str]) -> Candidate | None:
        matches = [
            value
            for value in values
            if len(value) >= 4 and ADDRESS_RE.search(value)
        ]
        return score_candidate(self.sensitive_type, len(values), matches)


LEXICON_DETECTORS = (PersonNameDetector(), AddressDetector())
