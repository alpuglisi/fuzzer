"""B1 rule's guard, prototyped: a regex that runs over a whole body (finditer / search /
findall / sub, unwindowed) must be linear by construction. Flags:
  (a) a nested repeat: a repeat with an unbounded maximum inside another repeat (neither
      possessive nor atomic);
  (b) a lazy repeat (MIN_REPEAT with max > 1);
  (c) an unbounded greedy repeat followed by a required element when the pattern's first
      consumed character can occur inside that repeat (a failed attempt then re-scans
      the run from every start: O(n^2) under finditer).
Run on the revision-3 and revision-4 prototypes' whole-body patterns."""
import re
import sys

try:
    from re import _constants as C
    from re import _parser as P
except ImportError:                       # pragma: no cover
    import sre_constants as C
    import sre_parse as P

MAXREPEAT = C.MAXREPEAT
_REPEATS = (C.MAX_REPEAT, C.MIN_REPEAT)
_POSSESSIVE = getattr(C, "POSSESSIVE_REPEAT", None)


def _chars(item):
    """The set of characters (as a predicate) one item can consume first, or None if
    unknown/any."""
    op, av = item
    if op == C.LITERAL:
        return lambda ch, v=av: ord(ch) == v
    if op == C.NOT_LITERAL:
        return lambda ch, v=av: ord(ch) != v
    if op == C.ANY:
        return lambda ch: True
    if op == C.IN:
        rx = re.compile("[" + "".join(_in_src(av)) + "]")
        return lambda ch, rx=rx: bool(rx.match(ch))
    if op == C.SUBPATTERN:
        sub = av[-1]
        return _first(list(sub))
    if op in _REPEATS or op == _POSSESSIVE:
        return _first(list(av[2]))
    if op == C.BRANCH:
        preds = [_first(list(b)) for b in av[1]]
        if any(p is None for p in preds):
            return None
        return lambda ch, preds=preds: any(p(ch) for p in preds)
    return None


def _in_src(av):
    out = []
    for op, a in av:
        if op == C.NEGATE:
            out.insert(0, "^")
        elif op == C.LITERAL:
            out.append(re.escape(chr(a)))
        elif op == C.RANGE:
            out.append(re.escape(chr(a[0])) + "-" + re.escape(chr(a[1])))
        elif op == C.CATEGORY:
            out.append({C.CATEGORY_DIGIT: r"\d", C.CATEGORY_NOT_DIGIT: r"\D",
                        C.CATEGORY_SPACE: r"\s", C.CATEGORY_NOT_SPACE: r"\S",
                        C.CATEGORY_WORD: r"\w", C.CATEGORY_NOT_WORD: r"\W"}.get(a, ""))
    return out


def _first(seq):
    for item in seq:
        op = item[0]
        if op in (C.AT, C.ASSERT, C.ASSERT_NOT):
            continue                       # zero-width: the first consumed item decides
        return _chars(item)
    return None


def _has_unbounded_repeat(seq) -> bool:
    for op, av in seq:
        if op in _REPEATS and av[1] == MAXREPEAT:
            return True
        if op in _REPEATS or op == _POSSESSIVE:
            if _has_unbounded_repeat(av[2]):
                return True
        elif op == C.SUBPATTERN:
            if _has_unbounded_repeat(av[-1]):
                return True
        elif op == C.BRANCH:
            if any(_has_unbounded_repeat(b) for b in av[1]):
                return True
    return False


def check(pattern: re.Pattern) -> list[str]:
    tree = P.parse(pattern.pattern, pattern.flags)
    problems = []
    start = _first(list(tree))

    def walk(seq, in_repeat):
        seq = list(seq)
        for i, (op, av) in enumerate(seq):
            if op in _REPEATS:
                lo, hi, sub = av
                if op == C.MIN_REPEAT and hi > 1:
                    problems.append("lazy repeat")
                if in_repeat and hi == MAXREPEAT:
                    problems.append("nested repeat")
                if hi > 1 and _has_unbounded_repeat(sub):
                    problems.append("nested repeat")
                if op == C.MAX_REPEAT and hi == MAXREPEAT and i + 1 < len(seq):
                    rest_required = any(o not in (C.AT,) and not (o in _REPEATS and a[0] == 0)
                                        for o, a in seq[i + 1:])
                    inner = _first(list(sub))
                    if rest_required and start is not None and inner is not None and \
                            any(start(ch) and inner(ch) for ch in map(chr, range(128))):
                        problems.append("unbounded run re-scanned from every start")
                walk(sub, True)
            elif op == _POSSESSIVE or op == getattr(C, "ATOMIC_GROUP", None):
                continue                   # no backtracking into it
            elif op == C.SUBPATTERN:
                walk(av[-1], in_repeat)
            elif op == C.BRANCH:
                for b in av[1]:
                    walk(b, in_repeat)
    walk(tree, False)
    return sorted(set(problems))


if __name__ == "__main__":
    sys.path.insert(0, "/tmp/claude-0/-home-user-fuzzer/2f299c5d-40a8-582c-a2d4-d0cdcbec2db1/scratchpad/au-redact")
    import proto3
    import proto3_rev3
    rev3 = ["_CAND", "_TYPE", "_MARKUP", "_RAWTEXT", "_JWT", "_PEM", "_USERINFO_FAST"]
    rev4 = ["_CAND", "_TYPE", "_MARKUP", "_RAW_TAG", "_JWT_HEAD", "_PEM", "_USERINFO_FAST",
            "_BEARER", "_PPK", "_AT"]
    print("== revision 3 whole-body patterns")
    for name in rev3:
        print(f"  {name:16s} {check(getattr(proto3_rev3, name)) or 'ok'}")
    print("== revision 4 whole-body patterns")
    for name in rev4:
        print(f"  {name:16s} {check(getattr(proto3, name)) or 'ok'}")
    print("  skeleton tags    ", check(re.compile(r"</?([A-Za-z][A-Za-z0-9:_-]{0,31})")) or "ok")
    print("== synthetic offenders")
    for src in (r"(a+)+b", r"<s>(.*?)</s>", r"eyJ[A-Za-z0-9_-]{5,}\.", r"x[^>]*>", r"(?:ab|a)*c"):
        print(f"  {src:28s} {check(re.compile(src, re.S)) or 'ok (MISSED)'}")
