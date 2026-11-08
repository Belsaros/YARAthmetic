"""Experimental SHA-256 Boolean circuit expressed as private YARA rules.

Rules are reusable gates, avoiding recursive inlining of SHA-256 state. They
evaluate once per scanned file, so inputs must refer to one candidate slot
selected consistently across the circuit.
Words and bytes below store bits least-significant first.

Algorithm and constants: NIST FIPS 180-4, sections 4.1.2, 4.2.2, 5 and 6.2.
https://doi.org/10.6028/NIST.FIPS.180-4
"""

INITIAL = (
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
)
CONSTANTS = (
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
    0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
    0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
    0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
    0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
    0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
    0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
    0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
    0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
)


def constant(value, width=32):
    return ["true" if (value >> bit) & 1 else "false" for bit in range(width)]


class BooleanCircuit:
    def __init__(self, prefix="sha"):
        self.prefix = prefix
        self.rules = []
        self.cache = {}

    def input(self, condition, strings=""):
        name = f"{self.prefix}_{len(self.rules)}"
        self.rules.append(
            f"private rule {name} {{ {strings} condition: {condition} }}\n"
        )
        return name

    def gate(self, operation, *arguments):
        if operation in ("and", "or", "xor"):
            arguments = tuple(sorted(arguments))
        key = (operation, *arguments)
        if key in self.cache:
            return self.cache[key]
        a = arguments[0]
        if operation == "not":
            if a in ("true", "false"):
                return "false" if a == "true" else "true"
            expression = f"not {a}"
        else:
            b = arguments[1]
            if a == b:
                return "false" if operation == "xor" else a
            if operation == "and":
                if "false" in arguments:
                    return "false"
                if "true" in arguments:
                    return b if a == "true" else a
                expression = f"{a} and {b}"
            elif operation == "or":
                if "true" in arguments:
                    return "true"
                if "false" in arguments:
                    return b if a == "false" else a
                expression = f"{a} or {b}"
            elif operation == "xor":
                if "false" in arguments:
                    return b if a == "false" else a
                if "true" in arguments:
                    return self.gate("not", b if a == "true" else a)
                expression = f"({a} and not {b}) or (not {a} and {b})"
            else:
                raise ValueError("unknown gate operation")
        result = self.input(expression)
        self.cache[key] = result
        if operation == "not":
            self.cache[("not", result)] = a
        return result

    def xor_words(self, *words):
        result = words[0]
        for word in words[1:]:
            result = [self.gate("xor", a, b) for a, b in zip(result, word)]
        return result

    def add(self, *words):
        result = words[0]
        for word in words[1:]:
            output = []
            carry = "false"
            for index, (a, b) in enumerate(zip(result, word)):
                different = self.gate("xor", a, b)
                output.append(self.gate("xor", different, carry))
                if index != 31:
                    carry = self.gate("or", self.gate("and", a, b), self.gate("and", different, carry))
            result = output
        return result

    def sigma(self, word, rotate_a, rotate_b, last, shift=False):
        def rotate(count):
            return word[count:] + word[:count]
        final = word[last:] + ["false"] * last if shift else rotate(last)
        return self.xor_words(rotate(rotate_a), rotate(rotate_b), final)

    def sha256(self, message):
        """Hash up to 55 symbolic bytes in a single padded SHA-256 block."""
        if len(message) > 55 or any(len(byte) != 8 for byte in message):
            raise ValueError("expected at most 55 eight-bit bytes")
        bit_length = len(message) * 8
        padded = list(message) + [constant(128, 8)]
        padded += [constant(0, 8) for _ in range(56 - len(padded))]
        padded += [constant(byte, 8) for byte in bit_length.to_bytes(8, "big")]
        schedule = [
            [bit for byte in reversed(padded[offset:offset + 4]) for bit in byte]
            for offset in range(0, 64, 4)
        ]
        for index in range(16, 64):
            schedule.append(self.add(
                schedule[index - 16],
                self.sigma(schedule[index - 15], 7, 18, 3, shift=True),
                schedule[index - 7],
                self.sigma(schedule[index - 2], 17, 19, 10, shift=True),
            ))
        initial = [constant(value) for value in INITIAL]
        a, b, c, d, e, f, g, h = initial
        for index in range(64):
            choose = [
                self.gate("or", self.gate("and", x, y), self.gate("and", self.gate("not", x), z))
                for x, y, z in zip(e, f, g)
            ]
            majority = [
                self.gate("or", self.gate("and", x, y), self.gate("and", self.gate("xor", x, y), z))
                for x, y, z in zip(a, b, c)
            ]
            t1 = self.add(h, self.sigma(e, 6, 11, 25), choose, constant(CONSTANTS[index]), schedule[index])
            t2 = self.add(self.sigma(a, 2, 13, 22), majority)
            a, b, c, d, e, f, g, h = self.add(t1, t2), a, b, c, self.add(d, t1), e, f, g
        return [self.add(before, after) for before, after in zip(initial, (a, b, c, d, e, f, g, h))]


def digest_bytes(words):
    return [word[shift:shift + 8] for word in words for shift in (24, 16, 8, 0)]
