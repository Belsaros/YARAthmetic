
============================================================
 Testing YARA 3.4.0
============================================================


=== Testing YARA 3.4.0 ===

============================= test session starts ==============================
platform linux -- Python 3.11.2, pytest-9.1.1, pluggy-1.6.0 -- /venv/bin/python
rootdir: /work
configfile: pyproject.toml
collecting ... collected 25 items

tests/test_luhn.py::test_reference_luhn_rejects_malformed_input[] PASSED [  4%]
tests/test_luhn.py::test_reference_luhn_rejects_malformed_input[411111111111111x] PASSED [  8%]
tests/test_luhn.py::test_reference_luhn_rejects_malformed_input[\uff14\uff11\uff11\uff11\uff11\uff11\uff11\uff11\uff11\uff11\uff11\uff11\uff11\uff11\uff11\uff11] PASSED [ 12%]
tests/test_luhn.py::test_luhn_vectors_exist PASSED                       [ 16%]
tests/test_luhn.py::test_luhn_vectors_are_ascii_digits PASSED            [ 20%]
tests/test_luhn.py::test_reference_luhn_vectors PASSED                   [ 24%]
tests/test_luhn_yara.py::test_generated_luhn_rule_matches_valid_sample FAILED [ 28%]
tests/test_luhn_yara.py::test_generated_luhn_rules_compile FAILED        [ 32%]
tests/test_luhn_yara.py::test_committed_luhn_rules_are_current PASSED    [ 36%]
tests/test_luhn_yara.py::test_generated_luhn_rule_rejects_invalid_sample FAILED [ 40%]
tests/test_luhn_yara.py::test_generated_luhn_rule_matches_when_any_candidate_is_valid FAILED [ 44%]
tests/test_luhn_yara.py::test_generated_luhn_rules_match_vectors FAILED  [ 48%]
tests/test_luhn_yara.py::test_generated_luhn_rule_matches_formatted_sample[formatted-19.txt-19] FAILED [ 52%]
tests/test_luhn_yara.py::test_generated_luhn_rule_matches_formatted_sample[formatted.txt-16] FAILED [ 56%]
tests/test_luhn_yara.py::test_generated_luhn_rule_matches_formatted_sample[formatted-hyphen.txt-16] FAILED [ 60%]
tests/test_luhn_yara.py::test_generated_luhn_rule_matches_formatted_sample[formatted-mixed.txt-16] FAILED [ 64%]
tests/test_luhn_yara.py::test_generated_luhn_rule_matches_formatted_sample[formatted-15.txt-15] FAILED [ 68%]
tests/test_luhn_yara.py::test_generated_luhn_rule_matches_formatted_sample[formatted-14.txt-14] FAILED [ 72%]
tests/test_luhn_yara.py::test_generated_luhn_rule_rejects_embedded_candidate FAILED [ 76%]
tests/test_luhn_yara.py::test_generated_luhn_rule_rejects_digit_embedded_candidate[94111111111111111] FAILED [ 80%]
tests/test_luhn_yara.py::test_generated_luhn_rule_rejects_digit_embedded_candidate[41111111111111119] FAILED [ 84%]
tests/test_luhn_yara.py::test_generated_luhn_rule_rejects_digit_embedded_candidate[941111111111111119] FAILED [ 88%]
tests/test_luhn_yara.py::test_generated_luhn_rule_allows_nondigit_boundaries[x4111111111111111] FAILED [ 92%]
tests/test_luhn_yara.py::test_generated_luhn_rule_allows_nondigit_boundaries[4111111111111111y] FAILED [ 96%]
tests/test_luhn_yara.py::test_generated_luhn_rule_allows_nondigit_boundaries[x4111111111111111y] FAILED [100%]

=================================== FAILURES ===================================
________________ test_generated_luhn_rule_matches_valid_sample _________________

tmp_path = PosixPath('/tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_match0')

    def test_generated_luhn_rule_matches_valid_sample(tmp_path):
        result = run_generated_rule(tmp_path, SAMPLES / "valid.txt")
    
>       assert result.returncode == 0, result.stderr
E       AssertionError: /tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_match0/luhn16.yar(5): warning: $compact is slowing down scanning (critical!)
E         /tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_match0/luhn16.yar(7): warning: $formatted is slowing down scanning (critical!)
E         /tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_match0/luhn16.yar(16): error: syntax error, unexpected $undefined
E         
E       assert 1 == 0
E        +  where 1 = CompletedProcess(args=['yara', '/tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_match0/luhn16.yar', '/work/tests/samples/luhn/valid.txt'], returncode=1, stdout='', stderr='/tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_match0/luhn16.yar(5): warning: $compact is slowing down scanning (critical!)\n/tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_match0/luhn16.yar(7): warning: $formatted is slowing down scanning (critical!)\n/tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_match0/luhn16.yar(16): error: syntax error, unexpected $undefined\n').returncode

tests/test_luhn_yara.py:44: AssertionError
______________________ test_generated_luhn_rules_compile _______________________

tmp_path = PosixPath('/tmp/pytest-of-root/pytest-0/test_generated_luhn_rules_comp0')

    def test_generated_luhn_rules_compile(tmp_path):
        for length in (14, 15, 16, 19):
            rule_path = tmp_path / f"luhn{length}.yar"
            rule_path.write_text(
                generate_luhn_rule(length),
                encoding="utf-8",
            )
    
            result = subprocess.run(
                [YARA, str(rule_path), "/dev/null"],
                capture_output=True,
                text=True,
            )
    
>           assert result.returncode == 0, (
                f"Luhn {length} failed to compile:\n{result.stderr}"
            )
E           AssertionError: Luhn 14 failed to compile:
E             /tmp/pytest-of-root/pytest-0/test_generated_luhn_rules_comp0/luhn14.yar(5): warning: $compact is slowing down scanning (critical!)
E             /tmp/pytest-of-root/pytest-0/test_generated_luhn_rules_comp0/luhn14.yar(7): warning: $formatted is slowing down scanning (critical!)
E             /tmp/pytest-of-root/pytest-0/test_generated_luhn_rules_comp0/luhn14.yar(16): error: syntax error, unexpected $undefined
E             
E           assert 1 == 0
E            +  where 1 = CompletedProcess(args=['yara', '/tmp/pytest-of-root/pytest-0/test_generated_luhn_rules_comp0/luhn14.yar', '/dev/null'], returncode=1, stdout='', stderr='/tmp/pytest-of-root/pytest-0/test_generated_luhn_rules_comp0/luhn14.yar(5): warning: $compact is slowing down scanning (critical!)\n/tmp/pytest-of-root/pytest-0/test_generated_luhn_rules_comp0/luhn14.yar(7): warning: $formatted is slowing down scanning (critical!)\n/tmp/pytest-of-root/pytest-0/test_generated_luhn_rules_comp0/luhn14.yar(16): error: syntax error, unexpected $undefined\n').returncode

tests/test_luhn_yara.py:61: AssertionError
_______________ test_generated_luhn_rule_rejects_invalid_sample ________________

tmp_path = PosixPath('/tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_rejec0')

    def test_generated_luhn_rule_rejects_invalid_sample(tmp_path):
        result = run_generated_rule(tmp_path, SAMPLES / "invalid.txt")
    
>       assert result.returncode == 0, result.stderr
E       AssertionError: /tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_rejec0/luhn16.yar(5): warning: $compact is slowing down scanning (critical!)
E         /tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_rejec0/luhn16.yar(7): warning: $formatted is slowing down scanning (critical!)
E         /tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_rejec0/luhn16.yar(16): error: syntax error, unexpected $undefined
E         
E       assert 1 == 0
E        +  where 1 = CompletedProcess(args=['yara', '/tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_rejec0/luhn16.yar', '/work/tests/samples/luhn/invalid.txt'], returncode=1, stdout='', stderr='/tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_rejec0/luhn16.yar(5): warning: $compact is slowing down scanning (critical!)\n/tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_rejec0/luhn16.yar(7): warning: $formatted is slowing down scanning (critical!)\n/tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_rejec0/luhn16.yar(16): error: syntax error, unexpected $undefined\n').returncode

tests/test_luhn_yara.py:77: AssertionError
_________ test_generated_luhn_rule_matches_when_any_candidate_is_valid _________

tmp_path = PosixPath('/tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_match1')

    def test_generated_luhn_rule_matches_when_any_candidate_is_valid(tmp_path):
        result = run_generated_rule(tmp_path, SAMPLES / "mixed.txt")
    
>       assert result.returncode == 0, result.stderr
E       AssertionError: /tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_match1/luhn16.yar(5): warning: $compact is slowing down scanning (critical!)
E         /tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_match1/luhn16.yar(7): warning: $formatted is slowing down scanning (critical!)
E         /tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_match1/luhn16.yar(16): error: syntax error, unexpected $undefined
E         
E       assert 1 == 0
E        +  where 1 = CompletedProcess(args=['yara', '/tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_match1/luhn16.yar', '/work/tests/samples/luhn/mixed.txt'], returncode=1, stdout='', stderr='/tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_match1/luhn16.yar(5): warning: $compact is slowing down scanning (critical!)\n/tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_match1/luhn16.yar(7): warning: $formatted is slowing down scanning (critical!)\n/tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_match1/luhn16.yar(16): error: syntax error, unexpected $undefined\n').returncode

tests/test_luhn_yara.py:83: AssertionError
___________________ test_generated_luhn_rules_match_vectors ____________________

tmp_path = PosixPath('/tmp/pytest-of-root/pytest-0/test_generated_luhn_rules_matc0')
load_vectors = [{'value': '4111111111111111', 'valid': True, 'description': 'Common public Visa test number'}, {'value': '41111111121...sposition'}, {'value': '1234567890123456', 'valid': False, 'description': 'Correct shape, invalid Luhn checksum'}, ...]

    def test_generated_luhn_rules_match_vectors(tmp_path, load_vectors):
        for vector in load_vectors:
            value = vector["value"]
            length = len(value)
    
            rule_path = ROOT / "generated" / f"luhn{length}.yar"
            rule_name = f"Valid_Luhn_{length}"
    
            sample_path = tmp_path / "candidate.txt"
            sample_path.write_text(value, encoding="ascii")
    
            result = subprocess.run(
                [YARA, str(rule_path), str(sample_path)],
                capture_output=True,
                text=True,
            )
    
>           assert result.returncode == 0, result.stderr
E           AssertionError: /work/generated/luhn16.yar(5): warning: $compact is slowing down scanning (critical!)
E             /work/generated/luhn16.yar(7): warning: $formatted is slowing down scanning (critical!)
E             /work/generated/luhn16.yar(16): error: syntax error, unexpected $undefined
E             
E           assert 1 == 0
E            +  where 1 = CompletedProcess(args=['yara', '/work/generated/luhn16.yar', '/tmp/pytest-of-root/pytest-0/test_generated_luhn_rules_matc0/candidate.txt'], returncode=1, stdout='', stderr='/work/generated/luhn16.yar(5): warning: $compact is slowing down scanning (critical!)\n/work/generated/luhn16.yar(7): warning: $formatted is slowing down scanning (critical!)\n/work/generated/luhn16.yar(16): error: syntax error, unexpected $undefined\n').returncode

tests/test_luhn_yara.py:103: AssertionError
____ test_generated_luhn_rule_matches_formatted_sample[formatted-19.txt-19] ____

tmp_path = PosixPath('/tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_match2')
sample_name = 'formatted-19.txt', length = 19

    @pytest.mark.parametrize(
        ("sample_name", "length"),
        [
            ("formatted-19.txt", 19),
            ("formatted.txt", 16),
            ("formatted-hyphen.txt", 16),
            ("formatted-mixed.txt", 16),
            ("formatted-15.txt", 15),
            ("formatted-14.txt", 14),
        ],
    )
    def test_generated_luhn_rule_matches_formatted_sample(tmp_path, sample_name, length):
        result = run_generated_rule(
            tmp_path,
            SAMPLES / sample_name,
            length=length,
        )
    
>       assert result.returncode == 0, result.stderr
E       AssertionError: /tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_match2/luhn19.yar(5): warning: $compact is slowing down scanning (critical!)
E         /tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_match2/luhn19.yar(7): warning: $formatted is slowing down scanning (critical!)
E         /tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_match2/luhn19.yar(16): error: syntax error, unexpected $undefined
E         
E       assert 1 == 0
E        +  where 1 = CompletedProcess(args=['yara', '/tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_match2/luhn19.yar', '/work/tests/samples/luhn/formatted-19.txt'], returncode=1, stdout='', stderr='/tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_match2/luhn19.yar(5): warning: $compact is slowing down scanning (critical!)\n/tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_match2/luhn19.yar(7): warning: $formatted is slowing down scanning (critical!)\n/tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_match2/luhn19.yar(16): error: syntax error, unexpected $undefined\n').returncode

tests/test_luhn_yara.py:131: AssertionError
_____ test_generated_luhn_rule_matches_formatted_sample[formatted.txt-16] ______

tmp_path = PosixPath('/tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_match3')
sample_name = 'formatted.txt', length = 16

    @pytest.mark.parametrize(
        ("sample_name", "length"),
        [
            ("formatted-19.txt", 19),
            ("formatted.txt", 16),
            ("formatted-hyphen.txt", 16),
            ("formatted-mixed.txt", 16),
            ("formatted-15.txt", 15),
            ("formatted-14.txt", 14),
        ],
    )
    def test_generated_luhn_rule_matches_formatted_sample(tmp_path, sample_name, length):
        result = run_generated_rule(
            tmp_path,
            SAMPLES / sample_name,
            length=length,
        )
    
>       assert result.returncode == 0, result.stderr
E       AssertionError: /tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_match3/luhn16.yar(5): warning: $compact is slowing down scanning (critical!)
E         /tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_match3/luhn16.yar(7): warning: $formatted is slowing down scanning (critical!)
E         /tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_match3/luhn16.yar(16): error: syntax error, unexpected $undefined
E         
E       assert 1 == 0
E        +  where 1 = CompletedProcess(args=['yara', '/tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_match3/luhn16.yar', '/work/tests/samples/luhn/formatted.txt'], returncode=1, stdout='', stderr='/tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_match3/luhn16.yar(5): warning: $compact is slowing down scanning (critical!)\n/tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_match3/luhn16.yar(7): warning: $formatted is slowing down scanning (critical!)\n/tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_match3/luhn16.yar(16): error: syntax error, unexpected $undefined\n').returncode

tests/test_luhn_yara.py:131: AssertionError
__ test_generated_luhn_rule_matches_formatted_sample[formatted-hyphen.txt-16] __

tmp_path = PosixPath('/tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_match4')
sample_name = 'formatted-hyphen.txt', length = 16

    @pytest.mark.parametrize(
        ("sample_name", "length"),
        [
            ("formatted-19.txt", 19),
            ("formatted.txt", 16),
            ("formatted-hyphen.txt", 16),
            ("formatted-mixed.txt", 16),
            ("formatted-15.txt", 15),
            ("formatted-14.txt", 14),
        ],
    )
    def test_generated_luhn_rule_matches_formatted_sample(tmp_path, sample_name, length):
        result = run_generated_rule(
            tmp_path,
            SAMPLES / sample_name,
            length=length,
        )
    
>       assert result.returncode == 0, result.stderr
E       AssertionError: /tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_match4/luhn16.yar(5): warning: $compact is slowing down scanning (critical!)
E         /tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_match4/luhn16.yar(7): warning: $formatted is slowing down scanning (critical!)
E         /tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_match4/luhn16.yar(16): error: syntax error, unexpected $undefined
E         
E       assert 1 == 0
E        +  where 1 = CompletedProcess(args=['yara', '/tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_match4/luhn16.yar', '/work/tests/samples/luhn/formatted-hyphen.txt'], returncode=1, stdout='', stderr='/tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_match4/luhn16.yar(5): warning: $compact is slowing down scanning (critical!)\n/tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_match4/luhn16.yar(7): warning: $formatted is slowing down scanning (critical!)\n/tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_match4/luhn16.yar(16): error: syntax error, unexpected $undefined\n').returncode

tests/test_luhn_yara.py:131: AssertionError
__ test_generated_luhn_rule_matches_formatted_sample[formatted-mixed.txt-16] ___

tmp_path = PosixPath('/tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_match5')
sample_name = 'formatted-mixed.txt', length = 16

    @pytest.mark.parametrize(
        ("sample_name", "length"),
        [
            ("formatted-19.txt", 19),
            ("formatted.txt", 16),
            ("formatted-hyphen.txt", 16),
            ("formatted-mixed.txt", 16),
            ("formatted-15.txt", 15),
            ("formatted-14.txt", 14),
        ],
    )
    def test_generated_luhn_rule_matches_formatted_sample(tmp_path, sample_name, length):
        result = run_generated_rule(
            tmp_path,
            SAMPLES / sample_name,
            length=length,
        )
    
>       assert result.returncode == 0, result.stderr
E       AssertionError: /tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_match5/luhn16.yar(5): warning: $compact is slowing down scanning (critical!)
E         /tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_match5/luhn16.yar(7): warning: $formatted is slowing down scanning (critical!)
E         /tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_match5/luhn16.yar(16): error: syntax error, unexpected $undefined
E         
E       assert 1 == 0
E        +  where 1 = CompletedProcess(args=['yara', '/tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_match5/luhn16.yar', '/work/tests/samples/luhn/formatted-mixed.txt'], returncode=1, stdout='', stderr='/tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_match5/luhn16.yar(5): warning: $compact is slowing down scanning (critical!)\n/tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_match5/luhn16.yar(7): warning: $formatted is slowing down scanning (critical!)\n/tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_match5/luhn16.yar(16): error: syntax error, unexpected $undefined\n').returncode

tests/test_luhn_yara.py:131: AssertionError
____ test_generated_luhn_rule_matches_formatted_sample[formatted-15.txt-15] ____

tmp_path = PosixPath('/tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_match6')
sample_name = 'formatted-15.txt', length = 15

    @pytest.mark.parametrize(
        ("sample_name", "length"),
        [
            ("formatted-19.txt", 19),
            ("formatted.txt", 16),
            ("formatted-hyphen.txt", 16),
            ("formatted-mixed.txt", 16),
            ("formatted-15.txt", 15),
            ("formatted-14.txt", 14),
        ],
    )
    def test_generated_luhn_rule_matches_formatted_sample(tmp_path, sample_name, length):
        result = run_generated_rule(
            tmp_path,
            SAMPLES / sample_name,
            length=length,
        )
    
>       assert result.returncode == 0, result.stderr
E       AssertionError: /tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_match6/luhn15.yar(5): warning: $compact is slowing down scanning (critical!)
E         /tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_match6/luhn15.yar(7): warning: $formatted is slowing down scanning (critical!)
E         /tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_match6/luhn15.yar(16): error: syntax error, unexpected $undefined
E         
E       assert 1 == 0
E        +  where 1 = CompletedProcess(args=['yara', '/tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_match6/luhn15.yar', '/work/tests/samples/luhn/formatted-15.txt'], returncode=1, stdout='', stderr='/tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_match6/luhn15.yar(5): warning: $compact is slowing down scanning (critical!)\n/tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_match6/luhn15.yar(7): warning: $formatted is slowing down scanning (critical!)\n/tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_match6/luhn15.yar(16): error: syntax error, unexpected $undefined\n').returncode

tests/test_luhn_yara.py:131: AssertionError
____ test_generated_luhn_rule_matches_formatted_sample[formatted-14.txt-14] ____

tmp_path = PosixPath('/tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_match7')
sample_name = 'formatted-14.txt', length = 14

    @pytest.mark.parametrize(
        ("sample_name", "length"),
        [
            ("formatted-19.txt", 19),
            ("formatted.txt", 16),
            ("formatted-hyphen.txt", 16),
            ("formatted-mixed.txt", 16),
            ("formatted-15.txt", 15),
            ("formatted-14.txt", 14),
        ],
    )
    def test_generated_luhn_rule_matches_formatted_sample(tmp_path, sample_name, length):
        result = run_generated_rule(
            tmp_path,
            SAMPLES / sample_name,
            length=length,
        )
    
>       assert result.returncode == 0, result.stderr
E       AssertionError: /tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_match7/luhn14.yar(5): warning: $compact is slowing down scanning (critical!)
E         /tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_match7/luhn14.yar(7): warning: $formatted is slowing down scanning (critical!)
E         /tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_match7/luhn14.yar(16): error: syntax error, unexpected $undefined
E         
E       assert 1 == 0
E        +  where 1 = CompletedProcess(args=['yara', '/tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_match7/luhn14.yar', '/work/tests/samples/luhn/formatted-14.txt'], returncode=1, stdout='', stderr='/tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_match7/luhn14.yar(5): warning: $compact is slowing down scanning (critical!)\n/tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_match7/luhn14.yar(7): warning: $formatted is slowing down scanning (critical!)\n/tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_match7/luhn14.yar(16): error: syntax error, unexpected $undefined\n').returncode

tests/test_luhn_yara.py:131: AssertionError
_____________ test_generated_luhn_rule_rejects_embedded_candidate ______________

tmp_path = PosixPath('/tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_rejec1')

    def test_generated_luhn_rule_rejects_embedded_candidate(tmp_path):
        result = run_generated_rule(
            tmp_path,
            SAMPLES / "embedded.txt",
            length=16,
        )
    
>       assert result.returncode == 0, result.stderr
E       AssertionError: /tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_rejec1/luhn16.yar(5): warning: $compact is slowing down scanning (critical!)
E         /tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_rejec1/luhn16.yar(7): warning: $formatted is slowing down scanning (critical!)
E         /tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_rejec1/luhn16.yar(16): error: syntax error, unexpected $undefined
E         
E       assert 1 == 0
E        +  where 1 = CompletedProcess(args=['yara', '/tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_rejec1/luhn16.yar', '/work/tests/samples/luhn/embedded.txt'], returncode=1, stdout='', stderr='/tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_rejec1/luhn16.yar(5): warning: $compact is slowing down scanning (critical!)\n/tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_rejec1/luhn16.yar(7): warning: $formatted is slowing down scanning (critical!)\n/tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_rejec1/luhn16.yar(16): error: syntax error, unexpected $undefined\n').returncode

tests/test_luhn_yara.py:141: AssertionError
_ test_generated_luhn_rule_rejects_digit_embedded_candidate[94111111111111111] _

tmp_path = PosixPath('/tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_rejec2')
value = '94111111111111111'

    @pytest.mark.parametrize(
        "value",
        [
            "94111111111111111",  # digit immediately before
            "41111111111111119",  # digit immediately after
            "941111111111111119", # digits on both sides
        ],
    )
    def test_generated_luhn_rule_rejects_digit_embedded_candidate(
        tmp_path,
        value,
    ):
        sample_path = tmp_path / "embedded.txt"
        sample_path.write_text(value, encoding="ascii")
    
        result = run_generated_rule(
            tmp_path,
            sample_path,
            length=16,
        )
    
>       assert result.returncode == 0, result.stderr
E       AssertionError: /tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_rejec2/luhn16.yar(5): warning: $compact is slowing down scanning (critical!)
E         /tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_rejec2/luhn16.yar(7): warning: $formatted is slowing down scanning (critical!)
E         /tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_rejec2/luhn16.yar(16): error: syntax error, unexpected $undefined
E         
E       assert 1 == 0
E        +  where 1 = CompletedProcess(args=['yara', '/tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_rejec2/luhn16.yar', '/tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_rejec2/embedded.txt'], returncode=1, stdout='', stderr='/tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_rejec2/luhn16.yar(5): warning: $compact is slowing down scanning (critical!)\n/tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_rejec2/luhn16.yar(7): warning: $formatted is slowing down scanning (critical!)\n/tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_rejec2/luhn16.yar(16): error: syntax error, unexpected $undefined\n').returncode

tests/test_luhn_yara.py:165: AssertionError
_ test_generated_luhn_rule_rejects_digit_embedded_candidate[41111111111111119] _

tmp_path = PosixPath('/tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_rejec3')
value = '41111111111111119'

    @pytest.mark.parametrize(
        "value",
        [
            "94111111111111111",  # digit immediately before
            "41111111111111119",  # digit immediately after
            "941111111111111119", # digits on both sides
        ],
    )
    def test_generated_luhn_rule_rejects_digit_embedded_candidate(
        tmp_path,
        value,
    ):
        sample_path = tmp_path / "embedded.txt"
        sample_path.write_text(value, encoding="ascii")
    
        result = run_generated_rule(
            tmp_path,
            sample_path,
            length=16,
        )
    
>       assert result.returncode == 0, result.stderr
E       AssertionError: /tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_rejec3/luhn16.yar(5): warning: $compact is slowing down scanning (critical!)
E         /tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_rejec3/luhn16.yar(7): warning: $formatted is slowing down scanning (critical!)
E         /tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_rejec3/luhn16.yar(16): error: syntax error, unexpected $undefined
E         
E       assert 1 == 0
E        +  where 1 = CompletedProcess(args=['yara', '/tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_rejec3/luhn16.yar', '/tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_rejec3/embedded.txt'], returncode=1, stdout='', stderr='/tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_rejec3/luhn16.yar(5): warning: $compact is slowing down scanning (critical!)\n/tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_rejec3/luhn16.yar(7): warning: $formatted is slowing down scanning (critical!)\n/tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_rejec3/luhn16.yar(16): error: syntax error, unexpected $undefined\n').returncode

tests/test_luhn_yara.py:165: AssertionError
_ test_generated_luhn_rule_rejects_digit_embedded_candidate[941111111111111119] _

tmp_path = PosixPath('/tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_rejec4')
value = '941111111111111119'

    @pytest.mark.parametrize(
        "value",
        [
            "94111111111111111",  # digit immediately before
            "41111111111111119",  # digit immediately after
            "941111111111111119", # digits on both sides
        ],
    )
    def test_generated_luhn_rule_rejects_digit_embedded_candidate(
        tmp_path,
        value,
    ):
        sample_path = tmp_path / "embedded.txt"
        sample_path.write_text(value, encoding="ascii")
    
        result = run_generated_rule(
            tmp_path,
            sample_path,
            length=16,
        )
    
>       assert result.returncode == 0, result.stderr
E       AssertionError: /tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_rejec4/luhn16.yar(5): warning: $compact is slowing down scanning (critical!)
E         /tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_rejec4/luhn16.yar(7): warning: $formatted is slowing down scanning (critical!)
E         /tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_rejec4/luhn16.yar(16): error: syntax error, unexpected $undefined
E         
E       assert 1 == 0
E        +  where 1 = CompletedProcess(args=['yara', '/tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_rejec4/luhn16.yar', '/tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_rejec4/embedded.txt'], returncode=1, stdout='', stderr='/tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_rejec4/luhn16.yar(5): warning: $compact is slowing down scanning (critical!)\n/tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_rejec4/luhn16.yar(7): warning: $formatted is slowing down scanning (critical!)\n/tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_rejec4/luhn16.yar(16): error: syntax error, unexpected $undefined\n').returncode

tests/test_luhn_yara.py:165: AssertionError
____ test_generated_luhn_rule_allows_nondigit_boundaries[x4111111111111111] ____

tmp_path = PosixPath('/tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_allow0')
value = 'x4111111111111111'

    @pytest.mark.parametrize(
        "value",
        [
            "x4111111111111111",
            "4111111111111111y",
            "x4111111111111111y",
        ],
    )
    def test_generated_luhn_rule_allows_nondigit_boundaries(
        tmp_path,
        value,
    ):
        sample_path = tmp_path / "bounded.txt"
        sample_path.write_text(value, encoding="ascii")
    
        result = run_generated_rule(
            tmp_path,
            sample_path,
            length=16,
        )
    
>       assert result.returncode == 0, result.stderr
E       AssertionError: /tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_allow0/luhn16.yar(5): warning: $compact is slowing down scanning (critical!)
E         /tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_allow0/luhn16.yar(7): warning: $formatted is slowing down scanning (critical!)
E         /tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_allow0/luhn16.yar(16): error: syntax error, unexpected $undefined
E         
E       assert 1 == 0
E        +  where 1 = CompletedProcess(args=['yara', '/tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_allow0/luhn16.yar', '/tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_allow0/bounded.txt'], returncode=1, stdout='', stderr='/tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_allow0/luhn16.yar(5): warning: $compact is slowing down scanning (critical!)\n/tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_allow0/luhn16.yar(7): warning: $formatted is slowing down scanning (critical!)\n/tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_allow0/luhn16.yar(16): error: syntax error, unexpected $undefined\n').returncode

tests/test_luhn_yara.py:189: AssertionError
____ test_generated_luhn_rule_allows_nondigit_boundaries[4111111111111111y] ____

tmp_path = PosixPath('/tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_allow1')
value = '4111111111111111y'

    @pytest.mark.parametrize(
        "value",
        [
            "x4111111111111111",
            "4111111111111111y",
            "x4111111111111111y",
        ],
    )
    def test_generated_luhn_rule_allows_nondigit_boundaries(
        tmp_path,
        value,
    ):
        sample_path = tmp_path / "bounded.txt"
        sample_path.write_text(value, encoding="ascii")
    
        result = run_generated_rule(
            tmp_path,
            sample_path,
            length=16,
        )
    
>       assert result.returncode == 0, result.stderr
E       AssertionError: /tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_allow1/luhn16.yar(5): warning: $compact is slowing down scanning (critical!)
E         /tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_allow1/luhn16.yar(7): warning: $formatted is slowing down scanning (critical!)
E         /tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_allow1/luhn16.yar(16): error: syntax error, unexpected $undefined
E         
E       assert 1 == 0
E        +  where 1 = CompletedProcess(args=['yara', '/tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_allow1/luhn16.yar', '/tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_allow1/bounded.txt'], returncode=1, stdout='', stderr='/tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_allow1/luhn16.yar(5): warning: $compact is slowing down scanning (critical!)\n/tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_allow1/luhn16.yar(7): warning: $formatted is slowing down scanning (critical!)\n/tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_allow1/luhn16.yar(16): error: syntax error, unexpected $undefined\n').returncode

tests/test_luhn_yara.py:189: AssertionError
___ test_generated_luhn_rule_allows_nondigit_boundaries[x4111111111111111y] ____

tmp_path = PosixPath('/tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_allow2')
value = 'x4111111111111111y'

    @pytest.mark.parametrize(
        "value",
        [
            "x4111111111111111",
            "4111111111111111y",
            "x4111111111111111y",
        ],
    )
    def test_generated_luhn_rule_allows_nondigit_boundaries(
        tmp_path,
        value,
    ):
        sample_path = tmp_path / "bounded.txt"
        sample_path.write_text(value, encoding="ascii")
    
        result = run_generated_rule(
            tmp_path,
            sample_path,
            length=16,
        )
    
>       assert result.returncode == 0, result.stderr
E       AssertionError: /tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_allow2/luhn16.yar(5): warning: $compact is slowing down scanning (critical!)
E         /tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_allow2/luhn16.yar(7): warning: $formatted is slowing down scanning (critical!)
E         /tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_allow2/luhn16.yar(16): error: syntax error, unexpected $undefined
E         
E       assert 1 == 0
E        +  where 1 = CompletedProcess(args=['yara', '/tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_allow2/luhn16.yar', '/tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_allow2/bounded.txt'], returncode=1, stdout='', stderr='/tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_allow2/luhn16.yar(5): warning: $compact is slowing down scanning (critical!)\n/tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_allow2/luhn16.yar(7): warning: $formatted is slowing down scanning (critical!)\n/tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_allow2/luhn16.yar(16): error: syntax error, unexpected $undefined\n').returncode

tests/test_luhn_yara.py:189: AssertionError
=========================== short test summary info ============================
FAILED tests/test_luhn_yara.py::test_generated_luhn_rule_matches_valid_sample
FAILED tests/test_luhn_yara.py::test_generated_luhn_rules_compile - Assertion...
FAILED tests/test_luhn_yara.py::test_generated_luhn_rule_rejects_invalid_sample
FAILED tests/test_luhn_yara.py::test_generated_luhn_rule_matches_when_any_candidate_is_valid
FAILED tests/test_luhn_yara.py::test_generated_luhn_rules_match_vectors - Ass...
FAILED tests/test_luhn_yara.py::test_generated_luhn_rule_matches_formatted_sample[formatted-19.txt-19]
FAILED tests/test_luhn_yara.py::test_generated_luhn_rule_matches_formatted_sample[formatted.txt-16]
FAILED tests/test_luhn_yara.py::test_generated_luhn_rule_matches_formatted_sample[formatted-hyphen.txt-16]
FAILED tests/test_luhn_yara.py::test_generated_luhn_rule_matches_formatted_sample[formatted-mixed.txt-16]
FAILED tests/test_luhn_yara.py::test_generated_luhn_rule_matches_formatted_sample[formatted-15.txt-15]
FAILED tests/test_luhn_yara.py::test_generated_luhn_rule_matches_formatted_sample[formatted-14.txt-14]
FAILED tests/test_luhn_yara.py::test_generated_luhn_rule_rejects_embedded_candidate
FAILED tests/test_luhn_yara.py::test_generated_luhn_rule_rejects_digit_embedded_candidate[94111111111111111]
FAILED tests/test_luhn_yara.py::test_generated_luhn_rule_rejects_digit_embedded_candidate[41111111111111119]
FAILED tests/test_luhn_yara.py::test_generated_luhn_rule_rejects_digit_embedded_candidate[941111111111111119]
FAILED tests/test_luhn_yara.py::test_generated_luhn_rule_allows_nondigit_boundaries[x4111111111111111]
FAILED tests/test_luhn_yara.py::test_generated_luhn_rule_allows_nondigit_boundaries[4111111111111111y]
FAILED tests/test_luhn_yara.py::test_generated_luhn_rule_allows_nondigit_boundaries[x4111111111111111y]
========================= 18 failed, 7 passed in 0.14s =========================

============================================================
 Testing YARA 3.5.0
============================================================


=== Testing YARA 3.5.0 ===

============================= test session starts ==============================
platform linux -- Python 3.11.2, pytest-9.1.1, pluggy-1.6.0 -- /venv/bin/python
rootdir: /work
configfile: pyproject.toml
collecting ... collected 25 items

tests/test_luhn.py::test_reference_luhn_rejects_malformed_input[] PASSED [  4%]
tests/test_luhn.py::test_reference_luhn_rejects_malformed_input[411111111111111x] PASSED [  8%]
tests/test_luhn.py::test_reference_luhn_rejects_malformed_input[\uff14\uff11\uff11\uff11\uff11\uff11\uff11\uff11\uff11\uff11\uff11\uff11\uff11\uff11\uff11\uff11] PASSED [ 12%]
tests/test_luhn.py::test_luhn_vectors_exist PASSED                       [ 16%]
tests/test_luhn.py::test_luhn_vectors_are_ascii_digits PASSED            [ 20%]
tests/test_luhn.py::test_reference_luhn_vectors PASSED                   [ 24%]
tests/test_luhn_yara.py::test_generated_luhn_rule_matches_valid_sample PASSED [ 28%]
tests/test_luhn_yara.py::test_generated_luhn_rules_compile PASSED        [ 32%]
tests/test_luhn_yara.py::test_committed_luhn_rules_are_current PASSED    [ 36%]
tests/test_luhn_yara.py::test_generated_luhn_rule_rejects_invalid_sample PASSED [ 40%]
tests/test_luhn_yara.py::test_generated_luhn_rule_matches_when_any_candidate_is_valid PASSED [ 44%]
tests/test_luhn_yara.py::test_generated_luhn_rules_match_vectors PASSED  [ 48%]
tests/test_luhn_yara.py::test_generated_luhn_rule_matches_formatted_sample[formatted-19.txt-19] PASSED [ 52%]
tests/test_luhn_yara.py::test_generated_luhn_rule_matches_formatted_sample[formatted.txt-16] PASSED [ 56%]
tests/test_luhn_yara.py::test_generated_luhn_rule_matches_formatted_sample[formatted-hyphen.txt-16] PASSED [ 60%]
tests/test_luhn_yara.py::test_generated_luhn_rule_matches_formatted_sample[formatted-mixed.txt-16] PASSED [ 64%]
tests/test_luhn_yara.py::test_generated_luhn_rule_matches_formatted_sample[formatted-15.txt-15] PASSED [ 68%]
tests/test_luhn_yara.py::test_generated_luhn_rule_matches_formatted_sample[formatted-14.txt-14] PASSED [ 72%]
tests/test_luhn_yara.py::test_generated_luhn_rule_rejects_embedded_candidate PASSED [ 76%]
tests/test_luhn_yara.py::test_generated_luhn_rule_rejects_digit_embedded_candidate[94111111111111111] PASSED [ 80%]
tests/test_luhn_yara.py::test_generated_luhn_rule_rejects_digit_embedded_candidate[41111111111111119] PASSED [ 84%]
tests/test_luhn_yara.py::test_generated_luhn_rule_rejects_digit_embedded_candidate[941111111111111119] PASSED [ 88%]
tests/test_luhn_yara.py::test_generated_luhn_rule_allows_nondigit_boundaries[x4111111111111111] PASSED [ 92%]
tests/test_luhn_yara.py::test_generated_luhn_rule_allows_nondigit_boundaries[4111111111111111y] PASSED [ 96%]
tests/test_luhn_yara.py::test_generated_luhn_rule_allows_nondigit_boundaries[x4111111111111111y] PASSED [100%]

============================== 25 passed in 0.14s ==============================

============================================================
 Testing YARA 3.6.3
============================================================


=== Testing YARA 3.6.3 ===

============================= test session starts ==============================
platform linux -- Python 3.11.2, pytest-9.1.1, pluggy-1.6.0 -- /venv/bin/python
rootdir: /work
configfile: pyproject.toml
collecting ... collected 25 items

tests/test_luhn.py::test_reference_luhn_rejects_malformed_input[] PASSED [  4%]
tests/test_luhn.py::test_reference_luhn_rejects_malformed_input[411111111111111x] PASSED [  8%]
tests/test_luhn.py::test_reference_luhn_rejects_malformed_input[\uff14\uff11\uff11\uff11\uff11\uff11\uff11\uff11\uff11\uff11\uff11\uff11\uff11\uff11\uff11\uff11] PASSED [ 12%]
tests/test_luhn.py::test_luhn_vectors_exist PASSED                       [ 16%]
tests/test_luhn.py::test_luhn_vectors_are_ascii_digits PASSED            [ 20%]
tests/test_luhn.py::test_reference_luhn_vectors PASSED                   [ 24%]
tests/test_luhn_yara.py::test_generated_luhn_rule_matches_valid_sample PASSED [ 28%]
tests/test_luhn_yara.py::test_generated_luhn_rules_compile PASSED        [ 32%]
tests/test_luhn_yara.py::test_committed_luhn_rules_are_current PASSED    [ 36%]
tests/test_luhn_yara.py::test_generated_luhn_rule_rejects_invalid_sample PASSED [ 40%]
tests/test_luhn_yara.py::test_generated_luhn_rule_matches_when_any_candidate_is_valid PASSED [ 44%]
tests/test_luhn_yara.py::test_generated_luhn_rules_match_vectors PASSED  [ 48%]
tests/test_luhn_yara.py::test_generated_luhn_rule_matches_formatted_sample[formatted-19.txt-19] PASSED [ 52%]
tests/test_luhn_yara.py::test_generated_luhn_rule_matches_formatted_sample[formatted.txt-16] PASSED [ 56%]
tests/test_luhn_yara.py::test_generated_luhn_rule_matches_formatted_sample[formatted-hyphen.txt-16] PASSED [ 60%]
tests/test_luhn_yara.py::test_generated_luhn_rule_matches_formatted_sample[formatted-mixed.txt-16] PASSED [ 64%]
tests/test_luhn_yara.py::test_generated_luhn_rule_matches_formatted_sample[formatted-15.txt-15] PASSED [ 68%]
tests/test_luhn_yara.py::test_generated_luhn_rule_matches_formatted_sample[formatted-14.txt-14] PASSED [ 72%]
tests/test_luhn_yara.py::test_generated_luhn_rule_rejects_embedded_candidate PASSED [ 76%]
tests/test_luhn_yara.py::test_generated_luhn_rule_rejects_digit_embedded_candidate[94111111111111111] PASSED [ 80%]
tests/test_luhn_yara.py::test_generated_luhn_rule_rejects_digit_embedded_candidate[41111111111111119] FAILED [ 84%]
tests/test_luhn_yara.py::test_generated_luhn_rule_rejects_digit_embedded_candidate[941111111111111119] PASSED [ 88%]
tests/test_luhn_yara.py::test_generated_luhn_rule_allows_nondigit_boundaries[x4111111111111111] PASSED [ 92%]
tests/test_luhn_yara.py::test_generated_luhn_rule_allows_nondigit_boundaries[4111111111111111y] PASSED [ 96%]
tests/test_luhn_yara.py::test_generated_luhn_rule_allows_nondigit_boundaries[x4111111111111111y] PASSED [100%]

=================================== FAILURES ===================================
_ test_generated_luhn_rule_rejects_digit_embedded_candidate[41111111111111119] _

tmp_path = PosixPath('/tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_rejec3')
value = '41111111111111119'

    @pytest.mark.parametrize(
        "value",
        [
            "94111111111111111",  # digit immediately before
            "41111111111111119",  # digit immediately after
            "941111111111111119", # digits on both sides
        ],
    )
    def test_generated_luhn_rule_rejects_digit_embedded_candidate(
        tmp_path,
        value,
    ):
        sample_path = tmp_path / "embedded.txt"
        sample_path.write_text(value, encoding="ascii")
    
        result = run_generated_rule(
            tmp_path,
            sample_path,
            length=16,
        )
    
        assert result.returncode == 0, result.stderr
>       assert result.stdout == ""
E       AssertionError: assert 'Valid_Luhn_1...mbedded.txt\n' == ''
E         
E         + Valid_Luhn_16 /tmp/pytest-of-root/pytest-0/test_generated_luhn_rule_rejec3/embedded.txt

tests/test_luhn_yara.py:166: AssertionError
=========================== short test summary info ============================
FAILED tests/test_luhn_yara.py::test_generated_luhn_rule_rejects_digit_embedded_candidate[41111111111111119]
========================= 1 failed, 24 passed in 0.15s =========================

============================================================
 Testing YARA 3.8.1
============================================================


=== Testing YARA 3.8.1 ===

============================= test session starts ==============================
platform linux -- Python 3.11.2, pytest-9.1.1, pluggy-1.6.0 -- /venv/bin/python
rootdir: /work
configfile: pyproject.toml
collecting ... collected 25 items

tests/test_luhn.py::test_reference_luhn_rejects_malformed_input[] PASSED [  4%]
tests/test_luhn.py::test_reference_luhn_rejects_malformed_input[411111111111111x] PASSED [  8%]
tests/test_luhn.py::test_reference_luhn_rejects_malformed_input[\uff14\uff11\uff11\uff11\uff11\uff11\uff11\uff11\uff11\uff11\uff11\uff11\uff11\uff11\uff11\uff11] PASSED [ 12%]
tests/test_luhn.py::test_luhn_vectors_exist PASSED                       [ 16%]
tests/test_luhn.py::test_luhn_vectors_are_ascii_digits PASSED            [ 20%]
tests/test_luhn.py::test_reference_luhn_vectors PASSED                   [ 24%]
tests/test_luhn_yara.py::test_generated_luhn_rule_matches_valid_sample PASSED [ 28%]
tests/test_luhn_yara.py::test_generated_luhn_rules_compile PASSED        [ 32%]
tests/test_luhn_yara.py::test_committed_luhn_rules_are_current PASSED    [ 36%]
tests/test_luhn_yara.py::test_generated_luhn_rule_rejects_invalid_sample PASSED [ 40%]
tests/test_luhn_yara.py::test_generated_luhn_rule_matches_when_any_candidate_is_valid PASSED [ 44%]
tests/test_luhn_yara.py::test_generated_luhn_rules_match_vectors PASSED  [ 48%]
tests/test_luhn_yara.py::test_generated_luhn_rule_matches_formatted_sample[formatted-19.txt-19] PASSED [ 52%]
tests/test_luhn_yara.py::test_generated_luhn_rule_matches_formatted_sample[formatted.txt-16] PASSED [ 56%]
tests/test_luhn_yara.py::test_generated_luhn_rule_matches_formatted_sample[formatted-hyphen.txt-16] PASSED [ 60%]
tests/test_luhn_yara.py::test_generated_luhn_rule_matches_formatted_sample[formatted-mixed.txt-16] PASSED [ 64%]
tests/test_luhn_yara.py::test_generated_luhn_rule_matches_formatted_sample[formatted-15.txt-15] PASSED [ 68%]
tests/test_luhn_yara.py::test_generated_luhn_rule_matches_formatted_sample[formatted-14.txt-14] PASSED [ 72%]
tests/test_luhn_yara.py::test_generated_luhn_rule_rejects_embedded_candidate PASSED [ 76%]
tests/test_luhn_yara.py::test_generated_luhn_rule_rejects_digit_embedded_candidate[94111111111111111] PASSED [ 80%]
tests/test_luhn_yara.py::test_generated_luhn_rule_rejects_digit_embedded_candidate[41111111111111119] PASSED [ 84%]
tests/test_luhn_yara.py::test_generated_luhn_rule_rejects_digit_embedded_candidate[941111111111111119] PASSED [ 88%]
tests/test_luhn_yara.py::test_generated_luhn_rule_allows_nondigit_boundaries[x4111111111111111] PASSED [ 92%]
tests/test_luhn_yara.py::test_generated_luhn_rule_allows_nondigit_boundaries[4111111111111111y] PASSED [ 96%]
tests/test_luhn_yara.py::test_generated_luhn_rule_allows_nondigit_boundaries[x4111111111111111y] PASSED [100%]

============================== 25 passed in 0.14s ==============================

============================================================
 Testing YARA 3.11.0
============================================================


=== Testing YARA 3.11.0 ===

============================= test session starts ==============================
platform linux -- Python 3.11.2, pytest-9.1.1, pluggy-1.6.0 -- /venv/bin/python
rootdir: /work
configfile: pyproject.toml
collecting ... collected 25 items

tests/test_luhn.py::test_reference_luhn_rejects_malformed_input[] PASSED [  4%]
tests/test_luhn.py::test_reference_luhn_rejects_malformed_input[411111111111111x] PASSED [  8%]
tests/test_luhn.py::test_reference_luhn_rejects_malformed_input[\uff14\uff11\uff11\uff11\uff11\uff11\uff11\uff11\uff11\uff11\uff11\uff11\uff11\uff11\uff11\uff11] PASSED [ 12%]
tests/test_luhn.py::test_luhn_vectors_exist PASSED                       [ 16%]
tests/test_luhn.py::test_luhn_vectors_are_ascii_digits PASSED            [ 20%]
tests/test_luhn.py::test_reference_luhn_vectors PASSED                   [ 24%]
tests/test_luhn_yara.py::test_generated_luhn_rule_matches_valid_sample PASSED [ 28%]
tests/test_luhn_yara.py::test_generated_luhn_rules_compile PASSED        [ 32%]
tests/test_luhn_yara.py::test_committed_luhn_rules_are_current PASSED    [ 36%]
tests/test_luhn_yara.py::test_generated_luhn_rule_rejects_invalid_sample PASSED [ 40%]
tests/test_luhn_yara.py::test_generated_luhn_rule_matches_when_any_candidate_is_valid PASSED [ 44%]
tests/test_luhn_yara.py::test_generated_luhn_rules_match_vectors PASSED  [ 48%]
tests/test_luhn_yara.py::test_generated_luhn_rule_matches_formatted_sample[formatted-19.txt-19] PASSED [ 52%]
tests/test_luhn_yara.py::test_generated_luhn_rule_matches_formatted_sample[formatted.txt-16] PASSED [ 56%]
tests/test_luhn_yara.py::test_generated_luhn_rule_matches_formatted_sample[formatted-hyphen.txt-16] PASSED [ 60%]
tests/test_luhn_yara.py::test_generated_luhn_rule_matches_formatted_sample[formatted-mixed.txt-16] PASSED [ 64%]
tests/test_luhn_yara.py::test_generated_luhn_rule_matches_formatted_sample[formatted-15.txt-15] PASSED [ 68%]
tests/test_luhn_yara.py::test_generated_luhn_rule_matches_formatted_sample[formatted-14.txt-14] PASSED [ 72%]
tests/test_luhn_yara.py::test_generated_luhn_rule_rejects_embedded_candidate PASSED [ 76%]
tests/test_luhn_yara.py::test_generated_luhn_rule_rejects_digit_embedded_candidate[94111111111111111] PASSED [ 80%]
tests/test_luhn_yara.py::test_generated_luhn_rule_rejects_digit_embedded_candidate[41111111111111119] PASSED [ 84%]
tests/test_luhn_yara.py::test_generated_luhn_rule_rejects_digit_embedded_candidate[941111111111111119] PASSED [ 88%]
tests/test_luhn_yara.py::test_generated_luhn_rule_allows_nondigit_boundaries[x4111111111111111] PASSED [ 92%]
tests/test_luhn_yara.py::test_generated_luhn_rule_allows_nondigit_boundaries[4111111111111111y] PASSED [ 96%]
tests/test_luhn_yara.py::test_generated_luhn_rule_allows_nondigit_boundaries[x4111111111111111y] PASSED [100%]

============================== 25 passed in 0.14s ==============================

============================================================
 Testing YARA 4.0.5
============================================================


=== Testing YARA 4.0.5 ===

============================= test session starts ==============================
platform linux -- Python 3.11.2, pytest-9.1.1, pluggy-1.6.0 -- /venv/bin/python
rootdir: /work
configfile: pyproject.toml
collecting ... collected 25 items

tests/test_luhn.py::test_reference_luhn_rejects_malformed_input[] PASSED [  4%]
tests/test_luhn.py::test_reference_luhn_rejects_malformed_input[411111111111111x] PASSED [  8%]
tests/test_luhn.py::test_reference_luhn_rejects_malformed_input[\uff14\uff11\uff11\uff11\uff11\uff11\uff11\uff11\uff11\uff11\uff11\uff11\uff11\uff11\uff11\uff11] PASSED [ 12%]
tests/test_luhn.py::test_luhn_vectors_exist PASSED                       [ 16%]
tests/test_luhn.py::test_luhn_vectors_are_ascii_digits PASSED            [ 20%]
tests/test_luhn.py::test_reference_luhn_vectors PASSED                   [ 24%]
tests/test_luhn_yara.py::test_generated_luhn_rule_matches_valid_sample PASSED [ 28%]
tests/test_luhn_yara.py::test_generated_luhn_rules_compile PASSED        [ 32%]
tests/test_luhn_yara.py::test_committed_luhn_rules_are_current PASSED    [ 36%]
tests/test_luhn_yara.py::test_generated_luhn_rule_rejects_invalid_sample PASSED [ 40%]
tests/test_luhn_yara.py::test_generated_luhn_rule_matches_when_any_candidate_is_valid PASSED [ 44%]
tests/test_luhn_yara.py::test_generated_luhn_rules_match_vectors PASSED  [ 48%]
tests/test_luhn_yara.py::test_generated_luhn_rule_matches_formatted_sample[formatted-19.txt-19] PASSED [ 52%]
tests/test_luhn_yara.py::test_generated_luhn_rule_matches_formatted_sample[formatted.txt-16] PASSED [ 56%]
tests/test_luhn_yara.py::test_generated_luhn_rule_matches_formatted_sample[formatted-hyphen.txt-16] PASSED [ 60%]
tests/test_luhn_yara.py::test_generated_luhn_rule_matches_formatted_sample[formatted-mixed.txt-16] PASSED [ 64%]
tests/test_luhn_yara.py::test_generated_luhn_rule_matches_formatted_sample[formatted-15.txt-15] PASSED [ 68%]
tests/test_luhn_yara.py::test_generated_luhn_rule_matches_formatted_sample[formatted-14.txt-14] PASSED [ 72%]
tests/test_luhn_yara.py::test_generated_luhn_rule_rejects_embedded_candidate PASSED [ 76%]
tests/test_luhn_yara.py::test_generated_luhn_rule_rejects_digit_embedded_candidate[94111111111111111] PASSED [ 80%]
tests/test_luhn_yara.py::test_generated_luhn_rule_rejects_digit_embedded_candidate[41111111111111119] PASSED [ 84%]
tests/test_luhn_yara.py::test_generated_luhn_rule_rejects_digit_embedded_candidate[941111111111111119] PASSED [ 88%]
tests/test_luhn_yara.py::test_generated_luhn_rule_allows_nondigit_boundaries[x4111111111111111] PASSED [ 92%]
tests/test_luhn_yara.py::test_generated_luhn_rule_allows_nondigit_boundaries[4111111111111111y] PASSED [ 96%]
tests/test_luhn_yara.py::test_generated_luhn_rule_allows_nondigit_boundaries[x4111111111111111y] PASSED [100%]

============================== 25 passed in 0.33s ==============================

============================================================
 Testing YARA 4.1.3
============================================================


=== Testing YARA 4.1.3 ===

============================= test session starts ==============================
platform linux -- Python 3.11.2, pytest-9.1.1, pluggy-1.6.0 -- /venv/bin/python
rootdir: /work
configfile: pyproject.toml
collecting ... collected 25 items

tests/test_luhn.py::test_reference_luhn_rejects_malformed_input[] PASSED [  4%]
tests/test_luhn.py::test_reference_luhn_rejects_malformed_input[411111111111111x] PASSED [  8%]
tests/test_luhn.py::test_reference_luhn_rejects_malformed_input[\uff14\uff11\uff11\uff11\uff11\uff11\uff11\uff11\uff11\uff11\uff11\uff11\uff11\uff11\uff11\uff11] PASSED [ 12%]
tests/test_luhn.py::test_luhn_vectors_exist PASSED                       [ 16%]
tests/test_luhn.py::test_luhn_vectors_are_ascii_digits PASSED            [ 20%]
tests/test_luhn.py::test_reference_luhn_vectors PASSED                   [ 24%]
tests/test_luhn_yara.py::test_generated_luhn_rule_matches_valid_sample PASSED [ 28%]
tests/test_luhn_yara.py::test_generated_luhn_rules_compile PASSED        [ 32%]
tests/test_luhn_yara.py::test_committed_luhn_rules_are_current PASSED    [ 36%]
tests/test_luhn_yara.py::test_generated_luhn_rule_rejects_invalid_sample PASSED [ 40%]
tests/test_luhn_yara.py::test_generated_luhn_rule_matches_when_any_candidate_is_valid PASSED [ 44%]
tests/test_luhn_yara.py::test_generated_luhn_rules_match_vectors PASSED  [ 48%]
tests/test_luhn_yara.py::test_generated_luhn_rule_matches_formatted_sample[formatted-19.txt-19] PASSED [ 52%]
tests/test_luhn_yara.py::test_generated_luhn_rule_matches_formatted_sample[formatted.txt-16] PASSED [ 56%]
tests/test_luhn_yara.py::test_generated_luhn_rule_matches_formatted_sample[formatted-hyphen.txt-16] PASSED [ 60%]
tests/test_luhn_yara.py::test_generated_luhn_rule_matches_formatted_sample[formatted-mixed.txt-16] PASSED [ 64%]
tests/test_luhn_yara.py::test_generated_luhn_rule_matches_formatted_sample[formatted-15.txt-15] PASSED [ 68%]
tests/test_luhn_yara.py::test_generated_luhn_rule_matches_formatted_sample[formatted-14.txt-14] PASSED [ 72%]
tests/test_luhn_yara.py::test_generated_luhn_rule_rejects_embedded_candidate PASSED [ 76%]
tests/test_luhn_yara.py::test_generated_luhn_rule_rejects_digit_embedded_candidate[94111111111111111] PASSED [ 80%]
tests/test_luhn_yara.py::test_generated_luhn_rule_rejects_digit_embedded_candidate[41111111111111119] PASSED [ 84%]
tests/test_luhn_yara.py::test_generated_luhn_rule_rejects_digit_embedded_candidate[941111111111111119] PASSED [ 88%]
tests/test_luhn_yara.py::test_generated_luhn_rule_allows_nondigit_boundaries[x4111111111111111] PASSED [ 92%]
tests/test_luhn_yara.py::test_generated_luhn_rule_allows_nondigit_boundaries[4111111111111111y] PASSED [ 96%]
tests/test_luhn_yara.py::test_generated_luhn_rule_allows_nondigit_boundaries[x4111111111111111y] PASSED [100%]

============================== 25 passed in 0.33s ==============================

============================================================
 Testing YARA 4.2.3
============================================================


=== Testing YARA 4.2.3 ===

============================= test session starts ==============================
platform linux -- Python 3.11.2, pytest-9.1.1, pluggy-1.6.0 -- /venv/bin/python
rootdir: /work
configfile: pyproject.toml
collecting ... collected 25 items

tests/test_luhn.py::test_reference_luhn_rejects_malformed_input[] PASSED [  4%]
tests/test_luhn.py::test_reference_luhn_rejects_malformed_input[411111111111111x] PASSED [  8%]
tests/test_luhn.py::test_reference_luhn_rejects_malformed_input[\uff14\uff11\uff11\uff11\uff11\uff11\uff11\uff11\uff11\uff11\uff11\uff11\uff11\uff11\uff11\uff11] PASSED [ 12%]
tests/test_luhn.py::test_luhn_vectors_exist PASSED                       [ 16%]
tests/test_luhn.py::test_luhn_vectors_are_ascii_digits PASSED            [ 20%]
tests/test_luhn.py::test_reference_luhn_vectors PASSED                   [ 24%]
tests/test_luhn_yara.py::test_generated_luhn_rule_matches_valid_sample PASSED [ 28%]
tests/test_luhn_yara.py::test_generated_luhn_rules_compile PASSED        [ 32%]
tests/test_luhn_yara.py::test_committed_luhn_rules_are_current PASSED    [ 36%]
tests/test_luhn_yara.py::test_generated_luhn_rule_rejects_invalid_sample PASSED [ 40%]
tests/test_luhn_yara.py::test_generated_luhn_rule_matches_when_any_candidate_is_valid PASSED [ 44%]
tests/test_luhn_yara.py::test_generated_luhn_rules_match_vectors PASSED  [ 48%]
tests/test_luhn_yara.py::test_generated_luhn_rule_matches_formatted_sample[formatted-19.txt-19] PASSED [ 52%]
tests/test_luhn_yara.py::test_generated_luhn_rule_matches_formatted_sample[formatted.txt-16] PASSED [ 56%]
tests/test_luhn_yara.py::test_generated_luhn_rule_matches_formatted_sample[formatted-hyphen.txt-16] PASSED [ 60%]
tests/test_luhn_yara.py::test_generated_luhn_rule_matches_formatted_sample[formatted-mixed.txt-16] PASSED [ 64%]
tests/test_luhn_yara.py::test_generated_luhn_rule_matches_formatted_sample[formatted-15.txt-15] PASSED [ 68%]
tests/test_luhn_yara.py::test_generated_luhn_rule_matches_formatted_sample[formatted-14.txt-14] PASSED [ 72%]
tests/test_luhn_yara.py::test_generated_luhn_rule_rejects_embedded_candidate PASSED [ 76%]
tests/test_luhn_yara.py::test_generated_luhn_rule_rejects_digit_embedded_candidate[94111111111111111] PASSED [ 80%]
tests/test_luhn_yara.py::test_generated_luhn_rule_rejects_digit_embedded_candidate[41111111111111119] PASSED [ 84%]
tests/test_luhn_yara.py::test_generated_luhn_rule_rejects_digit_embedded_candidate[941111111111111119] PASSED [ 88%]
tests/test_luhn_yara.py::test_generated_luhn_rule_allows_nondigit_boundaries[x4111111111111111] PASSED [ 92%]
tests/test_luhn_yara.py::test_generated_luhn_rule_allows_nondigit_boundaries[4111111111111111y] PASSED [ 96%]
tests/test_luhn_yara.py::test_generated_luhn_rule_allows_nondigit_boundaries[x4111111111111111y] PASSED [100%]

============================== 25 passed in 0.33s ==============================

YARAthmetic compatibility matrix
================================
YARA         RESULT
------------ ------
3.4.0        FAIL
3.5.0        PASS
3.6.3        FAIL
3.8.1        PASS
3.11.0       PASS
4.0.5        PASS
4.1.3        PASS
4.2.3        PASS
