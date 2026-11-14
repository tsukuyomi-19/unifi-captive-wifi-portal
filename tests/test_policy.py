import pytest

from conftest import (
    DISABLED_STUDENT_DN,
    SERVICE_ACCOUNT_DN,
    STAFF_DN,
    STUDENT_DN,
    TEACHER_DN,
    TEST_POLICY_TEXT,
)
from policy import PolicyError, load_policy, parse_policy


def test_classifies_ldap_dns(policy):
    assert policy.classify(STUDENT_DN) == "student"
    assert policy.classify(STAFF_DN) == "staff"


def test_classifies_teachers_via_the_tree_root(policy):
    """A teacher's DN is ou=...Teachers,ou=Teachers,ou=Staff & Teachers - it has
    no "ou=Staff" component of its own, so it is only matched by the root
    pattern. An earlier policy used bare "ou=Staff" and caught these only
    because "ou=Staff & Teachers" happens to contain that substring."""
    assert policy.classify(TEACHER_DN) == "staff"


def test_disabled_accounts_are_denied(policy):
    """Accounts under ou=_DISABLE ME include former students filed by
    graduation year. Their DN contains no "ou=Students", but they must be denied
    explicitly rather than by accident."""
    assert policy.classify(DISABLED_STUDENT_DN) == "disabled"
    assert policy.is_allowed("Campus Student", "disabled") is False
    assert policy.is_allowed("Campus Staff", "disabled") is False
    assert policy.other_ssids_for("disabled") == []


def test_service_accounts_are_denied(policy):
    assert policy.classify(SERVICE_ACCOUNT_DN) == "disabled"
    assert policy.other_ssids_for("disabled") == []


def test_deny_rules_take_precedence_over_allow_rules(policy):
    """Order matters. A disabled account whose DN also contained a live OU name
    must still be denied, so the deny rules are listed first."""
    hybrid = "uid=x,ou=Students,ou=_DISABLE ME,ou=Users,dc=example,dc=org"
    assert policy.classify(hybrid) == "disabled"


def test_classifies_directory_org_unit_paths(policy):
    assert policy.classify("/Students") == "student"
    assert policy.classify("/Staff & Teachers") == "staff"
    assert policy.classify("/Staff & Teachers/Teachers/High School Teachers") == "staff"


def test_classification_is_case_insensitive(policy):
    assert policy.classify(STUDENT_DN.upper()) == "student"
    assert policy.classify("/staff & TEACHERS") == "staff"


def test_unrecognized_ou_returns_none(policy):
    assert policy.classify("uid=x,ou=Contractors,ou=Users,dc=example,dc=org") is None
    assert policy.classify("") is None


def test_first_matching_rule_wins():
    """Order matters: a narrow rule above a broad one must take precedence."""
    p = parse_policy(
        """
        [roles]
        ou=Student Teachers -> staff
        ou=Student -> student
        [ssids]
        X -> student
        """
    )
    assert p.classify("uid=a,ou=Student Teachers,ou=Users") == "staff"
    assert p.classify("uid=b,ou=Students,ou=Users") == "student"


def test_ssid_allowlist(policy):
    assert policy.is_allowed("Campus Student", "student") is True
    assert policy.is_allowed("Campus Student", "staff") is False
    assert policy.is_allowed("Campus Staff", "staff") is True


def test_unlisted_ssid_denies_everyone(policy):
    """Fail closed - the previous hardcoded version fell through to authorize."""
    assert policy.is_allowed("Some Other Network", "student") is False
    assert policy.is_allowed("", "staff") is False


def test_ssid_comparison_is_case_sensitive(policy):
    assert policy.is_allowed("campus student", "student") is False


def test_multiple_roles_on_one_ssid():
    p = parse_policy(
        """
        [roles]
        ou=Students -> student
        ou=Staff -> staff
        [ssids]
        Shared -> student, staff
        """
    )
    assert p.is_allowed("Shared", "student") is True
    assert p.is_allowed("Shared", "staff") is True


def test_repeated_ssid_lines_union_rather_than_replace():
    p = parse_policy(
        """
        [roles]
        ou=Students -> student
        [ssids]
        Net -> student
        Net -> staff
        """
    )
    assert p.ssid_roles["Net"] == {"student", "staff"}


def test_other_ssids_for_role(policy):
    assert policy.other_ssids_for("student") == ["Campus Student"]
    assert policy.other_ssids_for("staff") == ["Campus Staff"]
    assert policy.other_ssids_for("nobody") == []


def test_patterns_may_contain_equals_signs():
    """"->" is the separator precisely so LDAP RDNs like ou=Students work."""
    p = parse_policy("[roles]\nou=Students -> student\n[ssids]\nA -> student\n")
    assert p.role_rules == [("ou=Students", "student")]


def test_comments_and_blank_lines_ignored():
    p = parse_policy(
        """
        # leading comment

        [roles]
        ou=Students -> student   # trailing comment
        [ssids]
        A -> student
        """
    )
    assert p.role_rules == [("ou=Students", "student")]
    assert p.ssid_roles == {"A": {"student"}}


@pytest.mark.parametrize(
    "text, fragment",
    [
        ("[roles]\nou=Students -> student\n", "no [ssids]"),
        ("[ssids]\nA -> student\n", "no [roles]"),
        ("[roles]\nbroken line\n[ssids]\nA -> b\n", "expected 'key -> value'"),
        ("ou=Students -> student\n", "before any [section]"),
        ("[nope]\na -> b\n", "unknown section"),
        ("[roles]\n -> student\n[ssids]\nA -> b\n", "empty key or value"),
    ],
)
def test_malformed_policy_raises_with_a_useful_message(text, fragment):
    with pytest.raises(PolicyError) as e:
        parse_policy(text)
    assert fragment in str(e.value)


def test_missing_file_names_the_path(tmp_path):
    missing = str(tmp_path / "absent.conf")
    with pytest.raises(PolicyError) as e:
        load_policy(missing)
    assert "absent.conf" in str(e.value)


def test_example_policy_file_parses():
    """The shipped example must always be valid - it is what operators copy."""
    from pathlib import Path

    example = Path(__file__).resolve().parent.parent / "ou-policy.conf.example"
    p = parse_policy(example.read_text(encoding="utf-8"))
    # Staff SSID is commented out on purpose there; see the file's own comments.
    assert p.known_ssids() == ["Campus Student"]
    # Every real OU shape the directory actually contains must classify.
    assert p.classify(STUDENT_DN) == "student"
    assert p.classify(STAFF_DN) == "staff"
    assert p.classify(TEACHER_DN) == "staff"
    assert p.classify(DISABLED_STUDENT_DN) == "disabled"
    assert p.classify(SERVICE_ACCOUNT_DN) == "disabled"
    # ...and only students may use the one enabled SSID.
    assert p.is_allowed("Campus Student", "student") is True
    assert p.is_allowed("Campus Student", "staff") is False
    assert p.is_allowed("Campus Student", "disabled") is False


def test_test_policy_text_is_itself_valid():
    assert parse_policy(TEST_POLICY_TEXT).known_ssids() == ["Campus Staff", "Campus Student"]
