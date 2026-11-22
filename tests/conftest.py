from __future__ import annotations

import pytest

from credential_sharing.actors.student import Student
from credential_sharing.sample_data import DEMO_STUDENT_PASSWORD
from credential_sharing.scenario import System, build_system, sample_record

COURSE_1 = "learningAgreement.agreedCourses.1"
COURSE_2 = "learningAgreement.agreedCourses.2"
COURSE_3 = "learningAgreement.agreedCourses.3"


class FakeClock:
    """Monotonic clock under test control (throttling, OTP and challenge expiry)."""

    def __init__(self) -> None:
        self.now = 1_000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def system(clock: FakeClock) -> System:
    return build_system(clock=clock)


@pytest.fixture
def student(system: System) -> Student:
    return system.new_student(sample_record())


@pytest.fixture
def holder(system: System, student: Student) -> Student:
    """A student whose wallet already holds a verified credential."""
    student.obtain_credential(system.issuer, DEMO_STUDENT_PASSWORD, system.otp_reader(student))
    return student


@pytest.fixture
def other_student(system: System) -> Student:
    record = sample_record() | {"givenName": "Aldo", "familyName": "Neri", "email": "aldo.neri@example.org"}
    return system.new_student(record)
