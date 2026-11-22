"""Fictional data used by the demo, the benchmarks and the tests."""

from __future__ import annotations

AE_NAME = "Ente di Accreditamento"
ISSUER_NAME = "Université de Rennes"
VERIFIER_NAME = "Università di Salerno"

DEMO_STUDENT_PASSWORD = "erasmus-demo-password"
DEMO_WALLET_PASSPHRASE = "wallet-demo-passphrase"

SAMPLE_RECORD: dict = {
    "givenName": "Giulia",
    "familyName": "Bianchi",
    "birthDate": "2001-04-12",
    "nationality": "IT",
    "email": "giulia.bianchi@studenti.example.org",
    "homeUniversity": {
        "name": "Università degli Studi di Salerno",
        "country": "Italia",
        "erasmusCode": "I SALERNO01",
    },
    "hostUniversity": {
        "name": "Université de Rennes",
        "country": "France",
        "erasmusCode": "F RENNES01",
    },
    "mobilityPeriod": {"startDate": "2025-09-22", "endDate": "2026-02-28"},
    "learningAgreement": {
        "semester": "2025/2026 - Semester 1",
        "agreedCourses": [
            {"id": 1, "title": "Data Science", "language": "English", "ects": 9,
             "status": "Passed", "grade": "27/30", "honor": False},
            {"id": 2, "title": "Automation", "language": "English", "ects": 9,
             "status": "Passed", "grade": "30/30", "honor": True},
            {"id": 3, "title": "Design and Analysis of Algorithms", "language": "English", "ects": 9,
             "status": "Failed", "grade": None, "honor": False},
            {"id": 4, "title": "Machine Learning", "language": "English", "ects": 9,
             "status": "Not taken", "grade": None, "honor": False},
            {"id": 5, "title": "Niveau de langue française - A2", "language": "French", "ects": 3,
             "status": "Passed", "grade": "Pass", "honor": False},
        ],
    },
    "optionalExperience": {
        "canteen": True,
        "dormitory": True,
        "extracurricularActivities": ["Erasmus Hackathon", "Atelier de théâtre"],
        "optionalCourses": [
            {"id": 6, "title": "Embedded Systems", "language": "English", "ects": 9,
             "status": "Not taken", "grade": None, "honor": False},
        ],
    },
}
