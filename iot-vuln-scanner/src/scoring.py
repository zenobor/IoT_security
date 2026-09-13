"""
scoring.py
Calcola un livello di rischio (basso/medio/alto) per ogni dispositivo.
"""


def calculate_risk(vulnerabilities: list[dict], iot_flags: dict) -> str:
    """
    Combina CVE trovate e flag delle regole IoT-specifiche
    per assegnare un livello di rischio.

    Returns:
        "low", "medium" o "high"
    """
    # TODO: definire una logica di scoring (es. pesi per tipo di problema)
    raise NotImplementedError
