import json
import os


def check_rbi_nbfc(name: str) -> dict:
    """
    Checks if a company appears in the RBI NBFC list.
    This function DOES NOT import orchestrator (avoids circular import).
    """

    try:
        # Path to rbi_list.json inside adapters folder
        base_path = os.path.dirname(__file__)
        file_path = os.path.join(base_path, "rbi_list.json")

        if not os.path.exists(file_path):
            return {"authorized": False, "error": "RBI list file missing"}

        # Load JSON file
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        nbfc_list = data.get("nbfc_list", [])
        query = name.lower()

        # Match partial or full name
        for nbfc in nbfc_list:
            if query in nbfc.lower():
                return {
                    "authorized": True,
                    "matched_name": nbfc
                }

        return {"authorized": False}

    except Exception as e:
        return {"authorized": False, "error": str(e)}
