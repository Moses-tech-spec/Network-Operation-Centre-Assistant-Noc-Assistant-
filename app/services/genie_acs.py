import json
import re
import time

import requests

from app.database.database import db
from app.config import GENIEACS


class GenieACS:
    """
    Core GenieACS service.
    Contains ALL ACS logic.
    Framework-agnostic and reusable across multiple platforms.

    Persistence is plain sqlite3 via app.database.database.db
    (matches the rest of app/services/*.py) — not a Django ORM.
    """

    def __init__(
        self,
        base_url=None,
        device_model=None,
        manufacturer=None,
        serial_number=None
    ):
        self.base_url = base_url or GENIEACS["base_url"]
        self.device_model = device_model
        self.manufacturer = manufacturer
        self.serial_number = serial_number
        self.device_id = None

        self.session = requests.Session()
        self.session.headers.update({
            "Content-Type": "application/json",
            "Accept": "application/json"
        })

    # ------------------------------------------------------------------
    # Compatibility & Utilities
    # ------------------------------------------------------------------

    def check_compatibility(self, integration_function):
        """
        Returns a dict-like row (sqlite3.Row -> dict) with:
        method, endpoint, parameters (already json.loads'd), id
        or None if no active, matching entry exists.
        """
        try:
            row = db.fetchone(
                """
                SELECT
                    cc.id AS id,
                    cc.method AS method,
                    cc.endpoint AS endpoint,
                    cc.parameters AS parameters
                FROM compatibility_chart cc
                JOIN integration_functions f
                    ON f.id = cc.integration_function_id
                WHERE f.title = ?
                    AND f.status = 'Active'
                    AND cc.status = 'Active'
                    AND LOWER(cc.model) = LOWER(?)
                    AND LOWER(cc.manufacturer) = LOWER(?)
                LIMIT 1
                """,
                (integration_function, self.device_model, self.manufacturer)
            )

            if not row:
                return None

            if row.get("parameters"):
                try:
                    row["parameters"] = json.loads(row["parameters"])
                except (TypeError, json.JSONDecodeError):
                    row["parameters"] = {}
            else:
                row["parameters"] = {}

            return row

        except Exception:
            return None

    def is_compatible(self, integration_function):
        spec = self.check_compatibility(integration_function)
        if not spec:
            return {"compatible": False}

        return {
            "compatible": True,
            "method": spec["method"],
            "endpoint": spec["endpoint"],
            "parameters": spec["parameters"]
        }

    def compile_parameters(self, template, data):

        def substitute(value, context):
            if isinstance(value, str):
                placeholders = re.findall(r"\{(\w+)\}", value)
                for key in placeholders:
                    if key in context:
                        value = value.replace(f"{{{key}}}", str(context[key]))
                return value

            if isinstance(value, list):
                return [substitute(v, context) for v in value]

            if isinstance(value, dict):
                return {k: substitute(v, context) for k, v in value.items()}

            return value

        return substitute(template, data)

    # ------------------------------------------------------------------
    # Device Resolution
    # ------------------------------------------------------------------

    def get_device_id_from_serial(self):
        if not self.serial_number:
            return None, "Serial number required"

        result = self.general_genieacs_call(
            integration_function="get_device_id",
            data={}
        )

        if result.get("data") and isinstance(result["data"], list) and result["data"]:
            self.device_id = result["data"][0].get("_id")
            return self.device_id, None

        return None, "Device not found"

    # ------------------------------------------------------------------
    # Core Orchestration
    # ------------------------------------------------------------------

    def execute(self, integration_function, data=None, requires_serial=True):
        if not self.base_url:
            return {"error": "base_url is required"}

        if integration_function != "fetch_devices":
            if not self.device_model or not self.manufacturer:
                return {
                    "error": "device_model and manufacturer are required"
                }

        if requires_serial:
            if not self.serial_number:
                return {"error": "Serial number required"}

            if not self.device_id:
                _, error = self.get_device_id_from_serial()
                if error:
                    return {"error": error}

        return self.general_genieacs_call(
            integration_function=integration_function,
            data=data or {}
        )

    # ------------------------------------------------------------------
    # Core GenieACS Call Engine
    # ------------------------------------------------------------------

    def general_genieacs_call(self, integration_function, data=None):
        if data is None:
            data = {}

        if integration_function == "fetch_devices":
            integration_spec = {
                "method": "GET",
                "endpoint": "devices",
                "parameters": {
                    "projection": "_id,_deviceId._SerialNumber"
                },
                "id": 0
            }
        else:
            integration_spec = self.check_compatibility(integration_function)

        if not integration_spec:
            return {
                "error": f"No compatible integration for {integration_function}"
            }

        url = f"{self.base_url}/{integration_spec['endpoint']}"

        if "{device_id}" in url:
            if not self.device_id:
                return {"error": "Device ID required"}
            url = url.replace("{device_id}", self.device_id)

        if "{serial_number}" in url and self.serial_number:
            url = url.replace("{serial_number}", self.serial_number)

        try:
            if integration_spec["method"] == "POST":
                payload = self.compile_parameters(
                    integration_spec["parameters"],
                    data
                )
                response = self.session.post(url, json=payload)

            elif integration_spec["method"] == "GET":
                params = self.compile_parameters(
                    integration_spec["parameters"],
                    data
                )

                if params.get("query") == "SERIAL_NUMBER_QUERY":
                    params["query"] = json.dumps({
                        "_deviceId._SerialNumber": self.serial_number
                    })

                response = self.session.get(url, params=params)

            else:
                return {"error": "Unsupported method"}

            # GenieACS commonly returns 202 Accepted for task-based
            # operations (refresh, set params, etc.) with no JSON body.
            data_out = None
            if response.status_code in (200, 202):
                try:
                    data_out = response.json()
                except ValueError:
                    data_out = None

            return {
                "status_code": response.status_code,
                "data": data_out,
                "compatibility_id": integration_spec["id"]
            }

        except requests.exceptions.RequestException as e:
            return {"error": str(e)}

    # ------------------------------------------------------------------
    # Single-Step Public Operations
    # ------------------------------------------------------------------

    def fetch_devices(self):
        return self.execute("fetch_devices", requires_serial=False)

    def get_device(self):
        return self.execute("get_device")

    def refresh_parameters(self):
        return self.execute("refresh_parameters")

    def summon_device(self):
        return self.execute("summon_device")

    def set_wifi_credentials(self, ssid, password):
        return self.execute(
            "set_wifi_password_AndSSID",
            {
                "ssid": ssid,
                "password": password
            }
        )

    def ssh_telnet_control(self, enable=True):
        return self.execute(
            "sshTelnet_control",
            {"enable": enable}
        )

    def ethernet_control(self, enable=True):
        return self.execute(
            "ethernet_control",
            {"enable": enable}
        )

    def dhcp_hosts(self):
        return self.execute("dhcp_hosts")

    # ------------------------------------------------------------------
    # Multi-Step PPPoE Provisioning
    # ------------------------------------------------------------------

    def set_pppoe_credentials(self, username, password, mtu=1500):
        if not self.device_id:
            _, error = self.get_device_id_from_serial()
            if error:
                return {"error": error}

        step1 = self.general_genieacs_call(
            "set_pppoe_credentials",
            {"step": "create_wan_device"}
        )
        if step1.get("status_code") not in (200, 202):
            return {"error": "WAN device creation failed", "detail": step1}

        time.sleep(1)

        step2 = self.general_genieacs_call(
            "set_pppoe_credentials",
            {"step": "create_ppp_connection"}
        )
        if step2.get("status_code") not in (200, 202):
            return {"error": "PPP connection creation failed", "detail": step2}

        time.sleep(1)

        step3 = self.general_genieacs_call(
            "set_pppoe_credentials",
            {
                "step": "apply_pppoe",
                "username": username,
                "password": password,
                "mtu": mtu
            }
        )
        if step3.get("status_code") not in (200, 202):
            return {"error": "Failed to apply PPPoE credentials", "detail": step3}

        self.summon_device()

        return {
            "success": True,
            "device_id": self.device_id,
            "status_code": step3.get("status_code")
        }

    # ------------------------------------------------------------------
    # Discovery / Metadata
    # ------------------------------------------------------------------

    def list_available_functions(self):
        rows = db.fetchall(
            """
            SELECT title, description, version, status
            FROM integration_functions
            WHERE status = 'Active'
            """
        )
        return rows

    def list_compatible_devices(self, integration_function):
        rows = db.fetchall(
            """
            SELECT
                cc.manufacturer AS manufacturer,
                cc.model AS model,
                cc.os AS os,
                cc.method AS method,
                cc.endpoint AS endpoint
            FROM compatibility_chart cc
            JOIN integration_functions f
                ON f.id = cc.integration_function_id
            WHERE f.title = ?
                AND cc.status = 'Active'
            """,
            (integration_function,)
        )
        return rows
