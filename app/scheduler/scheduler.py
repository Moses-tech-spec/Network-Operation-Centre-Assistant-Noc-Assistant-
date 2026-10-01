from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from app.services.daily_report import send_daily_report
from app.services.ospf import OSPFCollector
from app.services.bgp import BGPCollector
from app.services.firewall import FirewallCollector
from app.services.telemetry import TelemetryCollector
from app.services.inventory import InventoryCollector
from app.services.pppoe import PPPoECollector
from app.services.interfaces import InterfaceCollector
from app.services.incidents import IncidentEngine
from app.services.config_backup import commit_config_backups, apply_merged_proposals, detect_config_drift
from app.services.posture import run_posture_scan
from app.services.ppp_anomaly import detect_ppp_anomalies
from app.services.traffic_anomaly import detect_traffic_anomalies
from app.services.usage_history import LinkUsageCollector, QueueUsageCollector

scheduler = BackgroundScheduler()

# ==========================================================
# Jobs
# ==========================================================
def telemetry_job():
    print("Running Telemetry Collector...")
    TelemetryCollector.collect()

def inventory_job():
    print("Running Inventory Collector...")
    InventoryCollector.collect()

def pppoe_job():
    print("Running PPPoE Collector...")
    PPPoECollector.collect()

def interface_job():
    print("Running Interface Collector...")
    InterfaceCollector.collect()

def incident_job():
    print("Running Incident Engine...")
    IncidentEngine.run()

def config_backup_job():
    print("Running Config Backup...")
    result = commit_config_backups()
    if not result.get("success"):
        print(f"Config backup job reported failure: {result.get('message')}")

def apply_proposals_job():
    print("Checking for merged config proposals...")
    result = apply_merged_proposals()
    applied = [r for r in result.get("results", []) if r.get("status") == "applied"]
    if applied:
        print(f"Applied {len(applied)} merged proposal(s): {applied}")

def drift_detection_job():
    print("Checking for config drift...")
    result = detect_config_drift()
    drifted = [r for r in result.get("results", []) if r.get("status") == "drift"]
    if drifted:
        print(f"Drift detected: {drifted}")

def posture_scan_job():
    print("Running security posture scan...")
    results = run_posture_scan(include_version_check=False)
    print(f"Posture scan complete: {results}")

def posture_version_check_job():
    print("Running RouterOS version check...")
    results = run_posture_scan(include_version_check=True)
    print(f"Version check complete: {results}")

def ppp_anomaly_job():
    print("Checking for PPP anomalies...")
    results = detect_ppp_anomalies()
    print(f"PPP anomaly check complete: {results}")

def link_usage_job():
    print("Running Link Usage Collector...")
    LinkUsageCollector.collect()

def queue_usage_job():
    print("Running Queue Usage Collector...")
    QueueUsageCollector.collect()

def daily_report_job():
    print("Sending daily report...")
    send_daily_report()

def traffic_anomaly_job():
    print("Checking for traffic anomalies...")
    results = detect_traffic_anomalies()
    print(f"Traffic anomaly check complete: {results}")

# ==========================================================
# Scheduler
# ==========================================================
def start_scheduler():
    scheduler.add_job(
        ospf_job,
        "interval",
        minutes=5,
        id="ospf"
    )
    scheduler.add_job(
        bgp_job,
        "interval",
        minutes=2,
        id="bgp"
    )
    scheduler.add_job(
        firewall_job,
        "interval",
        minutes=2,
        id="firewall"
    )
    scheduler.add_job(
        telemetry_job,
        "interval",
        seconds=30,
        id="telemetry"
    )
    scheduler.add_job(
        inventory_job,
        "interval",
        minutes=5,
        id="inventory"
    )
    scheduler.add_job(
        pppoe_job,
        "interval",
        seconds=30,
        id="pppoe"
    )
    scheduler.add_job(
        interface_job,
        "interval",
        seconds=30,
        id="interfaces"
    )
    scheduler.add_job(
        incident_job,
        "interval",
        seconds=30,
        id="incident"
    )
    scheduler.add_job(
        config_backup_job,
        "interval",
        hours=24,
        id="config_backup"
    )
    scheduler.add_job(
        apply_proposals_job,
        "interval",
        minutes=5,
        id="apply_proposals"
    )
    scheduler.add_job(
        drift_detection_job,
        "interval",
        minutes=15,
        id="drift_detection"
    )
    scheduler.add_job(
        posture_scan_job,
        "interval",
        minutes=15,
        id="posture_scan"
    )
    scheduler.add_job(
        posture_version_check_job,
        "interval",
        hours=24,
        id="posture_version_check"
    )
    scheduler.add_job(
        ppp_anomaly_job,
        "interval",
        minutes=2,
        id="ppp_anomaly"
    )
    scheduler.add_job(
        link_usage_job,
        "interval",
        minutes=5,
        id="link_usage"
    )
    scheduler.add_job(
        queue_usage_job,
        "interval",
        minutes=5,
        id="queue_usage"
    )
    scheduler.add_job(
        daily_report_job,
        CronTrigger(hour=7, minute=0, timezone="Africa/Nairobi"),
        id="daily_report"
    )
    scheduler.add_job(
        traffic_anomaly_job,
        "interval",
        minutes=2,
        id="traffic_anomaly"
    )
    scheduler.start()
    print("===================================")
    print("Scheduler Started")
    print("Telemetry      : 30 seconds")
    print("Inventory      : 5 minutes")
    print("PPPoE          : 30 seconds")
    print("Interfaces     : 30 seconds")
    print("Incident Engine: 30 seconds")
    print("Config Backup  : 24 hours")
    print("Apply Proposals: 5 minutes")
    print("Drift Detection: 15 minutes")
    print("Posture Scan: 15 minutes")
    print("RouterOS Version Check: 24 hours")
    print("PPP Anomaly Detection: 2 minutes")
    print("Traffic Anomaly Detection: 2 minutes")
    print("Daily Report: 07:00 daily")
    print("===================================")

def stop_scheduler():
    scheduler.shutdown(wait=False)
    print("Scheduler Stopped")

# ==========================================
# Firewall
# ==========================================
def firewall_job():
    print("Running Firewall Collector...")
    FirewallCollector.collect()

# ==========================================
# BGP
# ==========================================
def bgp_job():
    print("Running BGP Collector...")
    BGPCollector.collect()

# ==========================================
# OSPF
# ==========================================
def ospf_job():
    print("Running OSPF Collector...")
    OSPFCollector.collect()
