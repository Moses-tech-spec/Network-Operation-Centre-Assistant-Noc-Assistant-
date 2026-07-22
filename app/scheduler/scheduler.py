from apscheduler.schedulers.background import BackgroundScheduler

from app.services.ospf import OSPFCollector
from app.services.bgp import BGPCollector
from app.services.firewall import FirewallCollector
from app.services.telemetry import TelemetryCollector
from app.services.inventory import InventoryCollector
from app.services.pppoe import PPPoECollector
from app.services.interfaces import InterfaceCollector
from app.services.incidents import IncidentEngine


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

    scheduler.start()

    print("===================================")
    print("Scheduler Started")
    print("Telemetry      : 30 seconds")
    print("Inventory      : 5 minutes")
    print("PPPoE          : 30 seconds")
    print("Interfaces     : 30 seconds")
    print("Incident Engine: 30 seconds")
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
