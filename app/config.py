import os
from dotenv import load_dotenv
load_dotenv()
ROUTERS = {
    "kincar": {
        "host": os.environ["KINCAR_HOST"],
        "port": int(os.environ.get("KINCAR_PORT", 8629)),
        "username": os.environ["KINCAR_USERNAME"],
        "password": os.environ["KINCAR_PASSWORD"],
        "ssh_port": int(os.environ.get("KINCAR_SSH_PORT", 42200)),
    },
    "kariokor": {
        "host": os.environ["KARIOKOR_HOST"],
        "port": int(os.environ.get("KARIOKOR_PORT", 8629)),
        "username": os.environ["KARIOKOR_USERNAME"],
        "password": os.environ["KARIOKOR_PASSWORD"],
        "ssh_port": int(os.environ.get("KARIOKOR_SSH_PORT", 22)),
    },
    "allsops": {
        "host": os.environ["ALLSOPS_HOST"],
        "port": int(os.environ.get("ALLSOPS_PORT", 8728)),
        "username": os.environ["ALLSOPS_USERNAME"],
        "password": os.environ["ALLSOPS_PASSWORD"],
        "ssh_port": int(os.environ.get("ALLSOPS_SSH_PORT", 2200)),
    },
}
GENIEACS = {
    "base_url": os.environ.get("GENIEACS_BASE_URL", "http://172.20.0.1:7557"),
}
