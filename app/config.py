import os
from dotenv import load_dotenv

load_dotenv()

ROUTERS = {
    "kincar": {
        "host": os.environ["KINCAR_HOST"],
        "port": int(os.environ.get("KINCAR_PORT", 8629)),
        "username": os.environ["KINCAR_USERNAME"],
        "password": os.environ["KINCAR_PASSWORD"],
    },
    "kariokor": {
        "host": os.environ["KARIOKOR_HOST"],
        "port": int(os.environ.get("KARIOKOR_PORT", 8629)),
        "username": os.environ["KARIOKOR_USERNAME"],
        "password": os.environ["KARIOKOR_PASSWORD"],
    },
}
