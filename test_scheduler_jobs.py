from app.scheduler.scheduler import scheduler
from app.scheduler.scheduler import start_scheduler

start_scheduler()

print()

print("Registered Jobs")

print("-------------------------")

for job in scheduler.get_jobs():

    print(job.id)
