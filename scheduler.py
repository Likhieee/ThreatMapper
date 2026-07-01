from apscheduler.schedulers.blocking import BlockingScheduler
import os

scheduler = BlockingScheduler()

@scheduler.scheduled_job('interval', minutes=1)
def update_data():
    print("Running Update...")
    os.system("python cve_collector.py")
    os.system("python threatfox_collector.py")
    os.system("python otx_collector.py")

    print("Update Complete!")

print("Scheduler Started...")

scheduler.start()