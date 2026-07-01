from queries.search_queries import *

print("\nThreat Actor")
print(get_actor_by_name("FIN6"))

print("\nMalware")
print(get_malware_by_name("Emotet"))

print("\nTechnique")
print(get_technique_by_id("T1059"))

print("\nCVE")
print(get_cve_by_id("CVE-1999-0095"))

print("\nIOC")
print(get_ioc_by_value("gnw.glamisrents.com"))

print(
    get_pulse_by_name(
        "Python Backdoor Threat Analysis Following an AI Deepfake Impersonation Campaign"
    )
)