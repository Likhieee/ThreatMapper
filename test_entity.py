from utils.entity_extractor import extract_actor

question = input("Question: ")

actor = extract_actor(question)

print("\nDetected Actor:")

print(actor)