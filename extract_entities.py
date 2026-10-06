import spacy
import os

nlp = spacy.load("en_core_web_sm")

folder = "extracted_text"

for file in os.listdir(folder):
    if file.endswith(".txt"):

        path = os.path.join(folder, file)

        with open(path, "r", encoding="utf-8") as f:
            text = f.read()

        doc = nlp(text[:5000])

        print("\nFILE:", file)

        for ent in doc.ents[:20]:
            print(ent.text, "->", ent.label_)