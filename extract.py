import fitz

pdf_path = input("Enter PDF path: ")

doc = fitz.open(pdf_path)

text = ""

for page in doc:
    text += page.get_text()

with open("output.txt", "w", encoding="utf-8") as f:
    f.write(text)

print("Text extracted successfully!")