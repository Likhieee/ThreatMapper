import fitz
import os

pdf_root = "CTI-HAL-main"
output_folder = "extracted_text"

os.makedirs(output_folder, exist_ok=True)

for root, dirs, files in os.walk(pdf_root):
    for file in files:
        if file.endswith(".pdf"):

            pdf_path = os.path.join(root, file)

            try:
                doc = fitz.open(pdf_path)

                text = ""

                for page in doc:
                    text += page.get_text()

                output_file = os.path.join(
                    output_folder,
                    file.replace(".pdf",".txt")
                )

                with open(output_file,"w",encoding="utf-8") as f:
                    f.write(text)

                print("Done:",file)

            except Exception as e:
                print(e)