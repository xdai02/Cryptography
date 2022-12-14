import os

REMOVE = [
    ".aux", ".bcf", ".idx",
    ".log", ".ptc", ".xml",
    ".gz", ".toc", ".out",
]

for root, dirs, files in os.walk(os.getcwd()):
    for file in files:
        postfix = file[file.rfind("."):]
        if postfix in REMOVE:
            try:
                os.remove(os.path.join(root, file))
                print("DELETED: " + file)
            except:
                pass
