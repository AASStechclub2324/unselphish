import pandas as pd
import numpy as np
import emoji
from collections import Counter
from printv import printv


def find_author(s):
    s = s.split(": ")
    if len(s)==2:
        return True
    else:
        return False

def getDatapoint(line):
    splitline = line.split(' - ')
    dateTime = splitline[0]

    message = " ".join(splitline[1:])
    if find_author(message):
        splitmessage = message.split(": ")
        author = splitmessage[0]

        message = " ".join(splitmessage[1:])
    else:
        author= None
    return author, message


def parse_chat_file(filename):
    data = []
    # conversation = 'WhatsApp Chat with Sapna.txt'
    printv("\n[+]Reading messages from file...\n")
    with open(filename, encoding="utf-8") as fp:
        messageBuffer = []
        author = None, None, None
        lines = fp.readlines()
        for line in lines[1:]:
            line = line.strip()
            author, message = getDatapoint(line)
            messageBuffer.append(message)
            if len(messageBuffer) > 0:
                data.append([author, ' '.join(messageBuffer)])
                messageBuffer.clear()
            else:
                messageBuffer.append(line)

    df = pd.DataFrame(data, columns=['Author', 'Message'])
    total_messages = df.shape[0]
    return df['Author'], df['Message']

if __name__ == "__main__":
    author, messages = parse_chat_file(r"C:\Users\USER\Desktop\Unselphish-root\Unselphish\resources\WhatsApp Chat with Mainak Dasgupta.txt")
    print(author)
    print(messages)
