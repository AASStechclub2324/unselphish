import regex
import pandas as pd
import numpy as np
import emoji
from collections import Counter
import matplotlib.pyplot as plt
from wordcloud import WordCloud, STOPWORDS, ImageColorGenerator
from printv import printv
import re

def startsWithDateAndTime(s):
    pattern = '^([0-9]+)(/)([0-9]+)(/)([0-9][0-9]), ([0-9]+):([0-9][0-9]) (AM|PM) -'
    result = re.match(pattern, s)
    if result:
        return True
    return False

def find_author(s):
    s = s.split(":")
    if len(s)==2:
        return True
    else:
        return False

def getDatapoint(line):
    splitline = line.split(' - ')
    dateTime = splitline[0]
    date, time = dateTime.split(", ")
    message = " ".join(splitline[1:])
    if find_author(message):
        splitmessage = message.split(": ")
        author = splitmessage[0]
        message = " ".join(splitmessage[1:])
    else:
        author= None
    return date, time, author, message


def parse_chat_file(filename):
    data = []
    # conversation = 'WhatsApp Chat with Sapna.txt'
    printv("\n[+]Reading messages from file...\n")
    try:
        print('true1')
        with open(filename, encoding="utf-8") as fp:
            print('true2')
            messageBuffer = []
            date, time, author = None, None, None
            lines = fp.readlines()
            for line in lines:
                line = line.strip()
                if startsWithDateAndTime(line):
                    print('true4')
                    date, time, author, message = getDatapoint(line)
                    messageBuffer.append(message)
                if len(messageBuffer) > 0:
                    data.append([date, time, author, ' '.join(messageBuffer)])
                    messageBuffer.clear()
                else:
                    messageBuffer.append(line)
    except:
        printv("\n[-]Failed to read and parse chat file\n")

    df = pd.DataFrame(data, columns=["Date", 'Time', 'Author', 'Message'])
    total_messages = df.shape[0]
    print(total_messages)
    return df['Author'], df['Message']

if __name__ == "__main__":
    author, messages = parse_chat_file(r"C:\Users\USER\Desktop\Unselphish-root\Unselphish\resources\WhatsApp Chat with Mainak Dasgupta.txt")
    print(author)
    print(messages)