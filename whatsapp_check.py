import sys
from whatsparser import WhatsParser 
from printv import printv
from emoji import get_emoji_regexp

def remove_emojis(message):
    try:
        message['content'] = get_emoji_regexp().sub(r'', message['content'])
    except:
        return message
    return message

def parse_chat_file(file):
    printv("\n[+]Reading messages from file...\n")
    try:
        messages = WhatsParser(file)    
    except:
        printv("\n[-]Failed to read and parse chat file\n")
    messages = [remove_emojis(message) for message in messages]
    # message['content']
    # message['datetime']
    # message['author']
    authors = []
    for message in messages:
        if message['author'] not in authors:
            authors.append(message['author'])

    return messages, authors


