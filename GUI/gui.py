import tkinter
from tkinter import filedialog
import tkinter.messagebox
import customtkinter
import os
from PIL import Image
 
records={'scanlink':[],'scandomain':[],'tremail':[],'singularmsg':[],'trwp':[],'scanfile':[]}

customtkinter.set_appearance_mode("System")  # Modes: "System" (standard), "Dark", "Light"
customtkinter.set_default_color_theme("blue")  # Themes: "blue" (standard), "green", "dark-blue"
 
app = customtkinter.CTk()
app.geometry('800x600')
app.title('Unselphish.exe')

frame_1 = customtkinter.CTkFrame(master=app)
frame_1.pack(anchor='e', expand=True, fill='both', in_=app, ipadx=5, ipady=5, padx=10, pady=10)

#file explorer window
def browseFiles():
    filename = filedialog.askopenfilename(initialdir = "/",
                                          title = "Select a File",
                                          filetypes = (("Text files",
                                                        "*.txt*"),
                                                       ("all files",
                                                        "*.*")))
    return filename

def scanLink():
    dialog = customtkinter.CTkInputDialog(text="Enter Link", title="Scan Link")
    records['scanlink'].append(dialog.get_input())
 
button_1 = customtkinter.CTkButton(master=frame_1, command=scanLink, text='Scan Link')
button_1.pack(pady=10, padx=10, anchor='w')
 
def scanDomain():
    dialog = customtkinter.CTkInputDialog(text="Enter Domain", title="Scan Domain")
    records['scandomain'].append(dialog.get_input())
 
button_2 = customtkinter.CTkButton(master=frame_1, command=scanDomain, text='Scan Domain')
button_2.pack(pady=10, padx=10, anchor='w')
 
def TRemail():
    records['tremail'].append(browseFiles())
 
button_3 = customtkinter.CTkButton(master=frame_1, command=TRemail, text='Threat Report from downloaded email (.eml)')
button_3.pack(pady=10, padx=10, anchor='w')
 
def SingularMsg():
    dialog = customtkinter.CTkInputDialog(text="Enter Singular Message", title="Scan Singular Message")
    records['singularmsg'].append(dialog.get_input())
 
button_4 = customtkinter.CTkButton(master=frame_1, command=SingularMsg, text='Scan Singular Message')
button_4.pack(pady=10, padx=10, anchor='w')
 
def TRwp():
    records['trwp'].append(browseFiles())
 
button_5 = customtkinter.CTkButton(master=frame_1, command=TRwp, text='Enter Threat Report from WhatsAap chat')
button_5.pack(pady=10, padx=10, anchor='w')
 
def scanFile():
    records['scanfile'].append(browseFiles())
 
button_6 = customtkinter.CTkButton(master=frame_1, command=scanFile, text='Scan File')
button_6.pack(pady=10, padx=10, anchor='w')

text_1 = customtkinter.CTkTextbox(master=frame_1, width=760, height=70)
text_1.pack(pady=10, padx=10, anchor='s', expand=True, fill='both')
text_1.insert("0.0", "...")
 
 
app.mainloop()