from colorama import Fore, Back, Style
# from colorama import just_fix_windows_console

# try:
#     just_fix_windows_console()
# except:
#     pass
def printv(text="", verbose_dec=True, color="WHITE"):
    if verbose_dec == True:
        if color == "WHITE":
            print(text)
        elif color == "RED":
            print(Fore.RED + str(text) + Style.RESET_ALL)